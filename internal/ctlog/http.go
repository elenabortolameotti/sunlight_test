package ctlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"filippo.io/sunlight/internal/my_crypto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SignedEntry represents a signed log entry with authentication
type SignedEntry struct {
	Data         []byte `json:"data"`
	Timestamp    int64  `json:"timestamp"`
	SigAlgorithm string `json:"sig_algorithm,omitempty"`

	// Single-signer format.
	// Used by threshold=1 entries and by staged partial submissions.
	EntityID  string `json:"entity_id,omitempty"`
	Signature []byte `json:"signature,omitempty"`

	// Multi-signer Ed25519 format.
	// Used when a staged entry is finalized with multiple Ed25519 signatures.
	EntityIDs  []string `json:"entity_ids,omitempty"`
	Signatures [][]byte `json:"signatures,omitempty"`

	// BLS aggregate format.
	// Used when a finalized entry stores an aggregate BLS signature.
	AggregateSignature []byte `json:"aggregate_signature,omitempty"`

	// BLS partial signature format.
	// Used when a single entity submits a BLS partial signature during staging.
	BLSSignature []byte `json:"bls_signature,omitempty"`

	// SignerTimestamps preserves every entity's original submission timestamp.
	// This is for auditability: the log entry Timestamp is LastSubmissionAt
	// (for validation), but all individual timestamps are kept here.
	SignerTimestamps []SignerTimestamp `json:"signer_timestamps,omitempty"`
}

// SignerTimestamp records a single entity's submission time.
type SignerTimestamp struct {
	EntityID  string `json:"entity_id"`
	Timestamp int64  `json:"timestamp"`
}

// IsTimestampValid checks if the timestamp is within acceptable window
func (e *SignedEntry) IsTimestampValid() bool {
	// Allow ±5 minutes from current time
	now := time.Now().UnixMilli()
	diff := now - e.Timestamp
	if diff < 0 {
		diff = -diff
	}
	return diff <= 5*60*1000 // 5 minutes in milliseconds
}

// Verify checks if the signature is valid for this entry
func (e *SignedEntry) Verify(pubKey ed25519.PublicKey) bool {
	// Reconstruct the signed data: data || entity_id || timestamp
	var buf bytes.Buffer
	buf.Write(e.Data)
	buf.WriteString(e.EntityID)
	buf.WriteString(fmt.Sprintf("%d", e.Timestamp))

	signedData := sha256.Sum256(buf.Bytes())
	return ed25519.Verify(pubKey, signedData[:], e.Signature)
}

func (l *Log) Handler() http.Handler {
	submitLabels := prometheus.Labels{"endpoint": "submit"}
	submit := http.Handler(http.HandlerFunc(l.submit))
	submit = promhttp.InstrumentHandlerCounter(l.m.ReqCount.MustCurryWith(submitLabels), submit)
	submit = promhttp.InstrumentHandlerDuration(l.m.ReqDuration.MustCurryWith(submitLabels), submit)
	submit = promhttp.InstrumentHandlerInFlight(l.m.ReqInFlight.With(submitLabels), submit)

	mux := http.NewServeMux()
	mux.Handle("POST /submit", submit)
	mux.Handle("OPTIONS /submit", submit)
	return http.MaxBytesHandler(mux, 128*1024)
}

func (l *Log) submit(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		rw.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	rsp, code, err := l.submitEntry(r.Context(), r.Body)
	if err != nil {
		l.c.Log.DebugContext(r.Context(), "submit error", "code", code, "err", err)
		if code == http.StatusServiceUnavailable {
			rw.Header().Set("Retry-After", fmt.Sprintf("%d", 30+rand.Intn(60)))
			http.Error(rw, "server busy, please retry later", code)
			return
		}
		http.Error(rw, err.Error(), code)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	if _, err := rw.Write(rsp); err != nil {
		l.c.Log.DebugContext(r.Context(), "failed to write submit response", "err", err)
		return
	}
}

// What the log does:
// pretendo data e timestamp
//parso la WBB entry
//controllo la policy
//se threshold == 1:
//   pretendo entity_id + signature
//   verifico Ed25519
//se threshold > 1:
//   pretendo entity_ids + aggregate_signature
//   verifico BLS aggregata

func (l *Log) verifySingleWBBEntry(signedEntry SignedEntry, wbbEntry WBBEntry) error {
	if signedEntry.EntityID == "" {
		return fmtErrorf("missing entity_id field")
	}
	if len(signedEntry.Signature) == 0 {
		return fmtErrorf("missing signature field")
	}

	entityRole, err := roleFromEntityID(signedEntry.EntityID)
	if err != nil {
		return fmtErrorf("invalid entity ID: %w", err)
	}

	if entityRole != wbbEntry.Role {
		return fmtErrorf(
			"entity %s cannot write as role %s",
			signedEntry.EntityID,
			wbbEntry.Role,
		)
	}

	pubKey, exists := l.entityKeys[signedEntry.EntityID]
	if !exists {
		return fmtErrorf("unknown entity: %s", signedEntry.EntityID)
	}

	if !signedEntry.Verify(pubKey) {
		return fmtErrorf("invalid signature")
	}

	return nil
}

func aggregateSignedMessage(data []byte, timestamp int64, entityIDs []string) []byte {
	var buf bytes.Buffer
	buf.Write(data)
	buf.WriteString(fmt.Sprintf("%d", timestamp))

	for _, entityID := range entityIDs {
		buf.WriteString("|")
		buf.WriteString(entityID)
	}

	h := sha256.Sum256(buf.Bytes())
	return h[:]
}

func (l *Log) verifyAggregateWBBEntry(signedEntry SignedEntry, wbbEntry WBBEntry) error {
	if len(signedEntry.EntityIDs) == 0 {
		return fmtErrorf("missing entity_ids field")
	}

	if len(signedEntry.AggregateSignature) == 0 {
		return fmtErrorf("missing aggregate_signature field")
	}

	if len(signedEntry.EntityIDs) < wbbEntry.Threshold {
		return fmtErrorf(
			"insufficient signatures: got %d, need %d",
			len(signedEntry.EntityIDs),
			wbbEntry.Threshold,
		)
	}

	seen := make(map[string]bool)
	pubKeys := make([][]byte, 0, len(signedEntry.EntityIDs))

	for _, entityID := range signedEntry.EntityIDs {
		if seen[entityID] {
			return fmtErrorf("duplicate signer: %s", entityID)
		}
		seen[entityID] = true

		entityRole, err := roleFromEntityID(entityID)
		if err != nil {
			return fmtErrorf("invalid entity ID %s: %w", entityID, err)
		}

		if entityRole != wbbEntry.Role {
			return fmtErrorf(
				"entity %s cannot write as role %s",
				entityID,
				wbbEntry.Role,
			)
		}

		pubKey, exists := l.entityBLSKeys[entityID]
		if !exists {
			return fmtErrorf("unknown BLS entity: %s", entityID)
		}

		pubKeys = append(pubKeys, pubKey)
	}

	msg := aggregateSignedMessage(
		signedEntry.Data,
		signedEntry.Timestamp,
		signedEntry.EntityIDs,
	)

	ok, err := my_crypto.VerifyAggregateBytes(
		pubKeys,
		msg,
		signedEntry.AggregateSignature,
	)
	if err != nil {
		return fmtErrorf("invalid aggregate signature: %w", err)
	}
	if !ok {
		return fmtErrorf("invalid aggregate signature")
	}

	return nil
}

func computeContentHash(wbbData string) [32]byte {
	return sha256.Sum256([]byte(wbbData))
}

func stagedSigners(staged *StagingEntry) []string {
	signers := make([]string, 0, len(staged.Submissions))
	for entityID := range staged.Submissions {
		signers = append(signers, entityID)
	}

	sort.Strings(signers)
	return signers
}

func (l *Log) stageSubmission(contentHash [32]byte, signedEntry SignedEntry, wbbEntry WBBEntry) (currentCount int, isNew bool, err error) {
	// Every staged submission is still a signed submission from one entity.
	// Before counting it toward the threshold, verify:
	// - entity_id is present;
	// - signature is present;
	// - signer role matches the WBB role;
	// - Ed25519 signature is valid.
	if err := l.verifySingleWBBEntry(signedEntry, wbbEntry); err != nil {
		return 0, false, err
	}

	// block the staging map
	l.stagingMu.Lock()
	defer l.stagingMu.Unlock()

	staged, ok := l.staging[contentHash]
	// if an entry does not exixt already, create it!
	if !ok {
		staged = &StagingEntry{
			WBBData:   string(signedEntry.Data),
			Phase:     wbbEntry.Phase,
			Role:      wbbEntry.Role,
			EntryType: wbbEntry.EntryType,
			Threshold: wbbEntry.Threshold,
			Content:   wbbEntry.Content,

			// non si conta due volte lo stesso entityID
			Submissions: make(map[string]*StagingSubmission),

			FirstSubmissionAt: signedEntry.Timestamp,
			LastSubmissionAt:  signedEntry.Timestamp,
		}

		l.staging[contentHash] = staged
		isNew = true //new entry created
	}

	// Security check: once this entry has already been published, this
	// function must not start counting a new threshold round for the same data.
	if staged.IsPublished {
		return len(staged.Submissions), false, fmtErrorf("entry already published")
	}

	// Security check: the same signer must not be counted twice.
	// Without this check, one entity could satisfy a threshold by submitting
	// multiple times for the same content.
	// for example a 3 threshold cannot be satisfied by TT-1, TT-1, TT-2!
	if _, exists := staged.Submissions[signedEntry.EntityID]; exists {
		return len(staged.Submissions), false, fmtErrorf("duplicate signer: %s", signedEntry.EntityID)
	}

	// Only after verification and duplicate checks, add the submission.
	staged.Submissions[signedEntry.EntityID] = &StagingSubmission{
		EntityID:  signedEntry.EntityID,
		Timestamp: signedEntry.Timestamp,
		Signature: signedEntry.Signature,
	}

	if signedEntry.Timestamp < staged.FirstSubmissionAt {
		staged.FirstSubmissionAt = signedEntry.Timestamp
	}
	if signedEntry.Timestamp > staged.LastSubmissionAt {
		staged.LastSubmissionAt = signedEntry.Timestamp
	}

	return len(staged.Submissions), isNew, nil
}

func (l *Log) checkThreshold(contentHash [32]byte) (count int, thresholdMet bool, err error) {
	l.stagingMu.Lock()
	defer l.stagingMu.Unlock()

	staged, ok := l.staging[contentHash]
	if !ok {
		return 0, false, fmtErrorf("staging entry not found")
	}

	count = len(staged.Submissions)
	thresholdMet = count >= staged.Threshold

	return count, thresholdMet, nil
}

func (l *Log) finalizeEntry(contentHash [32]byte, ctx context.Context) (leafIndex int64, err error) {
	l.stagingMu.Lock()

	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return 0, fmtErrorf("staging entry not found")
	}

	// If another request already finalized this staging entry, just return
	// the existing leaf index instead of publishing the same content twice.
	if staged.IsPublished {
		leafIndex := staged.LeafIndex
		l.stagingMu.Unlock()
		return leafIndex, nil
	}

	if len(staged.Submissions) < staged.Threshold {
		l.stagingMu.Unlock()
		return 0, fmtErrorf(
			"threshold not met: got %d, need %d",
			len(staged.Submissions),
			staged.Threshold,
		)
	}

	entityIDs := stagedSigners(staged)

	finalEntry := SignedEntry{
		Data:      []byte(staged.WBBData),
		Timestamp: staged.FirstSubmissionAt,
		EntityIDs: entityIDs,
	}

	if len(staged.RunningBLSAggregate) > 0 {
		// BLS case: the staging entry already maintains the aggregate
		// signature, so the finalized log entry stores the aggregate.
		finalEntry.SigAlgorithm = "bls"
		finalEntry.AggregateSignature = staged.RunningBLSAggregate
	} else {
		// Ed25519 case: collect one signature for each distinct signer.
		finalEntry.SigAlgorithm = "ed25519"

		signatures := make([][]byte, 0, len(entityIDs))
		for _, entityID := range entityIDs {
			submission := staged.Submissions[entityID]
			signatures = append(signatures, submission.Signature)
		}

		finalEntry.Signatures = signatures
	}

	entryBytes, err := json.Marshal(finalEntry)
	if err != nil {
		l.stagingMu.Unlock()
		return 0, fmtErrorf("failed to encode finalized entry: %w", err)
	}

	// Do not hold the staging lock while waiting for sequencing.
	// addLeafToPool / waitLeaf can block, and holding the lock here would
	// unnecessarily block other submissions.
	l.stagingMu.Unlock()

	e := &PendingLogEntry{Data: entryBytes}

	waitLeaf, _ := l.addLeafToPool(ctx, e)
	seq, err := waitLeaf(ctx)
	if err == errPoolFull || err == errEvicted {
		return 0, err
	} else if errors.As(err, new(SunsetLogError)) {
		return 0, err
	} else if err != nil {
		return 0, fmtErrorf("failed to sequence finalized entry: %w", err)
	}

	l.stagingMu.Lock()
	defer l.stagingMu.Unlock()

	staged, ok = l.staging[contentHash]
	if !ok {
		return seq.LeafIndex, nil
	}

	staged.IsPublished = true
	staged.LeafIndex = seq.LeafIndex

	return seq.LeafIndex, nil
}

// 1. esiste uno staging per quel contentHash;
// 2. quello staging è già pubblicato;
// 3. entityID coincide con signedEntry.EntityID;
// 4. i dati firmati sono gli stessi della entry già pubblicata;
// 5. il signer non è già presente;
// 6. la firma Ed25519 è valida;
// 7. il ruolo dell’entità è corretto.
func (l *Log) appendToPublishedEntry(contentHash [32]byte, signedEntry SignedEntry, entityID string) (leafIndex int64, totalSigners int, err error) {
	l.stagingMu.Lock()

	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return 0, 0, fmtErrorf("staging entry not found")
	}

	if !staged.IsPublished {
		l.stagingMu.Unlock()
		return 0, 0, fmtErrorf("staging entry is not published")
	}

	if signedEntry.EntityID != entityID {
		l.stagingMu.Unlock()
		return 0, 0, fmtErrorf(
			"entity ID mismatch: got %s, expected %s",
			signedEntry.EntityID,
			entityID,
		)
	}

	if string(signedEntry.Data) != staged.WBBData {
		l.stagingMu.Unlock()
		return 0, 0, fmtErrorf("submitted data does not match published staging entry")
	}

	if _, exists := staged.Submissions[entityID]; exists {
		l.stagingMu.Unlock()
		return staged.LeafIndex, len(staged.Submissions), fmtErrorf("duplicate signer: %s", entityID)
	}

	wbbEntry, err := ParseWBBEntry(staged.WBBData)
	if err != nil {
		l.stagingMu.Unlock()
		return 0, 0, fmtErrorf("invalid staged WBB data: %w", err)
	}

	l.stagingMu.Unlock()

	// Even if the entry is already published, the late arrival must still be
	// a valid signature from an entity with the correct role.
	if err := l.verifySingleWBBEntry(signedEntry, wbbEntry); err != nil {
		return 0, 0, err
	}

	l.stagingMu.Lock()
	defer l.stagingMu.Unlock()

	staged, ok = l.staging[contentHash]
	if !ok {
		return 0, 0, fmtErrorf("staging entry not found")
	}

	if !staged.IsPublished {
		return 0, 0, fmtErrorf("staging entry is not published")
	}

	if _, exists := staged.Submissions[entityID]; exists {
		return staged.LeafIndex, len(staged.Submissions), fmtErrorf("duplicate signer: %s", entityID)
	}

	staged.Submissions[entityID] = &StagingSubmission{
		EntityID:  entityID,
		Timestamp: signedEntry.Timestamp,
		Signature: signedEntry.Signature,
	}

	if signedEntry.Timestamp > staged.LastSubmissionAt {
		staged.LastSubmissionAt = signedEntry.Timestamp
	}

	return staged.LeafIndex, len(staged.Submissions), nil
}

type stagingPendingResponse struct {
	Status          string   `json:"status"`
	ContentHash     string   `json:"content_hash"`
	CurrentSigners  int      `json:"current_signers"`
	RequiredSigners int      `json:"required_signers"`
	Signers         []string `json:"signers"`
	Message         string   `json:"message"`
}

func (l *Log) makePendingResponse(contentHash [32]byte, currentCount int, requiredCount int) ([]byte, error) {
	l.stagingMu.Lock()
	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return nil, fmtErrorf("staging entry not found")
	}

	signers := stagedSigners(staged)
	l.stagingMu.Unlock()

	needMore := requiredCount - currentCount
	if needMore < 0 {
		needMore = 0
	}

	rsp := stagingPendingResponse{
		Status:          "pending",
		ContentHash:     hex.EncodeToString(contentHash[:]),
		CurrentSigners:  currentCount,
		RequiredSigners: requiredCount,
		Signers:         signers,
		Message:         fmt.Sprintf("need %d more signature(s)", needMore),
	}

	return json.Marshal(rsp)
}

type stagingPublishedResponse struct {
	Status             string   `json:"status"`
	ContentHash        string   `json:"content_hash"`
	LeafIndex          int64    `json:"leaf_index"`
	CurrentSigners     int      `json:"current_signers"`
	RequiredSigners    int      `json:"required_signers"`
	Signers            []string `json:"signers"`
	Message            string   `json:"message"`
	Algorithm          string            `json:"algorithm,omitempty"`
	Signatures         [][]byte          `json:"signatures,omitempty"`
	AggregateSignature []byte            `json:"aggregate_signature,omitempty"`
	SignerTimestamps   []SignerTimestamp `json:"signer_timestamps,omitempty"`
}

func (l *Log) makePublishedResponse(contentHash [32]byte, leafIndex int64, currentCount int, requiredCount int) ([]byte, error) {
	l.stagingMu.Lock()
	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return nil, fmtErrorf("staging entry not found")
	}

	signers := stagedSigners(staged)

	algorithm := "ed25519"
	var signatures [][]byte
	var aggregateSignature []byte

	if len(staged.RunningBLSAggregate) > 0 {
		algorithm = "bls"
		aggregateSignature = staged.RunningBLSAggregate
	} else {
		signatures = make([][]byte, 0, len(signers))
		for _, entityID := range signers {
			signatures = append(signatures, staged.Submissions[entityID].Signature)
		}
	}

	l.stagingMu.Unlock()

	// Collect all individual submission timestamps for audit
	signerTimestamps := make([]SignerTimestamp, 0, len(signers))
	for _, entityID := range signers {
		signerTimestamps = append(signerTimestamps, SignerTimestamp{
			EntityID:  entityID,
			Timestamp: staged.Submissions[entityID].Timestamp,
		})
	}

	rsp := stagingPublishedResponse{
		Status:          "published",
		ContentHash:     hex.EncodeToString(contentHash[:]),
		LeafIndex:       leafIndex,
		CurrentSigners:  currentCount,
		RequiredSigners: requiredCount,
		Signers:         signers,
		Message:         "threshold reached, entry published",

		Algorithm:          algorithm,
		Signatures:         signatures,
		AggregateSignature: aggregateSignature,
		SignerTimestamps:   signerTimestamps,
	}

	return json.Marshal(rsp)
}

type stagingAppendedResponse struct {
	Status           string            `json:"status"`
	ContentHash      string            `json:"content_hash"`
	LeafIndex        int64             `json:"leaf_index"`
	TotalSigners     int               `json:"total_signers"`
	Signers          []string          `json:"signers"`
	Message          string            `json:"message"`
	SignerTimestamps []SignerTimestamp `json:"signer_timestamps,omitempty"`
}

func (l *Log) makeAppendedResponse(contentHash [32]byte, leafIndex int64, totalSigners int) ([]byte, error) {
	l.stagingMu.Lock()
	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return nil, fmtErrorf("staging entry not found")
	}

	signers := stagedSigners(staged)
	l.stagingMu.Unlock()

	// Collect all individual submission timestamps for audit
	signerTimestamps := make([]SignerTimestamp, 0, len(signers))
	for _, entityID := range signers {
		signerTimestamps = append(signerTimestamps, SignerTimestamp{
			EntityID:  entityID,
			Timestamp: staged.Submissions[entityID].Timestamp,
		})
	}

	rsp := stagingAppendedResponse{
		Status:           "appended",
		ContentHash:      hex.EncodeToString(contentHash[:]),
		LeafIndex:        leafIndex,
		TotalSigners:     totalSigners,
		Signers:          signers,
		Message:          "signature appended to already published entry",
		SignerTimestamps: signerTimestamps,
	}

	return json.Marshal(rsp)
}

func (l *Log) submitEntry(ctx context.Context, reqBody io.ReadCloser) (response []byte, code int, err error) {
	labels := prometheus.Labels{"error": "", "source": "", "reused": ""}
	defer func() {
		if err != nil {
			labels["error"] = errorCategory(err)
		}
		l.m.AddChainCount.With(labels).Inc()
	}()

	body, err := io.ReadAll(reqBody)
	if err != nil {
		return nil, http.StatusInternalServerError, fmtErrorf("failed to read body: %w", err)
	}

	var signedEntry SignedEntry
	if err := json.Unmarshal(body, &signedEntry); err != nil {
		return nil, http.StatusBadRequest, fmtErrorf("invalid JSON: %w", err)
	}

	if len(signedEntry.Data) == 0 {
		return nil, http.StatusBadRequest, fmtErrorf("missing data field")
	}
	if signedEntry.Timestamp == 0 {
		return nil, http.StatusBadRequest, fmtErrorf("missing timestamp field")
	}

	if !signedEntry.IsTimestampValid() {
		return nil, http.StatusBadRequest, fmtErrorf("timestamp too old or in future (max ±5min skew)")
	}

	wbbEntry, err := ParseWBBEntry(string(signedEntry.Data))
	if err != nil {
		return nil, http.StatusBadRequest, fmtErrorf("invalid WBB format: %w", err)
	}

	allowed, err := CheckWBBWritePolicy(string(signedEntry.Data))
	if err != nil {
		return nil, http.StatusForbidden, fmtErrorf("write not authorized: %w", err)
	}
	if !allowed {
		return nil, http.StatusForbidden, fmtErrorf("write not authorized")
	}

	if wbbEntry.Threshold == 1 {
		// Threshold-1 entries are verified immediately and then continue
		// through the normal publication path below.
		if err := l.verifySingleWBBEntry(signedEntry, wbbEntry); err != nil {
			return nil, http.StatusForbidden, err
		}

	} else if len(signedEntry.EntityIDs) > 0 || len(signedEntry.AggregateSignature) > 0 {
		// Aggregate one-request path.
		//
		// This keeps support for entries that already arrive with all signer
		// identities and an aggregate signature. These entries do not need
		// staging, because the threshold is supposed to be satisfied in the
		// request itself.
		if err := l.verifyAggregateWBBEntry(signedEntry, wbbEntry); err != nil {
			return nil, http.StatusForbidden, err
		}

		// Continue through the normal immediate publication path below.

	} else {
		// Threshold > 1 entries submitted with EntityID + Signature use the new
		// server-side staging flow. Each request contributes one valid signer.
		contentHash := computeContentHash(string(signedEntry.Data))

		l.stagingMu.Lock()
		staged, exists := l.staging[contentHash]
		alreadyPublished := exists && staged.IsPublished
		l.stagingMu.Unlock()

		if alreadyPublished {
			leafIndex, totalSigners, err := l.appendToPublishedEntry(
				contentHash,
				signedEntry,
				signedEntry.EntityID,
			)
			if err != nil {
				return nil, http.StatusForbidden, err
			}

			rspBytes, err := l.makeAppendedResponse(contentHash, leafIndex, totalSigners)
			if err != nil {
				return nil, http.StatusInternalServerError, fmtErrorf("failed to encode appended response: %w", err)
			}

			return rspBytes, http.StatusOK, nil
		}

		_, _, err := l.stageSubmission(contentHash, signedEntry, wbbEntry)
		if err != nil {
			return nil, http.StatusForbidden, err
		}

		count, thresholdMet, err := l.checkThreshold(contentHash)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}

		if !thresholdMet {
			rspBytes, err := l.makePendingResponse(contentHash, count, wbbEntry.Threshold)
			if err != nil {
				return nil, http.StatusInternalServerError, fmtErrorf("failed to encode pending response: %w", err)
			}

			return rspBytes, http.StatusAccepted, nil
		}

		leafIndex, err := l.finalizeEntry(contentHash, ctx)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}

		rspBytes, err := l.makePublishedResponse(contentHash, leafIndex, count, wbbEntry.Threshold)
		if err != nil {
			return nil, http.StatusInternalServerError, fmtErrorf("failed to encode published response: %w", err)
		}

		return rspBytes, http.StatusOK, nil
	}

	entryBytes, err := json.Marshal(signedEntry)
	if err != nil {
		return nil, http.StatusInternalServerError, fmtErrorf("failed to encode entry: %w", err)
	}

	e := &PendingLogEntry{Data: entryBytes}

	waitLeaf, source := l.addLeafToPool(ctx, e)
	labels["source"] = source
	waitTimer := prometheus.NewTimer(l.m.AddChainWait)
	seq, err := waitLeaf(ctx)
	if source == "sequencer" && err != errEvicted {
		waitTimer.ObserveDuration()
	}
	if err == errEvicted {
		labels["source"] = "evicted"
	}
	if err == errPoolFull || err == errEvicted {
		return nil, http.StatusServiceUnavailable, err
	} else if errors.As(err, new(SunsetLogError)) {
		return nil, http.StatusGone, err
	} else if err != nil {
		return nil, http.StatusInternalServerError, fmtErrorf("failed to sequence leaf: %w", err)
	}

	dataHash := sha256.Sum256(signedEntry.Data)

	rsp := struct {
		LeafIndex int64    `json:"leaf_index"`
		Timestamp int64    `json:"timestamp"`
		DataHash  string   `json:"data_hash"`
		EntityID  string   `json:"entity_id,omitempty"`
		EntityIDs []string `json:"entity_ids,omitempty"`
	}{
		LeafIndex: seq.LeafIndex,
		Timestamp: seq.Timestamp,
		DataHash:  base64.StdEncoding.EncodeToString(dataHash[:]),
		EntityID:  signedEntry.EntityID,
		EntityIDs: signedEntry.EntityIDs,
	}

	rspBytes, err := json.Marshal(rsp)
	if err != nil {
		l.c.Log.ErrorContext(ctx, "failed to encode response", "err", err)
		return nil, http.StatusInternalServerError, fmtErrorf("failed to encode response: %w", err)
	}

	return rspBytes, http.StatusOK, nil
}

func roleFromEntityID(entityID string) (Role, error) {
	parts := strings.Split(entityID, "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("expected ROLE-ID format, got %q", entityID)
	}

	role := Role(parts[0])
	switch role {
	case RoleRT, RoleER, RoleBB, RoleTT:
		return role, nil
	default:
		return "", fmt.Errorf("unknown role %q", parts[0])
	}
}
