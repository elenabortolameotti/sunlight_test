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
	"strconv"
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

const wbbGracePeriod = 10 * time.Second

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
	// A staged submission must come from exactly one entity.
	if signedEntry.EntityID == "" {
		return 0, false, fmtErrorf("missing entity_id field")
	}

	// Detect which signature algorithm this submission is using.
	//
	// Ed25519 staging uses:
	//   signedEntry.Signature
	//
	// BLS staging uses:
	//   signedEntry.BLSSignature
	//
	// A submission must not contain both, and must not contain neither.
	hasEd25519Signature := len(signedEntry.Signature) > 0
	hasBLSSignature := len(signedEntry.BLSSignature) > 0

	if hasEd25519Signature == hasBLSSignature {
		return 0, false, fmtErrorf("submission must contain exactly one signature type")
	}

	algorithm := "ed25519"
	if hasBLSSignature {
		algorithm = "bls"
	}

	// Verify the single submission before counting it toward the threshold.
	switch algorithm {
	case "ed25519":
		if err := l.verifySingleWBBEntry(signedEntry, wbbEntry); err != nil {
			return 0, false, err
		}

	case "bls":
		// For BLS staging, we still need to enforce that the entity role
		// matches the WBB role.
		entityRole, err := roleFromEntityID(signedEntry.EntityID)
		if err != nil {
			return 0, false, fmtErrorf("invalid entity ID: %w", err)
		}

		if entityRole != wbbEntry.Role {
			return 0, false, fmtErrorf(
				"entity %s cannot write as role %s",
				signedEntry.EntityID,
				wbbEntry.Role,
			)
		}

		blsPubKey, exists := l.entityBLSKeys[signedEntry.EntityID]
		if !exists {
			return 0, false, fmtErrorf("unknown BLS entity: %s", signedEntry.EntityID)
		}

		msgInput := make([]byte, 0, len(signedEntry.Data)+len(signedEntry.EntityID)+20)
		msgInput = append(msgInput, signedEntry.Data...)
		msgInput = append(msgInput, signedEntry.EntityID...)
		msgInput = strconv.AppendInt(msgInput, signedEntry.Timestamp, 10)

		msg := sha256.Sum256(msgInput)

		ok, err := my_crypto.VerifyAggregateBytes(
			[][]byte{blsPubKey},
			msg[:],
			signedEntry.BLSSignature,
		)
		if err != nil {
			return 0, false, fmtErrorf("failed to verify BLS signature from %s: %w", signedEntry.EntityID, err)
		}
		if !ok {
			return 0, false, fmtErrorf("invalid BLS signature from %s", signedEntry.EntityID)
		}

	default:
		return 0, false, fmtErrorf("unsupported signature algorithm: %s", algorithm)
	}

	l.stagingMu.Lock()
	defer l.stagingMu.Unlock()

	staged, ok := l.staging[contentHash]
	if !ok {
		staged = &StagingEntry{
			WBBData:   string(signedEntry.Data),
			Phase:     wbbEntry.Phase,
			Role:      wbbEntry.Role,
			EntryType: wbbEntry.EntryType,
			Threshold: wbbEntry.Threshold,
			Content:   wbbEntry.Content,

			// The signature algorithm is fixed by the first submission.
			// Later submissions for the same content must use the same one.
			SigAlgorithm: algorithm,

			// Do not count the same entity twice.
			Submissions: make(map[string]*StagingSubmission),

			FirstSubmissionAt: signedEntry.Timestamp,
			LastSubmissionAt:  signedEntry.Timestamp,
		}

		l.staging[contentHash] = staged
		isNew = true
	}

	// Once this entry has already been published, this function must not
	// start counting a new threshold round for the same data.
	if staged.IsPublished {
		return len(staged.Submissions), false, fmtErrorf("entry already published")
	}

	// All submissions for the same staged entry must use the same algorithm.
	// This prevents mixing Ed25519 and BLS signatures for the same content.
	if staged.SigAlgorithm != algorithm {
		return len(staged.Submissions), false, fmtErrorf(
			"signature algorithm mismatch: staged entry uses %s, got %s",
			staged.SigAlgorithm,
			algorithm,
		)
	}

	// The same signer must not be counted twice.
	if _, exists := staged.Submissions[signedEntry.EntityID]; exists {
		return len(staged.Submissions), false, fmtErrorf("duplicate signer: %s", signedEntry.EntityID)
	}

	// Add the verified submission.
	staged.Submissions[signedEntry.EntityID] = &StagingSubmission{
		EntityID:     signedEntry.EntityID,
		Timestamp:    signedEntry.Timestamp,
		Signature:    signedEntry.Signature,
		BLSSignature: signedEntry.BLSSignature,
	}

	// Update the running BLS aggregate immediately.
	//
	// For Ed25519 we keep individual signatures, because standard Ed25519
	// signatures are not aggregated here.
	if algorithm == "bls" {
		if len(staged.RunningBLSAggregate) == 0 {
			staged.RunningBLSAggregate = append([]byte(nil), signedEntry.BLSSignature...)
		} else {
			aggregate, err := my_crypto.AggregateSignaturesBytes([][]byte{
				staged.RunningBLSAggregate,
				signedEntry.BLSSignature,
			})
			if err != nil {
				delete(staged.Submissions, signedEntry.EntityID)
				return len(staged.Submissions), false, fmtErrorf("failed to update BLS aggregate: %w", err)
			}

			staged.RunningBLSAggregate = aggregate
		}
	}

	if signedEntry.Timestamp < staged.FirstSubmissionAt {
		staged.FirstSubmissionAt = signedEntry.Timestamp
	}
	if signedEntry.Timestamp > staged.LastSubmissionAt {
		staged.LastSubmissionAt = signedEntry.Timestamp
	}

	return len(staged.Submissions), isNew, nil
}

// cleanupPublishedStagingForPhase removes published staging entries belonging
// to the given phase.
//
// This is only a memory cleanup: published entries are already stored in the
// append-only log, so removing them from the in-memory staging map does not
// remove anything from the Merkle tree.
//
// Unpublished entries are deliberately kept, because deleting them could lose
// partial signatures that have not reached publication yet.
func (l *Log) cleanupPublishedStagingForPhase(phase Phase) {
	l.stagingMu.Lock()
	defer l.stagingMu.Unlock()

	for contentHash, staged := range l.staging {
		if staged.IsPublished && staged.Phase == phase {
			delete(l.staging, contentHash)
		}
	}
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

//1. prende il lock sulla staging map
//2. recupera la staging entry
//3. se è già pubblicata, ritorna errore
//4. se la grace period è già partita, ritorna la deadline già esistente
//5. se non è ancora partita:
//   - imposta IsGracePeriodStarted = true
//   - imposta GracePeriodEndAt = now + 10 secondi
//6. rilascia il lock
//7. avvia un timer background
//8. quando il timer scade, chiama finalizeEntry()

func (l *Log) startGracePeriod(contentHash [32]byte) (endsAt int64, err error) {
	l.stagingMu.Lock()

	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return 0, fmtErrorf("staging entry not found")
	}

	// If the entry has already been published, there is no grace period to start.
	if staged.IsPublished {
		leafIndex := staged.LeafIndex
		l.stagingMu.Unlock()

		if leafIndex < 0 {
			return 0, fmtErrorf("entry already being published")
		}

		return 0, fmtErrorf("entry already published")
	}

	// If the grace period was already started by another request,
	// just return the existing deadline.
	if staged.IsGracePeriodStarted {
		endsAt := staged.GracePeriodEndAt
		l.stagingMu.Unlock()
		return endsAt, nil
	}

	// Start the grace period.
	//
	// We use Unix milliseconds because the rest of the SignedEntry timestamps
	// are also represented as Unix milliseconds.
	endsAt = time.Now().Add(wbbGracePeriod).UnixMilli()

	staged.IsGracePeriodStarted = true
	staged.GracePeriodEndAt = endsAt

	l.stagingMu.Unlock()

	// Background finalization.
	//
	// When the grace period expires, the server tries to finalize the entry.
	// finalizeEntry() is race-safe: if the entry was already published earlier,
	// it will not publish it twice.
	time.AfterFunc(wbbGracePeriod, func() {
		if _, err := l.finalizeEntry(contentHash, context.Background()); err != nil {
			l.c.Log.WarnContext(
				context.Background(),
				"failed to finalize WBB entry after grace period",
				"err", err,
			)
		}
	})

	return endsAt, nil
}

func (l *Log) checkAllSignersPresent(contentHash [32]byte) (count int, totalExpected int, allPresent bool, err error) {
	l.stagingMu.Lock()
	defer l.stagingMu.Unlock()

	staged, ok := l.staging[contentHash]
	if !ok {
		return 0, 0, false, fmtErrorf("staging entry not found")
	}

	count = len(staged.Submissions)

	for entityID := range l.entityKeys {
		entityRole, err := roleFromEntityID(entityID)
		if err != nil {
			continue
		}

		if entityRole == staged.Role {
			totalExpected++
		}
	}

	// BLS-only entities may exist only in entityBLSKeys. Count them too,
	// but avoid double-counting entities already present in entityKeys.
	for entityID := range l.entityBLSKeys {
		if _, alreadyCounted := l.entityKeys[entityID]; alreadyCounted {
			continue
		}

		entityRole, err := roleFromEntityID(entityID)
		if err != nil {
			continue
		}

		if entityRole == staged.Role {
			totalExpected++
		}
	}

	if totalExpected == 0 {
		return count, totalExpected, false, fmtErrorf("no expected signers found for role %s", staged.Role)
	}

	return count, totalExpected, count >= totalExpected, nil
}

func (l *Log) finalizeEntry(contentHash [32]byte, ctx context.Context) (leafIndex int64, err error) {
	l.stagingMu.Lock()

	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return 0, fmtErrorf("staging entry not found")
	}

	// If the entry has already been published, return the existing leaf index.
	// LeafIndex == -1 means that another goroutine is currently publishing it.
	if staged.IsPublished {
		leafIndex := staged.LeafIndex
		l.stagingMu.Unlock()

		if leafIndex < 0 {
			return 0, fmtErrorf("entry already being published")
		}

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

	signerTimestamps := make([]SignerTimestamp, 0, len(entityIDs))
	for _, entityID := range entityIDs {
		submission := staged.Submissions[entityID]

		signerTimestamps = append(signerTimestamps, SignerTimestamp{
			EntityID:  entityID,
			Timestamp: submission.Timestamp,
		})
	}

	finalEntry := SignedEntry{
		Data:             []byte(staged.WBBData),
		Timestamp:        staged.LastSubmissionAt,
		EntityIDs:        entityIDs,
		SignerTimestamps: signerTimestamps,
	}

	if len(staged.RunningBLSAggregate) > 0 {
		// BLS case: copy the aggregate signature while still holding the lock.
		finalEntry.SigAlgorithm = "bls"
		finalEntry.AggregateSignature = append([]byte(nil), staged.RunningBLSAggregate...)
	} else {
		// Ed25519 case: collect one signature for each distinct signer.
		finalEntry.SigAlgorithm = "ed25519"

		signatures := make([][]byte, 0, len(entityIDs))
		for _, entityID := range entityIDs {
			submission := staged.Submissions[entityID]
			signatures = append(signatures, append([]byte(nil), submission.Signature...))
		}

		finalEntry.Signatures = signatures
	}

	entryBytes, err := json.Marshal(finalEntry)
	if err != nil {
		l.stagingMu.Unlock()
		return 0, fmtErrorf("failed to encode finalized entry: %w", err)
	}

	// Atomic transition:
	// from "not published" to "publishing in progress".
	//
	// This must happen before releasing stagingMu. Otherwise another goroutine
	// could also pass the IsPublished check and publish the same content again.
	staged.IsPublished = true
	staged.LeafIndex = -1

	l.stagingMu.Unlock()

	e := &PendingLogEntry{Data: entryBytes}

	waitLeaf, _ := l.addLeafToPool(ctx, e)
	seq, err := waitLeaf(ctx)
	if err != nil {
		// Publishing failed. Roll back the publishing marker so the entry can
		// be retried later.
		l.stagingMu.Lock()
		if staged, ok := l.staging[contentHash]; ok && staged.LeafIndex == -1 {
			staged.IsPublished = false
			staged.LeafIndex = 0
		}
		l.stagingMu.Unlock()

		if err == errPoolFull || err == errEvicted {
			return 0, err
		}
		if errors.As(err, new(SunsetLogError)) {
			return 0, err
		}
		return 0, fmtErrorf("failed to sequence finalized entry: %w", err)
	}

	l.stagingMu.Lock()
	if staged, ok := l.staging[contentHash]; ok {
		staged.LeafIndex = seq.LeafIndex
		// Preserve the original leaf index so late arrivals always reference
		// the first published leaf, not a subsequent late-arrival leaf.
		if staged.OriginalLeafIndex == 0 {
			staged.OriginalLeafIndex = seq.LeafIndex
		}
	}
	l.stagingMu.Unlock()

	return seq.LeafIndex, nil
}

// appendToPublishedEntry handles a valid late arrival for an entry that has
// already been published.
//
// Important: a Merkle tree leaf is immutable. Therefore, a late signature
// cannot be appended to the already published leaf. Instead, this function
// creates a new log entry whose data is "ref:<referencedLeaf>", where
// referencedLeaf is the previously published leaf index.
//
// The staging area is still updated so that it tracks the latest known state,
// while the append-only log stores the full history.
func (l *Log) appendToPublishedEntry(
	contentHash [32]byte,
	signedEntry SignedEntry,
	entityID string,
	ctx context.Context,
) (referencedLeaf int64, newLeafIndex int64, totalSigners int, err error) {
	l.stagingMu.Lock()

	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return 0, 0, 0, fmtErrorf("staging entry not found")
	}

	if !staged.IsPublished {
		l.stagingMu.Unlock()
		return 0, 0, 0, fmtErrorf("staging entry is not published")
	}

	if staged.LeafIndex < 0 {
		l.stagingMu.Unlock()
		return 0, 0, 0, fmtErrorf("entry already being published")
	}

	if signedEntry.EntityID != entityID {
		l.stagingMu.Unlock()
		return 0, 0, 0, fmtErrorf(
			"entity ID mismatch: got %s, expected %s",
			signedEntry.EntityID,
			entityID,
		)
	}

	if string(signedEntry.Data) != staged.WBBData {
		l.stagingMu.Unlock()
		return 0, 0, 0, fmtErrorf("submitted data does not match published staging entry")
	}

	if _, exists := staged.Submissions[entityID]; exists {
		leafIndex := staged.LeafIndex
		count := len(staged.Submissions)
		l.stagingMu.Unlock()
		return leafIndex, leafIndex, count, fmtErrorf("duplicate signer: %s", entityID)
	}

	// Copy the data needed for signature verification before releasing the lock.
	wbbData := staged.WBBData
	stagedRole := staged.Role
	sigAlgorithm := staged.SigAlgorithm

	l.stagingMu.Unlock()

	wbbEntry, err := ParseWBBEntry(wbbData)
	if err != nil {
		return 0, 0, 0, fmtErrorf("invalid staged WBB data: %w", err)
	}

	// Even if the entry is already published, the late arrival must still be
	// a valid signature from an entity with the correct role.
	switch sigAlgorithm {
	case "ed25519":
		if err := l.verifySingleWBBEntry(signedEntry, wbbEntry); err != nil {
			return 0, 0, 0, err
		}

	case "bls":
		if len(signedEntry.BLSSignature) == 0 {
			return 0, 0, 0, fmtErrorf("staging entry uses BLS, expected bls_signature")
		}

		if len(signedEntry.Signature) > 0 {
			return 0, 0, 0, fmtErrorf("staging entry uses BLS, got ed25519 signature")
		}

		entityRole, err := roleFromEntityID(signedEntry.EntityID)
		if err != nil {
			return 0, 0, 0, fmtErrorf("invalid entity ID: %w", err)
		}

		if entityRole != stagedRole {
			return 0, 0, 0, fmtErrorf(
				"entity %s cannot write as role %s",
				signedEntry.EntityID,
				stagedRole,
			)
		}

		blsPubKey, exists := l.entityBLSKeys[signedEntry.EntityID]
		if !exists {
			return 0, 0, 0, fmtErrorf("unknown BLS entity: %s", signedEntry.EntityID)
		}

		msgInput := make([]byte, 0, len(signedEntry.Data)+len(signedEntry.EntityID)+20)
		msgInput = append(msgInput, signedEntry.Data...)
		msgInput = append(msgInput, signedEntry.EntityID...)
		msgInput = strconv.AppendInt(msgInput, signedEntry.Timestamp, 10)

		msg := sha256.Sum256(msgInput)

		ok, err := my_crypto.VerifyAggregateBytes(
			[][]byte{blsPubKey},
			msg[:],
			signedEntry.BLSSignature,
		)
		if err != nil {
			return 0, 0, 0, fmtErrorf("failed to verify BLS signature from %s: %w", signedEntry.EntityID, err)
		}
		if !ok {
			return 0, 0, 0, fmtErrorf("invalid BLS signature from %s", signedEntry.EntityID)
		}

	default:
		return 0, 0, 0, fmtErrorf("unsupported staging signature algorithm: %s", sigAlgorithm)
	}

	l.stagingMu.Lock()

	staged, ok = l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return 0, 0, 0, fmtErrorf("staging entry not found")
	}

	if !staged.IsPublished {
		l.stagingMu.Unlock()
		return 0, 0, 0, fmtErrorf("staging entry is not published")
	}

	if staged.LeafIndex < 0 {
		l.stagingMu.Unlock()
		return 0, 0, 0, fmtErrorf("entry already being published")
	}

	if _, exists := staged.Submissions[entityID]; exists {
		leafIndex := staged.LeafIndex
		count := len(staged.Submissions)
		l.stagingMu.Unlock()
		return leafIndex, leafIndex, count, fmtErrorf("duplicate signer: %s", entityID)
	}

	// Use OriginalLeafIndex so every late arrival references the first
	// published leaf, not a previous late-arrival leaf.
	if staged.OriginalLeafIndex != 0 {
		referencedLeaf = staged.OriginalLeafIndex
	} else {
		referencedLeaf = staged.LeafIndex
	}
	oldLastSubmissionAt := staged.LastSubmissionAt
	oldBLSAggregate := append([]byte(nil), staged.RunningBLSAggregate...)

	staged.Submissions[entityID] = &StagingSubmission{
		EntityID:     entityID,
		Timestamp:    signedEntry.Timestamp,
		Signature:    signedEntry.Signature,
		BLSSignature: signedEntry.BLSSignature,
	}

	if staged.SigAlgorithm == "bls" {
		if len(staged.RunningBLSAggregate) == 0 {
			staged.RunningBLSAggregate = append([]byte(nil), signedEntry.BLSSignature...)
		} else {
			aggregate, err := my_crypto.AggregateSignaturesBytes([][]byte{
				staged.RunningBLSAggregate,
				signedEntry.BLSSignature,
			})
			if err != nil {
				delete(staged.Submissions, entityID)
				staged.RunningBLSAggregate = oldBLSAggregate
				l.stagingMu.Unlock()
				return 0, 0, 0, fmtErrorf("failed to update BLS aggregate for late arrival: %w", err)
			}

			staged.RunningBLSAggregate = aggregate
		}
	}

	if signedEntry.Timestamp > staged.LastSubmissionAt {
		staged.LastSubmissionAt = signedEntry.Timestamp
	}

	totalSigners = len(staged.Submissions)

	refEntry := SignedEntry{
		Data:         []byte(fmt.Sprintf("ref:%d", referencedLeaf)),
		Timestamp:    signedEntry.Timestamp,
		EntityID:     entityID,
		SigAlgorithm: staged.SigAlgorithm,
	}

	switch staged.SigAlgorithm {
	case "ed25519":
		refEntry.Signature = signedEntry.Signature

	case "bls":
		refEntry.BLSSignature = signedEntry.BLSSignature
		refEntry.AggregateSignature = append([]byte(nil), staged.RunningBLSAggregate...)
	}

	entryBytes, err := json.Marshal(refEntry)
	if err != nil {
		delete(staged.Submissions, entityID)
		staged.LastSubmissionAt = oldLastSubmissionAt
		staged.RunningBLSAggregate = oldBLSAggregate
		l.stagingMu.Unlock()
		return 0, 0, 0, fmtErrorf("failed to encode late arrival reference entry: %w", err)
	}

	l.stagingMu.Unlock()

	e := &PendingLogEntry{Data: entryBytes}

	waitLeaf, _ := l.addLeafToPool(ctx, e)
	seq, err := waitLeaf(ctx)
	if err != nil {
		l.stagingMu.Lock()
		if staged, ok := l.staging[contentHash]; ok {
			delete(staged.Submissions, entityID)
			staged.LastSubmissionAt = oldLastSubmissionAt
			staged.RunningBLSAggregate = oldBLSAggregate
		}
		l.stagingMu.Unlock()

		if err == errPoolFull || err == errEvicted {
			return 0, 0, 0, err
		}
		if errors.As(err, new(SunsetLogError)) {
			return 0, 0, 0, err
		}
		return 0, 0, 0, fmtErrorf("failed to sequence late arrival reference entry: %w", err)
	}

	newLeafIndex = seq.LeafIndex

	l.stagingMu.Lock()
	if staged, ok := l.staging[contentHash]; ok {
		staged.LeafIndex = newLeafIndex
	}
	l.stagingMu.Unlock()

	return referencedLeaf, newLeafIndex, totalSigners, nil
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
	Status          string   `json:"status"`
	ContentHash     string   `json:"content_hash"`
	LeafIndex       int64    `json:"leaf_index"`
	Timestamp       int64    `json:"timestamp"`
	CurrentSigners  int      `json:"current_signers"`
	RequiredSigners int      `json:"required_signers"`
	Signers         []string `json:"signers"`
	Message         string   `json:"message"`

	Algorithm          string   `json:"algorithm,omitempty"`
	Signatures         [][]byte `json:"signatures,omitempty"`
	AggregateSignature []byte   `json:"aggregate_signature,omitempty"`

	SignerTimestamps []SignerTimestamp `json:"signer_timestamps,omitempty"`
}

func (l *Log) makePublishedResponse(contentHash [32]byte, leafIndex int64, currentCount int, requiredCount int) ([]byte, error) {
	l.stagingMu.Lock()
	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return nil, fmtErrorf("staging entry not found")
	}

	signers := stagedSigners(staged)
	publishedTimestamp := staged.LastSubmissionAt

	signerTimestamps := make([]SignerTimestamp, 0, len(signers))
	for _, entityID := range signers {
		submission := staged.Submissions[entityID]

		signerTimestamps = append(signerTimestamps, SignerTimestamp{
			EntityID:  entityID,
			Timestamp: submission.Timestamp,
		})
	}

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

	rsp := stagingPublishedResponse{
		Status:          "published",
		ContentHash:     hex.EncodeToString(contentHash[:]),
		LeafIndex:       leafIndex,
		Timestamp:       publishedTimestamp,
		CurrentSigners:  currentCount,
		RequiredSigners: requiredCount,
		Signers:         signers,
		Message:         "threshold reached, entry published",

		Algorithm:          algorithm,
		Signatures:         signatures,
		AggregateSignature: aggregateSignature,

		SignerTimestamps: signerTimestamps,
	}
	return json.Marshal(rsp)
}

type stagingGracePeriodResponse struct {
	Status           string   `json:"status"`
	ContentHash      string   `json:"content_hash"`
	CurrentSigners   int      `json:"current_signers"`
	RequiredSigners  int      `json:"required_signers"`
	TotalExpected    int      `json:"total_expected,omitempty"`
	Signers          []string `json:"signers"`
	GracePeriodEndAt int64    `json:"grace_period_end_at"`
	Message          string   `json:"message"`
}

func (l *Log) makeGracePeriodResponse(contentHash [32]byte, currentCount int, requiredCount int, totalExpected int, gracePeriodEndAt int64) ([]byte, error) {
	l.stagingMu.Lock()

	staged, ok := l.staging[contentHash]
	if !ok {
		l.stagingMu.Unlock()
		return nil, fmtErrorf("staging entry not found")
	}

	signers := stagedSigners(staged)

	l.stagingMu.Unlock()

	rsp := stagingGracePeriodResponse{
		Status:           "grace_period",
		ContentHash:      hex.EncodeToString(contentHash[:]),
		CurrentSigners:   currentCount,
		RequiredSigners:  requiredCount,
		TotalExpected:    totalExpected,
		Signers:          signers,
		GracePeriodEndAt: gracePeriodEndAt,
		Message:          "threshold reached, grace period active",
	}

	return json.Marshal(rsp)
}

type stagingAppendedResponse struct {
	Status           string            `json:"status"`
	ContentHash      string            `json:"content_hash"`
	ReferencedLeaf   int64             `json:"referenced_leaf"`
	LeafIndex        int64             `json:"leaf_index"`
	TotalSigners     int               `json:"total_signers"`
	Signers          []string          `json:"signers"`
	Message          string            `json:"message"`
	SignerTimestamps []SignerTimestamp `json:"signer_timestamps,omitempty"`
}

func (l *Log) makeAppendedResponse(contentHash [32]byte, referencedLeaf int64, newLeafIndex int64, totalSigners int) ([]byte, error) {
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
		ReferencedLeaf:   referencedLeaf,
		LeafIndex:        newLeafIndex,
		TotalSigners:     totalSigners,
		Signers:          signers,
		Message:          "late arrival appended as new log entry",
		SignerTimestamps: signerTimestamps,
	}

	return json.Marshal(rsp)
}

func statusCodeForStagingError(err error, fallback int) int {
	if err == nil {
		return fallback
	}

	errMsg := err.Error()

	if strings.Contains(errMsg, "staging entry not found") {
		return http.StatusNotFound
	}

	if strings.Contains(errMsg, "duplicate signer") ||
		strings.Contains(errMsg, "already published") ||
		strings.Contains(errMsg, "already being published") ||
		strings.Contains(errMsg, "signature algorithm mismatch") {
		return http.StatusConflict
	}

	return fallback
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
			referencedLeaf, newLeafIndex, totalSigners, err := l.appendToPublishedEntry(
				contentHash,
				signedEntry,
				signedEntry.EntityID,
				ctx,
			)
			if err != nil {
				return nil, statusCodeForStagingError(err, http.StatusForbidden), err
			}

			rspBytes, err := l.makeAppendedResponse(contentHash, referencedLeaf, newLeafIndex, totalSigners)
			if err != nil {
				return nil, http.StatusInternalServerError, fmtErrorf("failed to encode appended response: %w", err)
			}

			return rspBytes, http.StatusOK, nil
		}

		count, _, err := l.stageSubmission(contentHash, signedEntry, wbbEntry)
		if err != nil {
			return nil, statusCodeForStagingError(err, http.StatusForbidden), err
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

		// At this point the threshold has been reached.
		// Do not publish immediately: start or continue the grace period first.
		currentCount, totalExpected, allSignersPresent, err := l.checkAllSignersPresent(contentHash)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}

		// If all expected signers are already present, publish immediately.
		// This is the "early publication" path.
		if allSignersPresent {
			leafIndex, err := l.finalizeEntry(contentHash, ctx)
			if err != nil {
				errMsg := err.Error()

				if strings.Contains(errMsg, "entry already being published") ||
					strings.Contains(errMsg, "entry already published") {
					return nil, http.StatusConflict, err
				}

				return nil, http.StatusInternalServerError, err
			}

			rspBytes, err := l.makePublishedResponse(contentHash, leafIndex, currentCount, wbbEntry.Threshold)
			if err != nil {
				return nil, http.StatusInternalServerError, fmtErrorf("failed to encode published response: %w", err)
			}

			return rspBytes, http.StatusOK, nil
		}

		// Threshold is met, but not all expected signers are present.
		// Start the grace period, or reuse the already active one.
		gracePeriodEndAt, err := l.startGracePeriod(contentHash)
		if err != nil {
			return nil, statusCodeForStagingError(err, http.StatusInternalServerError), err
		}

		// If the grace period has already expired, finalize now.
		// This covers the case where the timer did not run yet, or a new request
		// arrives after the deadline.
		if time.Now().UnixMilli() >= gracePeriodEndAt {
			leafIndex, err := l.finalizeEntry(contentHash, ctx)
			if err != nil {
				return nil, statusCodeForStagingError(err, http.StatusInternalServerError), err
			}

			rspBytes, err := l.makePublishedResponse(contentHash, leafIndex, currentCount, wbbEntry.Threshold)
			if err != nil {
				return nil, http.StatusInternalServerError, fmtErrorf("failed to encode published response: %w", err)
			}

			return rspBytes, http.StatusOK, nil
		}

		// Grace period is active: return 202 Accepted.
		rspBytes, err := l.makeGracePeriodResponse(
			contentHash,
			currentCount,
			wbbEntry.Threshold,
			totalExpected,
			gracePeriodEndAt,
		)
		if err != nil {
			return nil, http.StatusInternalServerError, fmtErrorf("failed to encode grace period response: %w", err)
		}

		return rspBytes, http.StatusAccepted, nil
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
