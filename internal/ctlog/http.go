package ctlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"filippo.io/sunlight/internal/my_crypto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SignedEntry represents a signed log entry with authentication
type SignedEntry struct {
	// The actual data being logged
	Data []byte `json:"data"`

	// Entity identifier (maps to hardcoded public key)
	EntityID string `json:"entity_id,omitempty"`

	// Client-provided timestamp (Unix milliseconds) for replay protection
	Timestamp int64 `json:"timestamp"`

	// Signature over: SHA256(data || entity_id || timestamp)
	Signature []byte `json:"signature,omitempty"`

	EntityIDs          []string `json:"entity_ids,omitempty"`
	AggregateSignature []byte   `json:"aggregate_signature,omitempty"`
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
		if err := l.verifySingleWBBEntry(signedEntry, wbbEntry); err != nil {
			return nil, http.StatusForbidden, err
		}
	} else {
		if err := l.verifyAggregateWBBEntry(signedEntry, wbbEntry); err != nil {
			return nil, http.StatusForbidden, err
		}
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
