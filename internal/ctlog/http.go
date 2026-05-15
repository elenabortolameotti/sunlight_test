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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SignedEntry represents a signed log entry with authentication
type SignedEntry struct {
	// The actual data being logged
	Data []byte `json:"data"`
	
	// Entity identifier (maps to hardcoded public key)
	EntityID string `json:"entity_id"`
	
	// Client-provided timestamp (Unix milliseconds) for replay protection
	Timestamp int64 `json:"timestamp"`
	
	// Signature over: SHA256(data || entity_id || timestamp)
	Signature []byte `json:"signature"`
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

func (l *Log) submitEntry(ctx context.Context, reqBody io.ReadCloser) (response []byte, code int, err error) {
	labels := prometheus.Labels{"error": "", "entity_id": "", "source": ""}
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

	// Parse the signed entry
	var signedEntry SignedEntry
	if err := json.Unmarshal(body, &signedEntry); err != nil {
		return nil, http.StatusBadRequest, fmtErrorf("invalid JSON: %w", err)
	}

	// Validate required fields
	if len(signedEntry.Data) == 0 {
		return nil, http.StatusBadRequest, fmtErrorf("missing data field")
	}
	if signedEntry.EntityID == "" {
		return nil, http.StatusBadRequest, fmtErrorf("missing entity_id field")
	}
	if len(signedEntry.Signature) == 0 {
		return nil, http.StatusBadRequest, fmtErrorf("missing signature field")
	}
	if signedEntry.Timestamp == 0 {
		return nil, http.StatusBadRequest, fmtErrorf("missing timestamp field")
	}

	labels["entity_id"] = signedEntry.EntityID

	// Check timestamp for replay protection
	if !signedEntry.IsTimestampValid() {
		return nil, http.StatusBadRequest, fmtErrorf("timestamp too old or in future (max ±5min skew)")
	}

	// Get public key for this entity
	pubKey, exists := l.entityKeys[signedEntry.EntityID]
	if !exists {
		return nil, http.StatusUnauthorized, fmtErrorf("unknown entity: %s", signedEntry.EntityID)
	}

	// Verify signature
	if !signedEntry.Verify(pubKey) {
		return nil, http.StatusUnauthorized, fmtErrorf("invalid signature")
	}

	// Encode the signed entry for storage
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

	// Return response with leaf index and timestamp
	dataHash := sha256.Sum256(signedEntry.Data)
	rsp := struct {
		LeafIndex int64  `json:"leaf_index"`
		Timestamp int64  `json:"timestamp"`
		DataHash  string `json:"data_hash"`
		EntityID  string `json:"entity_id"`
	}{
		LeafIndex: seq.LeafIndex,
		Timestamp: seq.Timestamp,
		DataHash:  base64.StdEncoding.EncodeToString(dataHash[:]),
		EntityID:  signedEntry.EntityID,
	}
	rspBytes, err := json.Marshal(rsp)
	if err != nil {
		l.c.Log.ErrorContext(ctx, "failed to encode response", "err", err)
		return nil, http.StatusInternalServerError, fmtErrorf("failed to encode response: %w", err)
	}

	return rspBytes, http.StatusOK, nil
}
