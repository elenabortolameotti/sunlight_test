package ctlog

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"

	"filippo.io/sunlight/internal/reused"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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
			http.Error(rw, "this party is popular and the pool is full, please retry later", code)
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
	labels := prometheus.Labels{"error": "", "reused": ""}
	defer func() {
		if err != nil {
			labels["error"] = errorCategory(err)
		}
		l.m.AddChainCount.With(labels).Inc()
	}()
	if r, ok := ctx.Value(reused.ContextKey).(bool); ok {
		labels["reused"] = fmt.Sprintf("%t", r)
	}

	body, err := io.ReadAll(reqBody)
	if err != nil {
		return nil, http.StatusInternalServerError, fmtErrorf("failed to read body: %w", err)
	}

	// Accept raw data directly or JSON-wrapped data
	var data []byte
	if len(body) > 0 && body[0] == '{' {
		// Try to parse as JSON
		var req struct {
			Data []byte `json:"data"`
		}
		if err := json.Unmarshal(body, &req); err == nil && len(req.Data) > 0 {
			data = req.Data
		} else {
			// If JSON parsing fails or data is empty, use the raw body
			data = body
		}
	} else {
		// Raw data submission
		data = body
	}

	if len(data) == 0 {
		return nil, http.StatusBadRequest, fmtErrorf("empty data")
	}

	// Simple size check - max 16MB
	if len(data) > 16*1024*1024 {
		return nil, http.StatusBadRequest, fmtErrorf("data too large")
	}

	e := &PendingLogEntry{Data: data}

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

	// Return a simple JSON response with the leaf index and timestamp
	hash := sha256.Sum256(data)
	rsp := struct {
		LeafIndex int64  `json:"leaf_index"`
		Timestamp int64  `json:"timestamp"`
		DataHash  string `json:"data_hash"`
	}{
		LeafIndex: seq.LeafIndex,
		Timestamp: seq.Timestamp,
		DataHash:  base64.StdEncoding.EncodeToString(hash[:]),
	}
	rspBytes, err := json.Marshal(rsp)
	if err != nil {
		l.c.Log.ErrorContext(ctx, "failed to encode response", "err", err)
		return nil, http.StatusInternalServerError, fmtErrorf("failed to encode response: %w", err)
	}

	return rspBytes, http.StatusOK, nil
}
