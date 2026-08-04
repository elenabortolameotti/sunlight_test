package ctlog_test

// Tests for the PoC WBB patches P1–P5 (branch referendum-poc-wbb):
//
//	P1 read API (/entries, /entries/{index}, /phase, /checkpoint)
//	P2 disable_timestamp_validation
//	P3 grace_period_ms
//	P4 max_submit_body_bytes
//	P5 eligible_vids + revocation_commitment policy entry types

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/sunlight/internal/ctlog"
)

// --- helpers -----------------------------------------------------------------

func pocKeys(t *testing.T, ids ...string) (map[string]ed25519.PublicKey, map[string]ed25519.PrivateKey) {
	t.Helper()
	pubs := make(map[string]ed25519.PublicKey)
	privs := make(map[string]ed25519.PrivateKey)
	for _, id := range ids {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("generate key for %s: %v", id, err)
		}
		pubs[id] = pub
		privs[id] = priv
	}
	return pubs, privs
}

// startPoCLog creates a log, serves its handler over httptest, and runs a
// fast background sequencer (the submit handler blocks until sequencing).
func startPoCLog(t *testing.T, entityKeys map[string]ed25519.PublicKey, pmKey ed25519.PublicKey, tune func(*ctlog.Config)) *httptest.Server {
	t.Helper()

	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate log key: %v", err)
	}

	config := &ctlog.Config{
		Name:            "test.poc.example.com",
		Key:             logKey,
		Cache:           filepath.Join(t.TempDir(), "cache.db"),
		Backend:         NewMemoryBackend(t),
		Lock:            NewMemoryLockBackend(t),
		Log:             slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		EntityKeys:      entityKeys,
		PhaseManagerKey: pmKey,
	}
	if tune != nil {
		tune(config)
	}

	ctx := context.Background()
	if err := ctlog.CreateLog(ctx, config); err != nil {
		t.Fatalf("CreateLog: %v", err)
	}
	log, err := ctlog.LoadLog(ctx, config)
	if err != nil {
		t.Fatalf("LoadLog: %v", err)
	}
	t.Cleanup(func() { log.CloseCache() })

	server := httptest.NewServer(log.Handler())
	t.Cleanup(server.Close)

	seqCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-seqCtx.Done():
				return
			case <-ticker.C:
				_ = log.Sequence()
			}
		}
	}()

	return server
}

func pocSubmit(t *testing.T, server *httptest.Server, wbbData, entityID string, ts int64, priv ed25519.PrivateKey) (int, []byte) {
	t.Helper()
	entry := createSignedEntry(t, []byte(wbbData), entityID, ts, priv)
	resp := submitEntry(t, server.URL+"/submit", entry)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read submit response body: %v", err)
	}
	return resp.StatusCode, body
}

func pocGet(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", url, err)
	}
	return resp.StatusCode, body
}

type pocEntriesResponse struct {
	Count   int `json:"count"`
	Entries []struct {
		LeafIndex int64           `json:"leaf_index"`
		Timestamp int64           `json:"timestamp"`
		Entry     json.RawMessage `json:"entry"`
	} `json:"entries"`
}

// --- P1: read API ------------------------------------------------------------

func TestPoCReadAPI(t *testing.T) {
	pubs, privs := pocKeys(t, "ER-1")
	server := startPoCLog(t, pubs, nil, nil)

	now := time.Now().UnixMilli()
	for _, content := range []string{"alpha", "beta"} {
		code, body := pocSubmit(t, server, "setup,ER,election_pub_key,1,"+content, "ER-1", now, privs["ER-1"])
		if code != http.StatusOK {
			t.Fatalf("submit %q: expected 200, got %d: %s", content, code, body)
		}
	}

	// GET /entries
	code, body := pocGet(t, server.URL+"/entries")
	if code != http.StatusOK {
		t.Fatalf("GET /entries: expected 200, got %d", code)
	}
	var entries pocEntriesResponse
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("unmarshal /entries: %v\n%s", err, body)
	}
	if entries.Count != 2 || len(entries.Entries) != 2 {
		t.Fatalf("expected 2 entries, got count=%d len=%d", entries.Count, len(entries.Entries))
	}
	for i, e := range entries.Entries {
		if e.LeafIndex != int64(i) {
			t.Errorf("entry %d: expected leaf_index %d, got %d", i, i, e.LeafIndex)
		}
		var signed ctlog.SignedEntry
		if err := json.Unmarshal(e.Entry, &signed); err != nil {
			t.Fatalf("entry %d: unmarshal SignedEntry: %v", i, err)
		}
		if signed.EntityID != "ER-1" {
			t.Errorf("entry %d: expected entity ER-1, got %q", i, signed.EntityID)
		}
	}

	// GET /entries/1
	code, body = pocGet(t, server.URL+"/entries/1")
	if code != http.StatusOK {
		t.Fatalf("GET /entries/1: expected 200, got %d", code)
	}
	var single struct {
		LeafIndex int64           `json:"leaf_index"`
		Entry     json.RawMessage `json:"entry"`
	}
	if err := json.Unmarshal(body, &single); err != nil {
		t.Fatalf("unmarshal /entries/1: %v", err)
	}
	var signedSingle ctlog.SignedEntry
	if err := json.Unmarshal(single.Entry, &signedSingle); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	if !strings.Contains(string(signedSingle.Data), "beta") {
		t.Errorf("expected entry 1 to contain %q, got %q", "beta", signedSingle.Data)
	}

	// GET /entries/99 → 404; GET /entries/-1 → 400
	if code, _ := pocGet(t, server.URL+"/entries/99"); code != http.StatusNotFound {
		t.Errorf("GET /entries/99: expected 404, got %d", code)
	}
	if code, _ := pocGet(t, server.URL+"/entries/-1"); code != http.StatusBadRequest {
		t.Errorf("GET /entries/-1: expected 400, got %d", code)
	}

	// GET /phase
	code, body = pocGet(t, server.URL+"/phase")
	if code != http.StatusOK || !strings.Contains(string(body), `"phase":"setup"`) {
		t.Errorf("GET /phase: expected setup, got %d %s", code, body)
	}

	// GET /checkpoint — the signed note starts with the log origin name.
	code, body = pocGet(t, server.URL+"/checkpoint")
	if code != http.StatusOK {
		t.Fatalf("GET /checkpoint: expected 200, got %d", code)
	}
	if !strings.HasPrefix(string(body), "test.poc.example.com\n") {
		t.Errorf("checkpoint does not start with origin: %q", body)
	}
}

// --- P2: disable_timestamp_validation ----------------------------------------

func TestPoCDisableTimestampValidation(t *testing.T) {
	stale := time.Now().Add(-10 * time.Minute).UnixMilli()

	// Default (validation on): a 10-minute-old timestamp must be rejected.
	pubs, privs := pocKeys(t, "ER-1")
	server := startPoCLog(t, pubs, nil, nil)
	code, body := pocSubmit(t, server, "setup,ER,election_pub_key,1,stale", "ER-1", stale, privs["ER-1"])
	if code != http.StatusBadRequest {
		t.Errorf("validation on: expected 400 for stale timestamp, got %d: %s", code, body)
	}

	// Disabled: the same stale timestamp must be accepted.
	pubs2, privs2 := pocKeys(t, "ER-1")
	server2 := startPoCLog(t, pubs2, nil, func(c *ctlog.Config) {
		c.DisableTimestampValidation = true
	})
	code, body = pocSubmit(t, server2, "setup,ER,election_pub_key,1,stale", "ER-1", stale, privs2["ER-1"])
	if code != http.StatusOK {
		t.Errorf("validation off: expected 200 for stale timestamp, got %d: %s", code, body)
	}
}

// --- P3: grace_period_ms ------------------------------------------------------

func TestPoCGracePeriodMs(t *testing.T) {
	pubs, privs := pocKeys(t, "RT-1", "RT-2", "RT-3")
	server := startPoCLog(t, pubs, nil, func(c *ctlog.Config) {
		c.GracePeriod = 50 * time.Millisecond
	})

	wbbData := "setup,RT,acc_pub_key,2,pk_data_poc"
	now := time.Now().UnixMilli()

	// First signer: pending.
	code, body := pocSubmit(t, server, wbbData, "RT-1", now, privs["RT-1"])
	if code != http.StatusAccepted || !strings.Contains(string(body), `"status":"pending"`) {
		t.Fatalf("RT-1: expected 202 pending, got %d: %s", code, body)
	}

	// Second signer: threshold met, but RT-3 has not signed → grace period.
	code, body = pocSubmit(t, server, wbbData, "RT-2", now, privs["RT-2"])
	if code != http.StatusAccepted || !strings.Contains(string(body), `"status":"grace_period"`) {
		t.Fatalf("RT-2: expected 202 grace_period, got %d: %s", code, body)
	}
	var grace struct {
		GracePeriodEndAt int64 `json:"grace_period_end_at"`
	}
	if err := json.Unmarshal(body, &grace); err != nil {
		t.Fatalf("unmarshal grace response: %v", err)
	}
	delta := grace.GracePeriodEndAt - time.Now().UnixMilli()
	if delta > 1000 {
		t.Errorf("grace_period_ms override not applied: ends in %dms (default would be ~10000)", delta)
	}

	// After the (short) grace period, the entry is finalized and readable.
	time.Sleep(400 * time.Millisecond)
	code, body = pocGet(t, server.URL+"/entries")
	if code != http.StatusOK {
		t.Fatalf("GET /entries: %d", code)
	}
	var entries pocEntriesResponse
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("unmarshal /entries: %v", err)
	}
	if entries.Count != 1 {
		t.Fatalf("expected 1 published entry after grace period, got %d", entries.Count)
	}
	var signed ctlog.SignedEntry
	if err := json.Unmarshal(entries.Entries[0].Entry, &signed); err != nil {
		t.Fatalf("unmarshal published entry: %v", err)
	}
	if string(signed.Data) != wbbData {
		t.Errorf("expected published data %q, got %q", wbbData, signed.Data)
	}
	if len(signed.EntityIDs) != 2 {
		t.Errorf("expected 2 signers, got %v", signed.EntityIDs)
	}
}

// --- P4: max_submit_body_bytes -------------------------------------------------

func TestPoCMaxSubmitBodyBytes(t *testing.T) {
	pubs, privs := pocKeys(t, "ER-1")
	server := startPoCLog(t, pubs, nil, func(c *ctlog.Config) {
		c.MaxSubmitBodyBytes = 2048
	})

	now := time.Now().UnixMilli()

	// Small entry passes.
	code, body := pocSubmit(t, server, "setup,ER,election_pub_key,1,small", "ER-1", now, privs["ER-1"])
	if code != http.StatusOK {
		t.Fatalf("small entry: expected 200, got %d: %s", code, body)
	}

	// A body larger than 2048 bytes is rejected (413 from MaxBytesHandler).
	big := "setup,ER,election_pub_key,1," + strings.Repeat("A", 4096)
	code, body = pocSubmit(t, server, big, "ER-1", now, privs["ER-1"])
	if code != http.StatusRequestEntityTooLarge {
		t.Errorf("big entry: expected 413, got %d: %s", code, body)
	}
}

// --- P5: eligible_vids + revocation_commitment ------------------------------

func TestPoCNewPolicyEntryTypes(t *testing.T) {
	pubs, privs := pocKeys(t, "PM-1", "ER-1")
	pmPub := pubs["PM-1"]
	server := startPoCLog(t, pubs, pmPub, nil)

	now := time.Now().UnixMilli()

	// In setup phase both new types are rejected (wrong phase).
	code, body := pocSubmit(t, server, "setup,ER,eligible_vids,1,[1;2;3]", "ER-1", now, privs["ER-1"])
	if code != http.StatusForbidden {
		t.Errorf("eligible_vids in setup: expected 403, got %d: %s", code, body)
	}
	code, body = pocSubmit(t, server, "setup,ER,revocation_commitment,1,abc", "ER-1", now, privs["ER-1"])
	if code != http.StatusForbidden {
		t.Errorf("revocation_commitment in setup: expected 403, got %d: %s", code, body)
	}

	// setup → voting.
	code, body = pocSubmit(t, server, "setup,PM,phase_transition,1,voting", "PM-1", now, privs["PM-1"])
	if code != http.StatusOK {
		t.Fatalf("phase_transition to voting: expected 200, got %d: %s", code, body)
	}

	// revocation_commitment is allowed in voting; eligible_vids is not.
	code, body = pocSubmit(t, server, "voting,ER,revocation_commitment,1,commit-abc", "ER-1", now, privs["ER-1"])
	if code != http.StatusOK {
		t.Errorf("revocation_commitment in voting: expected 200, got %d: %s", code, body)
	}
	code, body = pocSubmit(t, server, "voting,ER,eligible_vids,1,[1;2;3]", "ER-1", now, privs["ER-1"])
	if code != http.StatusForbidden {
		t.Errorf("eligible_vids in voting: expected 403, got %d: %s", code, body)
	}

	// voting → tallying; eligible_vids becomes allowed.
	code, body = pocSubmit(t, server, "voting,PM,phase_transition,1,tallying", "PM-1", now, privs["PM-1"])
	if code != http.StatusOK {
		t.Fatalf("phase_transition to tallying: expected 200, got %d: %s", code, body)
	}
	code, body = pocSubmit(t, server, "tallying,ER,eligible_vids,1,[1;2;3]", "ER-1", now, privs["ER-1"])
	if code != http.StatusOK {
		t.Errorf("eligible_vids in tallying: expected 200, got %d: %s", code, body)
	}
}
