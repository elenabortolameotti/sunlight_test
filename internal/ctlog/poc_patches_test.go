package ctlog_test

// Tests for the PoC WBB patches P1–P5 (branch referendum-poc-wbb):
//
//	P1 read API (/entries, /entries/{index}, /phase, /checkpoint)
//	P2 disable_timestamp_validation
//	P3 grace_period_ms
//	P4 max_submit_body_bytes
//	P5 eligible_vids + revocation_commitment policy entry types
//	P7 only verified fields are sequenced (a public entry cannot be replayed
//	   into a second leaf by adding an unverified field)

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	server, _ := startPoCLogWithLog(t, entityKeys, pmKey, tune)
	return server
}

// startPoCLogWithLog is startPoCLog, also returning the log itself.
func startPoCLogWithLog(t *testing.T, entityKeys map[string]ed25519.PublicKey, pmKey ed25519.PublicKey, tune func(*ctlog.Config)) (*httptest.Server, *ctlog.Log) {
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

	// Cancel AND join the sequencer before the (earlier-registered, so
	// later-run) CloseCache cleanup: a Sequence() racing the cache close
	// panics the test binary with SQLITE_MISUSE inside sqlitex.Save.
	seqCtx, cancel := context.WithCancel(context.Background())
	var seqWg sync.WaitGroup
	seqWg.Add(1)
	t.Cleanup(func() {
		cancel()
		seqWg.Wait()
	})
	go func() {
		defer seqWg.Done()
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

	return server, log
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

func pocGet(t *testing.T, url string) (int, []byte, string) {
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
	return resp.StatusCode, body, resp.Header.Get("Access-Control-Allow-Origin")
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
	code, body, cors := pocGet(t, server.URL+"/entries")
	if code != http.StatusOK {
		t.Fatalf("GET /entries: expected 200, got %d", code)
	}
	if cors != "*" {
		t.Errorf("GET /entries: expected CORS *, got %q", cors)
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
	code, body, cors = pocGet(t, server.URL+"/entries/1")
	if code != http.StatusOK {
		t.Fatalf("GET /entries/1: expected 200, got %d", code)
	}
	if cors != "*" {
		t.Errorf("GET /entries/1: expected CORS *, got %q", cors)
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

	// GET /entries?start=1 serves the leaves from leaf 1 on; past the end,
	// none; a start that is not a leaf index is refused.
	code, body, _ = pocGet(t, server.URL+"/entries?start=1")
	if code != http.StatusOK {
		t.Fatalf("GET /entries?start=1: expected 200, got %d", code)
	}
	var from1 pocEntriesResponse
	if err := json.Unmarshal(body, &from1); err != nil {
		t.Fatalf("unmarshal /entries?start=1: %v", err)
	}
	if len(from1.Entries) != 1 || from1.Entries[0].LeafIndex != 1 {
		t.Fatalf("GET /entries?start=1: expected leaf 1 alone, got %s", body)
	}
	code, body, _ = pocGet(t, server.URL+"/entries?start=2")
	var past pocEntriesResponse
	if err := json.Unmarshal(body, &past); code != http.StatusOK || err != nil || len(past.Entries) != 0 {
		t.Fatalf("GET /entries?start=2: expected no entries, got %d %s", code, body)
	}
	for _, bad := range []string{"-1", "x"} {
		if code, _, _ := pocGet(t, server.URL+"/entries?start="+bad); code != http.StatusBadRequest {
			t.Errorf("GET /entries?start=%s: expected 400, got %d", bad, code)
		}
	}

	// GET /entries/99 → 404; GET /entries/-1 → 400
	if code, _, _ := pocGet(t, server.URL+"/entries/99"); code != http.StatusNotFound {
		t.Errorf("GET /entries/99: expected 404, got %d", code)
	}
	if code, _, _ := pocGet(t, server.URL+"/entries/-1"); code != http.StatusBadRequest {
		t.Errorf("GET /entries/-1: expected 400, got %d", code)
	}

	// GET /phase
	code, body, cors = pocGet(t, server.URL+"/phase")
	if code != http.StatusOK || !strings.Contains(string(body), `"phase":"setup"`) {
		t.Errorf("GET /phase: expected setup, got %d %s", code, body)
	}
	if cors != "*" {
		t.Errorf("GET /phase: expected CORS *, got %q", cors)
	}

	// GET /checkpoint — the signed note starts with the log origin name.
	code, body, cors = pocGet(t, server.URL+"/checkpoint")
	if code != http.StatusOK {
		t.Fatalf("GET /checkpoint: expected 200, got %d", code)
	}
	if cors != "*" {
		t.Errorf("GET /checkpoint: expected CORS *, got %q", cors)
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
	code, body, _ = pocGet(t, server.URL+"/entries")
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

func TestPoCMaxSubmitBodyBytesDefault(t *testing.T) {
	pubs, privs := pocKeys(t, "ER-1")
	server := startPoCLog(t, pubs, nil, nil) // default limit = 128 KiB

	now := time.Now().UnixMilli()

	// Just under 128 KiB total body passes.
	under := "setup,ER,election_pub_key,1," + strings.Repeat("A", 90*1024)
	code, body := pocSubmit(t, server, under, "ER-1", now, privs["ER-1"])
	if code != http.StatusOK {
		t.Fatalf("under default limit: expected 200, got %d: %s", code, body)
	}

	// Over 128 KiB returns 413.
	over := "setup,ER,election_pub_key,1," + strings.Repeat("A", 200*1024)
	code, body = pocSubmit(t, server, over, "ER-1", now, privs["ER-1"])
	if code != http.StatusRequestEntityTooLarge {
		t.Errorf("over default limit: expected 413, got %d: %s", code, body)
	}
}

// --- P5: eligible_vids + revocation_commitment ------------------------------

func TestPoCNewPolicyEntryTypes(t *testing.T) {
	pubs, privs := pocKeys(t, "PM-1", "ER-1", "BB-1")
	pmPub := pubs["PM-1"]
	server := startPoCLog(t, pubs, pmPub, nil)

	now := time.Now().UnixMilli()

	// In setup phase both new types are rejected (wrong phase).
	// The assigned-id commitment is a SETUP entry of the ER.
	if code, body := pocSubmit(t, server, "setup,ER,assigned_vids,1,[1;2;3]", "ER-1", now, privs["ER-1"]); code != http.StatusOK {
		t.Errorf("assigned_vids in setup: expected 200, got %d: %s", code, body)
	}
	// The tabulation tellers' public key shares are a SETUP entry of the ER
	// too; a ballot box may not write them, and not in the voting phase.
	if code, body := pocSubmit(t, server, "setup,ER,tt_public_shares,1,W10=", "ER-1", now, privs["ER-1"]); code != http.StatusOK {
		t.Errorf("tt_public_shares in setup: expected 200, got %d: %s", code, body)
	}
	if code, body := pocSubmit(t, server, "setup,BB,tt_public_shares,1,W10=", "BB-1", now, privs["BB-1"]); code != http.StatusForbidden {
		t.Errorf("tt_public_shares by a ballot box: expected 403, got %d: %s", code, body)
	}
	// A padded field is refused rather than trimmed: the verifiers that read
	// the log back trim nothing, so an entry accepted here must parse there.
	if code, body := pocSubmit(t, server, "setup, ER,assigned_vids,1,[1;2;3]", "ER-1", now, privs["ER-1"]); code == http.StatusOK {
		t.Errorf("padded role field: expected a refusal, got %d: %s", code, body)
	}
	if code, body := pocSubmit(t, server, "setup,ER,assigned_vids, 1,[1;2;3]", "ER-1", now, privs["ER-1"]); code == http.StatusOK {
		t.Errorf("padded threshold field: expected a refusal, got %d: %s", code, body)
	}
	code, body := pocSubmit(t, server, "setup,ER,eligible_vids,1,[1;2;3]", "ER-1", now, privs["ER-1"])
	if code != http.StatusForbidden {
		t.Errorf("eligible_vids in setup: expected 403, got %d: %s", code, body)
	}
	// A revocation commitment is accepted already in setup: enrollment, and
	// therefore revocation, happens inside the setup write window.
	code, body = pocSubmit(t, server, "setup,ER,revocation_commitment,1,early", "ER-1", now, privs["ER-1"])
	if code != http.StatusOK {
		t.Errorf("revocation_commitment in setup: expected 200, got %d: %s", code, body)
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

// The registration tellers, and only they, write the credential control
// elements, and only during tallying (paper Sec. 3.4.2 / Sec. 3.9 step 19).
func TestPoCCredentialControlPolicy(t *testing.T) {
	pubs, privs := pocKeys(t, "PM-1", "RT-1", "RT-2", "TT-1", "ER-1")
	server := startPoCLog(t, pubs, pubs["PM-1"], func(c *ctlog.Config) {
		c.GracePeriod = 50 * time.Millisecond
	})
	now := time.Now().UnixMilli()
	control := "tallying,RT,credential_control,2,elements"

	// Not before tallying.
	if code, body := pocSubmit(t, server, "setup,RT,credential_control,2,elements", "RT-1", now, privs["RT-1"]); code != http.StatusForbidden {
		t.Fatalf("credential_control in setup: HTTP %d (%s), want 403", code, body)
	}
	for _, step := range []string{"setup,PM,phase_transition,1,voting", "voting,PM,phase_transition,1,tallying"} {
		if code, body := pocSubmit(t, server, step, "PM-1", now, privs["PM-1"]); code != http.StatusOK {
			t.Fatalf("%s: HTTP %d: %s", step, code, body)
		}
	}
	// Not by another role, and not below the RT threshold.
	if code, body := pocSubmit(t, server, "tallying,TT,credential_control,3,elements", "TT-1", now, privs["TT-1"]); code != http.StatusForbidden {
		t.Fatalf("credential_control by a TT: HTTP %d (%s), want 403", code, body)
	}
	if code, body := pocSubmit(t, server, "tallying,RT,credential_control,1,elements", "RT-1", now, privs["RT-1"]); code != http.StatusForbidden {
		t.Fatalf("credential_control with threshold 1: HTTP %d (%s), want 403", code, body)
	}
	// Two tellers agreeing on the same data publish it.
	for _, id := range []string{"RT-1", "RT-2"} {
		if code, body := pocSubmit(t, server, control, id, now, privs[id]); code != http.StatusOK && code != http.StatusAccepted {
			t.Fatalf("credential_control by %s: HTTP %d: %s", id, code, body)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, body, _ := pocGet(t, server.URL+"/entries")
		if strings.Contains(string(body), "credential_control") || time.Now().After(deadline) {
			if !strings.Contains(string(body), "\"leaf_index\":2") {
				t.Fatalf("the credential_control entry was not sequenced: %s", body)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// --- P7: a submission is logged as verified, not as sent ----------------------

// Anyone can read the log. If unverified fields travelled with an entry into
// the leaf, anyone could take a published entry, add such a field and submit
// it again: the signature still verifies, the bytes differ, so the entry would
// be appended a SECOND time - a duplicate of a once-only artifact, and a leaf
// no entity can be held to.
func TestPoCReplayWithUnverifiedFieldIsNotASecondLeaf(t *testing.T) {
	pubs, privs := pocKeys(t, "ER-1")
	server := startPoCLog(t, pubs, nil, nil)
	const wbbData = "setup,ER,election_pub_key,1,pk_data_poc"
	now := time.Now().UnixMilli()

	if code, body := pocSubmit(t, server, wbbData, "ER-1", now, privs["ER-1"]); code != http.StatusOK {
		t.Fatalf("first submission: %d: %s", code, body)
	}

	// The published entry, exactly as the log serves it to everybody.
	code, body, _ := pocGet(t, server.URL+"/entries")
	if code != http.StatusOK {
		t.Fatalf("GET /entries: %d", code)
	}
	var entries pocEntriesResponse
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("unmarshal /entries: %v", err)
	}
	if entries.Count != 1 {
		t.Fatalf("expected 1 entry, got %d", entries.Count)
	}
	var published map[string]json.RawMessage
	if err := json.Unmarshal(entries.Entries[0].Entry, &published); err != nil {
		t.Fatalf("unmarshal published entry: %v", err)
	}

	// Replay it with one extra field the single-signer path does not verify.
	for _, extra := range []struct {
		field string
		value string
		want  int
	}{
		{"sig_algorithm", `"ed25519"`, http.StatusOK},     // ignored: same leaf
		{"entity_ids", `["ER-2"]`, http.StatusBadRequest}, // refused outright
		{"signatures", `["AAAA"]`, http.StatusBadRequest}, // refused outright
		{"signer_timestamps", `[]`, http.StatusOK},        // empty: nothing added
	} {
		replay := make(map[string]json.RawMessage, len(published)+1)
		for k, v := range published {
			replay[k] = v
		}
		replay[extra.field] = json.RawMessage(extra.value)
		raw, err := json.Marshal(replay)
		if err != nil {
			t.Fatalf("marshal replay: %v", err)
		}
		resp, err := http.Post(server.URL+"/submit", "application/json", strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("submit replay: %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != extra.want {
			t.Errorf("replay with %s: expected %d, got %d: %s",
				extra.field, extra.want, resp.StatusCode, got)
		}

		code, body, _ = pocGet(t, server.URL+"/entries")
		if code != http.StatusOK {
			t.Fatalf("GET /entries: %d", code)
		}
		if err := json.Unmarshal(body, &entries); err != nil {
			t.Fatalf("unmarshal /entries: %v", err)
		}
		if entries.Count != 1 {
			t.Fatalf("replay with %s created a second leaf: %d entries", extra.field, entries.Count)
		}
	}
}

// --- writer's share of the pool ---------------------------------------------

// One writer submitting as fast as it can fills its own share of the pool
// and no more: another writer's leaf still finds room in the same pool.
func TestPoCWriterPoolShare(t *testing.T) {
	pubs, _ := pocKeys(t, "BB-1", "BB-2")
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := &ctlog.Config{
		Name:       "test.poc.example.com",
		Key:        logKey,
		PoolSize:   4,
		Cache:      filepath.Join(t.TempDir(), "cache.db"),
		Backend:    NewMemoryBackend(t),
		Lock:       NewMemoryLockBackend(t),
		Log:        slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		EntityKeys: pubs,
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

	leaf := func(n int) *ctlog.PendingLogEntry {
		return &ctlog.PendingLogEntry{Data: []byte(fmt.Sprintf("leaf %d", n))}
	}
	// Two entities, a pool of 4: a share of 2 each.
	for n := 0; n < 2; n++ {
		if _, source := log.AddLeafToPoolAs(leaf(n), "BB-2"); source != "sequencer" {
			t.Fatalf("BB-2 leaf %d within its share: got %q", n, source)
		}
	}
	wait, source := log.AddLeafToPoolAs(leaf(2), "BB-2")
	if source != "ratelimit" {
		t.Fatalf("BB-2 past its share: expected ratelimit, got %q", source)
	}
	if _, err := wait(ctx); err != ctlog.ErrWriterShareFull {
		t.Fatalf("BB-2 past its share: expected ErrWriterShareFull, got %v", err)
	}
	if _, source := log.AddLeafToPoolAs(leaf(3), "BB-1"); source != "sequencer" {
		t.Fatalf("BB-1 while BB-2 is at its share: got %q", source)
	}
	if err := log.Sequence(); err != nil {
		t.Fatalf("Sequence: %v", err)
	}
	// A new pool, a new share.
	if _, source := log.AddLeafToPoolAs(leaf(4), "BB-2"); source != "sequencer" {
		t.Fatalf("BB-2 in the next pool: got %q", source)
	}
}

// --- staged entries that never complete -------------------------------------

// A ballot box's entry is its own statement: one that declares a threshold
// above 1 is refused, never staged to wait for co-signers that will not come.
func TestPoCBallotBoxEntriesAreSingleSigned(t *testing.T) {
	pubs, privs := pocKeys(t, "BB-1", "BB-2")
	server, log := startPoCLogWithLog(t, pubs, nil, nil)
	now := time.Now().UnixMilli()
	for _, data := range []string{
		"voting,BB,ballot_digest,2,junk",
		"voting,BB,ballot_metadata,2,junk",
		"voting,BB,cast_intended_proof,2,junk",
		"tallying,BB,encrypted_ballot,2,junk",
	} {
		if code, body := pocSubmit(t, server, data, "BB-2", now, privs["BB-2"]); code != http.StatusForbidden {
			t.Errorf("%s: expected 403, got %d: %s", data, code, body)
		}
	}
	if n := log.StagingLenForTest(); n != 0 {
		t.Errorf("expected nothing staged, got %d", n)
	}
	if code, body := pocSubmit(t, server, "voting,BB,ballot_digest,1,ok", "BB-2", now+1, privs["BB-2"]); code != http.StatusOK {
		t.Fatalf("threshold-1 ballot_digest: expected 200, got %d: %s", code, body)
	}
}

// One writer may hold only a bounded number of staged entries that are not
// published: a teller staging entries its co-signers never complete cannot
// grow the board's memory without limit. An entry that completes frees its
// place.
func TestPoCPendingStagingIsBoundedPerWriter(t *testing.T) {
	pubs, privs := pocKeys(t, "RT-1", "RT-2")
	server, log := startPoCLogWithLog(t, pubs, nil, nil)
	now := time.Now().UnixMilli()
	control := func(i int) string { return fmt.Sprintf("tallying,RT,credential_control,2,junk-%d", i) }
	for i := 0; i < ctlog.MaxPendingPerWriter; i++ {
		if code, body := pocSubmit(t, server, control(i), "RT-1", now, privs["RT-1"]); code != http.StatusAccepted {
			t.Fatalf("pending entry %d: expected 202, got %d: %s", i, code, body)
		}
	}
	over := ctlog.MaxPendingPerWriter
	if code, body := pocSubmit(t, server, control(over), "RT-1", now, privs["RT-1"]); code != http.StatusServiceUnavailable ||
		!strings.Contains(string(body), "waiting for co-signers") {
		t.Fatalf("entry past the bound: expected 503 naming the bound, got %d: %s", code, body)
	}
	if n := log.StagingLenForTest(); n != ctlog.MaxPendingPerWriter {
		t.Fatalf("expected %d staged, got %d", ctlog.MaxPendingPerWriter, n)
	}
	// RT-2 completes one of them: published, and RT-1 has a place again.
	if code, body := pocSubmit(t, server, control(0), "RT-2", now, privs["RT-2"]); code != http.StatusOK {
		t.Fatalf("completing entry 0: expected 200, got %d: %s", code, body)
	}
	if code, body := pocSubmit(t, server, control(over), "RT-1", now, privs["RT-1"]); code != http.StatusAccepted {
		t.Fatalf("after one completed: expected 202, got %d: %s", code, body)
	}
}

// The bound also covers the bytes a writer's pending entries hold: four
// times the largest submission the log accepts.
func TestPoCPendingStagingBytesAreBoundedPerWriter(t *testing.T) {
	pubs, privs := pocKeys(t, "RT-1", "RT-2")
	server, _ := startPoCLogWithLog(t, pubs, nil, nil)
	now := time.Now().UnixMilli()
	big := strings.Repeat("x", 60*1024)
	accepted := 0
	for i := 0; i < 20; i++ {
		data := fmt.Sprintf("tallying,RT,credential_control,2,%d-%s", i, big)
		code, body := pocSubmit(t, server, data, "RT-1", now, privs["RT-1"])
		if code == http.StatusServiceUnavailable {
			break
		}
		if code != http.StatusAccepted {
			t.Fatalf("pending entry %d: expected 202 or 503, got %d: %s", i, code, body)
		}
		accepted++
	}
	// 128 KiB default body cap: 512 KiB of pending data, eight 60 KiB entries.
	if accepted != 8 {
		t.Fatalf("expected 8 pending 60 KiB entries before the byte bound, got %d", accepted)
	}
}
