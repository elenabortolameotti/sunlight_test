package ctlog_test

// A restarted bulletin board must come back exactly where it was: the read
// index is rebuilt from the data tiles (and checked against the signed tree
// head) and the phase is replayed from the published phase_transition leaves.

import (
	"bytes"
	"compress/gzip"
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
	"sync"
	"testing"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/sunlight/internal/validation"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type ed25519PrivateKey = ed25519.PrivateKey

// runLog loads the log on config, serves it and sequences in the background.
// The returned stop function joins the sequencer and closes everything.
func runLog(t *testing.T, config *ctlog.Config) (*httptest.Server, func()) {
	t.Helper()
	log, err := ctlog.LoadLog(context.Background(), config)
	if err != nil {
		t.Fatalf("LoadLog: %v", err)
	}
	server := httptest.NewServer(log.Handler())
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = log.Sequence()
			}
		}
	}()
	return server, func() {
		cancel()
		wg.Wait()
		server.Close()
		log.CloseCache()
	}
}

func TestRestartKeepsEntriesAndPhase(t *testing.T) {
	pubs, privs := pocKeys(t, "PM-1", "RT-1", "RT-2", "ER-1")
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := &ctlog.Config{
		Name:            "restart.poc.example.com",
		Key:             logKey,
		Cache:           filepath.Join(t.TempDir(), "cache.db"),
		Backend:         NewMemoryBackend(t),
		Lock:            NewMemoryLockBackend(t),
		Log:             slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		EntityKeys:      pubs,
		PhaseManagerKey: pubs["PM-1"],
		GracePeriod:     50 * time.Millisecond,
	}
	if err := ctlog.CreateLog(context.Background(), config); err != nil {
		t.Fatalf("CreateLog: %v", err)
	}

	// -- first life: a threshold entry, then setup -> voting ---------------
	server, stop := runLog(t, config)
	now := time.Now().UnixMilli()
	for _, id := range []string{"RT-1", "RT-2"} {
		if code, body := pocSubmit(t, server, "setup,RT,acc_pub_key,2,before-restart", id, now, privs[id]); code != http.StatusOK && code != http.StatusAccepted {
			t.Fatalf("acc_pub_key by %s: HTTP %d: %s", id, code, body)
		}
	}
	if code, body := pocSubmit(t, server, "setup,PM,phase_transition,1,voting", "PM-1", now, privs["PM-1"]); code != http.StatusOK {
		t.Fatalf("phase transition: HTTP %d: %s", code, body)
	}
	deadline := time.Now().Add(5 * time.Second)
	var before validatedEntriesResponse
	for {
		before = fetchValidatedEntries(t, server)
		if before.Count >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 2 sequenced leaves, got %d", before.Count)
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()

	// -- second life: same storage, fresh process state ---------------------
	server, stop = runLog(t, config)
	defer stop()

	after := fetchValidatedEntries(t, server)
	if after.Count != before.Count {
		t.Fatalf("after restart /entries serves %d leaves, want %d", after.Count, before.Count)
	}
	for i := range before.Entries {
		b, a := before.Entries[i], after.Entries[i]
		if a.LeafIndex != b.LeafIndex || a.Timestamp != b.Timestamp || a.LeafHash != b.LeafHash || string(a.Entry) != string(b.Entry) {
			t.Fatalf("leaf %d changed across the restart", i)
		}
	}

	_, body, _ := pocGet(t, server.URL+"/phase")
	var phase struct {
		Phase string `json:"phase"`
	}
	if err := json.Unmarshal(body, &phase); err != nil || phase.Phase != "voting" {
		t.Fatalf("phase after restart = %q (%v), want voting", phase.Phase, err)
	}

	// The board enforces the replayed phase: setup writes are over, voting
	// writes work, and the log keeps growing from where it stopped.
	now = time.Now().UnixMilli()
	if code, body := pocSubmit(t, server, "setup,RT,acc_pub_key,2,after-restart", "RT-1", now, privs["RT-1"]); code != http.StatusForbidden {
		t.Fatalf("setup write after restart: HTTP %d (%s), want 403", code, body)
	}
	if code, body := pocSubmit(t, server, "voting,ER,revocation_commitment,1,after-restart", "ER-1", now, privs["ER-1"]); code != http.StatusOK {
		t.Fatalf("voting write after restart: HTTP %d: %s", code, body)
	}
	deadline = time.Now().Add(5 * time.Second)
	for fetchValidatedEntries(t, server).Count < before.Count+1 {
		if time.Now().After(deadline) {
			t.Fatal("the log did not grow after the restart")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// restartConfig is a fresh single-signer log for the restart tests.
func restartConfig(t *testing.T, name string) (*ctlog.Config, map[string]ed25519PrivateKey) {
	t.Helper()
	pubs, privs := pocKeys(t, "PM-1", "ER-1")
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := &ctlog.Config{
		Name:            name,
		Key:             logKey,
		Cache:           filepath.Join(t.TempDir(), "cache.db"),
		Backend:         NewMemoryBackend(t),
		Lock:            NewMemoryLockBackend(t),
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		EntityKeys:      pubs,
		PhaseManagerKey: pubs["PM-1"],
	}
	if err := ctlog.CreateLog(context.Background(), config); err != nil {
		t.Fatalf("CreateLog: %v", err)
	}
	return config, privs
}

// fillLog appends single-signer entries until the log holds n leaves.
func fillLog(t *testing.T, server *httptest.Server, priv ed25519PrivateKey, from, n int) {
	t.Helper()
	now := time.Now().UnixMilli()
	for i := from; i < n; i++ {
		data := fmt.Sprintf("setup,ER,revocation_commitment,1,leaf-%d", i)
		if code, body := pocSubmit(t, server, data, "ER-1", now, priv); code != http.StatusOK {
			t.Fatalf("leaf %d: HTTP %d: %s", i, code, body)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for fetchValidatedEntries(t, server).Count < n {
		if time.Now().After(deadline) {
			t.Fatalf("log did not reach %d leaves", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The index is rebuilt tile by tile: cover a partial tile, an exactly full
// tile and a full tile followed by a partial one (tile width 256), restarting
// at each size and checking every leaf.
func TestRestartAcrossTileBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("appends 257 leaves")
	}
	config, privs := restartConfig(t, "tiles.poc.example.com")
	size := 0
	for _, target := range []int{255, 256, 257} {
		server, stop := runLog(t, config)
		fillLog(t, server, privs["ER-1"], size, target)
		size = target
		before := fetchValidatedEntries(t, server)
		stop()

		server, stop = runLog(t, config)
		after := fetchValidatedEntries(t, server)
		stop()
		if after.Count != target {
			t.Fatalf("size %d: restart serves %d leaves", target, after.Count)
		}
		for i := range before.Entries {
			if after.Entries[i].LeafIndex != int64(i) || after.Entries[i].LeafHash != before.Entries[i].LeafHash {
				t.Fatalf("size %d: leaf %d changed across the restart", target, i)
			}
		}
	}
}

// A board whose stored leaves no longer match its signed tree head must
// refuse to start rather than serve them.
func TestRestartRefusesTamperedStorage(t *testing.T) {
	config, privs := restartConfig(t, "tamper.poc.example.com")
	server, stop := runLog(t, config)
	fillLog(t, server, privs["ER-1"], 0, 3)
	stop()

	backend := config.Backend.(*MemoryBackend)
	path := sunlight.TilePath(tlog.Tile{H: sunlight.TileHeight, L: -1, N: 0, W: 3})
	original, err := backend.Fetch(context.Background(), path)
	if err != nil {
		t.Fatalf("fetch data tile: %v", err)
	}
	upload := func(data []byte) {
		if err := backend.Upload(context.Background(), path, data, nil); err != nil {
			t.Fatalf("upload: %v", err)
		}
	}

	// 1. One byte of one leaf altered: the leaves no longer hash to the root.
	zr, err := gzip.NewReader(bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	flipped := append([]byte(nil), plain...)
	at := bytes.Index(flipped, []byte("leaf-1"))
	if at < 0 {
		// The entry data is base64 inside JSON: flip a byte well inside it.
		at = len(flipped) / 2
	}
	flipped[at] ^= 0x01
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(flipped)
	zw.Close()
	upload(buf.Bytes())
	if _, err := ctlog.LoadLog(context.Background(), config); err == nil {
		t.Fatal("a log with an altered leaf loaded")
	}

	// 2. Unreadable tile.
	upload([]byte("not a gzip stream"))
	if _, err := ctlog.LoadLog(context.Background(), config); err == nil {
		t.Fatal("a log with an unreadable data tile loaded")
	}

	// 3. Restored storage loads again.
	upload(original)
	log, err := ctlog.LoadLog(context.Background(), config)
	if err != nil {
		t.Fatalf("restored log: %v", err)
	}
	log.CloseCache()
}

// Every tree head the log signs must verify - with the verifier LoadLog
// applies to the lock checkpoint AND with the validators' verifier. ECDSA's r
// and s are occasionally shorter than 32 bytes; a variable-width encoding
// made about one honest signature in 260 unverifiable, which would have
// stopped a board from ever restarting. A foreign key must never verify.
func TestCheckpointSignatureAlwaysVerifies(t *testing.T) {
	const name = "sig.poc.example.com"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	own, err := ctlog.CheckpointVerifierForTest(name, key)
	if err != nil {
		t.Fatal(err)
	}
	validators, err := validation.NewCheckpointVerifier(name, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := ctlog.CheckpointVerifierForTest(name, other)
	if err != nil {
		t.Fatal(err)
	}

	rounds := 4000
	if testing.Short() {
		rounds = 600
	}
	for i := 0; i < rounds; i++ {
		var hash tlog.Hash
		rand.Read(hash[:])
		signed, err := ctlog.SignTreeHeadForTest(name, key, int64(i+1), hash, int64(1_700_000_000_000+i))
		if err != nil {
			t.Fatalf("round %d: sign: %v", i, err)
		}
		if _, err := note.Open(signed, note.VerifierList(own)); err != nil {
			t.Fatalf("round %d: the log cannot verify its own tree head: %v", i, err)
		}
		if _, err := note.Open(signed, note.VerifierList(validators)); err != nil {
			t.Fatalf("round %d: a validator cannot verify an honest tree head: %v", i, err)
		}
		if i < 50 {
			if _, err := note.Open(signed, note.VerifierList(foreign)); err == nil {
				t.Fatalf("round %d: a tree head verified under a foreign key", i)
			}
		}
	}
}

// A restarted board must still know which threshold entries it has already
// published, and who signed them. The log serves those signatures to
// everybody, so if the board forgot, anyone could send a published entry's
// own signatures back in and open a second round for the same data - a
// duplicate leaf for a once-only artifact, with no key of their own.
func TestRestartRefusesReplayOfPublishedThresholdSignatures(t *testing.T) {
	pubs, privs := pocKeys(t, "PM-1", "RT-1", "RT-2", "RT-3")
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := &ctlog.Config{
		Name:            "restart.replay.example.com",
		Key:             logKey,
		Cache:           filepath.Join(t.TempDir(), "cache.db"),
		Backend:         NewMemoryBackend(t),
		Lock:            NewMemoryLockBackend(t),
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		EntityKeys:      pubs,
		PhaseManagerKey: pubs["PM-1"],
		GracePeriod:     50 * time.Millisecond,
	}
	if err := ctlog.CreateLog(context.Background(), config); err != nil {
		t.Fatalf("CreateLog: %v", err)
	}

	const wbbData = "setup,RT,acc_pub_key,2,pk_data_poc"
	now := time.Now().UnixMilli()
	server, stop := runLog(t, config)
	// Two of the three tellers sign; the third is late (it signs only after
	// the restart, further down).
	for _, id := range []string{"RT-1", "RT-2"} {
		if code, body := pocSubmit(t, server, wbbData, id, now, privs[id]); code != http.StatusOK &&
			code != http.StatusAccepted {
			t.Fatalf("%s: %d: %s", id, code, body)
		}
	}
	time.Sleep(300 * time.Millisecond)
	entriesOf := func(server *httptest.Server) pocEntriesResponse {
		t.Helper()
		code, body, _ := pocGet(t, server.URL+"/entries")
		if code != http.StatusOK {
			t.Fatalf("GET /entries: %d", code)
		}
		var entries pocEntriesResponse
		if err := json.Unmarshal(body, &entries); err != nil {
			t.Fatalf("unmarshal /entries: %v", err)
		}
		return entries
	}
	published := entriesOf(server)
	if published.Count != 1 {
		t.Fatalf("expected 1 published entry, got %d", published.Count)
	}
	stop()

	// Restart, then replay the signatures the log itself publishes.
	server, stop = runLog(t, config)
	defer stop()
	for _, id := range []string{"RT-1", "RT-2"} {
		code, body := pocSubmit(t, server, wbbData, id, now, privs[id])
		if code != http.StatusConflict {
			t.Errorf("replay of %s after restart: expected 409, got %d: %s", id, code, body)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if after := entriesOf(server); after.Count != 1 {
		t.Fatalf("the replay created %d extra leaves", after.Count-1)
	}

	// A signer that never signed is still welcome after the restart: it is
	// logged as a late co-signature of the entry it signs, not as a new one.
	code, body := pocSubmit(t, server, wbbData, "RT-3", now+1, privs["RT-3"])
	if code != http.StatusOK {
		t.Fatalf("late co-signer after restart: %d: %s", code, body)
	}
	time.Sleep(300 * time.Millisecond)
	entries := entriesOf(server)
	if entries.Count != 2 {
		t.Fatalf("expected the original entry plus a late co-signature, got %d", entries.Count)
	}
	var late ctlog.SignedEntry
	if err := json.Unmarshal(entries.Entries[1].Entry, &late); err != nil {
		t.Fatalf("unmarshal late co-signature: %v", err)
	}
	if string(late.Data) != "ref:0" {
		t.Errorf("late co-signature must reference the ORIGINAL leaf, got %q", late.Data)
	}
	if late.EntityID != "RT-3" {
		t.Errorf("late co-signature signed by %q", late.EntityID)
	}
}

// The deduplication cache is a separate file the log can lose (a restore
// without it, a crash, an operator following upstream advice). Without the
// cache, a replay of any single-signer leaf the log SERVES - by anyone, no key
// needed - would be appended a second time: a duplicate of a once-only setup
// artifact. The cache is therefore reseeded from the log at startup.
func TestRestartWithoutCacheStillDeduplicates(t *testing.T) {
	config, privs := restartConfig(t, "restart.cache.example.com")
	server, stop := runLog(t, config)
	now := time.Now().UnixMilli()
	if code, body := pocSubmit(t, server, "setup,ER,election_pub_key,1,pk_data_poc", "ER-1", now, privs["ER-1"]); code != http.StatusOK {
		t.Fatalf("first submission: %d: %s", code, body)
	}
	code, body, _ := pocGet(t, server.URL+"/entries")
	if code != http.StatusOK {
		t.Fatalf("GET /entries: %d", code)
	}
	var served pocEntriesResponse
	if err := json.Unmarshal(body, &served); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if served.Count != 1 {
		t.Fatalf("expected 1 entry, got %d", served.Count)
	}
	stop()

	// Lose the cache, keep the log.
	if err := os.Remove(config.Cache); err != nil {
		t.Fatalf("remove cache: %v", err)
	}
	server, stop = runLog(t, config)
	defer stop()

	// Replay the leaf exactly as served.
	resp, err := http.Post(server.URL+"/submit", "application/json", bytes.NewReader(served.Entries[0].Entry))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replay: expected 200 (deduplicated), got %d: %s", resp.StatusCode, got)
	}
	time.Sleep(300 * time.Millisecond)
	code, body, _ = pocGet(t, server.URL+"/entries")
	if code != http.StatusOK {
		t.Fatalf("GET /entries: %d", code)
	}
	var after pocEntriesResponse
	if err := json.Unmarshal(body, &after); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if after.Count != 1 {
		t.Fatalf("the replay created %d extra leaves after the cache was lost", after.Count-1)
	}
}
