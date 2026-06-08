package ctlog_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/sunlight/internal/ctlog"
)

// signWBBEntry creates a signed WBB entry for any entity.
func signWBBEntry(wbbData, entityID string, priv ed25519.PrivateKey) map[string]interface{} {
	ts := time.Now().UnixMilli()
	var buf bytes.Buffer
	buf.WriteString(wbbData)
	buf.WriteString(entityID)
	buf.WriteString(fmt.Sprintf("%d", ts))
	msg := sha256.Sum256(buf.Bytes())
	sig := ed25519.Sign(priv, msg[:])
	return map[string]interface{}{
		"data":      base64.StdEncoding.EncodeToString([]byte(wbbData)),
		"entity_id": entityID,
		"timestamp": ts,
		"signature": base64.StdEncoding.EncodeToString(sig),
	}
}

func TestPhaseManagerTransitions(t *testing.T) {
	// Generate phase_manager key
	_, pmPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pmPub := pmPriv.Public().(ed25519.PublicKey)

	// Generate ER keys for WBB submissions
	_, er1Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	er1Pub := er1Priv.Public().(ed25519.PublicKey)

	// Create test log
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	config := &ctlog.Config{
		Name:  "test.wbb.example.com",
		Key:   logKey,
		Cache: filepath.Join(tmpDir, "cache.db"),
		Backend: NewMemoryBackend(t),
		Lock:    NewMemoryLockBackend(t),
		Log:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		EntityKeys: map[string]ed25519.PublicKey{
			"PM-1": pmPub, // Phase manager entity with its own key
			"ER-1": er1Pub,
		},
		EntityBLSKeys:   testEntityBLSKeys,
		PhaseManagerKey: pmPub,
	}

	ctx := context.Background()
	if err := ctlog.CreateLog(ctx, config); err != nil {
		t.Fatal(err)
	}
	log, err := ctlog.LoadLog(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer log.CloseCache()

	server := httptest.NewServer(log.Handler())
	defer server.Close()

	// Start the sequencer
	seqCtx, seqCancel := context.WithCancel(context.Background())
	defer seqCancel()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
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

	// --- Helper: post a submit ---
	postSubmit := func(body map[string]interface{}) *http.Response {
		b, _ := json.Marshal(body)
		resp, err := http.Post(server.URL+"/submit", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("POST /submit failed: %v", err)
		}
		return resp
	}

	// --- Helper: assert status ---
	assertStatus := func(resp *http.Response, want int, msg string) {
		t.Helper()
		if resp.StatusCode != want {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("%s: got %d, want %d, body: %s", msg, resp.StatusCode, want, string(body))
		}
		resp.Body.Close()
	}

	// 1. Unauthorized phase_manager (wrong key)
	t.Run("unauthorized phase_manager", func(t *testing.T) {
		_, wrongPriv, _ := ed25519.GenerateKey(nil)
		wbb := "setup,PM,phase_transition,1,voting"
		body := signWBBEntry(wbb, "PM-1", wrongPriv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusForbidden, "unauthorized PM should be rejected")
	})

	// 2. Current phase mismatch (server is setup, entry says voting)
	t.Run("current phase mismatch", func(t *testing.T) {
		wbb := "voting,PM,phase_transition,1,tallying"
		body := signWBBEntry(wbb, "PM-1", pmPriv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusForbidden, "mismatched current phase should be rejected")
	})

	// 3. Skip transition (setup -> tallying)
	t.Run("skip transition", func(t *testing.T) {
		wbb := "setup,PM,phase_transition,1,tallying"
		body := signWBBEntry(wbb, "PM-1", pmPriv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusForbidden, "skipping phase should be rejected")
	})

	// 4. Valid: setup -> voting
	t.Run("setup to voting", func(t *testing.T) {
		wbb := "setup,PM,phase_transition,1,voting"
		body := signWBBEntry(wbb, "PM-1", pmPriv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusOK, "valid transition should succeed")
	})

	// 5. Backwards transition (voting -> setup)
	t.Run("backwards transition", func(t *testing.T) {
		wbb := "voting,PM,phase_transition,1,setup"
		body := signWBBEntry(wbb, "PM-1", pmPriv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusForbidden, "backwards transition should be rejected")
	})

	// 6. Valid: voting -> tallying
	t.Run("voting to tallying", func(t *testing.T) {
		wbb := "voting,PM,phase_transition,1,tallying"
		body := signWBBEntry(wbb, "PM-1", pmPriv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusOK, "valid transition should succeed")
	})

	// 7. Terminal: tallying -> voting
	t.Run("terminal state", func(t *testing.T) {
		wbb := "tallying,PM,phase_transition,1,voting"
		body := signWBBEntry(wbb, "PM-1", pmPriv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusForbidden, "transition from terminal state should be rejected")
	})
}

func TestPhaseEnforcementOnSubmit(t *testing.T) {
	_, pmPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pmPub := pmPriv.Public().(ed25519.PublicKey)

	_, er1Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	er1Pub := er1Priv.Public().(ed25519.PublicKey)

	_, bb1Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bb1Pub := bb1Priv.Public().(ed25519.PublicKey)

	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	config := &ctlog.Config{
		Name:  "test.wbb.example.com",
		Key:   logKey,
		Cache: filepath.Join(tmpDir, "cache.db"),
		Backend: NewMemoryBackend(t),
		Lock:    NewMemoryLockBackend(t),
		Log:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		EntityKeys: map[string]ed25519.PublicKey{
			"PM-1": pmPub, // Phase manager entity
			"ER-1": er1Pub,
			"BB-1": bb1Pub,
		},
		EntityBLSKeys:   testEntityBLSKeys,
		PhaseManagerKey: pmPub,
	}

	ctx := context.Background()
	if err := ctlog.CreateLog(ctx, config); err != nil {
		t.Fatal(err)
	}
	log, err := ctlog.LoadLog(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer log.CloseCache()

	server := httptest.NewServer(log.Handler())
	defer server.Close()

	// Start the sequencer so staged entries don't block.
	seqCtx, seqCancel := context.WithCancel(context.Background())
	defer seqCancel()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
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

	// Helper to sign a WBB entry for a given entity.
	signWBB := func(phase, role, entryType, content string, threshold int, entityID string, priv ed25519.PrivateKey) map[string]interface{} {
		wbb := fmt.Sprintf("%s,%s,%s,%d,%s", phase, role, entryType, threshold, content)
		ts := time.Now().UnixMilli()
		var buf bytes.Buffer
		buf.WriteString(wbb)
		buf.WriteString(entityID)
		buf.WriteString(fmt.Sprintf("%d", ts))
		msg := sha256.Sum256(buf.Bytes())
		sig := ed25519.Sign(priv, msg[:])
		return map[string]interface{}{
			"data":      base64.StdEncoding.EncodeToString([]byte(wbb)),
			"entity_id": entityID,
			"timestamp": ts,
			"signature": base64.StdEncoding.EncodeToString(sig),
		}
	}

	postSubmit := func(body map[string]interface{}) *http.Response {
		b, _ := json.Marshal(body)
		resp, err := http.Post(server.URL+"/submit", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("POST /submit failed: %v", err)
		}
		return resp
	}

	assertStatus := func(resp *http.Response, want int, msg string) {
		t.Helper()
		if resp.StatusCode != want {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("%s: got %d, want %d, body: %s", msg, resp.StatusCode, want, string(body))
		}
		resp.Body.Close()
	}

	// 1. Setup entry during setup phase should succeed (ER with threshold 1)
	t.Run("setup entry in setup phase", func(t *testing.T) {
		body := signWBB("setup", "ER", "election_pub_key", "pk_data", 1, "ER-1", er1Priv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusOK, "setup entry should succeed in setup phase")
	})

	// 2. Voting entry during setup phase should be rejected
	t.Run("voting entry in setup phase", func(t *testing.T) {
		body := signWBB("voting", "BB", "ballot_digest", "digest1", 1, "BB-1", bb1Priv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusForbidden, "voting entry should be rejected in setup phase")
	})

	// 3. Advance to voting via logged phase_transition entry
	wbbPM := "setup,PM,phase_transition,1,voting"
	bodyPM := signWBBEntry(wbbPM, "PM-1", pmPriv)
	resp := postSubmit(bodyPM)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("failed to advance to voting phase: %d, body: %s", resp.StatusCode, string(body))
	}
	resp.Body.Close()

	// 4. Setup entry during voting phase should be rejected
	t.Run("setup entry in voting phase", func(t *testing.T) {
		body := signWBB("setup", "ER", "election_pub_key", "pk_data2", 1, "ER-1", er1Priv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusForbidden, "setup entry should be rejected in voting phase")
	})

	// 5. Voting entry during voting phase should succeed
	t.Run("voting entry in voting phase", func(t *testing.T) {
		body := signWBB("voting", "BB", "ballot_digest", "digest2", 1, "BB-1", bb1Priv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusOK, "voting entry should succeed in voting phase")
	})

	// 6. Advance to tallying via logged phase_transition entry
	wbbPM = "voting,PM,phase_transition,1,tallying"
	bodyPM = signWBBEntry(wbbPM, "PM-1", pmPriv)
	resp = postSubmit(bodyPM)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("failed to advance to tallying phase: %d, body: %s", resp.StatusCode, string(body))
	}
	resp.Body.Close()

	// 7. Tallying entry during tallying phase should succeed
	t.Run("tallying entry in tallying phase", func(t *testing.T) {
		body := signWBB("tallying", "BB", "encrypted_ballot", "ballot1", 1, "BB-1", bb1Priv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusOK, "tallying entry should succeed in tallying phase")
	})

	// 8. Voting entry during tallying phase should be rejected
	t.Run("voting entry in tallying phase", func(t *testing.T) {
		body := signWBB("voting", "BB", "ballot_digest", "digest3", 1, "BB-1", bb1Priv)
		resp := postSubmit(body)
		assertStatus(resp, http.StatusForbidden, "voting entry should be rejected in tallying phase")
	})
}
