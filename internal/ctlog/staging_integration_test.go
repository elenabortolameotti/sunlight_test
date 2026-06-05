package ctlog_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

// TestStagingIntegration runs a real end-to-end staging flow using the actual
// HTTP server and client. It exercises every code path in the staging mechanism.
func TestStagingIntegration(t *testing.T) {
	// --- 1. Setup keys ---
	_, rt1Priv, _ := ed25519.GenerateKey(rand.Reader)
	_, rt2Priv, _ := ed25519.GenerateKey(rand.Reader)
	_, rt3Priv, _ := ed25519.GenerateKey(rand.Reader)
	rt1Pub := rt1Priv.Public().(ed25519.PublicKey)
	rt2Pub := rt2Priv.Public().(ed25519.PublicKey)
	rt3Pub := rt3Priv.Public().(ed25519.PublicKey)

	logKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tmpDir := t.TempDir()
	config := &ctlog.Config{
		Name:       "test.log.example.com",
		Key:        logKey,
		Cache:      filepath.Join(tmpDir, "cache.db"),
		Backend:    NewMemoryBackend(t),
		Lock:       NewMemoryLockBackend(t),
		Log:        slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		EntityKeys: map[string]ed25519.PublicKey{"RT-1": rt1Pub, "RT-2": rt2Pub, "RT-3": rt3Pub},
	}

	ctx := context.Background()
	if err := ctlog.CreateLog(ctx, config); err != nil {
		t.Fatalf("create log: %v", err)
	}
	log, err := ctlog.LoadLog(ctx, config)
	if err != nil {
		t.Fatalf("load log: %v", err)
	}
	defer log.CloseCache()

	// Start sequencer.
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			_ = log.Sequence()
		}
	}()

	// Start real HTTP server.
	server := httptest.NewServer(log.Handler())
	defer server.Close()
	baseURL := server.URL

	// Helper.
	wbbSign := func(wbbData, entityID string, priv ed25519.PrivateKey) ctlog.SignedEntry {
		ts := time.Now().UnixMilli()
		var buf bytes.Buffer
		buf.WriteString(wbbData)
		buf.WriteString(entityID)
		buf.WriteString(fmt.Sprintf("%d", ts))
		msg := sha256.Sum256(buf.Bytes())
		return ctlog.SignedEntry{
			Data:      []byte(wbbData),
			EntityID:  entityID,
			Timestamp: ts,
			Signature: ed25519.Sign(priv, msg[:]),
		}
	}

	// --- 2. Submit RT-1 → pending ---
	wbb := "setup,RT,acc_pub_key,2,pk_data"
	resp1 := submitHTTP(t, baseURL+"/submit", wbbSign(wbb, "RT-1", rt1Priv))
	body1 := assertStatus(t, resp1, http.StatusAccepted, "RT-1 should be pending")
	assertJSONField(t, body1, "status", "pending")
	fmt.Printf("   RT-1 submit → %d: %s\n", http.StatusAccepted, string(body1))

	// --- 3. Submit RT-2 → threshold met, grace period starts ---
	resp2 := submitHTTP(t, baseURL+"/submit", wbbSign(wbb, "RT-2", rt2Priv))
	body2 := assertStatus(t, resp2, http.StatusAccepted, "RT-2 should start grace period")
	assertJSONField(t, body2, "status", "grace_period")
	fmt.Printf("   RT-2 submit → %d: %s\n", http.StatusAccepted, string(body2))

	// --- 4. Submit RT-3 → all signers present → early publication ---
	resp3 := submitHTTP(t, baseURL+"/submit", wbbSign(wbb, "RT-3", rt3Priv))
	body3 := assertStatus(t, resp3, http.StatusOK, "RT-3 should trigger early publication")
	assertJSONField(t, body3, "status", "published")
	fmt.Printf("   RT-3 submit → %d: %s\n", http.StatusOK, string(body3))

	// --- 5. Wait for grace period ---
	fmt.Println("   Waiting 11s for grace period...")
	time.Sleep(11 * time.Second)

	// --- 6. Submit RT-1 again → duplicate / already published ---
	respDup := submitHTTP(t, baseURL+"/submit", wbbSign(wbb, "RT-1", rt1Priv))
	bodyDup := assertStatus(t, respDup, http.StatusConflict, "RT-1 duplicate should be rejected")
	fmt.Printf("   RT-1 duplicate → %d: %s\n", http.StatusConflict, string(bodyDup))

	// --- 7. Submit RT-3 again → duplicate ---
	respDup3 := submitHTTP(t, baseURL+"/submit", wbbSign(wbb, "RT-3", rt3Priv))
	bodyDup3 := assertStatus(t, respDup3, http.StatusConflict, "RT-3 duplicate should be rejected")
	fmt.Printf("   RT-3 duplicate → %d: %s\n", http.StatusConflict, string(bodyDup3))

	fmt.Println("\n   Integration test passed: staging, grace period, and publication all work correctly")
}

func submitHTTP(t *testing.T, url string, entry ctlog.SignedEntry) *http.Response {
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func assertStatus(t *testing.T, resp *http.Response, want int, msg string) []byte {
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("%s: expected %d, got %d: %s", msg, want, resp.StatusCode, string(body))
	}
	return body
}

func assertJSONField(t *testing.T, body []byte, field, want string) {
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parse JSON: %v\nbody: %s", err, string(body))
	}
	got, ok := result[field].(string)
	if !ok || got != want {
		t.Fatalf("expected %s=%q, got %q (body: %s)", field, want, got, string(body))
	}
}
