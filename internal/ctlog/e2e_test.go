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
	"sync"
	"testing"
	"time"

	"filippo.io/sunlight/internal/ctlog"
	"github.com/prometheus/client_golang/prometheus"
)

// End-to-end test for the authentication flow
func TestE2ESignedEntrySubmission(t *testing.T) {
	// Generate entity keys for testing
	witnessPub, witnessPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate witness key: %v", err)
	}
	clientPub, _, _ := ed25519.GenerateKey(nil) // We don't need client-a private key for these tests

	// Generate log signing key (ECDSA)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate log key: %v", err)
	}

	// Create test log with entity keys using WBB-compatible entity IDs.
	// ER-1 and ER-2 are Election Registrar entities (threshold=1, simple path).
	tmpDir := t.TempDir()
	config := &ctlog.Config{
		Name:    "test.log.example.com",
		Key:     logKey,
		Cache:   filepath.Join(tmpDir, "cache.db"),
		Backend: NewMemoryBackend(t),
		Lock:    NewMemoryLockBackend(t),
		Log:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		EntityKeys: map[string]ed25519.PublicKey{
			"ER-1": witnessPub,
			"ER-2": clientPub,
		},
	}

	// Create the log
	ctx := context.Background()
	if err := ctlog.CreateLog(ctx, config); err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	log, err := ctlog.LoadLog(ctx, config)
	if err != nil {
		t.Fatalf("Failed to load log: %v", err)
	}
	defer log.CloseCache()

	// Create HTTP handler using the log's handler
	server := httptest.NewServer(log.Handler())
	defer server.Close()

	// Start the sequencer in the background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Try to sequence any pending entries
				_ = log.Sequence()
			}
		}
	}()

	// All test data must be in valid WBB format: phase,role,entry_type,threshold,content
	// We use ER (Election Registrar) entries with threshold=1 for the simple direct-publication path.
	validWBBData := func(content string) []byte {
		return []byte("setup,ER,election_pub_key,1," + content)
	}

	// Test 1: Submit valid signed entry
	t.Run("valid signed entry", func(t *testing.T) {
		data := validWBBData("hello_world")
		entityID := "ER-1"
		timestamp := time.Now().UnixMilli()

		signedEntry := createSignedEntry(t, data, entityID, timestamp, witnessPriv)

		resp := submitEntry(t, server.URL+"/submit", signedEntry)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("Expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		resp.Body.Close()
	})

	// Test 2: Submit unsigned entry (should fail)
	t.Run("unsigned entry rejected", func(t *testing.T) {
		unsignedEntry := ctlog.SignedEntry{
			Data:      validWBBData("unsigned_data"),
			EntityID:  "ER-1",
			Timestamp: time.Now().UnixMilli(),
			// No signature
		}

		resp := submitEntry(t, server.URL+"/submit", unsignedEntry)
		// Missing signature returns 403 (forbidden) from verifySingleWBBEntry
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 for unsigned entry, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	// Test 3: Submit with invalid signature (should fail)
	t.Run("invalid signature rejected", func(t *testing.T) {
		data := validWBBData("tampered_data")
		entityID := "ER-1"
		timestamp := time.Now().UnixMilli()

		// Create entry but with wrong signature
		signedEntry := createSignedEntry(t, data, entityID, timestamp, witnessPriv)
		signedEntry.Signature = append(signedEntry.Signature[:len(signedEntry.Signature)-1], byte(0xFF)) // Corrupt signature

		resp := submitEntry(t, server.URL+"/submit", signedEntry)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 for invalid signature, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	// Test 4: Submit with unknown entity (should fail)
	t.Run("unknown entity rejected", func(t *testing.T) {
		data := validWBBData("unknown_entity_data")
		entityID := "ER-99" // Valid role format but not in entity registry
		timestamp := time.Now().UnixMilli()

		_, unknownPriv, _ := ed25519.GenerateKey(nil)
		signedEntry := createSignedEntry(t, data, entityID, timestamp, unknownPriv)

		resp := submitEntry(t, server.URL+"/submit", signedEntry)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 for unknown entity, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	// Test 5: Submit with old timestamp (should fail)
	t.Run("old timestamp rejected", func(t *testing.T) {
		data := validWBBData("old_timestamp_data")
		entityID := "ER-1"
		timestamp := time.Now().Add(-10 * time.Minute).UnixMilli() // 10 minutes ago

		signedEntry := createSignedEntry(t, data, entityID, timestamp, witnessPriv)

		resp := submitEntry(t, server.URL+"/submit", signedEntry)
		// Invalid timestamp returns 400 (bad request)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 for old timestamp, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	// Test 6: Submit with future timestamp (should fail)
	t.Run("future timestamp rejected", func(t *testing.T) {
		data := validWBBData("future_timestamp_data")
		entityID := "ER-1"
		timestamp := time.Now().Add(10 * time.Minute).UnixMilli() // 10 minutes in future

		signedEntry := createSignedEntry(t, data, entityID, timestamp, witnessPriv)

		resp := submitEntry(t, server.URL+"/submit", signedEntry)
		// Invalid timestamp returns 400 (bad request)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 for future timestamp, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})
}

// Helper function to create a signed entry
func createSignedEntry(t *testing.T, data []byte, entityID string, timestamp int64, privateKey ed25519.PrivateKey) ctlog.SignedEntry {
	// Create the signing data (same logic as in SignedEntry.Verify)
	var buf bytes.Buffer
	buf.Write(data)
	buf.WriteString(entityID)
	buf.WriteString(fmt.Sprintf("%d", timestamp))
	signingData := sha256.Sum256(buf.Bytes())

	signature := ed25519.Sign(privateKey, signingData[:])

	return ctlog.SignedEntry{
		Data:      data,
		EntityID:  entityID,
		Timestamp: timestamp,
		Signature: signature,
	}
}

// Helper function to submit an entry
func submitEntry(t *testing.T, url string, entry ctlog.SignedEntry) *http.Response {
	jsonData, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to marshal entry: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		t.Fatalf("Failed to submit entry: %v", err)
	}

	return resp
}

// Test helpers (recreated from removed testlog_test.go)

type MemoryBackend struct {
	t  testing.TB
	mu sync.Mutex // Placeholder for mutex
	m  map[string][]byte
}

func NewMemoryBackend(t testing.TB) *MemoryBackend {
	return &MemoryBackend{
		t: t,
		m: make(map[string][]byte),
	}
}

func (b *MemoryBackend) Upload(ctx context.Context, key string, data []byte, opts *ctlog.UploadOptions) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[key] = data
	return nil
}

func (b *MemoryBackend) Fetch(ctx context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.m[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}
	return data, nil
}

func (b *MemoryBackend) Discard(ctx context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, key)
	return nil
}

func (b *MemoryBackend) Metrics() []prometheus.Collector { return nil }

type MemoryLockBackend struct {
	t  testing.TB
	mu sync.Mutex
	m  map[[sha256.Size]byte][]byte
}

func NewMemoryLockBackend(t testing.TB) *MemoryLockBackend {
	return &MemoryLockBackend{
		t: t,
		m: make(map[[sha256.Size]byte][]byte),
	}
}

func (b *MemoryLockBackend) Fetch(ctx context.Context, logID [sha256.Size]byte) (ctlog.LockedCheckpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.m[logID]
	if !ok {
		return nil, fmt.Errorf("log %x not found", logID)
	}
	return &memoryLockCheckpoint{logID: logID, data: data}, nil
}

func (b *MemoryLockBackend) Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[logID]; ok {
		return fmt.Errorf("log %x already exists", logID)
	}
	b.m[logID] = new
	return nil
}

func (b *MemoryLockBackend) Replace(ctx context.Context, old ctlog.LockedCheckpoint, new []byte) (ctlog.LockedCheckpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if old == nil {
		return nil, fmt.Errorf("old checkpoint is nil")
	}
	oldc := old.(*memoryLockCheckpoint)
	b.m[oldc.logID] = new
	return &memoryLockCheckpoint{logID: oldc.logID, data: new}, nil
}

type memoryLockCheckpoint struct {
	logID [sha256.Size]byte
	data  []byte
}

func (c *memoryLockCheckpoint) Bytes() []byte {
	return c.data
}
