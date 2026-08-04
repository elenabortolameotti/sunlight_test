package ctlog_test

// Test for the deterministic-sequencing half of patch P2: with
// DisableTimestampValidation enabled, the same submission sequence must
// produce byte-identical checkpoint text (origin, tree size, root hash)
// across independent logs. Entity keys are derived from fixed seeds — as
// the PoC ceremony does from the master seed — so Ed25519 signatures (and
// thus leaf bytes) are also identical across runs.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/sunlight/internal/ctlog"
)

// fixedSeededKeys returns deterministic entity keys: entity id → key pair
// derived from sha256-like fixed seeds (32 zero bytes + index suffix).
func fixedSeededKeys(t *testing.T, ids ...string) (map[string]ed25519.PublicKey, map[string]ed25519.PrivateKey) {
	t.Helper()
	pubs := make(map[string]ed25519.PublicKey)
	privs := make(map[string]ed25519.PrivateKey)
	for i, id := range ids {
		seed := make([]byte, 32)
		seed[31] = byte(i + 1)
		priv := ed25519.NewKeyFromSeed(seed)
		pubs[id] = priv.Public().(ed25519.PublicKey)
		privs[id] = priv
	}
	return pubs, privs
}

func TestPoCDeterministicSequencing(t *testing.T) {
	checkpointTexts := make([]string, 2)

	for run := 0; run < 2; run++ {
		pubs, privs := fixedSeededKeys(t, "ER-1")
		logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		config := &ctlog.Config{
			Name:                       "test.poc.example.com",
			Key:                        logKey,
			Cache:                      filepath.Join(t.TempDir(), "cache.db"),
			Backend:                    NewMemoryBackend(t),
			Lock:                       NewMemoryLockBackend(t),
			Log:                        slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
			EntityKeys:                 pubs,
			DisableTimestampValidation: true,
		}

		ctx := context.Background()
		if err := ctlog.CreateLog(ctx, config); err != nil {
			t.Fatalf("run %d CreateLog: %v", run, err)
		}
		log, err := ctlog.LoadLog(ctx, config)
		if err != nil {
			t.Fatalf("run %d LoadLog: %v", run, err)
		}

		// Fixed logical timestamps — identical on both runs.
		for i, content := range []string{"one", "two", "three"} {
			data := []byte("setup,ER,election_pub_key,1," + content)
			ts := int64(1700000000000 + i*1000)
			entry := createSignedEntry(t, data, "ER-1", ts, privs["ER-1"])
			raw, err := json.Marshal(entry)
			if err != nil {
				t.Fatalf("run %d marshal entry %d: %v", run, i, err)
			}
			wait, _ := log.AddLeafToPool(&ctlog.PendingLogEntry{Data: raw})
			if err := log.Sequence(); err != nil {
				t.Fatalf("run %d sequence %d: %v", run, i, err)
			}
			if _, err := wait(ctx); err != nil {
				t.Fatalf("run %d wait leaf %d: %v", run, i, err)
			}
		}

		// The checkpoint text (before the signature block) must be identical.
		rawCheckpoint, err := config.Backend.Fetch(ctx, "checkpoint")
		if err != nil {
			t.Fatalf("run %d fetch checkpoint: %v", run, err)
		}
		checkpointTexts[run] = strings.SplitN(string(rawCheckpoint), "\n\n", 2)[0]
		t.Logf("run %d checkpoint text: %q", run, checkpointTexts[run])
		log.CloseCache()
	}

	if checkpointTexts[0] != checkpointTexts[1] {
		t.Fatalf("checkpoint text differs across runs:\nrun0: %q\nrun1: %q",
			checkpointTexts[0], checkpointTexts[1])
	}
}
