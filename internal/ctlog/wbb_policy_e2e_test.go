package ctlog_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"filippo.io/sunlight/internal/my_crypto"
)

// TestWBBPolicyAllEntities tests the complete WBB policy integration
// This test suite is designed for TDD - the intern will implement policy enforcement
func TestWBBPolicyAllEntities(t *testing.T) {
	// Generate keys for all entity types
	entityKeys := generateTestEntityKeys(t)

	// Generate log signing key (ECDSA)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate log key: %v", err)
	}

	// Create test log with all entity keys
	tmpDir := t.TempDir()
	config := &ctlog.Config{
		Name:          "test.wbb.example.com",
		Key:           logKey,
		Cache:         filepath.Join(tmpDir, "cache.db"),
		Backend:       NewMemoryBackend(t),
		Lock:          NewMemoryLockBackend(t),
		Log:           slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		EntityKeys:    entityKeys,
		EntityBLSKeys: testEntityBLSKeys,
	}

	// Create and load the log
	ctx := context.Background()
	if err := ctlog.CreateLog(ctx, config); err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	log, err := ctlog.LoadLog(ctx, config)
	if err != nil {
		t.Fatalf("Failed to load log: %v", err)
	}
	defer log.CloseCache()

	// Create HTTP handler
	server := httptest.NewServer(log.Handler())
	defer server.Close()

	// Start the sequencer
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
				_ = log.Sequence()
			}
		}
	}()

	// Run all policy tests
	t.Run("Setup Phase - RT Entities", func(t *testing.T) {
		testSetupPhaseRT(t, server.URL, entityKeys)
	})

	t.Run("Setup Phase - ER Entities", func(t *testing.T) {
		testSetupPhaseER(t, server.URL, entityKeys)
	})

	t.Run("Voting Phase - BB Entities", func(t *testing.T) {
		testVotingPhaseBB(t, server.URL, entityKeys)
	})

	t.Run("Tallying Phase - BB Entities", func(t *testing.T) {
		testTallyingPhaseBB(t, server.URL, entityKeys)
	})

	t.Run("Tallying Phase - TT Entities", func(t *testing.T) {
		testTallyingPhaseTT(t, server.URL, entityKeys)
	})

	t.Run("Policy Violations", func(t *testing.T) {
		testPolicyViolations(t, server.URL, entityKeys)
	})

	t.Run("Threshold Enforcement", func(t *testing.T) {
		testThresholdEnforcement(t, server.URL, entityKeys)
	})
}

// ============ SETUP PHASE TESTS ============

func testSetupPhaseRT(t *testing.T, serverURL string, keys map[string]ed25519.PublicKey) {
	t.Run("RT can write acc_pub_key with threshold 2", func(t *testing.T) {
		// WBB format: phase,role,entry_type,threshold,content
		wbbData := "setup,RT,acc_pub_key,2,test_acc_public_key_data"

		// Create signed entry from RT-1
		entry := createAggregateWBBEntry(t, wbbData, []string{"RT-1", "RT-2"})

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("RT acc_pub_key submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected RT acc_pub_key submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("RT cannot write other entry types", func(t *testing.T) {
		wbbData := "setup,RT,election_pub_key,2,invalid_rt_writing_er_data"
		entry := createWBBEntry(t, wbbData, "RT-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		// Should be rejected - RT can only write acc_pub_key
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected policy violation for RT writing election_pub_key")
		}
		resp.Body.Close()
	})
}

func testSetupPhaseER(t *testing.T, serverURL string, keys map[string]ed25519.PublicKey) {
	t.Run("ER can write election_pub_key", func(t *testing.T) {
		wbbData := "setup,ER,election_pub_key,1,election_public_key_xyz"
		entry := createWBBEntry(t, wbbData, "ER-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("ER election_pub_key submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected ER election_pub_key submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("ER can write pseudonymous_id_count", func(t *testing.T) {
		wbbData := "setup,ER,pseudonymous_id_count,1,1000"
		entry := createWBBEntry(t, wbbData, "ER-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("ER pseudonymous_id count response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected ER election_pub_key submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("ER can write voter_id_merkle_root", func(t *testing.T) {
		wbbData := "setup,ER,voter_id_merkle_root,1,merkle_root_hash_abc123"
		entry := createWBBEntry(t, wbbData, "ER-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("ER voter_id merekle root submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected ER election_pub_key submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("ER cannot write RT entry types", func(t *testing.T) {
		wbbData := "setup,ER,acc_pub_key,1,invalid_er_writing_rt_data"
		entry := createWBBEntry(t, wbbData, "ER-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected policy violation for ER writing acc_pub_key")
		}
		resp.Body.Close()
	})
}

// ============ VOTING PHASE TESTS ============

func testVotingPhaseBB(t *testing.T, serverURL string, keys map[string]ed25519.PublicKey) {
	t.Run("BB can write ballot_digest", func(t *testing.T) {
		wbbData := "voting,BB,ballot_digest,1,ballot_hash_xyz789"
		entry := createWBBEntry(t, wbbData, "BB-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("BB ballot_digest submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected BB ballot_digest submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("BB can write ballot_metadata", func(t *testing.T) {
		wbbData := "voting,BB,ballot_metadata,1,metadata_json_content"
		entry := createWBBEntry(t, wbbData, "BB-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("BB ballot_metadata submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected BB ballot_metadata submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("BB can write cast_intended_proof", func(t *testing.T) {
		wbbData := "voting,BB,cast_intended_proof,1,proof_data_here"
		entry := createWBBEntry(t, wbbData, "BB-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("BB cast_as_intended_proof submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected BB cast_as_intended_proof submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})
}

// ============ TALLYING PHASE TESTS ============

func testTallyingPhaseBB(t *testing.T, serverURL string, keys map[string]ed25519.PublicKey) {
	t.Run("BB can write encrypted_ballot", func(t *testing.T) {
		wbbData := "tallying,BB,encrypted_ballot,1,encrypted_ballot_data"
		entry := createWBBEntry(t, wbbData, "BB-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("BB encrypted_ballot submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()
	})
}

func testTallyingPhaseTT(t *testing.T, serverURL string, keys map[string]ed25519.PublicKey) {
	t.Run("TT can write mixed_ballots with threshold 3", func(t *testing.T) {
		wbbData := "tallying,TT,mixed_ballots,3,mixed_shuffled_ballots"
		entry := createAggregateWBBEntry(t, wbbData, []string{"TT-1", "TT-2", "TT-3"})
		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("TT mixed_ballots submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected TT re_encryption_proof submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("TT can write re_encryption_proof", func(t *testing.T) {
		wbbData := "tallying,TT,re_encryption_proof,3,proof_of_re_encryption"
		entry := createAggregateWBBEntry(t, wbbData, []string{"TT-1", "TT-2", "TT-3"})

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("TT re_encryption_proof submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected TT re_encryption_proof submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("TT can write tally_result", func(t *testing.T) {
		wbbData := "tallying,TT,tally_result,3,final_election_results"
		entry := createAggregateWBBEntry(t, wbbData, []string{"TT-1", "TT-2", "TT-3"})

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("TT tally_result submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected TT re_encryption_proof submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("TT can write tally_proof", func(t *testing.T) {
		wbbData := "tallying,TT,tally_proof,3,proof_of_correct_tally"
		entry := createAggregateWBBEntry(t, wbbData, []string{"TT-1", "TT-2", "TT-3"})

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("TT tally_proof submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected TT re_encryption_proof submission to succeed, got %d: %s", resp.StatusCode, string(body))
		}
	})
}

// ============ POLICY VIOLATION TESTS ============

func testPolicyViolations(t *testing.T, serverURL string, keys map[string]ed25519.PublicKey) {
	t.Run("BB cannot write setup phase entries", func(t *testing.T) {
		wbbData := "setup,BB,acc_pub_key,1,invalid_bb_in_setup"
		entry := createWBBEntry(t, wbbData, "BB-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected policy violation: BB cannot write in setup phase")
		}
		resp.Body.Close()
	})

	t.Run("RT cannot write in voting phase", func(t *testing.T) {
		wbbData := "voting,RT,ballot_digest,1,invalid_rt_in_voting"
		entry := createWBBEntry(t, wbbData, "RT-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected policy violation: RT cannot write in voting phase")
		}
		resp.Body.Close()
	})

	t.Run("ER cannot write in tallying phase", func(t *testing.T) {
		wbbData := "tallying,ER,tally_result,1,invalid_er_in_tallying"
		entry := createWBBEntry(t, wbbData, "ER-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected policy violation: ER cannot write in tallying phase")
		}
		resp.Body.Close()
	})

	t.Run("TT cannot write in setup phase", func(t *testing.T) {
		wbbData := "setup,TT,election_pub_key,3,invalid_tt_in_setup"
		entry := createWBBEntry(t, wbbData, "TT-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected policy violation: TT cannot write in setup phase")
		}
		resp.Body.Close()
	})
}

// ============ THRESHOLD ENFORCEMENT TESTS ============

func testThresholdEnforcement(t *testing.T, serverURL string, keys map[string]ed25519.PublicKey) {
	t.Run("RT requires threshold 2 for acc_pub_key", func(t *testing.T) {
		// Single RT submission with threshold=1 should fail
		wbbData := "setup,RT,acc_pub_key,1,acc_key_with_insufficient_threshold"
		entry := createWBBEntry(t, wbbData, "RT-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		// Should be rejected - threshold 1 < required 2
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected threshold violation: RT needs at least 2 signatures for acc_pub_key")
		}
		resp.Body.Close()
	})

	t.Run("TT requires threshold 3 for mixed_ballots", func(t *testing.T) {
		// Single TT submission with threshold=1 should fail
		wbbData := "tallying,TT,mixed_ballots,1,mixed_with_insufficient_threshold"
		entry := createWBBEntry(t, wbbData, "TT-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		// Should be rejected - threshold 1 < required 3
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected threshold violation: TT needs at least 3 signatures for mixed_ballots")
		}
		resp.Body.Close()
	})

	t.Run("ER accepts threshold 1", func(t *testing.T) {
		// ER only needs threshold 1
		wbbData := "setup,ER,election_pub_key,1,election_key_threshold_1"
		entry := createWBBEntry(t, wbbData, "ER-1", keys)

		resp := submitEntry(t, serverURL+"/submit", entry)
		// This should pass - ER only needs threshold 1
		body, _ := io.ReadAll(resp.Body)
		t.Logf("ER threshold 1 submission response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()
	})

	// More controls
	t.Run("RT aggregate signature requires two distinct RT signers", func(t *testing.T) {
		// RT entries of type acc_pub_key require threshold 2.
		// This test sends only one RT signer, so the server must reject the entry
		// even if the BLS aggregate signature is otherwise well-formed.
		wbbData := "setup,RT,acc_pub_key,2,test_acc_public_key_data"

		entry := createAggregateWBBEntry(t, wbbData, []string{"RT-1"})

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("RT aggregate with one signer response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("expected RT aggregate with one signer to be rejected")
		}
	})

	t.Run("TT aggregate signature requires three distinct TT signers", func(t *testing.T) {
		// TT entries of type mixed_ballots require threshold 3.
		// This test provides only two TT signers, so the entry must not be accepted.
		wbbData := "tallying,TT,mixed_ballots,3,mixed_shuffled_ballots"

		entry := createAggregateWBBEntry(t, wbbData, []string{"TT-1", "TT-2"})

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("TT aggregate with two signers response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("expected TT aggregate with two signers to be rejected")
		}
	})

	t.Run("RT aggregate signature rejects duplicate signers", func(t *testing.T) {
		// The threshold must be satisfied by distinct entities.
		// Reusing the same signer twice must not count as two independent RT signatures.
		wbbData := "setup,RT,acc_pub_key,2,test_acc_public_key_data"

		entry := createAggregateWBBEntry(t, wbbData, []string{"RT-1", "RT-1"})

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("RT aggregate with duplicate signer response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("expected RT aggregate with duplicate signer to be rejected")
		}
	})

	t.Run("RT aggregate signature rejects signer with wrong role", func(t *testing.T) {
		// All signers in an aggregate signature must belong to the role declared
		// in the WBB entry. Here the entry claims role RT, but one signer is ER-1.
		wbbData := "setup,RT,acc_pub_key,2,test_acc_public_key_data"

		entry := createAggregateWBBEntry(t, wbbData, []string{"RT-1", "ER-1"})

		resp := submitEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("RT aggregate with wrong-role signer response: %d - %s", resp.StatusCode, string(body))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("expected RT aggregate with wrong-role signer to be rejected")
		}
	})
}

// ============ HELPER FUNCTIONS ============

// generateTestEntityKeys creates keys for all entity types used in WBB

var testEntityPrivateKeys map[string]ed25519.PrivateKey
var testEntityBLSSigners map[string]*my_crypto.BLSSigner
var testEntityBLSKeys map[string][]byte

func generateTestEntityKeys(t *testing.T) map[string]ed25519.PublicKey {
	keys := make(map[string]ed25519.PublicKey)

	testEntityPrivateKeys = make(map[string]ed25519.PrivateKey)
	testEntityBLSSigners = make(map[string]*my_crypto.BLSSigner)
	testEntityBLSKeys = make(map[string][]byte)

	addEntity := func(entityID string) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key for %s: %v", entityID, err)
		}

		keys[entityID] = pub
		testEntityPrivateKeys[entityID] = priv

		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("failed to generate BLS seed for %s: %v", entityID, err)
		}

		// Test-only key hash. It only needs to be unique in this test setup.
		keyHash := uint32(len(testEntityBLSSigners) + 1)

		blsSigner, err := my_crypto.NewBLSSignerFromSeed(entityID, keyHash, seed)
		if err != nil {
			t.Fatalf("failed to generate BLS signer for %s: %v", entityID, err)
		}

		blsPub, err := blsSigner.PublicKeyBytes()
		if err != nil {
			t.Fatalf("failed to serialize BLS public key for %s: %v", entityID, err)
		}

		testEntityBLSSigners[entityID] = blsSigner
		testEntityBLSKeys[entityID] = blsPub
	}

	for i := 1; i <= 3; i++ {
		addEntity(fmt.Sprintf("RT-%d", i))
	}

	for i := 1; i <= 2; i++ {
		addEntity(fmt.Sprintf("ER-%d", i))
	}

	for i := 1; i <= 2; i++ {
		addEntity(fmt.Sprintf("BB-%d", i))
	}

	for i := 1; i <= 5; i++ {
		addEntity(fmt.Sprintf("TT-%d", i))
	}

	return keys
}

// createWBBEntry creates a signed entry for WBB format data
func createWBBEntry(t *testing.T, wbbData, entityID string, keys map[string]ed25519.PublicKey) ctlog.SignedEntry {
	timestamp := time.Now().UnixMilli()

	priv, ok := testEntityPrivateKeys[entityID]
	if !ok {
		t.Fatalf("missing private key for entity %s", entityID)
	}

	// For now, create a placeholder signature
	// In real implementation, this would sign with the entity's private key
	entry := ctlog.SignedEntry{
		Data:      []byte(wbbData),
		EntityID:  entityID,
		Timestamp: timestamp,
	}
	var buf bytes.Buffer
	buf.Write(entry.Data)
	buf.WriteString(entry.EntityID)
	buf.WriteString(fmt.Sprintf("%d", entry.Timestamp))

	signedData := sha256.Sum256(buf.Bytes())
	entry.Signature = ed25519.Sign(priv, signedData[:])

	return entry
}

// submitEntry submits a signed entry to the server
// NOTE: This function is defined in e2e_test.go, using that version
// This comment is here to document that submitEntry should be imported from e2e_test.go

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

func createAggregateWBBEntry(t *testing.T, wbbData string, entityIDs []string) ctlog.SignedEntry {
	timestamp := time.Now().UnixMilli()
	data := []byte(wbbData)

	msg := aggregateSignedMessage(data, timestamp, entityIDs)

	signatures := make([][]byte, 0, len(entityIDs))
	for _, entityID := range entityIDs {
		signer, ok := testEntityBLSSigners[entityID]
		if !ok {
			t.Fatalf("missing BLS signer for entity %s", entityID)
		}

		sig, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("failed to create BLS signature for %s: %v", entityID, err)
		}

		signatures = append(signatures, sig)
	}

	aggSig, err := my_crypto.AggregateSignaturesBytes(signatures)
	if err != nil {
		t.Fatalf("failed to aggregate BLS signatures: %v", err)
	}

	return ctlog.SignedEntry{
		Data:               data,
		EntityIDs:          entityIDs,
		Timestamp:          timestamp,
		AggregateSignature: aggSig,
	}
}
