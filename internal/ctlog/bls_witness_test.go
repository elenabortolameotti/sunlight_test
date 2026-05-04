package ctlog_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/sunlight/internal/my_crypto"
	"filippo.io/sunlight/my_note"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/mod/sumdb/note"
)

// TestBLSWitnessSignatures tests the complete flow of BLS witness signatures:
// 1. Create a log with BLS witness key
// 2. Add certificates to the log
// 3. Verify checkpoint includes BLS aggregate signature
// 4. Client verifies aggregate BLS signature
func TestBLSWitnessSignatures(t *testing.T) {
	ctx := context.Background()

	// Generate log key (ECDSA for log)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate log key: %v", err)
	}

	// Generate witness key (BLS) with correct hash
	witnessSigner := generateWitnessKey(t, "test-witness")

	// Create test log with BLS witness key
	testLog := NewTestLogWithBLSWitness(t, logKey, witnessSigner)
	defer testLog.Close()

	// Add some certificates to the log
	t.Log("Adding certificates to the log...")
	for i := 0; i < 5; i++ {
		addTestCertificate(t, testLog)
	}

	// Wait for sequencing
	time.Sleep(200 * time.Millisecond)

	// Get the checkpoint
	checkpointBytes, err := testLog.Config.Backend.Fetch(ctx, "checkpoint")
	if err != nil {
		t.Fatalf("Failed to fetch checkpoint: %v", err)
	}

	t.Logf("Checkpoint:\n%s", string(checkpointBytes))

	// Verify the checkpoint has both log signature and BLS aggregate signature
	if err := verifyCheckpointSignatures(t, testLog, checkpointBytes); err != nil {
		t.Fatalf("Checkpoint signature verification failed: %v", err)
	}

	t.Log("✓ Checkpoint signatures verified successfully")
}

// TestBLSMultipleWitnesses tests aggregation of signatures from multiple witnesses
func TestBLSMultipleWitnesses(t *testing.T) {
	// Generate log key
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate log key: %v", err)
	}

	// Generate multiple witness keys
	numWitnesses := 3
	witnessSigners := make([]*my_crypto.BLSSigner, numWitnesses)
	witnessPubKeys := make([][]byte, numWitnesses)
	
	for i := 0; i < numWitnesses; i++ {
		// Generate unique name for each witness
		name := fmt.Sprintf("test-witness-%d", i)
		signer := generateWitnessKey(t, name)
		
		witnessSigners[i] = signer
		pubKeyBytes, err := signer.PublicKeyBytes()
		if err != nil {
			t.Fatalf("Failed to get public key %d: %v", i, err)
		}
		witnessPubKeys[i] = pubKeyBytes
	}

	// Use first witness for the log
	testLog := NewTestLogWithBLSWitness(t, logKey, witnessSigners[0])
	defer testLog.Close()

	// Add certificates
	for i := 0; i < 3; i++ {
		addTestCertificate(t, testLog)
	}
	time.Sleep(200 * time.Millisecond)

	// Get checkpoint
	checkpointBytes, err := testLog.Config.Backend.Fetch(context.Background(), "checkpoint")
	if err != nil {
		t.Fatalf("Failed to fetch checkpoint: %v", err)
	}

	// Parse checkpoint text - find the text part (before signatures)
	split := bytes.LastIndex(checkpointBytes, []byte("\n\n"))
	if split < 0 {
		t.Fatal("Invalid checkpoint format: no signature separator found")
	}
	
	checkpointText := checkpointBytes[:split+1] // Include one newline

	t.Logf("Checkpoint text to sign (length %d):", len(checkpointText))
	t.Logf("%q", string(checkpointText))

	// Have all witnesses sign the same message
	signatures := make([][]byte, numWitnesses)
	for i, signer := range witnessSigners {
		sig, err := signer.Sign(checkpointText)
		if err != nil {
			t.Fatalf("Failed to sign with witness %d: %v", i, err)
		}
		signatures[i] = sig
		t.Logf("Witness %d signature length: %d", i, len(sig))
	}

	// Aggregate signatures
	aggSigBytes, err := my_crypto.AggregateSignaturesBytes(signatures)
	if err != nil {
		t.Fatalf("Failed to aggregate signatures: %v", err)
	}
	t.Logf("Aggregate signature length: %d", len(aggSigBytes))

	// Verify aggregate signature
	valid, err := my_crypto.VerifyAggregateBytes(witnessPubKeys, checkpointText, aggSigBytes)
	if err != nil {
		t.Fatalf("Failed to verify aggregate: %v", err)
	}
	if !valid {
		t.Fatal("Aggregate signature verification failed")
	}

	t.Log("✓ Multiple witness BLS signatures aggregated and verified successfully")
}

// TestBLSSignerCreationAndSigning tests basic BLS signer operations
func TestBLSSignerCreationAndSigning(t *testing.T) {
	// Test creating signer from seed
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("Failed to generate seed: %v", err)
	}

	signer, err := my_crypto.NewBLSSignerFromSeed("test-signer", 12345, seed)
	if err != nil {
		t.Fatalf("Failed to create signer from seed: %v", err)
	}

	if signer.Name() != "test-signer" {
		t.Errorf("Expected name 'test-signer', got %q", signer.Name())
	}

	if signer.KeyHash() != 12345 {
		t.Errorf("Expected hash 12345, got %d", signer.KeyHash())
	}

	// Test signing
	msg := []byte("test message for BLS signing")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if len(sig) != 96 {
		t.Errorf("Expected signature length 96, got %d", len(sig))
	}

	// Test verification with the public key
	pk := signer.PublicKey()
	if pk == nil {
		t.Fatal("Public key is nil")
	}

	parsedSig, err := my_crypto.SignatureFromBytes(sig)
	if err != nil {
		t.Fatalf("Failed to parse signature: %v", err)
	}

	if !my_crypto.Verify(pk, msg, parsedSig) {
		t.Fatal("Signature verification failed")
	}

	t.Log("✓ BLS signer creation and signing works correctly")
}

// TestBLSInvalidSignatures tests that invalid signatures are rejected
func TestBLSInvalidSignatures(t *testing.T) {
	// Generate two different key pairs
	sk1, pk1, err := my_crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key 1: %v", err)
	}

	_, pk2, err := my_crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key 2: %v", err)
	}

	msg1 := []byte("message one")
	msg2 := []byte("message two")

	sig1 := my_crypto.Sign(sk1, msg1)

	// Test 1: Wrong message
	if my_crypto.Verify(pk1, msg2, sig1) {
		t.Error("Verification succeeded with wrong message")
	}

	// Test 2: Wrong public key
	if my_crypto.Verify(pk2, msg1, sig1) {
		t.Error("Verification succeeded with wrong public key")
	}

	// Test 3: Invalid signature bytes
	invalidSig := make([]byte, 96)
	rand.Read(invalidSig)
	_, err = my_crypto.SignatureFromBytes(invalidSig)
	if err == nil {
		t.Error("Expected error for invalid signature bytes")
	}

	// Test 4: Invalid public key bytes
	invalidPK := make([]byte, 48)
	rand.Read(invalidPK)
	_, err = my_crypto.PublicKeyFromBytes(invalidPK)
	if err == nil {
		t.Error("Expected error for invalid public key bytes")
	}

	t.Log("✓ Invalid BLS signatures are correctly rejected")
}

// TestBLSSignerInNoteFormat tests BLS signer integration with note format
func TestBLSSignerInNoteFormat(t *testing.T) {
	// Generate a BLS key pair with correct hash
	signer := generateWitnessKey(t, "bls-witness")

	// Get public key bytes for verifier
	pubKeyBytes, err := signer.PublicKeyBytes()
	if err != nil {
		t.Fatalf("Failed to get public key bytes: %v", err)
	}

	// Create verifier key
	vkey, err := my_note.NewBLSVerifierKey("bls-witness", pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create verifier key: %v", err)
	}
	t.Logf("Verifier key: %s", vkey)

	// Create verifier
	verifier, err := my_note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Create a test note
	testMsg := "test log checkpoint\n1234\nabcd1234...\n"

	// Sign with the BLS signer (using my_note aggregate sign)
	aggSig, err := my_note.AggregateSign([]byte(testMsg), signer)
	if err != nil {
		t.Fatalf("Failed to aggregate sign: %v", err)
	}

	// Verify the aggregate signature
	err = my_note.VerifyAggregate([]byte(testMsg), aggSig, my_note.VerifierList(verifier))
	if err != nil {
		t.Fatalf("Failed to verify aggregate: %v", err)
	}

	t.Log("✓ BLS signer works correctly with note format")
}

// Helper functions

type TestLogWithBLS struct {
	Log    *ctlog.Log
	Config *ctlog.Config
	t      *testing.T
	ctx    context.Context
	cancel context.CancelFunc
}

// generateWitnessKey generates a BLS signer with the correct key hash
func generateWitnessKey(t *testing.T, name string) *my_crypto.BLSSigner {
	t.Helper()
	
	// Generate a random seed
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("Failed to generate seed: %v", err)
	}
	
	// Create a temporary signer to get the public key
	tempSigner, err := my_crypto.NewBLSSignerFromSeed(name, 0, seed)
	if err != nil {
		t.Fatalf("Failed to create temp signer: %v", err)
	}
	
	// Get public key bytes
	pubKeyBytes, err := tempSigner.PublicKeyBytes()
	if err != nil {
		t.Fatalf("Failed to get public key bytes: %v", err)
	}
	
	// Calculate the correct hash (same as my_note.keyHash)
	// hash = sha256(name + "\n" + algBLS + pubkey)[:4]
	algBLS := byte(2) // algBLS constant from my_note
	pubkeyWithAlg := append([]byte{algBLS}, pubKeyBytes...)
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(pubkeyWithAlg)
	hash := binary.BigEndian.Uint32(h.Sum(nil))
	
	// Create the signer with the correct hash
	signer, err := my_crypto.NewBLSSignerFromSeed(name, hash, seed)
	if err != nil {
		t.Fatalf("Failed to create signer with correct hash: %v", err)
	}
	
	return signer
}

func NewTestLogWithBLSWitness(t *testing.T, logKey *ecdsa.PrivateKey, witnessKey *my_crypto.BLSSigner) *TestLogWithBLS {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	// Create memory backend and lock
	backend := NewMemoryBackend(t)
	lock := NewMemoryLockBackend(t)

	// Create witness verifier for the config
	witnessPubKey, err := witnessKey.PublicKeyBytes()
	if err != nil {
		t.Fatalf("Failed to get witness public key: %v", err)
	}
	witnessVKey, err := my_note.NewBLSVerifierKey(witnessKey.Name(), witnessPubKey)
	if err != nil {
		t.Fatalf("Failed to create witness verifier key: %v", err)
	}
	witnessVerifier, err := my_note.NewVerifier(witnessVKey)
	if err != nil {
		t.Fatalf("Failed to create witness verifier: %v", err)
	}

	// Create config with BLS witness key
	config := &ctlog.Config{
		Name:             "test.example.com/log",
		Key:              logKey,
		WitnessKeys:      []*my_crypto.BLSSigner{witnessKey},
		WitnessVerifiers: my_note.VerifierList(witnessVerifier),
		PoolSize:         100,
		Cache:            filepath.Join(t.TempDir(), "cache.db"),
		Backend:          backend,
		Lock:             lock,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		NotAfterStart:    time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfterLimit:    time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	// Create the log
	if err := ctlog.CreateLog(ctx, config); err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	// Load the log
	log, err := ctlog.LoadLog(ctx, config)
	if err != nil {
		t.Fatalf("Failed to load log: %v", err)
	}

	// Set test root
	if err := log.SetRootsFromPEM(ctx, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: testRoot,
	})); err != nil {
		t.Fatalf("Failed to set roots: %v", err)
	}

	// Start sequencer
	go func() {
		if err := log.RunSequencer(ctx, 50*time.Millisecond); err != nil {
			if err != context.Canceled {
				t.Logf("Sequencer error: %v", err)
			}
		}
	}()

	return &TestLogWithBLS{
		Log:    log,
		Config: config,
		t:      t,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (tl *TestLogWithBLS) Close() {
	tl.cancel()
	tl.Log.CloseCache()
}

func addTestCertificate(t *testing.T, tl *TestLogWithBLS) {
	t.Helper()

	// Create a simple test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &tl.Config.Key.PublicKey, tl.Config.Key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	entry := &ctlog.PendingLogEntry{
		Certificate: certDER,
		Issuers:     [][]byte{testRoot},
	}

	waitFunc, _ := tl.Log.AddLeafToPool(entry)
	
	// Wait for the entry to be sequenced
	ctx, cancel := context.WithTimeout(tl.ctx, 5*time.Second)
	defer cancel()
	
	if _, err := waitFunc(ctx); err != nil {
		t.Fatalf("Failed to add certificate: %v", err)
	}
}

func verifyCheckpointSignatures(t *testing.T, tl *TestLogWithBLS, checkpointBytes []byte) error {
	// Create log verifier
	logVerifier, err := sunlight.NewRFC6962Verifier(tl.Config.Name, tl.Config.Key.Public())
	if err != nil {
		return fmt.Errorf("failed to create log verifier: %w", err)
	}

	// Create witness verifier (use first witness key)
	if len(tl.Config.WitnessKeys) == 0 {
		return fmt.Errorf("no witness keys configured")
	}
	witnessPubKey, err := tl.Config.WitnessKeys[0].PublicKeyBytes()
	if err != nil {
		return fmt.Errorf("failed to get witness public key: %w", err)
	}

	witnessVKey, err := my_note.NewBLSVerifierKey(tl.Config.WitnessKeys[0].Name(), witnessPubKey)
	if err != nil {
		return fmt.Errorf("failed to create witness verifier key: %w", err)
	}

	witnessVerifier, err := my_note.NewVerifier(witnessVKey)
	if err != nil {
		return fmt.Errorf("failed to create witness verifier: %w", err)
	}

	// Open the mixed note (with both log and witness signatures)
	n, aggNote, err := my_note.OpenMixedNote(
		checkpointBytes,
		note.VerifierList(logVerifier),
		my_note.VerifierList(witnessVerifier),
	)
	if err != nil {
		return fmt.Errorf("failed to open mixed note: %w", err)
	}

	if n == nil {
		return fmt.Errorf("note is nil")
	}

	// Verify log signature exists
	if len(n.Sigs) == 0 {
		return fmt.Errorf("no log signatures found")
	}

	logSigFound := false
	for _, sig := range n.Sigs {
		if sig.Hash == logVerifier.KeyHash() {
			logSigFound = true
			break
		}
	}
	if !logSigFound {
		return fmt.Errorf("log signature not found")
	}

	t.Logf("✓ Found %d log signatures", len(n.Sigs))

	// Verify aggregate witness signature exists
	if aggNote == nil {
		return fmt.Errorf("no aggregate witness signature found")
	}

	if aggNote.Agg == nil {
		return fmt.Errorf("aggregate signature is nil")
	}

	t.Logf("✓ Found aggregate witness signature from %d witnesses", len(aggNote.Agg.Witnesses))

	// Parse and verify checkpoint content
	checkpoint, err := sunlight.ParseCheckpoint(n.Text)
	if err != nil {
		return fmt.Errorf("failed to parse checkpoint: %w", err)
	}

	t.Logf("✓ Checkpoint: size=%d, hash=%x", checkpoint.Tree.N, checkpoint.Tree.Hash[:8])

	return nil
}

// testRoot is defined in testlog_test.go
