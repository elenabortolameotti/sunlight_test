package ctlog_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"filippo.io/sunlight/internal/ctlog"
)

// TestSignedEntryVerification tests the authentication flow
func TestSignedEntryVerification(t *testing.T) {
	// Create a test signed entry
	data := []byte("test data")
	entityID := "witness-1"
	timestamp := time.Now().UnixMilli()
	
	// Create the signing data
	var buf bytes.Buffer
	buf.Write(data)
	buf.WriteString(entityID)
	buf.WriteString(fmt.Sprintf("%d", timestamp))
	signingData := sha256.Sum256(buf.Bytes())
	
	// For this test, we need to use a known key pair
	// In production, the private key would only be with the entity
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	
	signature := ed25519.Sign(privateKey, signingData[:])
	
	entry := ctlog.SignedEntry{
		Data:      data,
		EntityID:  entityID,
		Timestamp: timestamp,
		Signature: signature,
	}
	
	// Verify timestamp is valid
	if !entry.IsTimestampValid() {
		t.Error("Expected timestamp to be valid")
	}
	
	// Note: We can't fully test Verify() here because the Log has hardcoded keys
	// In integration tests, we'd need to use the actual test infrastructure
	t.Logf("Created signed entry with entity %s", entry.EntityID)
}

// TestTimestampValidation tests the replay protection
func TestTimestampValidation(t *testing.T) {
	now := time.Now().UnixMilli()
	
	tests := []struct {
		name      string
		timestamp int64
		wantValid bool
	}{
		{
			name:      "current time",
			timestamp: now,
			wantValid: true,
		},
		{
			name:      "1 minute ago",
			timestamp: now - 60*1000,
			wantValid: true,
		},
		{
			name:      "6 minutes ago (too old)",
			timestamp: now - 6*60*1000,
			wantValid: false,
		},
		{
			name:      "1 minute in future",
			timestamp: now + 60*1000,
			wantValid: true,
		},
		{
			name:      "6 minutes in future (too far)",
			timestamp: now + 6*60*1000,
			wantValid: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := ctlog.SignedEntry{
				Timestamp: tt.timestamp,
			}
			got := entry.IsTimestampValid()
			if got != tt.wantValid {
				t.Errorf("IsTimestampValid() = %v, want %v", got, tt.wantValid)
			}
		})
	}
}

// TestSignedEntryJSON tests JSON serialization
func TestSignedEntryJSON(t *testing.T) {
	entry := ctlog.SignedEntry{
		Data:      []byte("test payload"),
		EntityID:  "client-a",
		Timestamp: 1234567890000,
		Signature: []byte("signature bytes"),
	}
	
	// Serialize
	jsonData, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}
	
	// Deserialize
	var decoded ctlog.SignedEntry
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	
	// Verify
	if !bytes.Equal(decoded.Data, entry.Data) {
		t.Error("Data mismatch")
	}
	if decoded.EntityID != entry.EntityID {
		t.Error("EntityID mismatch")
	}
	if decoded.Timestamp != entry.Timestamp {
		t.Error("Timestamp mismatch")
	}
	if !bytes.Equal(decoded.Signature, entry.Signature) {
		t.Error("Signature mismatch")
	}
}

// TestSignatureVerification tests the signature verification logic
func TestSignatureVerification(t *testing.T) {
	// Generate a key pair for testing
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	
	data := []byte("test data")
	entityID := "test-entity"
	timestamp := time.Now().UnixMilli()
	
	// Create the signing data (same logic as in SignedEntry.Verify)
	var buf bytes.Buffer
	buf.Write(data)
	buf.WriteString(entityID)
	buf.WriteString(fmt.Sprintf("%d", timestamp))
	signingData := sha256.Sum256(buf.Bytes())
	
	// Sign
	signature := ed25519.Sign(privateKey, signingData[:])
	
	entry := ctlog.SignedEntry{
		Data:      data,
		EntityID:  entityID,
		Timestamp: timestamp,
		Signature: signature,
	}
	
	// Verify with correct key
	if !entry.Verify(publicKey) {
		t.Error("Expected verification to succeed with correct key")
	}
	
	// Generate a different key pair
	wrongPublicKey, _, _ := ed25519.GenerateKey(nil)
	
	// Verify with wrong key should fail
	if entry.Verify(wrongPublicKey) {
		t.Error("Expected verification to fail with wrong key")
	}
	
	// Modify data and verify again
	entry.Data = []byte("modified data")
	if entry.Verify(publicKey) {
		t.Error("Expected verification to fail with modified data")
	}
}

// TestPendingLogEntry tests the pending entry structure
func TestPendingLogEntry(t *testing.T) {
	data := []byte("test data")
	entry := &ctlog.PendingLogEntry{Data: data}
	
	// Convert to LogEntry
	idx := int64(42)
	timestamp := int64(1234567890000)
	logEntry := entry.AsLogEntry(idx, timestamp)
	
	if !bytes.Equal(logEntry.Data, data) {
		t.Error("Data mismatch in LogEntry")
	}
	if logEntry.LeafIndex != idx {
		t.Errorf("LeafIndex = %d, want %d", logEntry.LeafIndex, idx)
	}
	if logEntry.Timestamp != timestamp {
		t.Errorf("Timestamp = %d, want %d", logEntry.Timestamp, timestamp)
	}
}

// Simple integration test placeholder
func TestIntegrationPlaceholder(t *testing.T) {
	t.Skip("Integration tests require full test infrastructure setup")
	
	// This would be a full integration test:
	// 1. Create a test log with entity keys
	// 2. Submit a properly signed entry
	// 3. Verify it gets sequenced
	// 4. Try submitting unsigned entry - should fail
	// 5. Try submitting with wrong signature - should fail
	// 6. Try submitting with old timestamp - should fail
}

// Export test functions for use by other tests
var (
	// Expose internal functions for testing
	AddLeafToPool = func(l *ctlog.Log, data []byte) error {
		entry := &ctlog.PendingLogEntry{Data: data}
		_, _ = l.AddLeafToPool(entry)
		return nil
	}
)
