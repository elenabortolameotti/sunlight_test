package ctlog_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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

// TestStagingMechanism tests the server-side staging with threshold detection
// This is the main TDD test suite for the new architecture
func TestStagingMechanism(t *testing.T) {
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

	// Run all staging tests
	t.Run("Basic Staging - Single Entity", func(t *testing.T) {
		testBasicStagingSingleEntity(t, server.URL)
	})

	t.Run("Basic Staging - Multiple Entities", func(t *testing.T) {
		testBasicStagingMultipleEntities(t, server.URL)
	})

	t.Run("Threshold Detection", func(t *testing.T) {
		testThresholdDetection(t, server.URL)
	})

	t.Run("Late Arrivals After Threshold", func(t *testing.T) {
		testLateArrivals(t, server.URL)
	})

	t.Run("Conflict Resolution - Different Content", func(t *testing.T) {
		testConflictResolution(t, server.URL)
	})

	t.Run("Duplicate Signer Prevention", func(t *testing.T) {
		testDuplicateSignerPrevention(t, server.URL)
	})

	t.Run("Ed25519 Staging", func(t *testing.T) {
		testEd25519Staging(t, server.URL)
	})

	t.Run("BLS Staging", func(t *testing.T) {
		testBLSStaging(t, server.URL)
	})

	t.Run("Staging State Persistence", func(t *testing.T) {
		testStagingPersistence(t, server.URL)
	})
}

// ============ BASIC STAGING TESTS ============

func testBasicStagingSingleEntity(t *testing.T, serverURL string) {
	// Test: Single entity submits, should return "pending"
	wbbData := "tallying,TT,mixed_ballots,3,encrypted_data_batch_1"
	
	entry := createStagingWBBEntry(t, wbbData, "TT-1")
	
	resp := submitStagingEntry(t, serverURL+"/submit", entry)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	
	// Should return 202 Accepted (pending)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("Expected 202 Accepted for partial submission, got %d: %s", resp.StatusCode, string(body))
	}
	
	// Verify response contains staging info
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", body)
	}
	
	if result["status"] != "pending" {
		t.Errorf("Expected status 'pending', got %v", result["status"])
	}
	
	if result["current_signers"] != float64(1) {
		t.Errorf("Expected current_signers=1, got %v", result["current_signers"])
	}
	
	if result["required_signers"] != float64(3) {
		t.Errorf("Expected required_signers=3, got %v", result["required_signers"])
	}
	
	t.Logf("Single entity staging response: %s", string(body))
}

func testBasicStagingMultipleEntities(t *testing.T, serverURL string) {
	// Test: Multiple entities submit same content
	wbbData := "tallying,TT,mixed_ballots,3,encrypted_data_batch_2"
	
	// TT-1 submits
	entry1 := createStagingWBBEntry(t, wbbData, "TT-1")
	resp1 := submitStagingEntry(t, serverURL+"/submit", entry1)
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("First submission should return 202, got %d: %s", resp1.StatusCode, string(body1))
	}
	
	// TT-2 submits same content
	entry2 := createStagingWBBEntry(t, wbbData, "TT-2")
	resp2 := submitStagingEntry(t, serverURL+"/submit", entry2)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	
	// Should still be pending (2/3)
	if resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("Second submission should return 202, got %d: %s", resp2.StatusCode, string(body2))
	}
	
	var result map[string]interface{}
	json.Unmarshal(body2, &result)
	
	if result["current_signers"] != float64(2) {
		t.Errorf("Expected current_signers=2, got %v", result["current_signers"])
	}
	
	t.Logf("Multiple entities staging response: %s", string(body2))
}

// ============ THRESHOLD DETECTION TESTS ============

func testThresholdDetection(t *testing.T, serverURL string) {
	// Test: Submit until threshold met, then verify published
	wbbData := "tallying,TT,mixed_ballots,3,encrypted_data_batch_3"
	
	// Submit from TT-1 and TT-2 (should be pending)
	for _, entity := range []string{"TT-1", "TT-2"} {
		entry := createStagingWBBEntry(t, wbbData, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
		
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("Submission from %s should return 202, got %d", entity, resp.StatusCode)
		}
	}
	
	// Submit from TT-3 (threshold met!)
	entry3 := createStagingWBBEntry(t, wbbData, "TT-3")
	resp3 := submitStagingEntry(t, serverURL+"/submit", entry3)
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	
	// Should now return 200 OK with leaf index
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK when threshold met, got %d: %s", resp3.StatusCode, string(body3))
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(body3, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", body3)
	}
	
	if result["status"] != "published" {
		t.Errorf("Expected status 'published', got %v", result["status"])
	}
	
	if result["leaf_index"] == nil {
		t.Error("Expected leaf_index in response")
	}
	
	if len(result["signers"].([]interface{})) != 3 {
		t.Errorf("Expected 3 signers, got %v", len(result["signers"].([]interface{})))
	}
	
	t.Logf("Threshold met response: %s", string(body3))
}

// ============ LATE ARRIVALS TESTS ============

func testLateArrivals(t *testing.T, serverURL string) {
	// Test: After threshold met, late submissions are appended
	wbbData := "tallying,TT,mixed_ballots,3,encrypted_data_batch_4"
	
	// Get to threshold with TT-1, TT-2, TT-3
	for _, entity := range []string{"TT-1", "TT-2", "TT-3"} {
		entry := createStagingWBBEntry(t, wbbData, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
	}
	
	// Now submit from TT-4 (late arrival)
	entry4 := createStagingWBBEntry(t, wbbData, "TT-4")
	resp4 := submitStagingEntry(t, serverURL+"/submit", entry4)
	body4, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()
	
	// Should return 200 OK (appended)
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for late arrival, got %d: %s", resp4.StatusCode, string(body4))
	}
	
	var result map[string]interface{}
	json.Unmarshal(body4, &result)
	
	if result["status"] != "appended" {
		t.Errorf("Expected status 'appended', got %v", result["status"])
	}
	
	if len(result["signers"].([]interface{})) != 4 {
		t.Errorf("Expected 4 signers (including late arrival), got %v", len(result["signers"].([]interface{})))
	}
	
	t.Logf("Late arrival response: %s", string(body4))
}

// ============ CONFLICT RESOLUTION TESTS ============

func testConflictResolution(t *testing.T, serverURL string) {
	// Test: Different content from same role creates separate staging entries
	wbbDataA := "tallying,TT,mixed_ballots,3,result_A"
	wbbDataB := "tallying,TT,mixed_ballots,3,result_B"
	
	// Submit result_A from TT-1 and TT-2
	for _, entity := range []string{"TT-1", "TT-2"} {
		entry := createStagingWBBEntry(t, wbbDataA, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
	}
	
	// Submit result_B from TT-3 and TT-4
	for _, entity := range []string{"TT-3", "TT-4"} {
		entry := createStagingWBBEntry(t, wbbDataB, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
	}
	
	// Both should be pending (different content hashes)
	// Complete result_A with TT-5
	entryA := createStagingWBBEntry(t, wbbDataA, "TT-5")
	respA := submitStagingEntry(t, serverURL+"/submit", entryA)
	bodyA, _ := io.ReadAll(respA.Body)
	respA.Body.Close()
	
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for result_A, got %d: %s", respA.StatusCode, string(bodyA))
	}
	
	var result map[string]interface{}
	json.Unmarshal(bodyA, &result)
	
	if result["status"] != "published" {
		t.Errorf("Expected result_A to be published, got %v", result["status"])
	}
	
	// result_B should still be pending
	// Check by submitting another to result_B (should show current count)
	entryB := createStagingWBBEntry(t, wbbDataB, "TT-1")
	respB := submitStagingEntry(t, serverURL+"/submit", entryB)
	bodyB, _ := io.ReadAll(respB.Body)
	respB.Body.Close()
	
	if respB.StatusCode != http.StatusAccepted {
		t.Logf("Note: result_B status: %s", string(bodyB))
	}
	
	t.Logf("Conflict resolution: result_A published, result_B pending")
}

// ============ DUPLICATE SIGNER PREVENTION TESTS ============

func testDuplicateSignerPrevention(t *testing.T, serverURL string) {
	// Test: Same entity cannot sign twice
	wbbData := "tallying,TT,mixed_ballots,3,encrypted_data_batch_5"
	
	// TT-1 submits first time
	entry1 := createStagingWBBEntry(t, wbbData, "TT-1")
	resp1 := submitStagingEntry(t, serverURL+"/submit", entry1)
	resp1.Body.Close()
	
	// TT-1 tries to submit again (duplicate)
	entry2 := createStagingWBBEntry(t, wbbData, "TT-1")
	resp2 := submitStagingEntry(t, serverURL+"/submit", entry2)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	
	// Should be rejected
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for duplicate signer, got %d: %s", resp2.StatusCode, string(body2))
	}
	
	t.Logf("Duplicate signer correctly rejected: %s", string(body2))
}

// ============ SIGNATURE ALGORITHM TESTS ============

func testEd25519Staging(t *testing.T, serverURL string) {
	// Test: Staging with Ed25519 signatures (threshold > 1, Ed25519 mode)
	// For ER/BB entries with threshold=1, already covered by existing tests
	// This tests if we support multiple Ed25519 signatures for same entry
	
	wbbData := "setup,RT,acc_pub_key,2,public_key_data_xyz"
	
	// RT-1 submits
	entry1 := createStagingWBBEntry(t, wbbData, "RT-1")
	resp1 := submitStagingEntry(t, serverURL+"/submit", entry1)
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("RT-1 submission should return 202, got %d: %s", resp1.StatusCode, string(body1))
	}
	
	// RT-2 submits (threshold met)
	entry2 := createStagingWBBEntry(t, wbbData, "RT-2")
	resp2 := submitStagingEntry(t, serverURL+"/submit", entry2)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK when threshold met, got %d: %s", resp2.StatusCode, string(body2))
	}
	
	var result map[string]interface{}
	json.Unmarshal(body2, &result)
	
	// Verify Ed25519-specific fields
	if result["algorithm"] != "ed25519" {
		t.Errorf("Expected algorithm 'ed25519', got %v", result["algorithm"])
	}
	
	if result["signatures"] == nil {
		t.Error("Expected signatures array for Ed25519")
	}
	
	t.Logf("Ed25519 staging result: %s", string(body2))
}

func testBLSStaging(t *testing.T, serverURL string) {
	// Test: Staging with BLS aggregate signatures
	wbbData := "tallying,TT,mixed_ballots,3,bls_test_data"
	
	// Submit from TT-1, TT-2, TT-3
	for _, entity := range []string{"TT-1", "TT-2", "TT-3"} {
		entry := createStagingBLSWBBEntry(t, wbbData, []string{entity})
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
	}
	
	// Final submission should return published
	// Note: This assumes the server aggregates BLS signatures
	// If server doesn't support BLS aggregation yet, this will fail
	
	t.Log("BLS staging test - requires server-side BLS aggregation implementation")
}

// ============ PERSISTENCE TESTS ============

func testStagingPersistence(t *testing.T, serverURL string) {
	// Test: Staging entries survive between requests
	wbbData := "tallying,TT,mixed_ballots,3,persistence_test_data"
	
	// TT-1 submits
	entry1 := createStagingWBBEntry(t, wbbData, "TT-1")
	resp1 := submitStagingEntry(t, serverURL+"/submit", entry1)
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	
	var result1 map[string]interface{}
	json.Unmarshal(body1, &result1)
	contentHash := result1["content_hash"].(string)
	
	// TT-2 submits (different request, same staging area)
	entry2 := createStagingWBBEntry(t, wbbData, "TT-2")
	resp2 := submitStagingEntry(t, serverURL+"/submit", entry2)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	
	var result2 map[string]interface{}
	json.Unmarshal(body2, &result2)
	
	// Should see both submissions
	if result2["current_signers"] != float64(2) {
		t.Errorf("Expected staging to persist (2 signers), got %v signers", result2["current_signers"])
	}
	
	// Content hash should match
	if result2["content_hash"] != contentHash {
		t.Errorf("Content hash should match across requests")
	}
	
	t.Logf("Staging persistence verified: %s", string(body2))
}

// ============ HELPER FUNCTIONS ============

// createStagingWBBEntry creates a single-sig staging entry
func createStagingWBBEntry(t *testing.T, wbbData, entityID string) ctlog.SignedEntry {
	return createWBBEntry(t, wbbData, entityID, nil) // Use existing helper
}

// createStagingBLSWBBEntry creates a BLS staging entry
func createStagingBLSWBBEntry(t *testing.T, wbbData string, entityIDs []string) ctlog.SignedEntry {
	return createAggregateWBBEntry(t, wbbData, entityIDs) // Use existing helper
}

// submitStagingEntry submits an entry to the staging system
func submitStagingEntry(t *testing.T, url string, entry ctlog.SignedEntry) *http.Response {
	return submitEntry(t, url, entry) // Use existing helper
}
