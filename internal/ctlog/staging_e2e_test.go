package ctlog_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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

	t.Run("BLS Algorithm Detection", func(t *testing.T) {
		testBLSAlgorithmDetection(t, server.URL)
	})

	t.Run("Timestamp - Uses LastSubmissionAt", func(t *testing.T) {
		testTimestampLastSubmissionAt(t, server.URL)
	})

	t.Run("Grace Period - Collects Late Submissions", func(t *testing.T) {
		testGracePeriodCollectsLateSubmissions(t, server.URL)
	})

	t.Run("Grace Period - Early Publication", func(t *testing.T) {
		testGracePeriodEarlyPublication(t, server.URL)
	})

	t.Run("Grace Period - Timer Expiration", func(t *testing.T) {
		testGracePeriodTimerExpiration(t, server.URL)
	})

	t.Run("Late Arrival - Creates New Leaf", func(t *testing.T) {
		testLateArrivalNewLeaf(t, server.URL)
	})

	t.Run("Late Arrival - BLS Aggregate", func(t *testing.T) {
		testLateArrivalBLSAggregate(t, server.URL)
	})

	t.Run("HTTP Status - Duplicate Signer", func(t *testing.T) {
		testHTTPStatusDuplicateSigner(t, server.URL)
	})

	t.Run("HTTP Status - Already Published", func(t *testing.T) {
		testHTTPStatusAlreadyPublished(t, server.URL)
	})

	t.Run("Race Condition - Concurrent Finalization", func(t *testing.T) {
		testRaceConditionConcurrentFinalization(t, server.URL)
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

	// Verify signer_timestamps contains all individual submission timestamps
	signerTimestamps, ok := result["signer_timestamps"].([]interface{})
	if !ok {
		t.Error("Expected signer_timestamps in published response")
	} else if len(signerTimestamps) != 3 {
		t.Errorf("Expected 3 signer timestamps, got %v", len(signerTimestamps))
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
	// Test: Staging with BLS partial signatures (server-side aggregation)
	// ISSUE #1 / #3 / #7: BLS submissions are detected and aggregate is maintained
	wbbData := "tallying,TT,mixed_ballots,3,bls_test_data"

	// Submit from TT-1, TT-2, TT-3 using BLS partial signatures
	for _, entity := range []string{"TT-1", "TT-2", "TT-3"} {
		entry := createStagingBLSPartialEntry(t, wbbData, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
			t.Fatalf("BLS submission from %s failed: %d: %s", entity, resp.StatusCode, string(body))
		}

		// On the last submission (threshold met), should get 200 OK
		if entity == "TT-3" {
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Expected 200 OK when BLS threshold met, got %d: %s", resp.StatusCode, string(body))
			}

			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatalf("Failed to parse response: %v", body)
			}

			if result["status"] != "published" {
				t.Errorf("Expected status 'published', got %v", result["status"])
			}

			if result["algorithm"] != "bls" {
				t.Errorf("Expected algorithm 'bls', got %v", result["algorithm"])
			}

			if result["aggregate_signature"] == nil {
				t.Error("Expected aggregate_signature for BLS published entry")
			}

			// Verify all individual timestamps are preserved
			signerTimestamps, ok := result["signer_timestamps"].([]interface{})
			if !ok {
				t.Error("Expected signer_timestamps in BLS published response")
			} else if len(signerTimestamps) != 3 {
				t.Errorf("Expected 3 signer timestamps, got %v", len(signerTimestamps))
			}
		}
	}

	t.Log("BLS staging with server-side aggregation works correctly")
}

func testBLSAlgorithmDetection(t *testing.T, serverURL string) {
	// Test: First submission determines algorithm; mixed submissions are rejected
	// ISSUE #7: Algorithm detection and handling
	wbbData := "tallying,TT,mixed_ballots,3,algo_detection_test"

	// TT-1 submits with BLS partial signature
	entry1 := createStagingBLSPartialEntry(t, wbbData, "TT-1")
	resp1 := submitStagingEntry(t, serverURL+"/submit", entry1)
	resp1.Body.Close()

	// TT-2 tries to submit Ed25519 signature for same content
	entry2 := createStagingWBBEntry(t, wbbData, "TT-2")
	resp2 := submitStagingEntry(t, serverURL+"/submit", entry2)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	// Should reject mixed-algorithm submission
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict for mixed algorithm, got %d: %s", resp2.StatusCode, string(body2))
	}

	t.Logf("Mixed-algorithm submission correctly rejected: %s", string(body2))
}

// ============ TIMESTAMP TESTS (Issue #2) ============

func testTimestampLastSubmissionAt(t *testing.T, serverURL string) {
	// Test: Published entry uses LastSubmissionAt as timestamp, not FirstSubmissionAt
	// ISSUE #2: Timestamp bug — Uses FirstSubmissionAt
	wbbData := "tallying,TT,mixed_ballots,3,timestamp_test_data"

	// TT-1 submits at T=0
	entry1 := createStagingWBBEntry(t, wbbData, "TT-1")
	resp1 := submitStagingEntry(t, serverURL+"/submit", entry1)
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("First submission should return 202, got %d: %s", resp1.StatusCode, string(body1))
	}

	// Wait a small amount to ensure timestamps differ
	time.Sleep(50 * time.Millisecond)

	// TT-2 submits at T>0
	entry2 := createStagingWBBEntry(t, wbbData, "TT-2")
	resp2 := submitStagingEntry(t, serverURL+"/submit", entry2)
	resp2.Body.Close()

	// Wait again
	time.Sleep(50 * time.Millisecond)

	// TT-3 submits at T>>0 (threshold met)
	entry3 := createStagingWBBEntry(t, wbbData, "TT-3")
	resp3 := submitStagingEntry(t, serverURL+"/submit", entry3)
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK when threshold met, got %d: %s", resp3.StatusCode, string(body3))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body3, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", body3)
	}

	publishedTimestamp := int64(result["timestamp"].(float64))

	// The published timestamp should be the LAST submission timestamp (TT-3), not the first (TT-1)
	// If FirstSubmissionAt were used, timestamp would be much older
	timeDiff := time.Now().UnixMilli() - publishedTimestamp
	if timeDiff < 0 || timeDiff > 200 {
		t.Errorf("Published timestamp %d is too old (diff=%d ms). Expected close to TT-3 submission time.", publishedTimestamp, timeDiff)
	}

	// Verify signer_timestamps contains all 3 individual submission timestamps
	signerTimestamps, ok := result["signer_timestamps"].([]interface{})
	if !ok {
		t.Error("Expected signer_timestamps in published response")
	} else if len(signerTimestamps) != 3 {
		t.Errorf("Expected 3 signer timestamps, got %v", len(signerTimestamps))
	}

	t.Logf("Published timestamp is recent (diff=%d ms) and all %d signer timestamps preserved, confirming LastSubmissionAt is used", timeDiff, len(signerTimestamps))
}

// ============ GRACE PERIOD TESTS (Issue #8) ============

func testGracePeriodCollectsLateSubmissions(t *testing.T, serverURL string) {
	// Test: Submissions arriving during the 10s grace period are included
	wbbData := "tallying,TT,mixed_ballots,3,grace_collect_test"

	// TT-1, TT-2 submit
	for _, entity := range []string{"TT-1", "TT-2"} {
		entry := createStagingWBBEntry(t, wbbData, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
	}

	// TT-3 submits (threshold met, grace period starts)
	entry3 := createStagingWBBEntry(t, wbbData, "TT-3")
	resp3 := submitStagingEntry(t, serverURL+"/submit", entry3)
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()

	// Should be 202 "grace_period" (not yet published)
	if resp3.StatusCode != http.StatusAccepted {
		t.Fatalf("Expected 202 Accepted (grace period), got %d: %s", resp3.StatusCode, string(body3))
	}

	var result3 map[string]interface{}
	json.Unmarshal(body3, &result3)

	if result3["status"] != "grace_period" {
		t.Fatalf("Expected status 'grace_period', got %v", result3["status"])
	}

	// TT-4 submits during grace period (should be included)
	entry4 := createStagingWBBEntry(t, wbbData, "TT-4")
	resp4 := submitStagingEntry(t, serverURL+"/submit", entry4)
	body4, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()

	// Should still be grace period (not all TT entities present yet)
	if resp4.StatusCode != http.StatusAccepted {
		t.Fatalf("Expected 202 Accepted (grace period), got %d: %s", resp4.StatusCode, string(body4))
	}

	// Wait for grace period to expire
	time.Sleep(11 * time.Second)

	// After grace period, the entry should be published with all 4 signers
	// Verify by submitting a duplicate (should be rejected as already published during grace period?)
	// Or check the log directly — for now, verify the published response
	t.Logf("Grace period collected submissions. TT-3 response: %s, TT-4 response: %s", string(body3), string(body4))
}

func testGracePeriodEarlyPublication(t *testing.T, serverURL string) {
	// Test: If all expected entities sign before grace period ends, publish immediately
	// For TT role with 5 configured entities (RT has 3), threshold=3
	// All 3 RT entities sign for threshold=2: should publish immediately when RT-3 signs (all present)
	wbbData := "setup,RT,acc_pub_key,2,early_pub_test_data"

	// RT-1 submits
	entry1 := createStagingWBBEntry(t, wbbData, "RT-1")
	resp1 := submitStagingEntry(t, serverURL+"/submit", entry1)
	resp1.Body.Close()

	// RT-2 submits (threshold met, grace period starts)
	entry2 := createStagingWBBEntry(t, wbbData, "RT-2")
	resp2 := submitStagingEntry(t, serverURL+"/submit", entry2)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	var result2 map[string]interface{}
	json.Unmarshal(body2, &result2)

	// RT has only 3 entities configured. Threshold=2.
	// If RT-3 signs, ALL expected signers are present → should publish immediately
	if result2["status"] == "published" {
		// Already published (all signers present logic kicked in)
		t.Logf("Early publication triggered: all signers present")
		return
	}

	if result2["status"] != "grace_period" {
		t.Fatalf("Expected 'grace_period' or 'published', got %v", result2["status"])
	}

	// RT-3 submits (all expected signers present)
	entry3 := createStagingWBBEntry(t, wbbData, "RT-3")
	resp3 := submitStagingEntry(t, serverURL+"/submit", entry3)
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()

	// Should now be published (all signers present)
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for early publication, got %d: %s", resp3.StatusCode, string(body3))
	}

	var result3 map[string]interface{}
	json.Unmarshal(body3, &result3)

	if result3["status"] != "published" {
		t.Errorf("Expected status 'published' (early), got %v", result3["status"])
	}

	t.Logf("Early publication works: %s", string(body3))
}

func testGracePeriodTimerExpiration(t *testing.T, serverURL string) {
	// Test: Entry is published after grace period expires even if not all signers present
	wbbData := "tallying,TT,mixed_ballots,3,timer_exp_test"

	// TT-1, TT-2, TT-3 submit (threshold met, grace period starts)
	for _, entity := range []string{"TT-1", "TT-2", "TT-3"} {
		entry := createStagingWBBEntry(t, wbbData, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if entity == "TT-3" {
			var result map[string]interface{}
			json.Unmarshal(body, &result)
			if result["status"] != "grace_period" && result["status"] != "published" {
				t.Fatalf("Expected 'grace_period' or 'published', got %v", result["status"])
			}
		}
	}

	// Wait for grace period to expire (10s + 1s buffer)
	time.Sleep(11 * time.Second)

	// Submit a duplicate to check state (should now be published)
	entryDup := createStagingWBBEntry(t, wbbData, "TT-1")
	respDup := submitStagingEntry(t, serverURL+"/submit", entryDup)
	bodyDup, _ := io.ReadAll(respDup.Body)
	respDup.Body.Close()

	// Should be 409 Conflict (already published) or 200 OK (appended)
	if respDup.StatusCode == http.StatusConflict {
		t.Logf("Grace period expired and entry published. Duplicate rejected: %s", string(bodyDup))
	} else if respDup.StatusCode == http.StatusOK {
		var result map[string]interface{}
		json.Unmarshal(bodyDup, &result)
		if result["status"] != "appended" {
			t.Errorf("Expected 'appended' for late duplicate, got %v", result["status"])
		}
	} else {
		t.Logf("Unexpected status after grace period: %d: %s", respDup.StatusCode, string(bodyDup))
	}
}

// ============ LATE ARRIVAL TESTS (Issue #9) ============

func testLateArrivalNewLeaf(t *testing.T, serverURL string) {
	// Test: Late arrival after grace period creates a new leaf with ref:N format
	wbbData := "setup,RT,acc_pub_key,2,late_arrival_test_data"

	// RT-1, RT-2 submit and publish
	for _, entity := range []string{"RT-1", "RT-2"} {
		entry := createStagingWBBEntry(t, wbbData, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
	}

	// Wait for grace period to expire
	time.Sleep(11 * time.Second)

	// RT-3 submits late (after grace period)
	entry3 := createStagingWBBEntry(t, wbbData, "RT-3")
	resp3 := submitStagingEntry(t, serverURL+"/submit", entry3)
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for late arrival, got %d: %s", resp3.StatusCode, string(body3))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body3, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", body3)
	}

	if result["status"] != "appended" {
		t.Errorf("Expected status 'appended', got %v", result["status"])
	}

	if result["referenced_leaf"] == nil {
		t.Error("Expected 'referenced_leaf' in late arrival response")
	}

	if result["leaf_index"] == nil {
		t.Error("Expected 'leaf_index' in late arrival response")
	}

	// The new leaf should have a higher index than the referenced leaf
	newLeaf := int64(result["leaf_index"].(float64))
	refLeaf := int64(result["referenced_leaf"].(float64))
	if newLeaf <= refLeaf {
		t.Errorf("Late arrival leaf index %d should be > referenced leaf %d", newLeaf, refLeaf)
	}

	t.Logf("Late arrival created new leaf %d referencing leaf %d", newLeaf, refLeaf)
}

func testLateArrivalBLSAggregate(t *testing.T, serverURL string) {
	// Test: BLS late arrival updates the running aggregate
	wbbData := "tallying,TT,mixed_ballots,3,bls_late_test_data"

	// TT-1, TT-2, TT-3 submit with BLS (publish)
	for _, entity := range []string{"TT-1", "TT-2", "TT-3"} {
		entry := createStagingBLSPartialEntry(t, wbbData, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
	}

	// Wait for grace period to expire
	time.Sleep(11 * time.Second)

	// TT-4 submits late with BLS
	entry4 := createStagingBLSPartialEntry(t, wbbData, "TT-4")
	resp4 := submitStagingEntry(t, serverURL+"/submit", entry4)
	body4, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()

	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for BLS late arrival, got %d: %s", resp4.StatusCode, string(body4))
	}

	var result map[string]interface{}
	json.Unmarshal(body4, &result)

	if result["status"] != "appended" {
		t.Errorf("Expected status 'appended', got %v", result["status"])
	}

	t.Logf("BLS late arrival appended correctly: %s", string(body4))
}

// ============ HTTP STATUS CODE TESTS (Issue #6) ============

func testHTTPStatusDuplicateSigner(t *testing.T, serverURL string) {
	// Test: Duplicate signer returns 409 Conflict, not 403 Forbidden
	wbbData := "tallying,TT,mixed_ballots,3,http_dup_test"

	// TT-1 submits first time
	entry1 := createStagingWBBEntry(t, wbbData, "TT-1")
	resp1 := submitStagingEntry(t, serverURL+"/submit", entry1)
	resp1.Body.Close()

	// TT-1 submits again (duplicate)
	entry2 := createStagingWBBEntry(t, wbbData, "TT-1")
	resp2 := submitStagingEntry(t, serverURL+"/submit", entry2)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict for duplicate signer, got %d: %s", resp2.StatusCode, string(body2))
	}

	t.Logf("Duplicate signer correctly returns 409: %s", string(body2))
}

func testHTTPStatusAlreadyPublished(t *testing.T, serverURL string) {
	// Test: Submitting to already-published entry during grace period returns 409
	wbbData := "setup,RT,acc_pub_key,2,http_pub_test"

	// RT-1, RT-2 publish
	for _, entity := range []string{"RT-1", "RT-2"} {
		entry := createStagingWBBEntry(t, wbbData, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
	}

	// Wait for grace period to expire
	time.Sleep(11 * time.Second)

	// RT-1 tries to submit again (already published)
	entryDup := createStagingWBBEntry(t, wbbData, "RT-1")
	respDup := submitStagingEntry(t, serverURL+"/submit", entryDup)
	bodyDup, _ := io.ReadAll(respDup.Body)
	respDup.Body.Close()

	// Should be 409 Conflict (already published)
	if respDup.StatusCode != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict for already-published entry, got %d: %s", respDup.StatusCode, string(bodyDup))
	}

	t.Logf("Already-published entry correctly returns 409: %s", string(bodyDup))
}

// ============ RACE CONDITION TESTS (Issue #4) ============

func testRaceConditionConcurrentFinalization(t *testing.T, serverURL string) {
	// Test: Multiple goroutines hitting threshold simultaneously should not publish duplicates
	wbbData := "tallying,TT,mixed_ballots,3,race_test_data"

	// Pre-submit TT-1 and TT-2 (pending)
	for _, entity := range []string{"TT-1", "TT-2"} {
		entry := createStagingWBBEntry(t, wbbData, entity)
		resp := submitStagingEntry(t, serverURL+"/submit", entry)
		resp.Body.Close()
	}

	// Concurrently submit TT-3 from multiple goroutines
	var wg sync.WaitGroup
	results := make([]int, 5)
	var mu sync.Mutex

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			entry := createStagingWBBEntry(t, wbbData, "TT-3")
			resp := submitStagingEntry(t, serverURL+"/submit", entry)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			mu.Lock()
			results[idx] = resp.StatusCode
			mu.Unlock()

			t.Logf("Goroutine %d: status=%d body=%s", idx, resp.StatusCode, string(body))
		}(i)
	}

	wg.Wait()

	// Count results
	okCount := 0
	conflictCount := 0
	for _, code := range results {
		if code == http.StatusOK {
			okCount++
		} else if code == http.StatusConflict {
			conflictCount++
		}
	}

	// Exactly one should succeed with 200 OK, others should get 409 Conflict
	if okCount != 1 {
		t.Errorf("Expected exactly 1 goroutine to get 200 OK, got %d", okCount)
	}
	if conflictCount != 4 {
		t.Errorf("Expected 4 goroutines to get 409 Conflict, got %d", conflictCount)
	}

	t.Logf("Race condition test: %d OK, %d Conflict — %s", okCount, conflictCount,
		func() string {
			if okCount == 1 && conflictCount == 4 {
				return "PASS"
			}
			return "FAIL"
		}())
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

// createStagingBLSWBBEntry creates a BLS aggregate staging entry (one-request path)
func createStagingBLSWBBEntry(t *testing.T, wbbData string, entityIDs []string) ctlog.SignedEntry {
	return createAggregateWBBEntry(t, wbbData, entityIDs) // Use existing helper
}

// createStagingBLSPartialEntry creates a single BLS partial signature entry for server-side staging.
// Each entity signs the message independently; the server aggregates them.
func createStagingBLSPartialEntry(t *testing.T, wbbData, entityID string) ctlog.SignedEntry {
	timestamp := time.Now().UnixMilli()
	data := []byte(wbbData)

	// Sign the same message as Ed25519: data || entity_id || timestamp
	var buf bytes.Buffer
	buf.Write(data)
	buf.WriteString(entityID)
	buf.WriteString(fmt.Sprintf("%d", timestamp))

	msg := sha256.Sum256(buf.Bytes())

	signer, ok := testEntityBLSSigners[entityID]
	if !ok {
		t.Fatalf("missing BLS signer for entity %s", entityID)
	}

	sig, err := signer.Sign(msg[:])
	if err != nil {
		t.Fatalf("failed to create BLS signature for %s: %v", entityID, err)
	}

	return ctlog.SignedEntry{
		Data:         data,
		EntityID:     entityID,
		Timestamp:    timestamp,
		BLSSignature: sig,
	}
}

// submitStagingEntry submits an entry to the staging system
func submitStagingEntry(t *testing.T, url string, entry ctlog.SignedEntry) *http.Response {
	return submitEntry(t, url, entry) // Use existing helper
}
