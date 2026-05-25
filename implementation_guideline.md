# WBB Policy Implementation Guidelines

## What is TDD? (Test-Driven Development)

**TDD is a software development approach where you write tests BEFORE writing the actual code.**

### The TDD Cycle:
1. **RED**: Write a test that fails (because the feature doesn't exist yet)
2. **GREEN**: Write just enough code to make the test pass
3. **REFACTOR**: Clean up the code while keeping tests passing
4. **REPEAT**: Move to the next test

## Current Architecture

### 1. Message Structure (`internal/ctlog/http.go`)

```go
type SignedEntry struct {
    Data      []byte `json:"data"`      // WBB-formatted entry
    EntityID  string `json:"entity_id"` // Who is signing (e.g., "RT-1", "TT-1")
    Timestamp int64  `json:"timestamp"` // Unix milliseconds
    Signature []byte `json:"signature"` // Ed25519 or BLS signature
}
```

**WBB Format in Data field:**
```
phase,role,entry_type,threshold,content
```

Example: `"setup,RT,acc_pub_key,2,public_key_data"`

### 2. Entity Registry (`internal/ctlog/ctlog.go`)

Entity public keys are configured in `Config.EntityKeys`:

```go
config := &ctlog.Config{
    EntityKeys: map[string]ed25519.PublicKey{
        "RT-1": rt1PublicKey,
        "RT-2": rt2PublicKey,
        "ER-1": er1PublicKey,
        "BB-1": bb1PublicKey,
        "TT-1": tt1PublicKey,
        // ... etc
    },
}
```

### 3. Current Flow

1. Client submits `SignedEntry` JSON to `POST /submit`
2. Server validates JSON format
3. Server checks timestamp (±5 min window)
4. Server verifies signature using entity's public key
5. Server stores entry in log

## Implementation Roadmap

**Don't try to implement everything at once!** Work through these 5 phases in order.

### Phase 1: Fix Test Infrastructure
**Goal**: Make test helpers generate valid signatures

**Why first?** Without valid signatures, you can't test the actual policy logic.

**Files to modify:**
- `wbb_policy_e2e_test.go`: Update `generateTestEntityKeys()` and `createWBBEntry()`

**What to do:**
1. Store both public AND private keys in test setup
2. Generate real Ed25519 signatures using private keys
3. Remove placeholder signatures

**Verify:** Run `TestWBBPolicyAllEntities` - should see "invalid signature" errors disappear for valid entries

### Phase 2: Basic Policy Validation
**Goal**: Reject entries that violate basic policy rules

**Files to modify:**
- `internal/ctlog/http.go`: Add after signature verification (around line 140)

**What to add:**

```go
// Parse WBB entry from data
wbbEntry, err := ParseWBBEntry(string(signedEntry.Data))
if err != nil {
    return nil, http.StatusBadRequest, fmtErrorf("invalid WBB format: %w", err)
}

// Check if entity is authorized to write this entry type
role := Role(signedEntry.EntityID[:2]) // Extract "RT" from "RT-1"
if role != wbbEntry.Role {
    return nil, http.StatusForbidden, fmtErrorf("entity %s cannot write as role %s", 
        signedEntry.EntityID, wbbEntry.Role)
}

// Check write policy
allowed, err := CheckWBBWritePolicy(string(signedEntry.Data))
if err != nil || !allowed {
    return nil, http.StatusForbidden, fmtErrorf("write not authorized: %w", err)
}
```

**Tests to pass:**
- `RT_cannot_write_other_entry_types`
- `ER_cannot_write_RT_entry_types`
- `BB_cannot_write_setup_phase_entries`
- `RT_cannot_write_in_voting_phase`
- `ER_cannot_write_in_tallying_phase`
- `TT_cannot_write_in_setup_phase`

### Phase 3: Threshold Validation - Single Entity
**Goal**: Accept entries with threshold=1, reject entries with insufficient signatures

**Files to modify:**
- `internal/ctlog/http.go`: Add threshold checking logic after policy check

**What to do:**
1. Check if `wbbEntry.Threshold` matches expected value for entry type
2. For entries with threshold=1: process immediately (current behavior)
3. For entries with threshold>1: return 403 "insufficient signatures"

**Tests to pass:**
- `ER_accepts_threshold_1` (should pass with 200 OK)
- `RT_requires_threshold_2_for_acc_pub_key` (should fail with 403)
- `TT_requires_threshold_3_for_mixed_ballots` (should fail with 403)

// the last two tests pass but with 403 error

### Phase 4: Multi-Signature Support
**Goal**: Handle entries requiring multiple signatures (threshold > 1)

**This is the hardest part.** Choose ONE approach:

#### Option A: Staging Area
Store partial signatures and wait for threshold to be met.

**Files to modify:**
- `internal/ctlog/ctlog.go`: Add staging field to `Log` struct
- `internal/ctlog/http.go`: Handle partial signatures

**Implementation:**
1. Add to `Log` struct:
```go
type Log struct {
    // ... existing fields ...
    staging map[string][]SignedEntry // key: "phase,role,entry_type,content"
}
```

2. When receiving entry with threshold > 1:
   - Generate key: `key = phase + "," + role + "," + entry_type + "," + content`
   - Check staging area for existing partial entry
   - Verify signature is from a different entity than existing ones
   - Add to staging list
   - If len(staging[key]) >= threshold:
     * Aggregate all signatures
     * Store entry in log
     * Remove from staging
     * Return 200 OK
   - If len(staging[key]) < threshold:
     * Return 202 Accepted ("pending, need N more signatures")

#### Option B: Aggregate Signatures in One Request
Client sends all signatures in a single request.

**Files to modify:**
- `internal/ctlog/http.go`: Support multiple signatures

**Implementation:**
1. Modify `SignedEntry` to support multiple signers:
```go
type SignedEntry struct {
    Data       []byte            `json:"data"`
    EntityIDs  []string          `json:"entity_ids"`   // All signing entities
    Timestamp  int64             `json:"timestamp"`
    Signatures [][]byte          `json:"signatures"`   // Signatures in same order as EntityIDs
}
```

2. Verify ALL signatures:
```go
for i, entityID := range signedEntry.EntityIDs {
    pubKey, exists := l.entityKeys[entityID]
    if !exists {
        return nil, http.StatusUnauthorized, fmtErrorf("unknown entity: %s", entityID)
    }
    
    // Create temp entry for verification
    tempEntry := SignedEntry{
        Data:      signedEntry.Data,
        EntityID:  entityID,
        Timestamp: signedEntry.Timestamp,
        Signature: signedEntry.Signatures[i],
    }
    
    if !tempEntry.Verify(pubKey) {
        return nil, http.StatusUnauthorized, fmtErrorf("invalid signature from %s", entityID)
    }
}

// Check threshold
if len(signedEntry.EntityIDs) < wbbEntry.Threshold {
    return nil, http.StatusForbidden, fmtErrorf("insufficient signatures: got %d, need %d", 
        len(signedEntry.EntityIDs), wbbEntry.Threshold)
}
```

**Tests to pass:**
- `RT_can_write_acc_pub_key_with_threshold_2` (simulate 2 RT signatures)
- `TT_can_write_mixed_ballots_with_threshold_3` (simulate 3 TT signatures)

### Phase 5: Verification and Cleanup
**Goal**: Ensure all policy-compliant entries are accepted

**What to do:**
1. Test all valid entry type combinations
2. Verify correct HTTP responses (200 OK for valid, 403 for violations)
3. Verify entries are stored in log with correct metadata
4. Clean up any debug print statements
5. Add comments to complex logic

**Tests to pass (all should pass with 200 OK):**
- `ER_can_write_election_pub_key`
- `ER_can_write_pseudonymous_id_count`
- `ER_can_write_voter_id_merkle_root`
- `BB_can_write_ballot_digest`
- `BB_can_write_ballot_metadata`
- `BB_can_write_cast_intended_proof`
- `BB_can_write_encrypted_ballot`
- `TT_can_write_re_encryption_proof`
- `TT_can_write_tally_result`
- `TT_can_write_tally_proof`

## Response Codes Reference

| Code | Meaning | When to Use |
|------|---------|-------------|
| 200 OK | Success | Entry accepted and stored in log |
| 400 Bad Request | Invalid format | JSON parsing error, invalid WBB format, timestamp out of range |
| 401 Unauthorized | Auth failed | Unknown entity, invalid signature |
| 403 Forbidden | Policy violation | Role mismatch, wrong phase, threshold not met, entry type not allowed |
| 202 Accepted | Pending | Used in Option A when threshold not yet met (optional) |

## Testing Commands

```bash
# Run all tests
go test ./internal/ctlog/... -v

# Run only WBB policy tests
go test ./internal/ctlog/... -v -run TestWBBPolicyAllEntities

# Run specific phase tests
go test ./internal/ctlog/... -v -run TestWBBPolicyAllEntities/Setup_Phase
go test ./internal/ctlog/... -v -run TestWBBPolicyAllEntities/Voting_Phase
go test ./internal/ctlog/... -v -run TestWBBPolicyAllEntities/Tallying_Phase
go test ./internal/ctlog/... -v -run TestWBBPolicyAllEntities/Policy_Violations
go test ./internal/ctlog/... -v -run TestWBBPolicyAllEntities/Threshold_Enforcement

# Run specific test
go test ./internal/ctlog/... -v -run TestWBBPolicyAllEntities/Setup_Phase_-_RT_Entities/RT_can_write_acc_pub_key
```

## File Structure

```
internal/ctlog/
├── http.go                    # Main implementation: submitEntry(), policy checks
├── ctlog.go                   # Log struct, may add staging field
├── wbb_policy.go              # Already exists - policy rules and parsing
├── wbb_policy_e2e_test.go     # TDD tests - update createWBBEntry() first
└── e2e_test.go                # Shared test helpers (MemoryBackend, etc.)
```

---

## Policy Reference Table

| Phase | Role | Allowed Entry Types | Min Threshold |
|-------|------|---------------------|---------------|
| Setup | RT | acc_pub_key | 2 |
| Setup | ER | election_pub_key, pseudonymous_id_count, voter_id_merkle_root | 1 |
| Voting | BB | ballot_digest, ballot_metadata, cast_intended_proof | 1 |
| Tallying | BB | encrypted_ballot | 1 |
| Tallying | TT | mixed_ballots, re_encryption_proof, tally_result, tally_proof | 3 |

**Key Points:**
- Entities can ONLY write in their assigned phases
- RT and TT require multiple signatures (threshold > 1)
- ER and BB can write with single signature (threshold = 1)
- Each entry type is restricted to specific roles

---

## Quick References

If unclear about:

**WBB format:** See `wbb_policy.go` lines 46-52

**Policy rules:** See `wbb_policy.go` function `CheckWBBWritePolicy()`

**Test expectations:** Run tests with `-v` flag and check logged responses

**Signature verification:** See `http.go` function `Verify()`

**EntryType constants:** See `wbb_policy.go` lines 24-37

**Phase and Role constants:** See `wbb_policy.go` lines 14-22
