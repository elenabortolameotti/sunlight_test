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
| 202 Accepted | Pending | Threshold not yet met, or grace period active |
| 409 Conflict | Duplicate | Duplicate signer, entry already published |

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

---

# Server-Side Staging with Grace Period

## Key Concepts

- **Server-side staging**: Entities submit independently. The server collects partial signatures in memory.
- **Grace period**: When the threshold is met, a fixed 10-second grace period starts. Additional submissions arriving during this window are included in the final entry.
- **Early publication**: If all expected entities for a role have signed before the grace period ends, the entry is published immediately.
- **Late submissions**: Submissions arriving after the grace period ends are stored as **new leaves** in the Merkle tree. The content field is replaced with a reference to the original published entry (e.g., `ref:42`).
- **Timestamp**: The log entry `Timestamp` is the **last submission timestamp** (`LastSubmissionAt`), ensuring it always falls within the ±5 minute validation window. **All individual submission timestamps are preserved** in `SignerTimestamps` for auditability.

### Staging State Machine

```
[Collecting] --(threshold met)--> [Grace Period] --(timer expires)--> [Published]
                                      |
                                      +--(all signers present)--> [Published]
                                      |
                                      +--(new submission)--> [Grace Period] (timer continues)

[Published] --(late submission)--> [New Leaf with Reference]
```

## Required Data Structure Changes

### 1. Add Staging Types to `internal/ctlog/ctlog.go`

**Location:** After `Log` struct definition, add:

```go
// StagingEntry tracks partial signatures for a WBB entry
type StagingEntry struct {
    WBBData       string
    Phase         Phase
    Role          Role
    EntryType     EntryType
    Threshold     int
    Content       string
    SigAlgorithm  string  // "ed25519" or "bls"

    // Map of entityID -> submission
    Submissions   map[string]*StagingSubmission

    // For BLS: maintain running aggregate
    RunningBLSAggregate []byte

    // Tracking timestamps (computed from Submissions map)
    FirstSubmissionAt int64  // min of all submission timestamps (audit)
    LastSubmissionAt  int64  // max of all submission timestamps (used for log entry)

    // NEW: Grace period
    GracePeriodEndAt     int64    // Timestamp when grace period expires
    IsGracePeriodStarted bool     // Whether grace period has started

    // NEW: Expected signers for this role (from config at creation time)
    ExpectedEntityIDs []string

    IsPublished   bool
    LeafIndex     int64
}

type StagingSubmission struct {
    EntityID  string
    Timestamp int64     // When THIS entity submitted (per-entity timestamp)
                        // This timestamp is preserved in the final log entry
    Signature []byte    // Ed25519 signature (only for ed25519 entries)
    // Note: for BLS entries, individual signatures are aggregated immediately
    // into RunningBLSAggregate and do not need to be stored per-submission
}
```

### 2. Update Log Struct

**Location:** In `Log` struct definition, add field:

```go
type Log struct {
    // ... existing fields ...

    // staging tracks partial signatures waiting for threshold
    // Key: SHA256 hash of WBB data (phase,role,entry_type,threshold,content)
    staging map[[32]byte]*StagingEntry

    stagingMu sync.RWMutex // or sync.Mutex
}
```

### 3. Initialize Staging in LoadLog

**Location:** In `LoadLog()` function, after creating `Log` struct:

```go
return &Log{
    // ... existing fields ...
    staging: make(map[[32]byte]*StagingEntry),
}, nil
```

### 4. Populate ExpectedEntityIDs on Creation

When creating a new `StagingEntry`, look up all entities in `Config.EntityKeys` that match the entry's `Role` and populate `ExpectedEntityIDs`:

```go
for entityID := range l.entityKeys {
    if role, _ := roleFromEntityID(entityID); role == wbbEntry.Role {
        staged.ExpectedEntityIDs = append(staged.ExpectedEntityIDs, entityID)
    }
}
sort.Strings(staged.ExpectedEntityIDs)
```

## Required Function Implementations

### Function 1: `stageSubmission()`

**Location:** `internal/ctlog/http.go`

**Purpose:** Add a new submission to the staging area

**Parameters:**
- `contentHash [32]byte` - SHA256 of WBB data
- `signedEntry SignedEntry` - The submitted entry
- `wbbEntry WBBEntry` - Parsed WBB entry

**Logic:**
1. Verify the signer identity, role match, and signature (`verifySingleWBBEntry`)
2. Lock staging map
3. Check if staging entry exists for `contentHash`
4. If not, create new `StagingEntry` and populate `ExpectedEntityIDs`
5. Security check: if `IsPublished` and grace period has ended, reject (late arrivals go through `appendToPublishedEntry`)
6. Security check: duplicate signer prevention
7. Detect signature algorithm on first submission:
   - If `BLSSignature` present -> `SigAlgorithm = "bls"`
   - If `Signature` present -> `SigAlgorithm = "ed25519"`
   - Reject if algorithm mismatches existing entry
8. Store submission:
   - **Ed25519**: store individual `Signature` in `StagingSubmission` (cannot aggregate)
   - **BLS**: immediately aggregate into `RunningBLSAggregate` using `my_crypto.AggregateSignaturesBytes()`. Individual BLS signatures need not be stored per-submission because only the aggregate matters
9. Update `FirstSubmissionAt` and `LastSubmissionAt`
10. Return current signer count

**Returns:** `(currentCount int, isNew bool, err error)`

### Function 2: `checkThreshold()`

**Location:** `internal/ctlog/http.go`

**Purpose:** Check if threshold is met for a staging entry

**Parameters:**
- `contentHash [32]byte`

**Logic:**
1. Look up staging entry
2. Count unique submissions
3. Return count and whether `count >= threshold`

**Returns:** `(count int, thresholdMet bool, err error)`

### Function 3: `startGracePeriod()`

**Location:** `internal/ctlog/http.go`

**Purpose:** Start the 10-second grace period when threshold is first met

**Parameters:**
- `contentHash [32]byte`

**Logic:**
1. Lock staging map
2. Set `IsGracePeriodStarted = true`
3. Set `GracePeriodEndAt = now + 10 seconds`
4. Unlock

**Returns:** `error`

### Function 4: `finalizeEntry()`

**Location:** `internal/ctlog/http.go`

**Purpose:** Convert staging entry to final log entry and publish

**Parameters:**
- `contentHash [32]byte`
- `ctx context.Context`

**Logic:**
1. Lock staging map
2. Get staging entry
3. If already published, return existing leaf index
4. If threshold not met, error
5. **Atomic transition**: Set `IsPublished = true` with sentinel `LeafIndex = -1`
6. Build final `SignedEntry`:
   - `Data` from `WBBData`
   - `Timestamp` from `LastSubmissionAt`
   - `EntityIDs` from all submissions
   - `SignerTimestamps` from all submissions (for audit: every entity's original submission time)
   - For BLS: `SigAlgorithm = "bls"`, `AggregateSignature = RunningBLSAggregate`
   - For Ed25519: `SigAlgorithm = "ed25519"`, `Signatures` array
7. Marshal, unlock
8. Call `addLeafToPool()` and `waitLeaf()`
9. Re-lock, store actual `LeafIndex`, unlock

**Returns:** `(leafIndex int64, err error)`

### Function 5: `checkAllSignersPresent()`

**Location:** `internal/ctlog/http.go`

**Purpose:** Check if every expected entity has submitted

**Parameters:**
- `contentHash [32]byte`

**Logic:**
1. Lock staging map
2. Compare `len(Submissions)` with `len(ExpectedEntityIDs)`
3. Unlock

**Returns:** `(allPresent bool, err error)`

### Function 6: `appendToPublishedEntry()`

**Location:** `internal/ctlog/http.go`

**Purpose:** Handle late arrivals after grace period has ended

**Parameters:**
- `contentHash [32]byte`
- `signedEntry SignedEntry`
- `entityID string`
- `ctx context.Context`

**Logic:**
1. Validate that staging entry exists and `IsPublished == true`
2. Validate that grace period has ended (`now > GracePeriodEndAt`)
3. Verify signature using `verifySingleWBBEntry`
4. Add submission to staging submissions map
5. **For BLS late arrivals**: aggregate the new BLS signature into `RunningBLSAggregate`
6. Update `LastSubmissionAt`
7. Append new `{entity_id, timestamp}` to `SignerTimestamps` in staging
8. **Create new log entry** with reference format:
   ```go
   refEntry := SignedEntry{
       Data:      []byte(fmt.Sprintf("ref:%d", staged.LeafIndex)),
       Timestamp: signedEntry.Timestamp,
       EntityID:  entityID,
       Signature: signedEntry.Signature,        // Ed25519 late arrival
       // or: BLSSignature: signedEntry.BLSSignature,  // BLS late arrival
       SigAlgorithm: staged.SigAlgorithm,
   }
   ```
9. Marshal and submit to log via `addLeafToPool`
10. Update `staged.LeafIndex` to point to new entry
11. Return new leaf index

**Returns:** `(leafIndex int64, totalSigners int, err error)`

### Function 7: `computeContentHash()`

**Location:** `internal/ctlog/http.go`

**Purpose:** Generate unique hash for WBB content

**Parameters:**
- `wbbData string` - Full WBB entry string

**Logic:**
- `SHA256(wbbData)`

**Returns:** `[32]byte`

## New Flow for `submitEntry()`

```
1. Parse JSON -> SignedEntry
2. Validate basic fields (data, timestamp)
3. Check timestamp validity (±5min)
4. Parse WBB entry
5. Validate WBB format
6. Check policy (CheckWBBWritePolicy)
7. Compute contentHash = SHA256(signedEntry.Data)
8. Check if already published:
   - If yes AND grace period ended: call appendToPublishedEntry()
   - Return 200 OK with "appended" status
9. Check if in staging:
   - If yes: add submission to existing staging
   - If no: create new staging entry
10. Verify signature (single or BLS)
11. Call checkThreshold()
12. If threshold met and grace period NOT started:
    - Call startGracePeriod()
    - Call checkAllSignersPresent()
    - If all signers present: call finalizeEntry() (early publish)
    - Return 202 Accepted with "grace_period" status
13. If threshold met and grace period IS active:
    - Call checkAllSignersPresent()
    - If all signers present: call finalizeEntry() (early publish)
    - Return 202 Accepted with "grace_period" status
14. If grace period expired:
    - Call finalizeEntry()
    - Return 200 OK with "published" status
15. If threshold not met:
    - Return 202 Accepted with "pending" status
```

### Response Formats:

**202 Accepted (Pending — threshold not yet met):**
```json
{
  "status": "pending",
  "content_hash": "abc123...",
  "current_signers": 2,
  "required_signers": 3,
  "signers": ["TT-1", "TT-2"],
  "message": "need 1 more signature"
}
```

**202 Accepted (Grace Period — threshold met, waiting):**
```json
{
  "status": "grace_period",
  "content_hash": "abc123...",
  "grace_period_ends_at": 1715927050000,
  "current_signers": 3,
  "required_signers": 3,
  "signers": ["TT-1", "TT-2", "TT-3"],
  "message": "threshold met, grace period active"
}
```

**200 OK (Published):**
```json
{
  "status": "published",
  "leaf_index": 42,
  "timestamp": 1715927045000,
  "data_hash": "base64hash",
  "signers": ["TT-1", "TT-2", "TT-3"],
  "algorithm": "ed25519",
  "signatures": [[...], [...], [...]],
  "signer_timestamps": [
    {"entity_id": "TT-1", "timestamp": 1715927041000},
    {"entity_id": "TT-2", "timestamp": 1715927043000},
    {"entity_id": "TT-3", "timestamp": 1715927045000}
  ]
}
```

**200 OK (Appended — late arrival after grace period):**
```json
{
  "status": "appended",
  "content_hash": "abc123...",
  "leaf_index": 43,
  "referenced_leaf": 42,
  "total_signers": 4,
  "signers": ["TT-1", "TT-2", "TT-3", "TT-4"],
  "message": "late signature recorded as new leaf"
}
```

## Late Submission Reference Format

Late arrivals (after the grace period has ended) **must** be stored as new leaves in the Merkle tree.

### Reference Entry Structure

The late submission leaf uses the standard `SignedEntry` structure, but the `Data` field contains a reference instead of the original WBB data:

```json
{
  "data": "ref:42",
  "timestamp": 1715927060000,
  "entity_id": "TT-4",
  "signature": "...",
  "sig_algorithm": "ed25519"
}
```

Where:
- `data`: `"ref:<leaf_index>"` — a clear reference to the original published entry
- `timestamp`: The timestamp of this late submission
- `entity_id`: The entity submitting the late signature
- `signature`: The entity's signature over `data || entity_id || timestamp`
- `sig_algorithm`: The signature algorithm used

### Verification of Reference Entry

```go
refEntry := SignedEntry{
    Data:      []byte("ref:42"),
    EntityID:  "TT-4",
    Timestamp: 1715927060000,
    Signature: sig,
}

// Verify using same logic as regular entries
ok := refEntry.Verify(pubKey)
```

## Updated SignedEntry Storage Format

When stored in the log (after threshold met), `SignedEntry` should be:

```go
type SignerTimestamp struct {
    EntityID  string `json:"entity_id"`
    Timestamp int64  `json:"timestamp"`  // Per-entity submission timestamp
}

type SignedEntry struct {
    Data               []byte   `json:"data"`                          // WBB entry or "ref:N"
    Timestamp          int64    `json:"timestamp"`                     // Last submission time (for validation)
    SigAlgorithm       string   `json:"sig_algorithm,omitempty"`      // "ed25519" or "bls"

    // For single-sig (threshold=1)
    EntityID           string   `json:"entity_id,omitempty"`
    Signature          []byte   `json:"signature,omitempty"`

    // For multi-sig Ed25519
    EntityIDs          []string `json:"entity_ids,omitempty"`
    Signatures         [][]byte `json:"signatures,omitempty"`

    // For multi-sig BLS
    AggregateSignature []byte   `json:"aggregate_signature,omitempty"`

    // NEW: For BLS partial signatures during staging
    BLSSignature       []byte   `json:"bls_signature,omitempty"`

    // NEW: Audit trail — all individual submission timestamps are preserved
    SignerTimestamps   []SignerTimestamp `json:"signer_timestamps,omitempty"`
}
```

## Implementation Order

### Phase 1: Data Structures
1. Add `StagingEntry` and `StagingSubmission` types to `ctlog.go`
2. Add `staging` map and `stagingMu` to `Log` struct
3. Initialize staging in `LoadLog`
4. Add `BLSSignature` field to `SignedEntry`

### Phase 2: Core Staging Functions
1. Implement `computeContentHash()`
2. Implement `stageSubmission()` with algorithm detection
3. Implement `checkThreshold()`
4. Test basic staging without threshold detection

### Phase 3: Grace Period
1. Implement `startGracePeriod()`
2. Implement `checkAllSignersPresent()`
3. Update `submitEntry()` flow to handle grace period states
4. Add "grace_period" response format
5. Test grace period behavior (timer, early publication)

### Phase 4: Finalization
1. Implement `finalizeEntry()` with atomic state transition
2. Implement `appendToPublishedEntry()` with reference format
3. Test threshold detection, finalization, and late arrivals

### Phase 5: Algorithm Support
1. Ensure Ed25519 staging works (multiple signatures stored)
2. Ensure BLS staging works (aggregate maintained, `RunningBLSAggregate` populated)
3. Test both paths thoroughly
4. Test late arrivals for both Ed25519 and BLS

## Testing Commands

```bash
# Run all staging tests
go test ./internal/ctlog/... -v -run TestStagingMechanism

# Run specific test groups
go test ./internal/ctlog/... -v -run TestStagingMechanism/Basic_Staging
go test ./internal/ctlog/... -v -run TestStagingMechanism/Threshold_Detection
go test ./internal/ctlog/... -v -run TestStagingMechanism/Late_Arrivals_After_Threshold
go test ./internal/ctlog/... -v -run TestStagingMechanism/Conflict_Resolution
go test ./internal/ctlog/... -v -run TestStagingMechanism/Duplicate_Signer_Prevention
go test ./internal/ctlog/... -v -run TestStagingMechanism/Ed25519_Staging
go test ./internal/ctlog/... -v -run TestStagingMechanism/BLS_Staging
go test ./internal/ctlog/... -v -run TestStagingMechanism/BLS_Algorithm_Detection
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Timestamp_-_Uses_LastSubmissionAt"
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Grace_Period_-_Collects_Late_Submissions"
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Grace_Period_-_Early_Publication"
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Grace_Period_-_Timer_Expiration"
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Late_Arrival_-_Creates_New_Leaf"
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Late_Arrival_-_BLS_Aggregate"
go test ./internal/ctlog/... -v -run "TestStagingMechanism/HTTP_Status_-_Duplicate_Signer"
go test ./internal/ctlog/... -v -run "TestStagingMechanism/HTTP_Status_-_Already_Published"
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Race_Condition_-_Concurrent_Finalization"
go test ./internal/ctlog/... -v -run TestStagingMechanism/Staging_State_Persistence

# Run all WBB tests (old + new)
go test ./internal/ctlog/... -v -run "TestWBB|TestStaging"
```

## Files to Modify

1. `internal/ctlog/ctlog.go` — Add staging types, initialize staging, add `BLSSignature` to `SignedEntry`
2. `internal/ctlog/http.go` — Implement grace period logic, rewrite `submitEntry()`, add reference format for late arrivals
3. `internal/ctlog/staging_e2e_test.go` — Update tests to cover grace period and late arrival scenarios

---

# Issues

## ISSUE #1: Timestamp Bug — Uses FirstSubmissionAt

**File:** `internal/ctlog/http.go`

### Problem

`finalizeEntry()` uses `FirstSubmissionAt` as the log entry timestamp, but this timestamp may be >5 minutes old when the entry is published, causing it to fail validation.

```bash
$ grep -n "FirstSubmissionAt\|LastSubmissionAt" internal/ctlog/http.go
308:    if signedEntry.Timestamp < staged.FirstSubmissionAt {
309:        staged.FirstSubmissionAt = signedEntry.Timestamp
311:    if signedEntry.Timestamp > staged.LastSubmissionAt {
312:        staged.LastSubmissionAt = signedEntry.Timestamp
363:        Timestamp: staged.FirstSubmissionAt,  // bug
```

### Impact

Scenario:
- T+0: TT-1 submits (`FirstSubmissionAt = T+0`)
- T+6min: TT-2 submits (`LastSubmissionAt = T+6min`)
- T+10min: TT-3 submits, threshold met!
- `finalizeEntry` sets `Timestamp = T+0`
- When `IsTimestampValid()` runs: T+0 is >5 minutes old
- Entry is rejected even though threshold was met

### Fix

Change line 363 in `finalizeEntry()`:

Before:
```go
finalEntry := SignedEntry{
    Data:      []byte(staged.WBBData),
    Timestamp: staged.FirstSubmissionAt,  // bug
    EntityIDs: entityIDs,
}
```

After:
```go
finalEntry := SignedEntry{
    Data:      []byte(staged.WBBData),
    Timestamp: staged.LastSubmissionAt,   // fixed: use last for validation
    EntityIDs: entityIDs,
}
```

**Important:** While `Timestamp` is `LastSubmissionAt`, **all individual submission timestamps must still be preserved** in `SignerTimestamps` for auditability. Do not discard the per-entity timestamps when building the final entry.

### Tests to Verify This Fix

```bash
# Run the timestamp-specific test
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Timestamp_-_Uses_LastSubmissionAt"

# Verify all basic threshold tests still pass
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Threshold_Detection"
```

**What the test checks:**
- Three entities submit with small time gaps
- Published entry's `Timestamp` is the LAST submission time, not the first
- Verifies `LastSubmissionAt` is used for the log entry `Timestamp` field
- Verifies `signer_timestamps` is present in the response and contains all 3 individual timestamps

## ISSUE #2: BLS Staging Is Not Implemented

**File:** `internal/ctlog/http.go`

### Problem

The `RunningBLSAggregate` field exists in `StagingEntry` struct but is never populated. The code reads from it during finalization and response generation, but nothing ever writes to it.
The field is read in multiple places:
- Line 367: `if len(staged.RunningBLSAggregate) > 0 {` (in finalizeEntry)
- Line 569: `if len(staged.RunningBLSAggregate) > 0 {` (in makePublishedResponse)

But nowhere in the codebase is it assigned a value.

### Impact

BLS staging will never work:
1. Entity submits with BLS signature
2. Server stores submission but ignores `BLSSignature` field
3. `RunningBLSAggregate` remains empty
4. When threshold met, `len(staged.RunningBLSAggregate) > 0` is false
5. Server falls through to Ed25519 path
6. Tries to collect Ed25519 signatures that don't exist
7. Finalization fails or produces invalid entry

### Fix

See Part 2, Function 1 (`stageSubmission()`) for the correct BLS handling. In summary:

1. Detect BLS vs Ed25519 on first submission
2. Set `staged.SigAlgorithm`
3. **For BLS**: immediately aggregate into `RunningBLSAggregate` — individual signatures need not be stored per-submission
4. **For Ed25519**: store individual `Signature` in `StagingSubmission` (cannot aggregate)

### Tests to Verify This Fix

```bash
# Run the BLS staging test
go test ./internal/ctlog/... -v -run "TestStagingMechanism/BLS_Staging"

# Verify BLS entries publish with correct algorithm and aggregate signature
go test ./internal/ctlog/... -v -run "TestStagingMechanism/BLS_Staging"
```

**What the test checks:**
- Three TT entities submit BLS partial signatures for the same content
- Third submission triggers publication (threshold=3)
- Response has `status: "published"`, `algorithm: "bls"`, and `aggregate_signature` present
- Response does NOT have `signatures` array (BLS uses aggregate, not individual sigs)

## ISSUE #3: BLS Submissions Are Not Detected and Aggregate Is Never Maintained

**File:** `internal/ctlog/http.go`

### Problem

The staging code does not detect when a client submits a BLS signature, and therefore never maintains the running BLS aggregate. The `RunningBLSAggregate` field is never written to.

In `stageSubmission()`:
```go
staged.Submissions[signedEntry.EntityID] = &StagingSubmission{
    EntityID:  signedEntry.EntityID,
    Timestamp: signedEntry.Timestamp,
    Signature: signedEntry.Signature,  // Always stores Ed25519 path
    // BLS path is completely missing
}
// RunningBLSAggregate is never updated!
```

### Impact

1. BLS staging will never work — `RunningBLSAggregate` is always empty
2. When threshold is met, the code falls through to the Ed25519 path
3. Final entry tries to collect Ed25519 signatures that don't exist
4. BLS late arrivals cannot update the aggregate

### Fix

Add BLS detection and aggregate maintenance in `stageSubmission()`:

```go
// Detect algorithm on first submission
if isNew {
    if len(signedEntry.BLSSignature) > 0 {
        staged.SigAlgorithm = "bls"
    } else if len(signedEntry.Signature) > 0 {
        staged.SigAlgorithm = "ed25519"
    } else {
        return 0, false, fmtErrorf("no signature provided")
    }
}

// Verify consistency — cannot mix algorithms
if staged.SigAlgorithm == "bls" && len(signedEntry.BLSSignature) == 0 {
    return 0, false, fmtErrorf("staging entry uses BLS, expected bls_signature")
}
if staged.SigAlgorithm == "ed25519" && len(signedEntry.Signature) == 0 {
    return 0, false, fmtErrorf("staging entry uses Ed25519, expected signature")
}

// Store submission
staged.Submissions[signedEntry.EntityID] = &StagingSubmission{
    EntityID:  signedEntry.EntityID,
    Timestamp: signedEntry.Timestamp,
}

// For BLS: immediately aggregate — individual sigs need not be stored
if staged.SigAlgorithm == "bls" {
    if len(staged.RunningBLSAggregate) == 0 {
        staged.RunningBLSAggregate = signedEntry.BLSSignature
    } else {
        newAgg, err := my_crypto.AggregateSignaturesBytes(
            [][]byte{staged.RunningBLSAggregate, signedEntry.BLSSignature},
        )
        if err != nil {
            return 0, false, fmtErrorf("BLS aggregation failed: %w", err)
        }
        staged.RunningBLSAggregate = newAgg
    }
} else {
    // Ed25519: store individual signature (cannot aggregate)
    staged.Submissions[signedEntry.EntityID].Signature = signedEntry.Signature
}
```

Also add `BLSSignature []byte` field to `SignedEntry` struct.

### Tests to Verify This Fix

```bash
# Run the BLS staging test (same as Issue #1 — this is the implementation)
go test ./internal/ctlog/... -v -run "TestStagingMechanism/BLS_Staging"

# Run the BLS late-arrival test to verify aggregate is maintained
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Late_Arrival_-_BLS_Aggregate"
```

**What the test checks:**
- BLS partial signatures are detected and aggregated server-side
- Late BLS arrivals update the running aggregate correctly
- `RunningBLSAggregate` field is populated (verify with `grep -n "RunningBLSAggregate="`)

## ISSUE #4: Algorithm Detection and Handling

**File:** `internal/ctlog/http.go`

### Problem

The current code does not:
1. Detect which algorithm the client is using
2. Store BLS signatures in staging submissions
3. Maintain running BLS aggregate for staged entries
4. Correctly distinguish between Ed25519 and BLS during finalization

### Impact

- BLS submissions are not handled correctly in staging
- The system cannot aggregate BLS signatures server-side
- Ed25519 multi-sig works but BLS multi-sig does not

### Fix

See Part 2, Function 1 (`stageSubmission()`) for correct algorithm detection. Summary:

1. Detect algorithm on first submission (`Signature` vs `BLSSignature`)
2. Store `SigAlgorithm` on `StagingEntry`
3. Reject mixed-algorithm submissions for the same entry
4. Finalize using the correct path (Ed25519 array vs BLS aggregate)

### Tests to Verify This Fix

```bash
# Run the algorithm detection test (mixed algorithms should be rejected)
go test ./internal/ctlog/... -v -run "TestStagingMechanism/BLS_Algorithm_Detection"

# Verify Ed25519 staging still works
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Ed25519_Staging"

# Verify BLS staging works
go test ./internal/ctlog/... -v -run "TestStagingMechanism/BLS_Staging"
```

**What the test checks:**
- First BLS submission sets `SigAlgorithm = "bls"` on the staging entry
- Subsequent Ed25519 submission for the same content is rejected with 409 Conflict
- Ed25519 entries still work (verified by separate test)
- BLS entries still work (verified by separate test)

## ISSUE #5: Race Condition in finalizeEntry

**File:** `internal/ctlog/http.go`
**Priority:** Fix third (must be done before grace period and late arrivals)

### Problem

`finalizeEntry()` releases the staging mutex while calling `addLeafToPool()`, then re-acquires it. Between unlock and re-lock, another goroutine can modify the staging entry.

```go
func (l *Log) finalizeEntry(contentHash [32]byte, ctx context.Context) (leafIndex int64, err error) {
    l.stagingMu.Lock()
    // ... check if published, check threshold ...
    l.stagingMu.Unlock()  // <-- lock released

    // Race window: other goroutines can modify staging here!
    waitLeaf, _ := l.addLeafToPool(ctx, e)
    seq, err := waitLeaf(ctx)

    l.stagingMu.Lock()    // <-- lock re-acquired
    // ... mark as published ...
}
```

### Impact

Two concurrent requests for the same content:
1. Request A: passes `!IsPublished` check, releases lock, waits for sequencing
2. Request B: passes `!IsPublished` check (still false!), also starts sequencing
3. Result: Same content published TWICE with two different leaf indices

### Fix

Atomic state transition

```go
func (l *Log) finalizeEntry(contentHash [32]byte, ctx context.Context) (leafIndex int64, err error) {
    l.stagingMu.Lock()

    staged, ok := l.staging[contentHash]
    if !ok {
        l.stagingMu.Unlock()
        return 0, fmtErrorf("staging entry not found")
    }

    if staged.IsPublished {
        l.stagingMu.Unlock()
        return staged.LeafIndex, nil
    }

    // Atomically mark as "publishing" to block other finalize attempts
    staged.IsPublished = true
    staged.LeafIndex = -1  // Sentinel value: "publishing in progress"

    // Copy needed data while holding lock
    entryBytes := make([]byte, len(finalEntryBytes))
    copy(entryBytes, finalEntryBytes)

    l.stagingMu.Unlock()

    // Now safe to sequence without lock
    waitLeaf, _ := l.addLeafToPool(ctx, e)
    seq, err := waitLeaf(ctx)

    // Update with actual leaf index
    l.stagingMu.Lock()
    if staged, ok := l.staging[contentHash]; ok {
        staged.LeafIndex = seq.LeafIndex
    }
    l.stagingMu.Unlock()

    return seq.LeafIndex, nil
}
```

### Tests to Verify This Fix

```bash
# Run the race condition test
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Race_Condition_-_Concurrent_Finalization"

# Run with race detector (slower but catches data races)
go test ./internal/ctlog/... -race -v -run "TestStagingMechanism/Race_Condition"
```

**What the test checks:**
- 5 goroutines simultaneously submit the threshold-triggering signature
- Exactly 1 goroutine gets 200 OK (published)
- 4 goroutines get 409 Conflict (duplicate / already published)
- No duplicate leaf indices are created

**How to interpret failures:**
- If >1 goroutine gets 200 OK: race condition still exists (same content published twice)
- If all get 200 OK: `IsPublished` check is not atomic
- If any get 500: locking logic is incorrect

## ISSUE #6: Missing Grace Period Implementation

**File:** `internal/ctlog/http.go`
**Priority:** Fix fourth (adds new state machine)

### Problem

The current implementation publishes entries immediately when the threshold is met. In our new implementation a grace period should be added. I discussed with Longo and this solution should fix most of the *late arrivals*.

### Fix

Implement the full grace period state machine (see Part 2, "New Flow for submitEntry()"):

1. Add `GracePeriodEndAt` and `IsGracePeriodStarted` fields to `StagingEntry`
2. Implement `startGracePeriod()` function
3. Implement `checkAllSignersPresent()` function
4. Update `submitEntry()` to:
   - Start grace period when threshold is first met
   - Return `202 "grace_period"` while grace period is active
   - Call `finalizeEntry()` when grace period expires OR all signers present
5. Use a background timer or the next incoming submission to trigger finalization after grace period ends

Recommended approach: Use `time.AfterFunc()` or a dedicated goroutine per staging entry to trigger finalization at `GracePeriodEndAt`.

### Tests to Verify This Fix

```bash
# Test grace period collects late submissions (slow: ~12 seconds)
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Grace_Period_-_Collects_Late_Submissions"

# Test early publication when all signers are present
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Grace_Period_-_Early_Publication"

# Test timer expiration publishes after 10s (slow: ~12 seconds)
go test ./internal/ctlog/... -v -run "TestStagingPeriod_-_Timer_Expiration"
```

**What each test checks:**

**Collects Late Submissions:**
- TT-1, TT-2 submit -> pending
- TT-3 submits -> threshold met, grace period starts → 202 "grace_period"
- TT-4 submits during grace period -> still 202 "grace_period" (included in staging)
- After 10s, entry is published with all 4 signers

**Early Publication:**
- RT role has 3 expected entities, threshold=2
- RT-1, RT-2 submit -> threshold met, grace period starts
- RT-3 submits (all expected signers present) -> published immediately (before timer expires)
- Verifies early publication bypasses grace period wait

**Timer Expiration:**
- TT-1, TT-2, TT-3 submit -> threshold met, grace period starts
- No more submissions
- After 10s, entry is published automatically
- Duplicate submission after grace period -> 409 Conflict (already published)

**Note:** Grace period tests are slow (require real-time sleeps). Run individually during development.

## ISSUE #7: Late Arrivals Don't Create New Log Entries

**File:** `internal/ctlog/http.go`
**Function:** `appendToPublishedEntry()`
**Priority:** Fix fifth (depends on grace period)

### Problem

When a late arrival comes in (after the entry is published), the current code only stores it in the in-memory staging map and returns the existing leaf index. The Merkle tree never sees the new signature.

### The Core Issue: Append-Only Logs Are Immutable

In a Merkle tree / append-only log:
- Once leaf N is published, it **cannot be modified**
- You cannot "append" a signature to an existing leaf
- The hash of leaf N is part of the tree forever

**Current (broken) behavior:**
```
Leaf 42: signers=[RT-1, RT-2]       <- Published at threshold
Staging: signers=[RT-1, RT-2, RT-3]  <- Late arrival in memory only
Staging: signers=[RT-1, RT-2, RT-3, RT-4]  <- Another late arrival in memory only
```

The Merkle tree only has 2 signers, but staging claims 4. The log is inconsistent.

### Solution: Create New Log Entries for Late Arrivals

**Every late arrival creates a new log entry** with a reference to the original:

```
Leaf 42: data="setup,RT,acc_pub_key,2,pk" signers=[RT-1, RT-2]  <- First publication
Leaf 43: data="ref:42" entity_id=RT-3 signature=...              <- NEW entry: late arrival
Leaf 44: data="ref:42" entity_id=RT-4 signature=...              <- NEW entry: another late arrival
```

### Implementation

Modify `appendToPublishedEntry()` to:

1. Add late arrival to staging submissions (existing behavior)
2. **Build a new `SignedEntry` with reference format:**
   ```go
   refEntry := SignedEntry{
       Data:      []byte(fmt.Sprintf("ref:%d", staged.LeafIndex)),
       Timestamp: signedEntry.Timestamp,
       EntityID:  entityID,
       Signature: signedEntry.Signature,
       SigAlgorithm: staged.SigAlgorithm,
   }
   ```
3. Marshal and submit to log as new entry (use `addLeafToPool`)
4. Update `staged.LeafIndex` to point to new entry
5. Return the new leaf index

### Important Note

The staging area tracks the latst version, but the Merkle tree contains all versions. This means:
- `staged.LeafIndex` always points to the most recent log entry
- A client reading only that leaf gets the reference, which points back to the original
- The full history is in the log for audit purposes

### Tests to Verify This Fix

```bash
# Test late arrival creates new leaf with ref:N format (slow: ~12 seconds)
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Late_Arrival_-_Creates_New_Leaf"

# Test BLS late arrival updates aggregate and creates new leaf (slow: ~12 seconds)
go test ./internal/ctlog/... -v -run "TestStagingMechanism/Late_Arrival_-_BLS_Aggregate"
```

**What each test checks:**

**Creates New Leaf:**
- RT-1, RT-2 submit and publish (threshold=2)
- Wait for grace period to expire
- RT-3 submits late -> 200 OK with `status: "appended"`
- Response contains `referenced_leaf` (original leaf index) and `leaf_index` (new leaf)
- New leaf index > referenced leaf index

**BLS Aggregate:**
- TT-1, TT-2, TT-3 submit BLS partial signatures and publish
- Wait for grace period to expire
- TT-4 submits BLS late -> 200 OK with `status: "appended"`
- Verifies BLS aggregate is updated in staging
- New leaf is created with BLS reference format

## ISSUE #8: Wrong HTTP Status Codes

**File:** `internal/ctlog/http.go`
**Priority:** Fix sixth (polish, can be done anytime)

### Problem

Several error conditions return incorrect HTTP status codes:
- Duplicate signer: current = 403 Forbidden, correct = 409 Conflict
- Entry already published: current = 403 Forbidden, correct = 409 Conflict
- Staging entry not found: current = 403 Forbidden, correct = 404 Not Found

```go
// Line 723: duplicate signer returns 403
_, _, err := l.stageSubmission(contentHash, signedEntry, wbbEntry)
if err != nil {
    return nil, http.StatusForbidden, err  // Should be 409
}
```

### Fix

Add error type detection in `submitEntry()`:

```go
_, _, err := l.stageSubmission(contentHash, signedEntry, wbbEntry)
if err != nil {
    if strings.Contains(err.Error(), "duplicate signer") {
        return nil, http.StatusConflict, err  // 409
    }
    if strings.Contains(err.Error(), "already published") {
        return nil, http.StatusConflict, err  // 409
    }
    return nil, http.StatusForbidden, err
}
```

### Tests to Verify This Fix

```bash
# Test duplicate signer returns 409 Conflict
go test ./internal/ctlog/... -v -run "TestStagingMechanism/HTTP_Status_-_Duplicate_Signer"

# Test already-published entry returns 409 Conflict
go test ./internal/ctlog/... -v -run "TestStagingMechanism/HTTP_Status_-_Already_Published"
```

**What each test checks:**

**Duplicate Signer:**
- TT-1 submits first time -> 202 Accepted
- TT-1 submits again (same content) -> 409 Conflict (not 403 Forbidden)

**Already Published:**
- RT-1, RT-2 submit and publish (threshold=2)
- Wait for grace period to expire
- RT-1 submits again -> 409 Conflict (already published, not 403 Forbidden)

## ISSUE #9: Staging Cleanup Between Phases

**File:** `internal/ctlog/ctlog.go` and `internal/ctlog/http.go`
**Priority:** Fix seventh (optional: cleanup between phases)

### Problem

Published staging entries are never removed from the `staging` map. Over time, memory grows.

### Scope Note

This is out of scope for the core staging implementation. The system will work without cleanup. However, this is not best practice.

### Minimal Fix (Cleanup Between Phases)

When the system transitions from one phase to the next (e.g., setup -> voting), clean up published entries from the previous phase:

```go
func (l *Log) cleanupPublishedStagingForPhase(phase Phase) {
    l.stagingMu.Lock()
    defer l.stagingMu.Unlock()

    for hash, staged := range l.staging {
        if staged.IsPublished && staged.Phase == phase {
            delete(l.staging, hash)
        }
    }
}
```

Call after phase transition, before starting the new phase.

### Tests to Verify This Fix

There is no automated test for this issue in the current test suite. Verify manually:

```bash
# Run a full test suite that exercises multiple phases
go test ./internal/ctlog/... -v -run TestStagingMechanism

# Check memory usage before and after phase transitions
# (Requires adding instrumentation or profiling)
```

**Manual verification:**
1. Submit entries in Setup phase
2. Verify they are published
3. Transition to Voting phase
4. Call `cleanupPublishedStagingForPhase(PhaseSetup)`
5. Verify the `staging` map no longer contains Setup-phase entries

## Running All Tests

After all fixes are applied, run the complete test suite:

```bash
# Run all staging tests
go test ./internal/ctlog/... -v -run TestStagingMechanism

# Run with race detector (slower but thorough)
go test ./internal/ctlog/... -race -v -run TestStagingMechanism

# Run all WBB tests
go test ./internal/ctlog/... -v

# Full verification
go test ./internal/ctlog/... -race -v
```
