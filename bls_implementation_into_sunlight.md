# BLS Witness Signatures Implementation Guide

## Goal

Replace Ed25519 witness signatures with BLS signatures in Sunlight, using a pinned list of witness public keys. This enables O(1) verification via signature aggregation.

## Core Changes Summary

**Before**: Each witness signs with Ed25519, all signatures stored separately (64 bytes × N)
**After**: Each witness signs with BLS, log aggregates into single signature (96 bytes total)

## Implementation Roadmap

---

## Phase 1: Extend BLS Library for Sunlight Integration

**File**: `internal/my_crypto/bls.go`

### 1.1 Add note.Verifier Implementation

The existing `BLSSigner` already has `Sign()`, `Name()`, `KeyHash()`. Add `Verifier()` method and create `BLSVerifier`:

```go
// Verifier returns a note.Verifier for this signer.
func (s *BLSSigner) Verifier() note.Verifier {
	return &BLSVerifier{
		name:    s.name,
		keyHash: s.keyHash,
		pk:      s.pk,
	}
}

// SecretKey returns the secret key.
func (s *BLSSigner) SecretKey() *blst.SecretKey {
	return s.sk
}

// BLSVerifier implements note.Verifier for BLS signatures.
type BLSVerifier struct {
	name    string
	keyHash uint32
	pk      *blst.P1Affine
}

func (v *BLSVerifier) Name() string    { return v.name }
func (v *BLSVerifier) KeyHash() uint32 { return v.keyHash }

func (v *BLSVerifier) Verify(msg, sig []byte) bool {
	if v == nil || v.pk == nil {
		return false
	}
	signature, err := SignatureFromBytes(sig)
	if err != nil {
		return false
	}
	return Verify(v.pk, msg, signature)
}
```

### 1.2 Add Key Derivation from Seed

Witnesses need deterministic key generation from saved seeds:

```go
// GenerateKeyFromSeed deriva una chiave BLS da un seed di 32 byte.
func GenerateKeyFromSeed(seed []byte) (*blst.SecretKey, *blst.P1Affine, error) {
	if len(seed) != 32 {
		return nil, nil, fmt.Errorf("seed deve essere 32 byte, ricevuti %d", len(seed))
	}

	sk := blst.KeyGen(seed)
	if sk == nil {
		return nil, nil, errors.New("KeyGen ha restituito nil")
	}

	pk := new(blst.P1Affine).From(sk)
	if pk == nil {
		return nil, nil, errors.New("impossibile derivare la public key")
	}

	return sk, pk, nil
}
```

### 1.3 Add Batch Aggregation

More efficient than iterative `Aggregate()`:

```go
// AggregateBatch aggregates multiple signatures at once.
// Returns: σ_agg = σ₁ ⋅ σ₂ ⋅ ... ⋅ σₙ in G₂
func AggregateBatch(sigs []*blst.P2Affine) (*blst.P2Affine, error) {
	if len(sigs) == 0 {
		return nil, errors.New("no signatures to aggregate")
	}
	if len(sigs) == 1 {
		return sigs[0], nil
	}

	agg := new(blst.P2Aggregate)
	for _, sig := range sigs {
		if !agg.Add(sig, false) {
			return nil, errors.New("failed to add signature to aggregate")
		}
	}

	return agg.ToAffine(), nil
}
```

---

## Phase 2: Configuration

**File**: `cmd/sunlight/sunlight.go`

### 2.1 Add Witness Configuration to LogConfig

```go
type LogConfig struct {
	// ... existing fields ...
	
	// Witnesses is a pinned list of authorized witnesses.
	// Only these witnesses can sign checkpoints.
	Witnesses []WitnessEntry `yaml:"witnesses"`
	
	// WitnessPolicy controls aggregation timing.
	WitnessPolicy WitnessPolicy `yaml:"witness_policy"`
}

type WitnessEntry struct {
	ID     string `yaml:"id"`     // Unique identifier (e.g., "witness-1")
	PubKey string `yaml:"pubkey"` // Base64-encoded 48-byte BLS pubkey
}

type WitnessPolicy struct {
	MinimumCount        int `yaml:"minimum_count"`         // Min signatures before aggregation (0 = all)
	TimeoutSeconds      int `yaml:"timeout_seconds"`       // Max wait time
	PushIntervalSeconds int `yaml:"push_interval_seconds"` // How often witnesses check
}
```

### 2.2 Parse and Validate Configuration

In the config parsing loop:

```go
// Parse witness configurations
witnessPubkeys := make(map[string]*blst.P1Affine)
for i, w := range lc.Witnesses {
	if w.ID == "" {
		fatalError(logger, "witness missing ID", "index", i)
	}
	
	// Check duplicates
	if _, exists := witnessPubkeys[w.ID]; exists {
		fatalError(logger, "duplicate witness ID", "id", w.ID)
	}
	
	// Decode pubkey
	pkBytes, err := base64.StdEncoding.DecodeString(w.PubKey)
	if err != nil {
		fatalError(logger, "invalid witness pubkey base64", "id", w.ID, "err", err)
	}
	
	if len(pkBytes) != 48 {
		fatalError(logger, "witness pubkey must be 48 bytes", "id", w.ID, "got", len(pkBytes))
	}
	
	pk, err := mycrypto.PublicKeyFromBytes(pkBytes)
	if err != nil {
		fatalError(logger, "invalid BLS public key", "id", w.ID, "err", err)
	}
	
	witnessPubkeys[w.ID] = pk
}
```

### 2.3 Pass to ctlog.Config

```go
cc := &ctlog.Config{
	// ... existing ...
	Witnesses:     witnessPubkeys,  // map[string]*blst.P1Affine
	WitnessPolicy: lc.WitnessPolicy,
}
```

**File**: `internal/ctlog/ctlog.go` - Add to Config struct:

```go
type Config struct {
	// ... existing ...
	Witnesses     map[string]*blst.P1Affine
	WitnessPolicy WitnessPolicy
}
```

---

## Phase 3: Pending Signature Pool

**File**: `internal/ctlog/witness_pool.go` (create new)

The log needs to collect individual BLS signatures before aggregating them.

### 3.1 Add Witness State to Log Struct

**File**: `internal/ctlog/ctlog.go`:

```go
type Log struct {
	// ... existing fields ...
	
	// Witness configuration (pinned pubkeys from config)
	witnessPubkeys map[string]*blst.P1Affine
	
	// Pending signatures for current checkpoint
	pendingMu         sync.RWMutex
	pendingSigs       map[string]*blst.P2Affine // witness ID -> signature
	pendingCheckpoint []byte                    // Checkpoint being witnessed
	pendingStartTime  time.Time
	
	// Aggregated state
	aggregatedCheckpoint []byte
	aggregatedWitnesses  []string
}
```

Initialize in `LoadLog()`:

```go
l := &Log{
	// ... existing ...
	witnessPubkeys:    config.Witnesses,
	pendingSigs:       make(map[string]*blst.P2Affine),
	pendingStartTime:  time.Now(),
}

// Load any existing checkpoint
if len(sth) > 0 {
	l.pendingCheckpoint = sth
	// Extract existing signatures if present
	l.extractExistingSignatures(sth)
}
```

### 3.2 Implement Pool Operations

**File**: `internal/ctlog/witness_pool.go`:

```go
package ctlog

import (
	"errors"
	"fmt"
	"sort"
	"time"
	
	"filippo.io/sunlight/internal/my_crypto"
	"github.com/supranational/blst"
)

// AddPendingSignature validates and stores a witness signature.
func (l *Log) AddPendingSignature(witnessID string, sigBytes []byte) error {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	
	// Verify witness is authorized
	pk, ok := l.witnessPubkeys[witnessID]
	if !ok {
		return fmt.Errorf("unauthorized witness: %s", witnessID)
	}
	
	// Check not already signed
	if _, exists := l.pendingSigs[witnessID]; exists {
		return fmt.Errorf("witness %s already signed", witnessID)
	}
	
	// Deserialize
	sig, err := mycrypto.SignatureFromBytes(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	
	// Verify signature
	msg := extractCheckpointMessage(l.pendingCheckpoint)
	if !mycrypto.Verify(pk, msg, sig) {
		return fmt.Errorf("signature verification failed")
	}
	
	l.pendingSigs[witnessID] = sig
	l.m.WitnessPendingCount.Set(float64(len(l.pendingSigs)))
	
	l.c.Log.Info("added witness signature",
		"witness", witnessID,
		"pending", len(l.pendingSigs),
		"total", len(l.witnessPubkeys))
	
	return nil
}

// ShouldAggregate checks if aggregation conditions are met.
func (l *Log) ShouldAggregate() bool {
	l.pendingMu.RLock()
	defer l.pendingMu.RUnlock()
	
	if len(l.pendingSigs) == 0 {
		return false
	}
	
	// All witnesses signed
	if len(l.pendingSigs) == len(l.witnessPubkeys) {
		return true
	}
	
	// Minimum count
	min := l.c.WitnessPolicy.MinimumCount
	if min > 0 && len(l.pendingSigs) >= min {
		return true
	}
	
	// Timeout
	timeout := time.Duration(l.c.WitnessPolicy.TimeoutSeconds) * time.Second
	if timeout > 0 && time.Since(l.pendingStartTime) >= timeout {
		return true
	}
	
	return false
}

func (l *Log) GetPendingWitnesses() []string {
	l.pendingMu.RLock()
	defer l.pendingMu.RUnlock()
	
	ids := make([]string, 0, len(l.pendingSigs))
	for id := range l.pendingSigs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (l *Log) ResetPending(checkpoint []byte) {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	
	l.pendingSigs = make(map[string]*blst.P2Affine)
	l.pendingCheckpoint = checkpoint
	l.pendingStartTime = time.Now()
	l.aggregatedCheckpoint = nil
	l.aggregatedWitnesses = nil
	l.m.WitnessPendingCount.Set(0)
}

// extractCheckpointMessage extracts the text portion before signatures.
func extractCheckpointMessage(checkpoint []byte) []byte {
	lines := bytes.Split(checkpoint, []byte("\n"))
	var text [][]byte
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("— ")) {
			break
		}
		text = append(text, line)
	}
	return bytes.Join(text, []byte("\n"))
}
```

---

## Phase 4: Aggregation Logic

**File**: `internal/ctlog/witness_pool.go` (continue)

### 4.1 Aggregate Signatures

```go
// AggregateSignatures combines pending signatures into single BLS aggregate.
func (l *Log) AggregateSignatures() ([]byte, []string, error) {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	
	if len(l.pendingSigs) == 0 {
		return nil, nil, errors.New("no signatures to aggregate")
	}
	
	// Get sorted witness IDs for deterministic ordering
	ids := make([]string, 0, len(l.pendingSigs))
	for id := range l.pendingSigs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	
	// Collect signatures in order
	var sigs []*blst.P2Affine
	for _, id := range ids {
		sigs = append(sigs, l.pendingSigs[id])
	}
	
	// Aggregate
	timer := prometheus.NewTimer(l.m.WitnessAggregationDur)
	agg, err := mycrypto.AggregateBatch(sigs)
	timer.ObserveDuration()
	
	if err != nil {
		return nil, nil, fmt.Errorf("aggregation failed: %w", err)
	}
	
	return mycrypto.SignatureToBytes(agg), ids, nil
}
```

### 4.2 Create Aggregated Checkpoint Format

The aggregated format replaces individual signatures with single aggregate:

```go
// CreateAggregatedCheckpoint creates final checkpoint format.
func (l *Log) CreateAggregatedCheckpoint(aggSig []byte, witnessIDs []string) ([]byte, error) {
	l.pendingMu.RLock()
	pendingCheckpoint := l.pendingCheckpoint
	l.pendingMu.RUnlock()
	
	// Parse existing checkpoint
	n, err := note.Open(pendingCheckpoint, nil)
	if err != nil {
		return nil, err
	}
	
	// Remove individual witness signatures, keep log signature
	var filtered []note.Signature
	for _, sig := range n.Sigs {
		// Keep non-witness signatures
		if !strings.HasPrefix(sig.Name, "witness-") ||
		   sig.Name == "witness-aggregate" ||
		   sig.Name == "witness-list" {
			filtered = append(filtered, sig)
		}
	}
	n.Sigs = filtered
	
	// Add aggregate signature
	n.Sigs = append(n.Sigs, note.Signature{
		Name:   "witness-aggregate",
		Hash:   0,
		Base64: base64.StdEncoding.EncodeToString(aggSig),
	})
	
	// Add witness list (just IDs)
	listJSON, _ := json.Marshal(witnessIDs)
	n.Sigs = append(n.Sigs, note.Signature{
		Name:   "witness-list",
		Hash:   0,
		Base64: base64.StdEncoding.EncodeToString(listJSON),
	})
	
	// Serialize
	return serializeNote(n), nil
}

// serializeNote manually serializes a note.
func serializeNote(n *note.Note) []byte {
	var b bytes.Buffer
	b.WriteString(n.Text)
	b.WriteByte('\n')
	for _, sig := range n.Sigs {
		fmt.Fprintf(&b, "— %s %d\n%s\n", sig.Name, sig.Hash, sig.Base64)
	}
	return b.Bytes()
}
```

### 4.3 Aggregation Trigger and Verification

**File**: `internal/ctlog/ctlog.go`:

```go
// RunAggregationWatcher starts background aggregation monitoring.
func (l *Log) RunAggregationWatcher(ctx context.Context) {
	if len(l.witnessPubkeys) == 0 {
		return
	}
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if l.ShouldAggregate() {
				if err := l.performAggregation(ctx); err != nil {
					l.c.Log.Error("aggregation failed", "err", err)
					l.m.WitnessAggregationFailed.Inc()
				}
			}
		}
	}
}

func (l *Log) performAggregation(ctx context.Context) error {
	// Aggregate
	aggSig, witnessIDs, err := l.AggregateSignatures()
	if err != nil {
		return err
	}
	
	// Create checkpoint
	aggregated, err := l.CreateAggregatedCheckpoint(aggSig, witnessIDs)
	if err != nil {
		return err
	}
	
	// Verify before storing
	if err := l.verifyAggregate(aggregated, aggSig, witnessIDs); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	
	// Store
	if err := l.c.Backend.Upload(ctx, "checkpoint", aggregated, optsCheckpoint); err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	
	// Update state
	l.pendingMu.Lock()
	l.aggregatedCheckpoint = aggregated
	l.aggregatedWitnesses = witnessIDs
	l.pendingMu.Unlock()
	
	l.m.WitnessAggregatedCount.Set(float64(len(witnessIDs)))
	l.m.CheckpointFormat.Set(1)
	
	l.c.Log.Info("aggregation complete", "witnesses", len(witnessIDs))
	return nil
}

func (l *Log) verifyAggregate(checkpoint, aggSig []byte, witnessIDs []string) error {
	// Collect pubkeys
	var pks []*blst.P1Affine
	for _, id := range witnessIDs {
		pk, ok := l.witnessPubkeys[id]
		if !ok {
			return fmt.Errorf("unknown witness: %s", id)
		}
		pks = append(pks, pk)
	}
	
	// Deserialize
	sig, err := mycrypto.SignatureFromBytes(aggSig)
	if err != nil {
		return err
	}
	
	// Verify
	msg := extractCheckpointMessage(checkpoint)
	if !mycrypto.FastAggregateVerify(pks, msg, sig) {
		return errors.New("FastAggregateVerify failed")
	}
	
	return nil
}
```

---

## Phase 5: HTTP API

**File**: `internal/ctlog/http.go`

### 5.1 Add Endpoints

```go
// GET /ct/v1/checkpoint-for-signing
func (l *Log) getCheckpointForSigning(rw http.ResponseWriter, r *http.Request) {
	l.pendingMu.RLock()
	checkpoint := l.pendingCheckpoint
	aggregated := l.aggregatedCheckpoint
	l.pendingMu.RUnlock()
	
	if aggregated != nil {
		http.Error(rw, "already aggregated", http.StatusNotFound)
		return
	}
	if checkpoint == nil {
		http.Error(rw, "no checkpoint", http.StatusNotFound)
		return
	}
	
	rw.Header().Set("Content-Type", "text/plain")
	rw.Write(checkpoint)
}

// POST /ct/v1/submit-signature
func (l *Log) submitSignature(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		WitnessID string `json:"witness_id"`
		Signature []byte `json:"signature"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "invalid JSON", http.StatusBadRequest)
		return
	}
	
	if len(req.Signature) != 96 {
		http.Error(rw, fmt.Sprintf("signature must be 96 bytes, got %d", 
			len(req.Signature)), http.StatusBadRequest)
		return
	}
	
	if err := l.AddPendingSignature(req.WitnessID, req.Signature); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	
	rw.WriteHeader(http.StatusOK)
	json.NewEncoder(rw).Encode(map[string]interface{}{
		"status":        "accepted",
		"pending_count": l.GetPendingCount(),
	})
}

// GET /ct/v1/witness-status
func (l *Log) getWitnessStatus(rw http.ResponseWriter, r *http.Request) {
	l.pendingMu.RLock()
	pending := len(l.pendingSigs)
	isAgg := l.aggregatedCheckpoint != nil
	aggWitnesses := l.aggregatedWitnesses
	l.pendingMu.RUnlock()
	
	json.NewEncoder(rw).Encode(map[string]interface{}{
		"pending_count":      pending,
		"total_witnesses":    len(l.witnessPubkeys),
		"pending_witnesses":  l.GetPendingWitnesses(),
		"is_aggregated":      isAgg,
		"aggregated_witnesses": aggWitnesses,
	})
}
```

### 5.2 Register in Handler

```go
func (l *Log) Handler() http.Handler {
	// ... existing handlers ...
	
	mux.Handle("GET /ct/v1/checkpoint-for-signing",
		http.HandlerFunc(l.getCheckpointForSigning))
	mux.Handle("POST /ct/v1/submit-signature",
		http.HandlerFunc(l.submitSignature))
	mux.Handle("GET /ct/v1/witness-status",
		http.HandlerFunc(l.getWitnessStatus))
	
	// ...
}
```

---

## Phase 6: Update Witness Client

**File**: `internal/witness/witness.go`

### 6.1 Replace Ed25519 with BLS

```go
type Witness struct {
	c Config
	
	// BLS instead of Ed25519
	blsSigner *mycrypto.BLSSigner
	blsPubkey []byte
	
	client      *http.Client
	logVerifier note.Verifier
	lastSigned  []byte // Hash of last signed checkpoint
}

type Config struct {
	Name      string
	LogURL    string
	BLSSecret string // Path to 32-byte seed file
	Log       *slog.Logger
}
```

### 6.2 Initialize with BLS

```go
func NewWitness(ctx context.Context, config *Config) (*Witness, error) {
	// Load BLS key
	seed, err := os.ReadFile(config.BLSSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to load BLS seed: %w", err)
	}
	
	if len(seed) != 32 {
		return nil, fmt.Errorf("BLS seed must be 32 bytes, got %d", len(seed))
	}
	
	sk, pk, err := mycrypto.GenerateKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}
	
	// Compute key hash (like Sunlight does for other keys)
	keyHash := computeKeyHash(pk)
	
	blsSigner := mycrypto.NewBLSSigner(config.Name, keyHash, sk)
	
	return &Witness{
		c:           config,
		blsSigner:   blsSigner,
		blsPubkey:   mycrypto.PublicKeyToBytes(pk),
		client:      &http.Client{Timeout: 30 * time.Second},
		logVerifier: config.LogVerifier,
	}, nil
}
```

### 6.3 Implement Passive Witnessing

```go
func (w *Witness) Run(ctx context.Context) error {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := w.checkAndSign(ctx); err != nil {
				w.c.Log.Error("witnessing failed", "err", err)
			}
		}
	}
}

func (w *Witness) checkAndSign(ctx context.Context) error {
	// Fetch checkpoint
	checkpoint, err := w.fetchCheckpoint(ctx)
	if err != nil {
		return err
	}
	if checkpoint == nil {
		return nil
	}
	
	// Verify log signature
	if err := w.verifyCheckpoint(checkpoint); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	
	// Check if already signed
	hash := sha256.Sum256(checkpoint)
	if bytes.Equal(hash[:], w.lastSigned) {
		return nil
	}
	
	// Sign with BLS
	msg := extractCheckpointMessage(checkpoint)
	sig := mycrypto.Sign(w.blsSigner.SecretKey(), msg)
	sigBytes := mycrypto.SignatureToBytes(sig)
	
	// Submit
	if err := w.submitSignature(ctx, sigBytes); err != nil {
		return err
	}
	
	w.lastSigned = hash[:]
	w.c.Log.Info("witnessed checkpoint", "hash", fmt.Sprintf("%x", hash[:8]))
	return nil
}

func (w *Witness) fetchCheckpoint(ctx context.Context) ([]byte, error) {
	url := fmt.Sprintf("%s/ct/v1/checkpoint-for-signing", w.c.LogURL)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d", resp.StatusCode)
	}
	
	return io.ReadAll(resp.Body)
}

func (w *Witness) submitSignature(ctx context.Context, sig []byte) error {
	url := fmt.Sprintf("%s/ct/v1/submit-signature", w.c.LogURL)
	
	body, _ := json.Marshal(map[string]interface{}{
		"witness_id": w.c.Name,
		"signature":  sig,
	})
	
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submission failed: %s", body)
	}
	
	return nil
}

func (w *Witness) verifyCheckpoint(checkpoint []byte) error {
	// Parse and verify log's signature
	_, err := note.Open(checkpoint, note.VerifierList(w.logVerifier))
	return err
}
```

---

## Phase 7: Client Verification

**File**: New `aggregated_checkpoint.go` in main package

### 7.1 Parse Aggregated Format

```go
package sunlight

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	
	"filippo.io/sunlight/internal/my_crypto"
	"golang.org/x/mod/sumdb/note"
)

// AggregatedCheckpoint represents a checkpoint with BLS aggregate.
type AggregatedCheckpoint struct {
	Origin       string
	Tree         tlog.Tree
	AggregateSig []byte
	WitnessIDs   []string
}

// ParseAggregatedCheckpoint parses the aggregated format.
func ParseAggregatedCheckpoint(noteBytes []byte) (*AggregatedCheckpoint, error) {
	n, err := note.Open(noteBytes, nil)
	if err != nil {
		return nil, err
	}
	
	cp, err := ParseCheckpoint(n.Text)
	if err != nil {
		return nil, err
	}
	
	result := &AggregatedCheckpoint{
		Origin: cp.Origin,
		Tree:   cp.Tree,
	}
	
	for _, sig := range n.Sigs {
		switch sig.Name {
		case "witness-aggregate":
			result.AggregateSig, _ = base64.StdEncoding.DecodeString(sig.Base64)
		case "witness-list":
			listJSON, _ := base64.StdEncoding.DecodeString(sig.Base64)
			json.Unmarshal(listJSON, &result.WitnessIDs)
		}
	}
	
	if result.AggregateSig == nil {
		return nil, errors.New("no aggregate signature")
	}
	
	return result, nil
}

// IsAggregatedFormat checks if checkpoint uses aggregated format.
func IsAggregatedFormat(noteBytes []byte) bool {
	n, _ := note.Open(noteBytes, nil)
	if n == nil {
		return false
	}
	for _, sig := range n.Sigs {
		if sig.Name == "witness-aggregate" {
			return true
		}
	}
	return false
}
```

### 7.2 Verify Aggregate

```go
// VerifyAggregate verifies the BLS aggregate using witness pubkeys.
func (ac *AggregatedCheckpoint) VerifyAggregate(witnessPubkeys map[string][]byte) error {
	// Collect pubkeys in order
	var pks []*blst.P1Affine
	for _, id := range ac.WitnessIDs {
		pkBytes, ok := witnessPubkeys[id]
		if !ok {
			return fmt.Errorf("unknown witness: %s", id)
		}
		
		pk, err := mycrypto.PublicKeyFromBytes(pkBytes)
		if err != nil {
			return fmt.Errorf("invalid pubkey for %s: %w", id, err)
		}
		pks = append(pks, pk)
	}
	
	// Deserialize aggregate
	sig, err := mycrypto.SignatureFromBytes(ac.AggregateSig)
	if err != nil {
		return fmt.Errorf("invalid aggregate: %w", err)
	}
	
	// Reconstruct message
	msg := []byte(FormatCheckpoint(Checkpoint{
		Origin: ac.Origin,
		Tree:   ac.Tree,
	}))
	
	// Verify
	if !mycrypto.FastAggregateVerify(pks, msg, sig) {
		return errors.New("BLS verification failed")
	}
	
	return nil
}
```

### 7.3 Update Client.Checkpoint()

**File**: `client.go`:

```go
func (c *Client) Checkpoint(ctx context.Context) (torchwood.Checkpoint, *note.Note, error) {
	signedNote, err := c.r.ReadEndpoint(ctx, "checkpoint")
	if err != nil {
		return torchwood.Checkpoint{}, nil, err
	}
	
	// Check if aggregated format
	if IsAggregatedFormat(signedNote) && len(c.cc.WitnessPubkeys) > 0 {
		aggCP, err := ParseAggregatedCheckpoint(signedNote)
		if err != nil {
			return torchwood.Checkpoint{}, nil, 
				fmt.Errorf("parse aggregated: %w", err)
		}
		
		// Verify BLS aggregate
		if err := aggCP.VerifyAggregate(c.cc.WitnessPubkeys); err != nil {
			return torchwood.Checkpoint{}, nil,
				fmt.Errorf("verify aggregate: %w", err)
		}
		
		return torchwood.Checkpoint{
			Origin: aggCP.Origin,
			Tree:   aggCP.Tree,
		}, nil, nil
	}
	
	// Fall back to classical format
	// ... existing code ...
}
```

---

## Phase 8: Metrics

**File**: `internal/ctlog/metrics.go`:

```go
type metrics struct {
	// ... existing ...
	
	WitnessPendingCount      prometheus.Gauge
	WitnessAggregatedCount   prometheus.Gauge
	WitnessAggregationDur    prometheus.Histogram
	WitnessAggregationFailed prometheus.Counter
	CheckpointFormat         prometheus.Gauge // 0=classical, 1=aggregated
}

func initMetrics() metrics {
	return metrics{
		// ... existing ...
		
		WitnessPendingCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sunlight_witness_pending_count",
			Help: "Pending witness signatures",
		}),
		WitnessAggregatedCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sunlight_witness_aggregated_count",
			Help: "Witnesses in current aggregate",
		}),
		WitnessAggregationDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "sunlight_witness_aggregation_duration_seconds",
			Help:    "Time to aggregate signatures",
			Buckets: prometheus.DefBuckets,
		}),
		WitnessAggregationFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sunlight_witness_aggregation_failed_total",
			Help: "Failed aggregation attempts",
		}),
		CheckpointFormat: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sunlight_checkpoint_format",
			Help: "0=classical, 1=aggregated",
		}),
	}
}
```

---

## Testing

### Unit Tests

```go
func TestAddPendingSignature(t *testing.T) {
	// Setup log with 1 witness
	// Test: valid signature accepted
	// Test: unauthorized witness rejected
	// Test: duplicate signature rejected
	// Test: invalid signature rejected
}

func TestAggregateSignatures(t *testing.T) {
	// Setup with 3 signatures
	// Aggregate
	// Verify result is valid BLS aggregate
}

func TestAggregatedCheckpointFormat(t *testing.T) {
	// Create checkpoint
	// Verify format contains "witness-aggregate" and "witness-list"
	// Verify no individual signatures present
}
```

### Integration Test

```go
func TestEndToEndBLSWitness(t *testing.T) {
	// 1. Start log with 3 witnesses configured
	// 2. Create checkpoint
	// 3. Start 3 witness clients
	// 4. Wait for all to sign
	// 5. Trigger aggregation
	// 6. Verify aggregated checkpoint
	// 7. Verify client can parse and verify
}
```

---

## Summary of Files Modified

1. `internal/my_crypto/bls.go` - Add note.Verifier, key derivation, batch aggregation
2. `cmd/sunlight/sunlight.go` - Parse witness config
3. `internal/ctlog/ctlog.go` - Add witness state, aggregation watcher
4. `internal/ctlog/witness_pool.go` - NEW: Pending pool and aggregation logic
5. `internal/ctlog/http.go` - Add 3 HTTP endpoints
6. `internal/ctlog/metrics.go` - Add 4 metrics
7. `internal/witness/witness.go` - Replace Ed25519 with BLS
8. `aggregated_checkpoint.go` - NEW: Client-side parsing and verification
9. `client.go` - Support aggregated format

---

## Key Differences from Ed25519

| Aspect | Ed25519 | BLS |
|--------|---------|-----|
| Signature size | 64 bytes | 96 bytes |
| Aggregate size | 64N bytes | 96 bytes |
| Verification | O(N) | O(1) |
| Key format | 32 bytes | 48 bytes |
| Library | Standard | blst (BLS12-381) |
