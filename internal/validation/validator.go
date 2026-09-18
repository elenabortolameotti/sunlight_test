package validation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/my_crypto"
)

// Config configures one validator process.
type Config struct {
	// Name is the validator id registered in the log's validator_bls_keys.
	Name string
	// Signer holds the validator's BLS key.
	Signer *my_crypto.BLSSigner
	// LogURL is the log's submission prefix, e.g. https://127.0.0.1:8090/wbb.
	LogURL string
	// HTTPClient talks to the log (must trust the cluster CA).
	HTTPClient *http.Client
	// LogPublicKey verifies checkpoints. When nil it is fetched once from
	// <LogURL>/log.json.
	LogPublicKey *ecdsa.PublicKey
	// Delay is the deliberate pause before signing each leaf, so an observer
	// can watch validations land one by one.
	Delay time.Duration
	// Logger receives one line per verified leaf; nil discards.
	Logger *slog.Logger
}

// Validator rebuilds the Merkle tree from the log's published leaves,
// checks it against the signed checkpoint, and BLS-signs every leaf it has
// verified and not signed before.
type Validator struct {
	c        Config
	verifier note.Verifier
	origin   string
}

// Report summarises one validation pass.
type Report struct {
	Origin    string
	TreeSize  int64
	Root      tlog.Hash
	Validated []int64
	Skipped   int
}

// New creates a validator; the checkpoint verifier is set up lazily on the
// first pass because the origin line comes from the checkpoint itself.
func New(c Config) (*Validator, error) {
	if c.Name == "" {
		return nil, errors.New("validator name is required")
	}
	if c.Signer == nil {
		return nil, errors.New("validator signer is required")
	}
	if c.LogURL == "" {
		return nil, errors.New("log URL is required")
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	c.LogURL = strings.TrimRight(c.LogURL, "/")
	return &Validator{c: c}, nil
}

// Run validates forever, once per interval, until the context ends.
func (v *Validator) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if report, err := v.RunOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			v.c.Logger.Warn("validation pass failed", "validator", v.c.Name, "err", err)
		} else if len(report.Validated) > 0 {
			v.c.Logger.Info("validation pass complete", "validator", v.c.Name,
				"tree_size", report.TreeSize, "validated", len(report.Validated))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// RunOnce performs one full pass: fetch + verify the checkpoint, rebuild the
// tree from the published leaves, then prove, sign and submit every leaf not
// yet validated by this validator.
func (v *Validator) RunOnce(ctx context.Context) (Report, error) {
	checkpoint, err := v.fetchCheckpoint(ctx)
	if err != nil {
		return Report{}, err
	}
	report := Report{Origin: checkpoint.Origin, TreeSize: checkpoint.N, Root: checkpoint.Hash}

	entries, err := v.fetchEntries(ctx)
	if err != nil {
		return report, err
	}
	if int64(len(entries.Entries)) < checkpoint.N {
		return report, fmt.Errorf("log serves %d leaves but the checkpoint covers %d",
			len(entries.Entries), checkpoint.N)
	}

	leaves := make([]tlog.Hash, checkpoint.N)
	for i := int64(0); i < checkpoint.N; i++ {
		e := entries.Entries[i]
		if e.LeafIndex != i {
			return report, fmt.Errorf("leaf %d served at position %d", e.LeafIndex, i)
		}
		leaves[i] = LeafHash(e.Entry, e.LeafIndex, e.Timestamp)
	}
	tree, err := BuildTree(leaves)
	if err != nil {
		return report, err
	}
	root, err := tree.Root()
	if err != nil {
		return report, err
	}
	if root != checkpoint.Hash {
		return report, fmt.Errorf("%w: tree size %d, rebuilt %x, signed %x",
			ErrTreeMismatch, checkpoint.N, root[:], checkpoint.Hash[:])
	}

	for i := int64(0); i < checkpoint.N; i++ {
		if entries.Entries[i].validatedBy(v.c.Name) {
			report.Skipped++
			continue
		}
		if err := tree.ProveAndCheck(i, root, leaves[i]); err != nil {
			return report, err
		}
		if v.c.Delay > 0 {
			select {
			case <-ctx.Done():
				return report, ctx.Err()
			case <-time.After(v.c.Delay):
			}
		}
		msg := Message(checkpoint.Origin, i, leaves[i])
		sig, err := v.c.Signer.Sign(msg)
		if err != nil {
			return report, fmt.Errorf("sign leaf %d: %w", i, err)
		}
		if err := v.submit(ctx, i, sig); err != nil {
			return report, err
		}
		report.Validated = append(report.Validated, i)
		v.c.Logger.Info("leaf verified and signed", "validator", v.c.Name,
			"leaf_index", i, "leaf_hash", fmt.Sprintf("%x", leaves[i][:8]),
			"tree_size", checkpoint.N)
	}
	return report, nil
}

type sequencedEntry struct {
	LeafIndex   int64           `json:"leaf_index"`
	Timestamp   int64           `json:"timestamp"`
	Entry       json.RawMessage `json:"entry"`
	Validations []struct {
		ValidatorID string `json:"validator_id"`
	} `json:"validations"`
}

func (e *sequencedEntry) validatedBy(name string) bool {
	for _, val := range e.Validations {
		if val.ValidatorID == name {
			return true
		}
	}
	return false
}

type entriesResponse struct {
	Count      int              `json:"count"`
	Entries    []sequencedEntry `json:"entries"`
	Validators []string         `json:"validators"`
}

func (v *Validator) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.c.LogURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (v *Validator) fetchCheckpoint(ctx context.Context) (sunlight.Checkpoint, error) {
	raw, err := v.get(ctx, "/checkpoint")
	if err != nil {
		return sunlight.Checkpoint{}, err
	}
	origin, _, ok := strings.Cut(string(raw), "\n")
	if !ok || origin == "" {
		return sunlight.Checkpoint{}, errors.New("malformed checkpoint: missing origin line")
	}
	if v.verifier == nil || v.origin != origin {
		if err := v.setupVerifier(ctx, origin); err != nil {
			return sunlight.Checkpoint{}, err
		}
	}
	n, err := note.Open(raw, note.VerifierList(v.verifier))
	if err != nil {
		return sunlight.Checkpoint{}, fmt.Errorf("checkpoint signature: %w", err)
	}
	checkpoint, err := sunlight.ParseCheckpoint(n.Text)
	if err != nil {
		return sunlight.Checkpoint{}, fmt.Errorf("checkpoint: %w", err)
	}
	if checkpoint.Origin != origin {
		return sunlight.Checkpoint{}, fmt.Errorf("checkpoint origin %q differs from note origin %q",
			checkpoint.Origin, origin)
	}
	return checkpoint, nil
}

func (v *Validator) setupVerifier(ctx context.Context, origin string) error {
	key := v.c.LogPublicKey
	if key == nil {
		fetched, err := v.fetchLogKey(ctx)
		if err != nil {
			return err
		}
		key = fetched
		v.c.LogPublicKey = key
	}
	verifier, err := NewCheckpointVerifier(origin, key)
	if err != nil {
		return err
	}
	v.verifier = verifier
	v.origin = origin
	return nil
}

func (v *Validator) fetchLogKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	raw, err := v.get(ctx, "/log.json")
	if err != nil {
		return nil, err
	}
	var info struct {
		PublicKeyDER []byte `json:"public_key_der"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("log.json: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(info.PublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("log.json public key: %w", err)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("log.json public key is %T, want ECDSA", pub)
	}
	return key, nil
}

func (v *Validator) fetchEntries(ctx context.Context) (entriesResponse, error) {
	raw, err := v.get(ctx, "/entries")
	if err != nil {
		return entriesResponse{}, err
	}
	var entries entriesResponse
	if err := json.Unmarshal(raw, &entries); err != nil {
		return entriesResponse{}, fmt.Errorf("entries: %w", err)
	}
	sort.SliceStable(entries.Entries, func(i, j int) bool {
		return entries.Entries[i].LeafIndex < entries.Entries[j].LeafIndex
	})
	return entries, nil
}

func (v *Validator) submit(ctx context.Context, leafIndex int64, signature []byte) error {
	body, err := json.Marshal(map[string]any{
		"validator_id": v.c.Name,
		"leaf_index":   leafIndex,
		"signature":    signature,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.c.LogURL+"/validations", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST /validations: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /validations for leaf %d: HTTP %d: %s",
			leafIndex, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}
