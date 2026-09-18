package ctlog_test

// Tests for PoC WBB patch P6 (branch referendum-poc-wbb): validators that
// rebuild the Merkle tree from the published leaves, check it against the
// signed checkpoint, and BLS-sign every leaf through POST /validations.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/sunlight/internal/my_crypto"
	"filippo.io/sunlight/internal/validation"
)

func validatorSigner(t *testing.T, name string, fill byte) *my_crypto.BLSSigner {
	t.Helper()
	seed := bytes.Repeat([]byte{fill}, 32)
	signer, err := my_crypto.NewBLSSignerFromSeed(name, 0, seed)
	if err != nil {
		t.Fatalf("validator signer %s: %v", name, err)
	}
	return signer
}

type validatedEntriesResponse struct {
	Count      int                    `json:"count"`
	Entries    []ctlog.ValidatedEntry `json:"entries"`
	Validators []string               `json:"validators"`
}

func fetchValidatedEntries(t *testing.T, server *httptest.Server) validatedEntriesResponse {
	t.Helper()
	resp, err := http.Get(server.URL + "/entries")
	if err != nil {
		t.Fatalf("GET /entries: %v", err)
	}
	defer resp.Body.Close()
	var out validatedEntriesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /entries: %v", err)
	}
	return out
}

// startValidatedLog starts a log with two registered validators and two
// published threshold entries; returns the server, the log key and signers.
func startValidatedLog(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey, *my_crypto.BLSSigner, *my_crypto.BLSSigner) {
	t.Helper()
	pubs, privs := pocKeys(t, "RT-1", "RT-2", "RT-3")
	v1 := validatorSigner(t, "V-1", 0x11)
	v2 := validatorSigner(t, "V-2", 0x22)
	pk1, _ := v1.PublicKeyBytes()
	pk2, _ := v2.PublicKeyBytes()

	var logKey *ecdsa.PrivateKey
	server := startPoCLog(t, pubs, nil, func(c *ctlog.Config) {
		c.DisableTimestampValidation = true
		c.GracePeriod = 50 * time.Millisecond
		c.ValidatorBLSKeys = map[string][]byte{"V-1": pk1, "V-2": pk2}
		logKey = c.Key
	})

	for _, data := range []string{
		"setup,RT,acc_pub_key,2,first-leaf",
		"setup,RT,acc_pub_key,2,second-leaf",
	} {
		for _, id := range []string{"RT-1", "RT-2"} {
			status, body := pocSubmit(t, server, data, id, 1, privs[id])
			if status != http.StatusOK && status != http.StatusAccepted {
				t.Fatalf("submit %s by %s: HTTP %d: %s", data, id, status, body)
			}
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if fetchValidatedEntries(t, server).Count >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("two leaves were not sequenced in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return server, logKey, v1, v2
}

func newTestValidator(t *testing.T, server *httptest.Server, signer *my_crypto.BLSSigner, key *ecdsa.PublicKey) *validation.Validator {
	t.Helper()
	v, err := validation.New(validation.Config{
		Name:         signer.Name(),
		Signer:       signer,
		LogURL:       server.URL,
		HTTPClient:   server.Client(),
		LogPublicKey: key,
	})
	if err != nil {
		t.Fatalf("validator %s: %v", signer.Name(), err)
	}
	return v
}

func TestP6ValidatorsSignEveryVerifiedLeaf(t *testing.T) {
	server, logKey, v1, v2 := startValidatedLog(t)
	ctx := t.Context()

	entries := fetchValidatedEntries(t, server)
	if got, want := strings.Join(entries.Validators, ","), "V-1,V-2"; got != want {
		t.Fatalf("validators = %q, want %q", got, want)
	}
	for _, e := range entries.Entries {
		if len(e.Validations) != 0 || e.AggregateSignature != nil {
			t.Fatalf("leaf %d already carries validations", e.LeafIndex)
		}
		if len(e.LeafHash) != 64 {
			t.Fatalf("leaf %d: leaf_hash %q is not a hex SHA-256", e.LeafIndex, e.LeafHash)
		}
	}

	// First validator: verifies the checkpoint, rebuilds the tree, signs both leaves.
	first := newTestValidator(t, server, v1, &logKey.PublicKey)
	report, err := first.RunOnce(ctx)
	if err != nil {
		t.Fatalf("V-1 pass: %v", err)
	}
	if report.TreeSize != 2 || len(report.Validated) != 2 || report.Skipped != 0 {
		t.Fatalf("V-1 report = %+v, want tree 2, 2 validated", report)
	}
	entries = fetchValidatedEntries(t, server)
	for _, e := range entries.Entries {
		if len(e.Validations) != 1 || e.Validations[0].ValidatorID != "V-1" {
			t.Fatalf("leaf %d validations = %+v, want V-1 only", e.LeafIndex, e.Validations)
		}
	}

	// A second pass is idempotent.
	report, err = first.RunOnce(ctx)
	if err != nil {
		t.Fatalf("V-1 second pass: %v", err)
	}
	if len(report.Validated) != 0 || report.Skipped != 2 {
		t.Fatalf("V-1 second pass report = %+v, want nothing new", report)
	}

	// Second validator: both leaves now carry two signatures whose aggregate
	// verifies in one shot against both public keys.
	second := newTestValidator(t, server, v2, &logKey.PublicKey)
	if _, err := second.RunOnce(ctx); err != nil {
		t.Fatalf("V-2 pass: %v", err)
	}
	entries = fetchValidatedEntries(t, server)
	pk1, _ := v1.PublicKeyBytes()
	pk2, _ := v2.PublicKeyBytes()
	for _, e := range entries.Entries {
		if len(e.Validations) != 2 || e.Validations[0].ValidatorID != "V-1" || e.Validations[1].ValidatorID != "V-2" {
			t.Fatalf("leaf %d validations = %+v, want V-1 and V-2", e.LeafIndex, e.Validations)
		}
		leafHash := validation.LeafHash(e.Entry, e.LeafIndex, e.Timestamp)
		msg := validation.Message(report.Origin, e.LeafIndex, leafHash)
		ok, err := my_crypto.VerifyAggregateBytes([][]byte{pk1, pk2}, msg, e.AggregateSignature)
		if err != nil || !ok {
			t.Fatalf("leaf %d: aggregate signature does not verify (ok=%v err=%v)", e.LeafIndex, ok, err)
		}
		// The aggregate does not verify for a different leaf index.
		wrong := validation.Message(report.Origin, e.LeafIndex+7, leafHash)
		if ok, _ := my_crypto.VerifyAggregateBytes([][]byte{pk1, pk2}, wrong, e.AggregateSignature); ok {
			t.Fatalf("leaf %d: aggregate verified for a foreign message", e.LeafIndex)
		}
	}
}

func TestP6ValidatorRefusesForeignCheckpointKey(t *testing.T) {
	server, _, v1, _ := startValidatedLog(t)
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := newTestValidator(t, server, v1, &foreign.PublicKey)
	if _, err := v.RunOnce(t.Context()); err == nil || !strings.Contains(err.Error(), "checkpoint signature") {
		t.Fatalf("expected a checkpoint signature failure, got %v", err)
	}
	for _, e := range fetchValidatedEntries(t, server).Entries {
		if len(e.Validations) != 0 {
			t.Fatalf("leaf %d was signed despite an unverifiable checkpoint", e.LeafIndex)
		}
	}
}

func postValidation(t *testing.T, server *httptest.Server, body map[string]any) (int, string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(server.URL+"/validations", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /validations: %v", err)
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(text))
}

func TestP6ValidationEndpointRejectsBadSubmissions(t *testing.T) {
	server, _, v1, _ := startValidatedLog(t)
	entries := fetchValidatedEntries(t, server)
	leaf := entries.Entries[0]
	leafHash := validation.LeafHash(leaf.Entry, leaf.LeafIndex, leaf.Timestamp)
	// The log name used by startPoCLog.
	origin := "test.poc.example.com"
	good, err := v1.Sign(validation.Message(origin, leaf.LeafIndex, leafHash))
	if err != nil {
		t.Fatal(err)
	}
	stranger := validatorSigner(t, "V-9", 0x99)
	strangerSig, _ := stranger.Sign(validation.Message(origin, leaf.LeafIndex, leafHash))
	otherLeaf, _ := v1.Sign(validation.Message(origin, leaf.LeafIndex+1, leafHash))

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"unknown validator", map[string]any{"validator_id": "V-9", "leaf_index": 0, "signature": strangerSig}, http.StatusForbidden},
		{"missing leaf", map[string]any{"validator_id": "V-1", "leaf_index": 42, "signature": good}, http.StatusNotFound},
		{"malformed signature", map[string]any{"validator_id": "V-1", "leaf_index": 0, "signature": []byte("short")}, http.StatusBadRequest},
		{"signature over another leaf", map[string]any{"validator_id": "V-1", "leaf_index": 0, "signature": otherLeaf}, http.StatusBadRequest},
		{"valid", map[string]any{"validator_id": "V-1", "leaf_index": 0, "signature": good}, http.StatusOK},
		{"valid again (idempotent)", map[string]any{"validator_id": "V-1", "leaf_index": 0, "signature": good}, http.StatusOK},
	}
	for _, tc := range cases {
		status, body := postValidation(t, server, tc.body)
		if status != tc.want {
			t.Fatalf("%s: HTTP %d (%s), want %d", tc.name, status, body, tc.want)
		}
	}
	entries = fetchValidatedEntries(t, server)
	if got := entries.Entries[0].Validations; len(got) != 1 || got[0].ValidatorID != "V-1" {
		t.Fatalf("leaf 0 validations = %+v, want exactly V-1", got)
	}
	if got := entries.Entries[1].Validations; len(got) != 0 {
		t.Fatalf("leaf 1 validations = %+v, want none", got)
	}
}
