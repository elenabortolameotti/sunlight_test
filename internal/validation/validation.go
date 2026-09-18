// Package validation implements the WBB validators of the referendum PoC
// (fork patch P6): independent parties that rebuild the log's Merkle tree
// from the published leaves, check it against the signed checkpoint, and
// BLS-sign every leaf they have verified. The log collects those signatures
// per leaf and serves them next to the entry, so a reader can see how many
// validators vouch for each message.
package validation

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"filippo.io/sunlight"
)

// MessagePrefix domain-separates validator signatures from every other BLS
// signature in the system.
const MessagePrefix = "wbb-validation/v1"

// Message is the exact byte string a validator signs for one leaf: the
// protocol tag, the log origin, the leaf index and the leaf's Merkle hash.
func Message(origin string, leafIndex int64, leafHash tlog.Hash) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%d\n%x\n", MessagePrefix, origin, leafIndex, leafHash[:]))
}

// LeafHash recomputes the Merkle leaf hash of a sequenced entry exactly as
// the log does when it appends the leaf.
func LeafHash(data []byte, leafIndex, timestamp int64) tlog.Hash {
	e := &sunlight.LogEntry{Data: data, LeafIndex: leafIndex, Timestamp: timestamp}
	return tlog.RecordHash(e.MerkleTreeLeaf())
}

// NewCheckpointVerifier returns a note verifier for checkpoints signed by
// the WBB log: ECDSA P-256 over SHA-256 of the note text, encoded as
// timestamp || r || s, with the log's key hash scheme.
func NewCheckpointVerifier(name string, key *ecdsa.PublicKey) (note.Verifier, error) {
	if name == "" {
		return nil, errors.New("empty log name")
	}
	if key == nil {
		return nil, errors.New("nil log public key")
	}
	pkix, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &checkpointVerifier{name: name, keyHash: keyHashBytes(name, pkix), key: key}, nil
}

type checkpointVerifier struct {
	name    string
	keyHash uint32
	key     *ecdsa.PublicKey
}

func (v *checkpointVerifier) Name() string    { return v.name }
func (v *checkpointVerifier) KeyHash() uint32 { return v.keyHash }
func (v *checkpointVerifier) Verify(msg, sig []byte) bool {
	// timestamp (8 bytes) || r (32 bytes) || s (32 bytes), fixed width.
	const scalar = 32
	if len(sig) != 8+2*scalar {
		return false
	}
	sigData := sig[8:]
	r := new(big.Int).SetBytes(sigData[:scalar])
	s := new(big.Int).SetBytes(sigData[scalar:])
	digest := sha256.Sum256(msg)
	return ecdsa.Verify(v.key, digest[:], r, s)
}

// ErrTreeMismatch is returned when the Merkle root rebuilt from the
// published leaves differs from the root in the signed checkpoint.
var ErrTreeMismatch = errors.New("rebuilt Merkle root does not match the signed checkpoint")

// Tree is a Merkle tree rebuilt in memory from leaf hashes, in the same
// storage layout the log uses (so proofs match the log's tiles).
type Tree struct {
	n      int64
	hashes map[int64]tlog.Hash
}

// BuildTree appends the given leaf hashes, in order, to an empty tree.
func BuildTree(leaves []tlog.Hash) (*Tree, error) {
	t := &Tree{hashes: make(map[int64]tlog.Hash, 2*len(leaves)+1)}
	for _, leaf := range leaves {
		hashes, err := tlog.StoredHashesForRecordHash(t.n, leaf, t.reader())
		if err != nil {
			return nil, fmt.Errorf("leaf %d: %w", t.n, err)
		}
		base := tlog.StoredHashIndex(0, t.n)
		for i, h := range hashes {
			t.hashes[base+int64(i)] = h
		}
		t.n++
	}
	return t, nil
}

func (t *Tree) reader() tlog.HashReaderFunc {
	return func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, 0, len(indexes))
		for _, i := range indexes {
			h, ok := t.hashes[i]
			if !ok {
				return nil, fmt.Errorf("stored hash %d not available", i)
			}
			out = append(out, h)
		}
		return out, nil
	}
}

// Size is the number of leaves in the tree.
func (t *Tree) Size() int64 { return t.n }

// Root is the Merkle root of the whole tree.
func (t *Tree) Root() (tlog.Hash, error) {
	return tlog.TreeHash(t.n, t.reader())
}

// ProveAndCheck produces the inclusion proof of leaf `index` against the
// tree of the given size and root and verifies it, exactly as an external
// auditor with the log's tiles would.
func (t *Tree) ProveAndCheck(index int64, root tlog.Hash, leafHash tlog.Hash) error {
	proof, err := tlog.ProveRecord(t.n, index, t.reader())
	if err != nil {
		return fmt.Errorf("inclusion proof for leaf %d: %w", index, err)
	}
	if err := tlog.CheckRecord(proof, t.n, root, index, leafHash); err != nil {
		return fmt.Errorf("inclusion proof for leaf %d: %w", index, err)
	}
	return nil
}

// keyHashBytes is the log's note key-hash construction:
// SHA-256(name || "\n" || 0x03 || PKIX(key))[:4].
func keyHashBytes(name string, pkix []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte{0x03})
	h.Write(pkix)
	return binary.BigEndian.Uint32(h.Sum(nil))
}
