package validation

import (
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func TestTreeRootAndInclusionProofs(t *testing.T) {
	leaves := make([]tlog.Hash, 5)
	for i := range leaves {
		leaves[i] = LeafHash([]byte{byte(i), 'x'}, int64(i), 1000+int64(i))
	}
	tree, err := BuildTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	root, err := tree.Root()
	if err != nil {
		t.Fatal(err)
	}
	for i, leaf := range leaves {
		if err := tree.ProveAndCheck(int64(i), root, leaf); err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
	}
	// A leaf hash that is not in the tree fails its inclusion proof.
	stranger := LeafHash([]byte("stranger"), 2, 1002)
	if err := tree.ProveAndCheck(2, root, stranger); err == nil {
		t.Fatal("foreign leaf passed the inclusion proof")
	}
	// Changing any leaf changes the root.
	leaves[3] = stranger
	other, _ := BuildTree(leaves)
	otherRoot, _ := other.Root()
	if otherRoot == root {
		t.Fatal("root unchanged after replacing a leaf")
	}
}

func TestLeafHashDependsOnEveryField(t *testing.T) {
	base := LeafHash([]byte("data"), 1, 2)
	if LeafHash([]byte("datA"), 1, 2) == base {
		t.Fatal("data ignored")
	}
	if LeafHash([]byte("data"), 2, 2) == base {
		t.Fatal("leaf index ignored")
	}
	if LeafHash([]byte("data"), 1, 3) == base {
		t.Fatal("timestamp ignored")
	}
}

func TestMessageIsDomainSeparated(t *testing.T) {
	var h tlog.Hash
	msg := string(Message("127.0.0.1/wbb", 7, h))
	if msg[:len(MessagePrefix)] != MessagePrefix {
		t.Fatalf("message %q lacks the prefix", msg)
	}
	if msg == string(Message("127.0.0.1/wbb", 8, h)) || msg == string(Message("other/wbb", 7, h)) {
		t.Fatal("message does not bind origin and leaf index")
	}
}
