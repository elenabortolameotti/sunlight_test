package my_crypto

import (
	"testing"

	blst "github.com/supranational/blst/bindings/go"
)

func TestBLSAggregateSameMessage(t *testing.T) {
	msg := []byte("checkpoint to be witnessed")

	const n = 3
	var pks []*blst.P1Affine
	var sigs []*blst.P2Affine

	for i := 0; i < n; i++ {
		sk, pk, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		sig := Sign(sk, msg)
		if sig == nil {
			t.Fatal("Sign returned nil")
		}

		pks = append(pks, pk)
		sigs = append(sigs, sig)
	}

	aggSig, err := Aggregate(sigs)
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	if !FastAggregateVerify(pks, msg, aggSig) {
		t.Fatal("FastAggregateVerify failed on valid aggregate signature")
	}
}

func TestBLSAggregateWrongMessage(t *testing.T) {
	msg := []byte("checkpoint to be witnessed")
	wrongMsg := []byte("different checkpoint")

	const n = 3
	var pks []*blst.P1Affine
	var sigs []*blst.P2Affine

	for i := 0; i < n; i++ {
		sk, pk, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		sig := Sign(sk, msg)
		if sig == nil {
			t.Fatal("Sign returned nil")
		}

		pks = append(pks, pk)
		sigs = append(sigs, sig)
	}

	aggSig, err := Aggregate(sigs)
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	if FastAggregateVerify(pks, wrongMsg, aggSig) {
		t.Fatal("FastAggregateVerify succeeded on wrong message")
	}
}
