package my_crypto

import "testing"

func TestBLSSignerSign(t *testing.T) {
	sk, pk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	signer, err := NewBLSSigner("witness-1", 1234, sk)
	if err != nil {
		t.Fatalf("NewBLSSigner failed: %v", err)
	}

	msg := []byte("signed by BLSSigner")

	sigBytes, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("BLSSigner.Sign failed: %v", err)
	}

	sig, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("SignatureFromBytes failed: %v", err)
	}

	if !Verify(pk, msg, sig) {
		t.Fatal("Verify failed for BLSSigner signature")
	}
}
