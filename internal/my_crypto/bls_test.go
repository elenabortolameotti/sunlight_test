package my_crypto

import (
	"testing"
)

func TestBLSSignVerify(t *testing.T) {
	sk, pk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := []byte("hello bls")

	sig := Sign(sk, msg)
	if sig == nil {
		t.Fatal("Sign returned nil")
	}

	if !Verify(pk, msg, sig) {
		t.Fatal("Verify failed on valid signature")
	}
}

func TestBLSSignVerifyWrongMessage(t *testing.T) {
	sk, pk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := []byte("hello bls")
	wrongMsg := []byte("wrong message")

	sig := Sign(sk, msg)
	if sig == nil {
		t.Fatal("Sign returned nil")
	}

	if Verify(pk, wrongMsg, sig) {
		t.Fatal("Verify succeeded on wrong message")
	}
}

func TestBLSSerializeDeserialize(t *testing.T) {
	sk, pk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := []byte("serialization test")

	sig := Sign(sk, msg)
	if sig == nil {
		t.Fatal("Sign returned nil")
	}

	pkBytes, err := PublicKeyToBytes(pk)
	if err != nil {
		t.Fatalf("PublicKeyToBytes failed: %v", err)
	}

	sigBytes, err := SignatureToBytes(sig)
	if err != nil {
		t.Fatalf("SignatureToBytes failed: %v", err)
	}

	pk2, err := PublicKeyFromBytes(pkBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}

	sig2, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("SignatureFromBytes failed: %v", err)
	}

	if !Verify(pk2, msg, sig2) {
		t.Fatal("Verify failed after serialize/deserialize")
	}
}
