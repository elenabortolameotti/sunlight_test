package my_crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

// Domain Separation Tag di protocollo.
// MinPk: PK in G1, SIG in G2.
var dstBLS = []byte("SUNLIGHT_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

// BLSSigner implementa un signer BLS compatibile con un'interfaccia tipo note.Signer.
type BLSSigner struct {
	name    string
	keyHash uint32
	sk      *blst.SecretKey
	pk      *blst.P1Affine
}

func NewBLSSignerFromSeed(name string, keyHash uint32, seed []byte) (*BLSSigner, error) {
	if len(seed) != 32 {
		return nil, errors.New("seed length must be 32 bytes")
	}
	sk := blst.KeyGen(seed)
	if sk == nil {
		return nil, errors.New("KeyGen returned nil")
	}
	return NewBLSSigner(name, keyHash, sk)
}

func NewBLSSigner(name string, keyHash uint32, sk *blst.SecretKey) (*BLSSigner, error) {
	if name == "" {
		return nil, errors.New("nome signer vuoto")
	}
	if sk == nil {
		return nil, errors.New("secret key nil")
	}

	pk := new(blst.P1Affine).From(sk)
	if pk == nil {
		return nil, errors.New("impossibile derivare la public key dalla secret key")
	}

	return &BLSSigner{
		name:    name,
		keyHash: keyHash,
		sk:      sk,
		pk:      pk,
	}, nil
}

func (s *BLSSigner) Name() string {
	return s.name
}

func (s *BLSSigner) KeyHash() uint32 {
	return s.keyHash
}

func (s *BLSSigner) PublicKey() *blst.P1Affine {
	return s.pk
}

func (s *BLSSigner) PublicKeyBytes() ([]byte, error) {
	if s == nil || s.pk == nil {
		return nil, errors.New("public key nil")
	}
	return s.pk.Compress(), nil
}

// Sign firma msg e restituisce la firma compressa (96 byte).
func (s *BLSSigner) Sign(msg []byte) ([]byte, error) {
	if s == nil || s.sk == nil {
		return nil, errors.New("BLS signer senza secret key")
	}
	if len(msg) == 0 {
		return nil, errors.New("messaggio vuoto")
	}

	sig := Sign(s.sk, msg)
	if sig == nil {
		return nil, errors.New("firma BLS fallita")
	}

	return sig.Compress(), nil
}

// GenerateKey crea una nuova coppia di chiavi BLS.
func GenerateKey() (*blst.SecretKey, *blst.P1Affine, error) {
	var ikm [32]byte
	if _, err := rand.Read(ikm[:]); err != nil {
		return nil, nil, fmt.Errorf("impossibile leggere entropia random: %w", err)
	}

	sk := blst.KeyGen(ikm[:])
	if sk == nil {
		return nil, nil, errors.New("KeyGen ha restituito nil")
	}

	pk := new(blst.P1Affine).From(sk)
	if pk == nil {
		return nil, nil, errors.New("impossibile derivare la public key")
	}

	return sk, pk, nil
}

// Sign firma il messaggio con la secret key e restituisce una firma in G2.
func Sign(sk *blst.SecretKey, msg []byte) *blst.P2Affine {
	if sk == nil || len(msg) == 0 {
		return nil
	}
	return new(blst.P2Affine).Sign(sk, msg, dstBLS)
}

// Verify verifica una firma singola sul messaggio.
func Verify(pk *blst.P1Affine, msg []byte, sig *blst.P2Affine) bool {
	if pk == nil || sig == nil || len(msg) == 0 {
		return false
	}

	return sig.Verify(true, pk, true, msg, dstBLS)
}

// Aggregate aggrega più firme sullo stesso messaggio in una singola firma.
func Aggregate(signatures []*blst.P2Affine) (*blst.P2Affine, error) {
	if len(signatures) == 0 {
		return nil, errors.New("nessuna firma fornita per l'aggregazione")
	}

	agg := new(blst.P2Aggregate)
	if !agg.Aggregate(signatures, true) {
		return nil, errors.New("aggregazione fallita: una delle firme non è valida")
	}

	return agg.ToAffine(), nil
}

// FastAggregateVerify verifica una firma aggregata prodotta da più witness
// che hanno firmato tutti lo stesso messaggio.
func FastAggregateVerify(pks []*blst.P1Affine, msg []byte, aggSig *blst.P2Affine) bool {
	if len(pks) == 0 || aggSig == nil || len(msg) == 0 {
		return false
	}

	return aggSig.FastAggregateVerify(true, pks, msg, dstBLS)
}

// PublicKeyFromBytes decodifica una public key compressa (48 byte)
// e verifica che sia valida e nel subgroup corretto.
func PublicKeyFromBytes(b []byte) (*blst.P1Affine, error) {
	if len(b) == 0 {
		return nil, errors.New("empty public key")
	}

	pk := new(blst.P1Affine).Uncompress(b)
	if pk == nil || !pk.KeyValidate() {
		return nil, errors.New("invalid BLS public key")
	}

	return pk, nil
}

// SignatureFromBytes decodifica una firma compressa (96 byte)
// e verifica che sia valida e nel subgroup corretto.
func SignatureFromBytes(b []byte) (*blst.P2Affine, error) {
	if len(b) == 0 {
		return nil, errors.New("empty signature")
	}

	sig := new(blst.P2Affine).Uncompress(b)
	if sig == nil || !sig.SigValidate(true) {
		return nil, errors.New("invalid BLS signature")
	}

	return sig, nil
}

// PublicKeyToBytes serializza una public key in formato compresso (48 byte).
func PublicKeyToBytes(pk *blst.P1Affine) ([]byte, error) {
	if pk == nil {
		return nil, errors.New("public key is nil")
	}
	return pk.Compress(), nil
}

// SignatureToBytes serializza una firma in formato compresso (96 byte).
func SignatureToBytes(sig *blst.P2Affine) ([]byte, error) {
	if sig == nil {
		return nil, errors.New("signature is nil")
	}
	return sig.Compress(), nil
}

// AggregateSignature rappresenta una cosignatura aggregata dei witness.
// Witnesses contiene gli identificatori dei witness inclusi nella firma aggregata.
// La scelta del formato degli ID (stringhe, nomi, fingerprint, bitmap esterna)
// dipende dal tuo protocollo.
type AggregateSignature struct {
	Witnesses []string `json:"witnesses"`
	Sig       []byte   `json:"sig"`
}

func AggregateSignaturesBytes(signatures [][]byte) ([]byte, error) {
	parsed := make([]*blst.P2Affine, 0, len(signatures))
	for _, raw := range signatures {
		sig, err := SignatureFromBytes(raw)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, sig)
	}

	agg, err := Aggregate(parsed)
	if err != nil {
		return nil, err
	}

	return SignatureToBytes(agg)
}

func VerifyAggregateBytes(pubkeys [][]byte, msg []byte, aggSig []byte) (bool, error) {
	pks := make([]*blst.P1Affine, 0, len(pubkeys))
	for _, raw := range pubkeys {
		pk, err := PublicKeyFromBytes(raw)
		if err != nil {
			return false, err
		}
		pks = append(pks, pk)
	}

	sig, err := SignatureFromBytes(aggSig)
	if err != nil {
		return false, err
	}

	return FastAggregateVerify(pks, msg, sig), nil
}

/*
// BuildAggregateSignature aggrega più firme e produce una struttura pronta
// da serializzare o trasportare.
func BuildAggregateSignature(witnesses []string, signatures []*blst.P2Affine) (*AggregateSignature, error) {
	if len(witnesses) == 0 {
		return nil, errors.New("lista witness vuota")
	}
	if len(signatures) == 0 {
		return nil, errors.New("lista firme vuota")
	}
	if len(witnesses) != len(signatures) {
		return nil, errors.New("numero witness e numero firme non coincidono")
	}

	aggSig, err := Aggregate(signatures)
	if err != nil {
		return nil, err
	}

	sigBytes, err := SignatureToBytes(aggSig)
	if err != nil {
		return nil, err
	}

	return &AggregateSignature{
		Witnesses: witnesses,
		Sig:       sigBytes,
	}, nil
}

// VerifyAggregateSignature verifica una firma aggregata dato il set delle public key
// dei witness che hanno firmato lo stesso messaggio.
func VerifyAggregateSignature(pks []*blst.P1Affine, msg []byte, agg *AggregateSignature) (bool, error) {
	if agg == nil {
		return false, errors.New("aggregate signature nil")
	}
	if len(msg) == 0 {
		return false, errors.New("messaggio vuoto")
	}
	if len(pks) == 0 {
		return false, errors.New("nessuna public key fornita")
	}

	sig, err := SignatureFromBytes(agg.Sig)
	if err != nil {
		return false, err
	}

	return FastAggregateVerify(pks, msg, sig), nil
}*/
