package mynote

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"filippo.io/sunlight/internal/my_crypto"
)

// A Verifier verifies messages signed with a specific key.
type Verifier interface {
	// Name returns the server name associated with the key.
	Name() string

	// KeyHash returns the key hash.
	KeyHash() uint32

	// Verify reports whether sig is a valid signature of msg.
	Verify(msg, sig []byte) bool
}

// A Signer signs messages using a specific key.
type Signer interface {
	// Name returns the server name associated with the key.
	Name() string

	// KeyHash returns the key hash.
	KeyHash() uint32

	// Sign returns a signature for the given message.
	Sign(msg []byte) ([]byte, error)
}

// keyHash computes the key hash for the given server name and encoded public key.
func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}

var (
	errVerifierID   = errors.New("malformed verifier id")
	errVerifierAlg  = errors.New("unknown verifier algorithm")
	errVerifierHash = errors.New("invalid verifier hash")
)

const (
	algEd25519      = 1
	algBLS          = 2
	algBLSAggregate = 3
)

func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func NewVerifier(vkey string) (Verifier, error) {
	name, vkey := chop(vkey, "+")
	hash16, key64 := chop(vkey, "+")
	hash, err1 := strconv.ParseUint(hash16, 16, 32)
	key, err2 := base64.StdEncoding.DecodeString(key64)
	if len(hash16) != 8 || err1 != nil || err2 != nil || !isValidName(name) || len(key) == 0 {
		return nil, errVerifierID
	}
	if uint32(hash) != keyHash(name, key) {
		return nil, errVerifierHash
	}

	v := &verifier{
		name: name,
		hash: uint32(hash),
	}

	alg, key := key[0], key[1:]
	switch alg {
	default:
		return nil, errVerifierAlg

	case algBLS:
		pk, err := my_crypto.PublicKeyFromBytes(key)
		if err != nil {
			return nil, errVerifierID
		}

		v.pubkey = append([]byte(nil), key...)

		v.verify = func(msg, sig []byte) bool {
			parsedSig, err := my_crypto.SignatureFromBytes(sig)
			if err != nil {
				return false
			}
			return my_crypto.Verify(pk, msg, parsedSig)
		}
	}

	return v, nil
}

func chop(s, sep string) (before, after string) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+len(sep):]
}

// verifier is a trivial Verifier implementation.
type verifier struct {
	name   string
	hash   uint32
	pubkey []byte
	verify func([]byte, []byte) bool
}

func (v *verifier) PublicKeyBytes() ([]byte, error) {
	if len(v.pubkey) == 0 {
		return nil, errVerifierID
	}
	return append([]byte(nil), v.pubkey...), nil
}

func (v *verifier) Name() string                { return v.name }
func (v *verifier) KeyHash() uint32             { return v.hash }
func (v *verifier) Verify(msg, sig []byte) bool { return v.verify(msg, sig) }

func NewSigner(skey string) (Signer, error) {
	priv1, skey := chop(skey, "+")
	priv2, skey := chop(skey, "+")
	name, skey := chop(skey, "+")
	hash16, key64 := chop(skey, "+")
	hash, err1 := strconv.ParseUint(hash16, 16, 32)
	key, err2 := base64.StdEncoding.DecodeString(key64)
	if priv1 != "PRIVATE" || priv2 != "KEY" || len(hash16) != 8 || err1 != nil || err2 != nil || !isValidName(name) || len(key) == 0 {
		return nil, errSignerID
	}

	s := &signer{
		name: name,
		hash: uint32(hash),
	}

	var pubkey []byte

	alg, key := key[0], key[1:]
	switch alg {
	default:
		return nil, errSignerAlg

	case algBLS:
		if len(key) != 32 {
			return nil, errSignerID
		}

		blsSigner, err := my_crypto.NewBLSSignerFromSeed(name, uint32(hash), key)
		if err != nil {
			return nil, errSignerID
		}

		pubkeyBytes, err := blsSigner.PublicKeyBytes()
		if err != nil {
			return nil, errSignerID
		}

		pubkey = append([]byte{algBLS}, pubkeyBytes...)
		s.sign = blsSigner.Sign
	}

	if uint32(hash) != keyHash(name, pubkey) {
		return nil, errSignerHash
	}

	return s, nil
}

var (
	errSignerID   = errors.New("malformed verifier id")
	errSignerAlg  = errors.New("unknown verifier algorithm")
	errSignerHash = errors.New("invalid verifier hash")
)

// signer is a trivial Signer implementation.
type signer struct {
	name string
	hash uint32
	sign func([]byte) ([]byte, error)
}

func (s *signer) Name() string                    { return s.name }
func (s *signer) KeyHash() uint32                 { return s.hash }
func (s *signer) Sign(msg []byte) ([]byte, error) { return s.sign(msg) }

func GenerateKey(rand io.Reader, name string) (skey, vkey string, err error) {
	if !isValidName(name) {
		return "", "", errSignerID
	}

	var seed [32]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return "", "", err
	}

	blsSigner, err := my_crypto.NewBLSSignerFromSeed(name, 0, seed[:])
	if err != nil {
		return "", "", err
	}

	pubBytes, err := blsSigner.PublicKeyBytes()
	if err != nil {
		return "", "", err
	}

	pubkey := append([]byte{algBLS}, pubBytes...)
	privkey := append([]byte{algBLS}, seed[:]...)
	h := keyHash(name, pubkey)

	skey = fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s",
		name, h, base64.StdEncoding.EncodeToString(privkey))

	vkey = fmt.Sprintf("%s+%08x+%s",
		name, h, base64.StdEncoding.EncodeToString(pubkey))

	return skey, vkey, nil
}

func NewBLSVerifierKey(name string, key []byte) (string, error) {
	if !isValidName(name) {
		return "", errVerifierID
	}
	if len(key) != 48 {
		return "", fmt.Errorf("invalid public key size %d, expected 48", len(key))
	}

	pubkey := append([]byte{algBLS}, key...)
	hash := keyHash(name, pubkey)

	b64Key := base64.StdEncoding.EncodeToString(pubkey)
	return fmt.Sprintf("%s+%08x+%s", name, hash, b64Key), nil
}

// A Verifiers is a collection of known verifier keys.
type Verifiers interface {
	// Verifier returns the Verifier associated with the key
	// identified by the name and hash.
	// If the name, hash pair is unknown, Verifier should return
	// an UnknownVerifierError.
	Verifier(name string, hash uint32) (Verifier, error)
}

// An UnknownVerifierError indicates that the given key is not known.
// The Open function records signatures without associated verifiers as
// unverified signatures.
type UnknownVerifierError struct {
	Name    string
	KeyHash uint32
}

func (e *UnknownVerifierError) Error() string {
	return fmt.Sprintf("unknown key %s+%08x", e.Name, e.KeyHash)
}

// An ambiguousVerifierError indicates that the given name and hash
// match multiple keys passed to [VerifierList].
// (If this happens, some malicious actor has taken control of the
// verifier list, at which point we may as well give up entirely,
// but we diagnose the problem instead.)
type ambiguousVerifierError struct {
	name string
	hash uint32
}

func (e *ambiguousVerifierError) Error() string {
	return fmt.Sprintf("ambiguous key %s+%08x", e.name, e.hash)
}

// VerifierList returns a [Verifiers] implementation that uses the given list of verifiers.
func VerifierList(list ...Verifier) Verifiers {
	m := make(verifierMap)
	for _, v := range list {
		k := nameHash{v.Name(), v.KeyHash()}
		m[k] = append(m[k], v)
	}
	return m
}

type nameHash struct {
	name string
	hash uint32
}

type verifierMap map[nameHash][]Verifier

func (m verifierMap) Verifier(name string, hash uint32) (Verifier, error) {
	v, ok := m[nameHash{name, hash}]
	if !ok {
		return nil, &UnknownVerifierError{name, hash}
	}
	if len(v) > 1 {
		return nil, &ambiguousVerifierError{name, hash}
	}
	return v[0], nil
}

// A Note is a text and signatures.
type Note struct {
	Text           string      // text of note
	Sigs           []Signature // verified signatures
	UnverifiedSigs []Signature // unverified signatures
}

// A Signature is a single signature found in a note.
type Signature struct {
	// Name and Hash give the name and key hash
	// for the key that generated the signature.
	Name string
	Hash uint32

	// Base64 records the base64-encoded signature bytes.
	Base64 string
}

// An UnverifiedNoteError indicates that the note
// successfully parsed but had no verifiable signatures.
type UnverifiedNoteError struct {
	Note *Note
}

func (e *UnverifiedNoteError) Error() string {
	return "note has no verifiable signatures"
}

// An InvalidSignatureError indicates that the given key was known
// and the associated Verifier rejected the signature.
type InvalidSignatureError struct {
	Name string
	Hash uint32
}

func (e *InvalidSignatureError) Error() string {
	return fmt.Sprintf("invalid signature for key %s+%08x", e.Name, e.Hash)
}

var (
	errMalformedNote      = errors.New("malformed note")
	errInvalidSigner      = errors.New("invalid signer")
	errMismatchedVerifier = errors.New("verifier name or hash doesn't match signature")

	sigSplit  = []byte("\n\n")
	sigPrefix = []byte("— ")
)

func Open(msg []byte, known Verifiers) (*Note, error) {
	if known == nil {
		// Treat nil Verifiers as empty list, to produce useful error instead of crash.
		known = VerifierList()
	}

	// Must have valid UTF-8 with no non-newline ASCII control characters.
	for i := 0; i < len(msg); {
		r, size := utf8.DecodeRune(msg[i:])
		if r < 0x20 && r != '\n' || r == utf8.RuneError && size == 1 {
			return nil, errMalformedNote
		}
		i += size
	}

	// Must end with signature block preceded by blank line.
	split := bytes.LastIndex(msg, sigSplit)
	if split < 0 {
		return nil, errMalformedNote
	}
	text, sigs := msg[:split+1], msg[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, errMalformedNote
	}

	n := &Note{
		Text: string(text),
	}

	// Parse and verify signatures.
	// Ignore duplicate signatures.
	seen := make(map[nameHash]bool)
	seenUnverified := make(map[string]bool)
	numSig := 0
	for len(sigs) > 0 {
		// Pull out next signature line.
		// We know sigs[len(sigs)-1] == '\n', so IndexByte always finds one.
		i := bytes.IndexByte(sigs, '\n')
		line := sigs[:i]
		sigs = sigs[i+1:]

		if !bytes.HasPrefix(line, sigPrefix) {
			return nil, errMalformedNote
		}
		line = line[len(sigPrefix):]
		name, b64 := chop(string(line), " ")
		sig, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || !isValidName(name) || b64 == "" || len(sig) < 5 {
			return nil, errMalformedNote
		}
		hash := binary.BigEndian.Uint32(sig[0:4])
		sig = sig[4:]

		if numSig++; numSig > 100 {
			// Avoid spending forever parsing a note with many signatures.
			return nil, errMalformedNote
		}

		v, err := known.Verifier(name, hash)
		if _, ok := err.(*UnknownVerifierError); ok {
			// Drop repeated identical unverified signatures.
			if seenUnverified[string(line)] {
				continue
			}
			seenUnverified[string(line)] = true
			n.UnverifiedSigs = append(n.UnverifiedSigs, Signature{Name: name, Hash: hash, Base64: b64})
			continue
		}
		if err != nil {
			return nil, err
		}

		// Check that known.Verifier returned the right verifier.
		if v.Name() != name || v.KeyHash() != hash {
			return nil, errMismatchedVerifier
		}

		// Drop repeated signatures by a single verifier.
		if seen[nameHash{name, hash}] {
			continue
		}
		seen[nameHash{name, hash}] = true

		ok := v.Verify(text, sig)
		if !ok {
			return nil, &InvalidSignatureError{name, hash}
		}

		n.Sigs = append(n.Sigs, Signature{Name: name, Hash: hash, Base64: b64})
	}

	// Parsed and verified all the signatures.
	if len(n.Sigs) == 0 {
		return nil, &UnverifiedNoteError{n}
	}
	return n, nil
}

func Sign(n *Note, signers ...Signer) ([]byte, error) {
	var buf bytes.Buffer
	if !strings.HasSuffix(n.Text, "\n") {
		return nil, errMalformedNote
	}
	buf.WriteString(n.Text)

	// Prepare signatures.
	var sigs bytes.Buffer
	have := make(map[nameHash]bool)
	for _, s := range signers {
		name := s.Name()
		hash := s.KeyHash()
		have[nameHash{name, hash}] = true
		if !isValidName(name) {
			return nil, errInvalidSigner
		}

		sig, err := s.Sign(buf.Bytes()) // buf holds n.Text
		if err != nil {
			return nil, err
		}

		var hbuf [4]byte
		binary.BigEndian.PutUint32(hbuf[:], hash)
		b64 := base64.StdEncoding.EncodeToString(append(hbuf[:], sig...))
		sigs.WriteString("— ")
		sigs.WriteString(name)
		sigs.WriteString(" ")
		sigs.WriteString(b64)
		sigs.WriteString("\n")
	}

	buf.WriteString("\n")

	// Emit existing signatures not replaced by new ones.
	for _, list := range [][]Signature{n.Sigs, n.UnverifiedSigs} {
		for _, sig := range list {
			name, hash := sig.Name, sig.Hash
			if !isValidName(name) {
				return nil, errMalformedNote
			}
			if have[nameHash{name, hash}] {
				continue
			}
			// Double-check hash against base64.
			raw, err := base64.StdEncoding.DecodeString(sig.Base64)
			if err != nil || len(raw) < 4 || binary.BigEndian.Uint32(raw) != hash {
				return nil, errMalformedNote
			}
			buf.WriteString("— ")
			buf.WriteString(sig.Name)
			buf.WriteString(" ")
			buf.WriteString(sig.Base64)
			buf.WriteString("\n")
		}
	}
	buf.Write(sigs.Bytes())

	return buf.Bytes(), nil
}
