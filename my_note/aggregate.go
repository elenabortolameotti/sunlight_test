package mynote

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"filippo.io/sunlight/internal/my_crypto"
)

type WitnessID struct {
	Name string
	Hash uint32
}

type AggregateWitnessSignature struct {
	Witnesses []WitnessID
	Sig       []byte
}

type WitnessVerifier interface {
	Verifier
	PublicKeyBytes() ([]byte, error)
}

var (
	errNoWitnesses               = errors.New("no witnesses")
	errDuplicateWitness          = errors.New("duplicate witness")
	errInvalidAggregateSignature = errors.New("invalid aggregate signature")
	errInvalidWitnessVerifier    = errors.New("invalid witness verifier")
)

var aggSigPrefix = []byte("— witness-agg ")

type AggregateNote struct {
	Text string
	Agg  *AggregateWitnessSignature
}

type aggregatePayload struct {
	Witnesses []WitnessID `json:"witnesses"`
	Sig       string      `json:"sig"`
}

func AggregateSign(msg []byte, signers ...Signer) (*AggregateWitnessSignature, error) {
	if len(msg) == 0 {
		return nil, errMalformedNote
	}
	if len(signers) == 0 {
		return nil, errNoWitnesses
	}

	seen := make(map[nameHash]bool)
	witnesses := make([]WitnessID, 0, len(signers))
	sigs := make([][]byte, 0, len(signers))

	for _, s := range signers {
		name := s.Name()
		hash := s.KeyHash()

		if !isValidName(name) {
			return nil, errInvalidSigner
		}

		k := nameHash{name, hash}
		if seen[k] {
			return nil, errDuplicateWitness
		}
		seen[k] = true

		sig, err := s.Sign(msg)
		if err != nil {
			return nil, err
		}

		witnesses = append(witnesses, WitnessID{Name: name, Hash: hash})
		sigs = append(sigs, sig)
	}

	aggSig, err := my_crypto.AggregateSignaturesBytes(sigs)
	if err != nil {
		return nil, err
	}

	return &AggregateWitnessSignature{
		Witnesses: witnesses,
		Sig:       aggSig,
	}, nil
}

func VerifyAggregate(msg []byte, agg *AggregateWitnessSignature, known Verifiers) error {
	if len(msg) == 0 {
		return errMalformedNote
	}
	if agg == nil || len(agg.Witnesses) == 0 || len(agg.Sig) == 0 {
		return errInvalidAggregateSignature
	}
	if known == nil {
		known = VerifierList()
	}

	seen := make(map[nameHash]bool)
	pubkeys := make([][]byte, 0, len(agg.Witnesses))

	for _, w := range agg.Witnesses {
		if !isValidName(w.Name) {
			return errInvalidAggregateSignature
		}

		k := nameHash{w.Name, w.Hash}
		if seen[k] {
			return errDuplicateWitness
		}
		seen[k] = true

		v, err := known.Verifier(w.Name, w.Hash)
		if err != nil {
			return err
		}

		wv, ok := v.(WitnessVerifier)
		if !ok {
			return errInvalidWitnessVerifier
		}

		pubkey, err := wv.PublicKeyBytes()
		if err != nil {
			return err
		}

		pubkeys = append(pubkeys, pubkey)
	}

	ok, err := my_crypto.VerifyAggregateBytes(pubkeys, msg, agg.Sig)
	if err != nil {
		return err
	}
	if !ok {
		return errInvalidAggregateSignature
	}

	return nil
}

// Idea:
// <testo della note>
// witness-agg name1+hash1,name2+hash2 base64(aggregateSig)

// es: checkpoint text...
// — witness-agg alice+12345678,bob+abcdef00 MEUCIQD...

func SignAggregateNote(n *Note, signers ...Signer) ([]byte, error) {
	var buf bytes.Buffer

	if n == nil || !strings.HasSuffix(n.Text, "\n") {
		return nil, errMalformedNote
	}
	buf.WriteString(n.Text)

	// aggregatesign: prende il testo della note;
	// lo fa firmare da ogni witness;
	// raccoglie le firme singole;
	// le aggrega in una sola firma BLS;
	agg, err := AggregateSign([]byte(n.Text), signers...)
	if err != nil {
		return nil, err
	}

	var witnesses []string
	for _, w := range agg.Witnesses {
		if !isValidName(w.Name) {
			return nil, errInvalidSigner
		}
		witnesses = append(witnesses, fmt.Sprintf("%s+%08x", w.Name, w.Hash))
	}

	buf.WriteString("\n")
	buf.Write(aggSigPrefix)
	buf.WriteString(strings.Join(witnesses, ","))
	buf.WriteString(" ")
	buf.WriteString(base64.StdEncoding.EncodeToString(agg.Sig))
	buf.WriteString("\n")

	return buf.Bytes(), nil
}

// Scopo: prende una nota testuale aggregata, la parsea, estrae testo, witness e firma,
// poi verifica la firma aggregata.
func OpenAggregateNote(msg []byte, known Verifiers) (*AggregateNote, error) {
	if known == nil {
		known = VerifierList()
	}

	for i := 0; i < len(msg); {
		r, size := utf8.DecodeRune(msg[i:])
		if r < 0x20 && r != '\n' || r == utf8.RuneError && size == 1 {
			return nil, errMalformedNote
		}
		i += size
	}

	split := bytes.LastIndex(msg, sigSplit)
	if split < 0 {
		return nil, errMalformedNote
	}

	text, sigs := msg[:split+1], msg[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, errMalformedNote
	}

	line := bytes.TrimSuffix(sigs, []byte("\n"))
	if !bytes.HasPrefix(line, aggSigPrefix) {
		return nil, errMalformedNote
	}

	line = line[len(aggSigPrefix):]
	witnessList, sig64 := chop(string(line), " ")
	if witnessList == "" || sig64 == "" {
		return nil, errMalformedNote
	}

	sig, err := base64.StdEncoding.DecodeString(sig64)
	if err != nil || len(sig) == 0 {
		return nil, errMalformedNote
	}

	witnessParts := strings.Split(witnessList, ",")
	witnesses := make([]WitnessID, 0, len(witnessParts))

	for _, part := range witnessParts {
		name, hash16 := chop(part, "+")
		hash, err := strconv.ParseUint(hash16, 16, 32)
		if len(hash16) != 8 || err != nil || !isValidName(name) {
			return nil, errMalformedNote
		}

		witnesses = append(witnesses, WitnessID{
			Name: name,
			Hash: uint32(hash),
		})
	}

	agg := &AggregateWitnessSignature{
		Witnesses: witnesses,
		Sig:       sig,
	}

	if err := VerifyAggregate(text, agg, known); err != nil {
		return nil, err
	}

	return &AggregateNote{
		Text: string(text),
		Agg:  agg,
	}, nil
}
