package my_crypto

import (
	"crypto/rand"
	"testing"

	blst "github.com/supranational/blst/bindings/go"
)

func TestVerificaSeria(t *testing.T) {
	// Setup iniziale
	ikm := make([]byte, 32)
	rand.Read(ikm)
	sk := blst.KeyGen(ikm)
	pk := new(blst.P1Affine).From(sk)
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

	msgGiusto := []byte("Messaggio Originale")
	msgFalso := []byte("Messaggio Manomesso")

	// Creiamo la firma sul messaggio GIUSTO
	sig := new(blst.P2Affine).Sign(sk, msgGiusto, dst)

	// TEST 1: Deve passare
	if !sig.Verify(true, pk, true, msgGiusto, dst) {
		t.Fatal("ERRORE: La libreria non riconosce la firma valida!")
	}

	// TEST 2: Deve FALLIRE (e noi lo facciamo fallire apposta)
	// Se la libreria è corretta, sig.Verify restituirà FALSE.
	// Se restituisce TRUE sul messaggio falso, allora forziamo l'errore del test.
	if sig.Verify(true, pk, true, msgFalso, dst) {
		t.Errorf("FALLIMENTO SICUREZZA: La libreria ha accettato il messaggio falso!")
	} else {
		t.Log("SUCCESSO: La libreria ha correttamente rifiutato il messaggio manomesso.")
	}
}
