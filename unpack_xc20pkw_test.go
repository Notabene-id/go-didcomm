package didcomm_test

import (
	"context"
	"crypto/ecdh"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	didcomm "github.com/notabene-id/go-didcomm"
	"github.com/notabene-id/go-didcomm/softkey"
)

//go:embed testdata/xc20pkw_authcrypt.json
var xc20pkwEnvelope []byte

// Fixed test vector: an ECDH-1PU (draft-03) authcrypt JWE sealed with
// XChaCha20-Poly1305 (alg ECDH-1PU+XC20PKW, enc XC20P), as emitted by DIDComm-JS
// senders — alg/epk and the key-wrap iv/tag live in the per-recipient header.
// Keys are throwaway test material.
const (
	xcSenderDID     = "did:web:sender.example"
	xcSenderKAKid   = "did:web:sender.example#key-1"
	xcSenderPub     = "pzthwY3lDE5Psd09xw25q89AdxvkfUgEb-Vs4c-hmX0"
	xcRecipientDID  = "did:web:recipient.example"
	xcRecipientKA   = "did:web:recipient.example#key-1"
	xcRecipientPriv = "eB__AtWqOjYET7yGWibtY0IqnLRWcUImicENbXGExVA"
)

// TestUnpackXC20PKWAuthcrypt decrypts an ECDH-1PU+XC20PKW / XC20P authcrypt JWE
// and authenticates the sender via skid, proving interoperability with the
// XChaCha20-Poly1305 DIDComm profile whose alg/epk/iv/tag sit in the
// per-recipient header.
func TestUnpackXC20PKWAuthcrypt(t *testing.T) {
	store, err := softkey.New(&didcomm.KeyMaterial{
		DID:             xcRecipientDID,
		SigningKID:      xcRecipientDID + "#key-2",
		KeyAgreementKID: xcRecipientKA,
		Ed25519Seed:     make([]byte, 32), // unused: authcrypt needs no signing key
		X25519Private:   mustB64(t, xcRecipientPriv),
	})
	if err != nil {
		t.Fatal(err)
	}

	resolver := didcomm.NewInMemoryResolver()
	resolver.Store(xcSenderDoc(t))

	msg, meta, err := didcomm.NewClient(resolver, store).Unpack(context.Background(), xc20pkwEnvelope)
	if err != nil {
		t.Fatalf("unpack XC20PKW authcrypt: %v", err)
	}
	if meta.Mode != didcomm.ModeAuthcrypt {
		t.Fatalf("mode = %d, want authcrypt", meta.Mode)
	}
	if meta.SenderDID != xcSenderDID {
		t.Fatalf("verified sender = %q, want %q", meta.SenderDID, xcSenderDID)
	}
	if msg.ID != "xc20pkw-authcrypt-1" {
		t.Fatalf("id = %q", msg.ID)
	}
	if len(msg.To) != 1 || msg.To[0] != xcRecipientDID {
		t.Fatalf("to = %v, want [%q]", msg.To, xcRecipientDID)
	}
	var body struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body.Note == "" {
		t.Fatalf("body not decrypted: %s", msg.Body)
	}
}

func xcSenderDoc(t *testing.T) *didcomm.DIDDocument {
	t.Helper()
	pub, err := ecdh.X25519().NewPublicKey(mustB64(t, xcSenderPub))
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, xcSenderKAKid); err != nil {
		t.Fatal(err)
	}
	return &didcomm.DIDDocument{
		ID: xcSenderDID,
		KeyAgreement: []didcomm.VerificationMethod{
			{ID: xcSenderKAKid, Type: "JsonWebKey2020", Controller: xcSenderDID, PublicKey: key},
		},
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	out, err := b64.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return out
}
