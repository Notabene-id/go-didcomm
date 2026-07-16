package didcomm_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/mr-tron/base58"

	didcomm "github.com/notabene-id/go-didcomm"
	"github.com/notabene-id/go-didcomm/internal/convert"
	"github.com/notabene-id/go-didcomm/softkey"
)

// TestPackSkipsNonX25519KeyAgreementKey reproduces the interop failure against a
// recipient whose keyAgreement lists a P-256 PII key before its X25519 transport
// key — a shape some VASP DID documents publish. Pack must skip the P-256 key and
// encrypt to the X25519 one, rather than blindly take keyAgreement[0] and fail
// with "unsupported key type".
func TestPackSkipsNonX25519KeyAgreementKey(t *testing.T) {
	senderKM, senderDoc := newX25519Party(t, "did:web:sender.example")
	recipientKM, recipientDoc := newX25519Party(t, "did:web:recipient.example")

	// Prepend a P-256 PII key to keyAgreement, ahead of the X25519 transport key.
	recipientDoc.KeyAgreement = append(
		[]didcomm.VerificationMethod{piiP256VM(t, recipientDoc.ID)},
		recipientDoc.KeyAgreement...,
	)

	resolver := didcomm.NewInMemoryResolver()
	resolver.Store(senderDoc)
	resolver.Store(recipientDoc)
	client := didcomm.NewClient(resolver, mustSoftkey(t, senderKM, recipientKM))

	msg := &didcomm.Message{
		ID:   "ka-select-1",
		Type: "https://example.com/echo",
		From: senderKM.DID,
		To:   []string{recipientKM.DID},
		Body: json.RawMessage(`{"note":"hi"}`),
	}

	packed, err := client.Pack(context.Background(), msg, didcomm.WithProfile(didcomm.ProfileAuthcrypt1PUv3))
	if err != nil {
		t.Fatalf("pack (must skip P-256 PII key, pick X25519): %v", err)
	}
	got, meta, err := client.Unpack(context.Background(), packed)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if got.ID != msg.ID || meta.SenderDID != senderKM.DID {
		t.Fatalf("round trip mismatch: id=%q sender=%q", got.ID, meta.SenderDID)
	}
}

// TestPackEncryptsToAllX25519KeyAgreementKeys confirms a message is encrypted to
// every X25519 keyAgreement key a recipient publishes, so the recipient can
// decrypt with whichever it holds — not only the first. The P-256 PII key is
// still skipped.
func TestPackEncryptsToAllX25519KeyAgreementKeys(t *testing.T) {
	senderKM, senderDoc := newX25519Party(t, "did:web:sender.example")
	const rdid = "did:web:recipient.example"
	kaA, vmA := newX25519Member(t, rdid, "#ka-a")
	kaB, vmB := newX25519Member(t, rdid, "#ka-b")
	recipientDoc := &didcomm.DIDDocument{
		ID:           rdid,
		KeyAgreement: []didcomm.VerificationMethod{piiP256VM(t, rdid), vmA, vmB},
	}

	resolver := didcomm.NewInMemoryResolver()
	resolver.Store(senderDoc)
	resolver.Store(recipientDoc)

	msg := &didcomm.Message{
		ID:   "multi-1",
		Type: "https://example.com/echo",
		From: senderKM.DID,
		To:   []string{rdid},
		Body: json.RawMessage(`{"note":"hi"}`),
	}
	packed, err := didcomm.NewClient(resolver, mustSoftkey(t, senderKM)).
		Pack(context.Background(), msg, didcomm.WithProfile(didcomm.ProfileAuthcrypt1PUv3))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	// The envelope carries a recipient entry for both X25519 keys, not the P-256.
	var jwe struct {
		Recipients []json.RawMessage `json:"recipients"`
	}
	if err := json.Unmarshal(packed, &jwe); err != nil {
		t.Fatal(err)
	}
	if len(jwe.Recipients) != 2 {
		t.Fatalf("recipients = %d, want 2 (both X25519 keys)", len(jwe.Recipients))
	}

	// A holder of only the first key and a holder of only the second can each open it.
	for _, km := range []*didcomm.KeyMaterial{kaA, kaB} {
		got, meta, uErr := didcomm.NewClient(resolver, mustSoftkey(t, km)).
			Unpack(context.Background(), packed)
		if uErr != nil {
			t.Fatalf("unpack with %s only: %v", km.KeyAgreementKID, uErr)
		}
		if got.ID != msg.ID || meta.SenderDID != senderKM.DID {
			t.Fatalf("round trip mismatch for %s", km.KeyAgreementKID)
		}
	}
}

// TestPackConvertsEd25519KeyAgreementKey confirms an Ed25519 key published for
// key agreement is converted to its X25519 (Montgomery) form and encrypted to,
// rather than being rejected as non-X25519.
func TestPackConvertsEd25519KeyAgreementKey(t *testing.T) {
	senderKM, senderDoc := newX25519Party(t, "did:web:sender.example")
	const rdid = "did:web:recipient.example"
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kaKID := rdid + "#ed-ka"
	recipientDoc := &didcomm.DIDDocument{
		ID:           rdid,
		KeyAgreement: []didcomm.VerificationMethod{{ID: kaKID, Type: "JsonWebKey2020", Controller: rdid, PublicKey: importJWK(t, edPub, kaKID)}},
	}
	resolver := didcomm.NewInMemoryResolver()
	resolver.Store(senderDoc)
	resolver.Store(recipientDoc)

	msg := &didcomm.Message{ID: "ed-1", Type: "https://example.com/echo", From: senderKM.DID, To: []string{rdid}, Body: json.RawMessage(`{}`)}
	packed, err := didcomm.NewClient(resolver, mustSoftkey(t, senderKM)).
		Pack(context.Background(), msg, didcomm.WithProfile(didcomm.ProfileAuthcrypt1PUv3))
	if err != nil {
		t.Fatalf("pack to Ed25519 keyAgreement key: %v", err)
	}
	if n := recipientCount(t, packed); n != 1 {
		t.Fatalf("recipients = %d, want 1", n)
	}
}

// TestPackDedupesEquivalentKeyAgreementKeys confirms a document that lists the
// same key twice — an Ed25519 key and its own X25519 Montgomery form — is
// encrypted to only once, not duplicated.
func TestPackDedupesEquivalentKeyAgreementKeys(t *testing.T) {
	senderKM, senderDoc := newX25519Party(t, "did:web:sender.example")
	const rdid = "did:web:recipient.example"
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xb, err := convert.Ed25519PublicToX25519(edPub)
	if err != nil {
		t.Fatal(err)
	}
	xPub, err := ecdh.X25519().NewPublicKey(xb)
	if err != nil {
		t.Fatal(err)
	}
	recipientDoc := &didcomm.DIDDocument{
		ID: rdid,
		KeyAgreement: []didcomm.VerificationMethod{
			{ID: rdid + "#x", Type: "JsonWebKey2020", Controller: rdid, PublicKey: importJWK(t, xPub, rdid+"#x")},
			{ID: rdid + "#ed", Type: "JsonWebKey2020", Controller: rdid, PublicKey: importJWK(t, edPub, rdid+"#ed")},
		},
	}
	resolver := didcomm.NewInMemoryResolver()
	resolver.Store(senderDoc)
	resolver.Store(recipientDoc)

	msg := &didcomm.Message{ID: "dedup-1", Type: "https://example.com/echo", From: senderKM.DID, To: []string{rdid}, Body: json.RawMessage(`{}`)}
	packed, err := didcomm.NewClient(resolver, mustSoftkey(t, senderKM)).
		Pack(context.Background(), msg, didcomm.WithProfile(didcomm.ProfileAuthcrypt1PUv3))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if n := recipientCount(t, packed); n != 1 {
		t.Fatalf("recipients = %d, want 1 (deduped)", n)
	}
}

// TestParseSkipsUnsupportedKeyType confirms an unsupported keyAgreement key
// (unknown type, base58-encoded) does not fail the whole document — the usable
// X25519 key remains selectable.
func TestParseSkipsUnsupportedKeyType(t *testing.T) {
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x58 := base58.Encode(xPriv.PublicKey().Bytes())
	exotic58 := base58.Encode(make([]byte, 33)) // valid base58, unsupported type
	docJSON := `{"id":"did:web:x","keyAgreement":[` +
		`{"id":"did:web:x#exotic","type":"EcdsaSecp256k1VerificationKey2019","publicKeyBase58":"` + exotic58 + `"},` +
		`{"id":"did:web:x#ka","type":"X25519KeyAgreementKey2019","publicKeyBase58":"` + x58 + `"}]}`

	var doc didcomm.DIDDocument
	if err = json.Unmarshal([]byte(docJSON), &doc); err != nil {
		t.Fatalf("document must parse despite an unsupported key: %v", err)
	}
	vm, err := doc.FindEncryptionKey()
	if err != nil {
		t.Fatalf("FindEncryptionKey: %v", err)
	}
	if vm.ID != "did:web:x#ka" {
		t.Fatalf("selected %q, want did:web:x#ka", vm.ID)
	}
}

func recipientCount(t *testing.T, packed []byte) int {
	t.Helper()
	var jwe struct {
		Recipients []json.RawMessage `json:"recipients"`
	}
	if err := json.Unmarshal(packed, &jwe); err != nil {
		t.Fatal(err)
	}
	return len(jwe.Recipients)
}

func newX25519Party(t *testing.T, did string) (*didcomm.KeyMaterial, *didcomm.DIDDocument) {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKID, kaKID := did+"#key-1", did+"#key-agreement"
	km := &didcomm.KeyMaterial{
		DID:             did,
		SigningKID:      signingKID,
		KeyAgreementKID: kaKID,
		Ed25519Seed:     edPriv.Seed(),
		X25519Private:   xPriv.Bytes(),
	}
	doc := &didcomm.DIDDocument{
		ID: did,
		Authentication: []didcomm.VerificationMethod{
			{ID: signingKID, Type: "JsonWebKey2020", Controller: did, PublicKey: importJWK(t, edPub, signingKID)},
		},
		KeyAgreement: []didcomm.VerificationMethod{
			{ID: kaKID, Type: "JsonWebKey2020", Controller: did, PublicKey: importJWK(t, xPriv.PublicKey(), kaKID)},
		},
	}
	return km, doc
}

// newX25519Member builds one X25519 key-agreement key (key material + its
// verification method) under did with the given fragment.
func newX25519Member(t *testing.T, did, frag string) (*didcomm.KeyMaterial, didcomm.VerificationMethod) {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kaKID := did + frag
	km := &didcomm.KeyMaterial{
		DID:             did,
		SigningKID:      did + "#sign" + frag,
		KeyAgreementKID: kaKID,
		Ed25519Seed:     edPriv.Seed(),
		X25519Private:   xPriv.Bytes(),
	}
	vm := didcomm.VerificationMethod{
		ID: kaKID, Type: "JsonWebKey2020", Controller: did, PublicKey: importJWK(t, xPriv.PublicKey(), kaKID),
	}
	return km, vm
}

// piiP256VM builds a P-256 JsonWebKey2020 verification method, mirroring a
// non-transport PII key some DID documents place in keyAgreement.
func piiP256VM(t *testing.T, did string) didcomm.VerificationMethod {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := did + "#pii"
	return didcomm.VerificationMethod{ID: kid, Type: "JsonWebKey2020", Controller: did, PublicKey: importJWK(t, ec.Public(), kid)}
}

func importJWK(t *testing.T, pub any, kid string) jwk.Key {
	t.Helper()
	key, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("import jwk: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	return key
}

func mustSoftkey(t *testing.T, kms ...*didcomm.KeyMaterial) didcomm.KeyStore {
	t.Helper()
	s, err := softkey.New(kms...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
