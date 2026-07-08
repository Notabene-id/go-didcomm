package didcomm_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	didcomm "github.com/notabene-id/go-didcomm"
	"github.com/notabene-id/go-didcomm/internal/jose"
	"github.com/notabene-id/go-didcomm/softkey"
)

// protectedHeader decodes the base64url "protected" header of a general-JSON JWE.
func protectedHeader(t *testing.T, env []byte) map[string]any {
	t.Helper()
	var wire struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal(env, &wire); err != nil {
		t.Fatalf("parse JWE: %v", err)
	}
	raw, err := b64.DecodeString(wire.Protected)
	if err != nil {
		t.Fatalf("decode protected: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("parse protected: %v", err)
	}
	return hdr
}

func expectedAPV(kids ...string) string {
	sum := sha256.Sum256([]byte(join(kids)))
	return b64.EncodeToString(sum[:])
}

// join sorts and "."-concatenates kids, mirroring the DIDComm apv rule. Kept
// trivial and independent of the library so the test asserts against a second
// implementation of the algorithm.
func join(kids []string) string {
	sorted := append([]string(nil), kids...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	out := ""
	for i, k := range sorted {
		if i > 0 {
			out += "."
		}
		out += k
	}
	return out
}

// TestPackSetsAPVForAnoncrypt confirms the anoncrypt/signed-anoncrypt envelope
// carries the spec apv and no apu (anonymous sender).
func TestPackSetsAPVForAnoncrypt(t *testing.T) {
	p := newParties(t)
	env, err := p.client.Pack(context.Background(), p.message(),
		didcomm.WithProfile(didcomm.ProfileSignedAnoncrypt))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	hdr := protectedHeader(t, env)

	if got, want := hdr["apv"], expectedAPV(p.bob.KeyAgreementKID); got != want {
		t.Fatalf("apv = %v, want %v", got, want)
	}
	if _, ok := hdr["apu"]; ok {
		t.Fatalf("anoncrypt must not carry apu, got %v", hdr["apu"])
	}
	if _, ok := hdr["skid"]; ok {
		t.Fatalf("anoncrypt must not carry skid, got %v", hdr["skid"])
	}
}

// TestPackSetsAPUAPVForAuthcrypt confirms authcrypt carries apu = base64url(skid)
// and the apv over the recipient set.
func TestPackSetsAPUAPVForAuthcrypt(t *testing.T) {
	p := newParties(t)
	env, err := p.client.Pack(context.Background(), p.message(),
		didcomm.WithProfile(didcomm.ProfileAuthcrypt1PUv3))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	hdr := protectedHeader(t, env)

	if got, want := hdr["skid"], p.alice.KeyAgreementKID; got != want {
		t.Fatalf("skid = %v, want %v", got, want)
	}
	if got, want := hdr["apu"], b64.EncodeToString([]byte(p.alice.KeyAgreementKID)); got != want {
		t.Fatalf("apu = %v, want %v", got, want)
	}
	if got, want := hdr["apv"], expectedAPV(p.bob.KeyAgreementKID); got != want {
		t.Fatalf("apv = %v, want %v", got, want)
	}
}

// TestUnpackRejectsMissingAPV confirms a non-compliant peer that omits apv is
// rejected. Such an envelope would otherwise decrypt cleanly (the empty apv is
// self-consistent between its KDF and header), so this isolates the binding
// check from the AAD, which cannot see a missing field.
func TestUnpackRejectsMissingAPV(t *testing.T) {
	ctx := context.Background()
	_, alice, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bob, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	store, err := softkey.New(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := didcomm.DefaultResolver()
	client := didcomm.NewClient(resolver, store)

	// A well-formed inner signed message from Alice to Bob, anoncrypted to Bob
	// but with apv omitted.
	inner := signAs(t, alice, &didcomm.Message{
		ID: "no-apv", Type: "t", From: alice.DID, To: []string{bob.DID},
		Body: json.RawMessage(`{}`),
	})
	env := anoncryptTo(t, bob.KeyAgreementKID, bob.X25519Private, nil, inner)

	if _, _, err := client.Unpack(ctx, env); !errors.Is(err, didcomm.ErrDecryptFailed) {
		t.Fatalf("Unpack(missing apv) err = %v, want ErrDecryptFailed", err)
	}

	// Sanity check: the identical envelope WITH the correct apv unpacks.
	apv := sha256.Sum256([]byte(bob.KeyAgreementKID))
	envOK := anoncryptTo(t, bob.KeyAgreementKID, bob.X25519Private, apv[:], inner)
	if _, _, err := client.Unpack(ctx, envOK); err != nil {
		t.Fatalf("Unpack(correct apv) err = %v, want nil", err)
	}
}

// TestUnpackRejectsExpired confirms a message whose expires_time has passed is
// rejected, and a future expiry is accepted.
func TestUnpackRejectsExpired(t *testing.T) {
	p := newParties(t)
	ctx := context.Background()

	past := time.Unix(1000, 0).UTC() // 1970
	expired := p.message()
	expired.ExpiresAt = &past
	if _, _, err := p.client.Unpack(ctx, mustPack(t, p, expired)); !errors.Is(err, didcomm.ErrMessageExpired) {
		t.Fatalf("Unpack(expired) err = %v, want ErrMessageExpired", err)
	}

	future := time.Now().Add(time.Hour)
	fresh := p.message()
	fresh.ExpiresAt = &future
	if _, _, err := p.client.Unpack(ctx, mustPack(t, p, fresh)); err != nil {
		t.Fatalf("Unpack(fresh) err = %v, want nil", err)
	}
}

// mustPack packs with default options or fails the test.
func mustPack(t *testing.T, p testParties, msg *didcomm.Message) []byte {
	t.Helper()
	env, err := p.client.Pack(context.Background(), msg)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return env
}

// TestSurreptitiousForwardingRejected is the end-to-end anti-forwarding check:
// Alice signs a message addressed to Bob; a malicious Bob re-encrypts that exact
// signed payload (anoncrypt) to Charlie. Charlie's Unpack verifies Alice's
// signature but rejects the message because Charlie is not in "to".
func TestSurreptitiousForwardingRejected(t *testing.T) {
	ctx := context.Background()
	_, alice, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bob, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, charlie, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	store, err := softkey.New(alice, bob, charlie)
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := didcomm.DefaultResolver()
	client := didcomm.NewClient(resolver, store)

	// Alice's inner signed JWS, addressed to Bob only.
	innerJWS := signAs(t, alice, &didcomm.Message{
		ID: "fwd-1", Type: "t", From: alice.DID, To: []string{bob.DID},
		Body: json.RawMessage(`{}`),
	})

	// Malicious re-encryption (anoncrypt) of that payload to Charlie.
	apv := sha256.Sum256([]byte(charlie.KeyAgreementKID))
	forged := anoncryptTo(t, charlie.KeyAgreementKID, charlie.X25519Private, apv[:], innerJWS)

	if _, _, err := client.Unpack(ctx, forged); !errors.Is(err, didcomm.ErrRecipientMismatch) {
		t.Fatalf("Unpack(forwarded) err = %v, want ErrRecipientMismatch", err)
	}
}

// anoncryptTo builds an ECDH-ES anoncrypt JWE to a single recipient, exactly as a
// forwarding attacker with only the recipient's public key could. apv is passed
// through verbatim so tests can exercise both compliant and apv-omitting peers.
func anoncryptTo(t *testing.T, recipKID string, recipX25519Priv, apv, plaintext []byte) []byte {
	t.Helper()
	recipPriv, err := ecdh.X25519().NewPrivateKey(recipX25519Priv)
	if err != nil {
		t.Fatal(err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	z, err := eph.ECDH(recipPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	env, err := jose.Encrypt(&jose.EncryptRequest{
		Enc: jose.EncA256GCM, Alg: jose.AlgECDHESA256KW, Serialization: jose.GeneralJSON,
		Typ: "application/didcomm-encrypted+json", EphemeralPub: eph.PublicKey().Bytes(),
		APV: apv, Plaintext: plaintext,
		Recipients: []jose.Recipient{{KID: recipKID, Z: z}},
	})
	if err != nil {
		t.Fatalf("build anoncrypt: %v", err)
	}
	return env
}
