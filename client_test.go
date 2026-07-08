package didcomm_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	didcomm "github.com/notabene-id/go-didcomm"
	"github.com/notabene-id/go-didcomm/softkey"
)

var b64 = base64.RawURLEncoding

// testParties sets up Alice and Bob as did:key identities sharing one softkey
// store, with a resolver that auto-resolves did:key.
type testParties struct {
	client *didcomm.Client
	alice  *didcomm.KeyMaterial
	bob    *didcomm.KeyMaterial
}

func newParties(t *testing.T) testParties {
	t.Helper()
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
	return testParties{client: didcomm.NewClient(resolver, store), alice: alice, bob: bob}
}

func (p testParties) message() *didcomm.Message {
	return &didcomm.Message{
		ID:   "msg-1",
		Type: "https://example.com/greeting",
		From: p.alice.DID,
		To:   []string{p.bob.DID},
		Body: json.RawMessage(`{"text":"hello"}`),
	}
}

// TestRoundTripProfiles verifies every authenticated profile packs, unpacks, and
// binds the verified sender to "from".
func TestRoundTripProfiles(t *testing.T) {
	p := newParties(t)
	ctx := context.Background()

	profiles := []struct {
		name    string
		profile didcomm.Profile
		mode    didcomm.Mode
		enc     bool
	}{
		{"signed-anoncrypt", didcomm.ProfileSignedAnoncrypt, didcomm.ModeSigned, true},
		{"authcrypt-1pu-v3", didcomm.ProfileAuthcrypt1PUv3, didcomm.ModeAuthcrypt, true},
		{"authcrypt-1pu-v4", didcomm.ProfileAuthcrypt1PUv4, didcomm.ModeAuthcrypt, true},
		{"signed-only", didcomm.ProfileSigned, didcomm.ModeSigned, false},
	}
	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			packed, err := p.client.Pack(ctx, p.message(), didcomm.WithProfile(tc.profile))
			if err != nil {
				t.Fatalf("pack: %v", err)
			}
			msg, meta, err := p.client.Unpack(ctx, packed)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if msg.ID != "msg-1" {
				t.Fatalf("message id = %q", msg.ID)
			}
			if meta.SenderDID != p.alice.DID {
				t.Fatalf("sender = %q, want %q", meta.SenderDID, p.alice.DID)
			}
			if meta.Mode != tc.mode || meta.Encrypted != tc.enc {
				t.Fatalf("mode/enc = %d/%v, want %d/%v", meta.Mode, meta.Encrypted, tc.mode, tc.enc)
			}
		})
	}
}

// TestRoundTripCompactAndCBC covers the compact serialization and the
// A256CBC-HS512 content encryption paths.
func TestRoundTripCompactAndCBC(t *testing.T) {
	p := newParties(t)
	ctx := context.Background()

	packed, err := p.client.Pack(
		ctx, p.message(),
		didcomm.WithProfile(didcomm.ProfileSignedAnoncrypt),
		didcomm.WithContentEncryption(didcomm.ContentA256CBCHS512),
		didcomm.WithSerialization(didcomm.Compact),
	)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	msg, meta, err := p.client.Unpack(ctx, packed)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if msg.ID != "msg-1" || meta.SenderDID != p.alice.DID {
		t.Fatalf("round trip mismatch: id=%q sender=%q", msg.ID, meta.SenderDID)
	}
}

// TestUnpackRejectsPlain confirms an unsigned message is rejected by Unpack and
// only accepted by UnpackUnverified with no verified sender. This is the
// regression for the plain-message injection vulnerability (TX-1296).
func TestUnpackRejectsPlain(t *testing.T) {
	p := newParties(t)
	ctx := context.Background()
	plain := []byte(`{"id":"x","type":"t","from":"did:web:victim","body":{}}`)

	if _, _, err := p.client.Unpack(ctx, plain); !errors.Is(err, didcomm.ErrUnauthenticated) {
		t.Fatalf("Unpack(plain) err = %v, want ErrUnauthenticated", err)
	}

	msg, meta, err := p.client.UnpackUnverified(ctx, plain)
	if err != nil {
		t.Fatalf("UnpackUnverified(plain): %v", err)
	}
	if meta.SenderDID != "" {
		t.Fatalf("plain SenderDID = %q, want empty", meta.SenderDID)
	}
	if msg.From != "did:web:victim" {
		t.Fatalf("from = %q", msg.From) // present but explicitly unverified
	}
}

// TestAnoncryptRequiresUnverified confirms anonymous encryption is rejected by
// Unpack (no verifiable sender) and returned by UnpackUnverified.
func TestAnoncryptRequiresUnverified(t *testing.T) {
	p := newParties(t)
	ctx := context.Background()

	packed, err := p.client.Pack(ctx, p.message(), didcomm.WithProfile(didcomm.ProfileAnoncrypt))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if _, _, uErr := p.client.Unpack(ctx, packed); !errors.Is(uErr, didcomm.ErrUnauthenticated) {
		t.Fatalf("Unpack(anoncrypt) err = %v, want ErrUnauthenticated", uErr)
	}
	msg, meta, err := p.client.UnpackUnverified(ctx, packed)
	if err != nil {
		t.Fatalf("UnpackUnverified(anoncrypt): %v", err)
	}
	if meta.Mode != didcomm.ModeAnoncrypt || meta.SenderDID != "" || msg.ID != "msg-1" {
		t.Fatalf("anoncrypt meta = %+v", meta)
	}
}

// TestPackErrors covers the pack-time guard rails.
func TestPackErrors(t *testing.T) {
	p := newParties(t)
	ctx := context.Background()

	noID := &didcomm.Message{Type: "t", Body: []byte(`{}`)}
	if _, err := p.client.Pack(ctx, noID); !errors.Is(err, didcomm.ErrInvalidMessage) {
		t.Fatalf("missing id err = %v, want ErrInvalidMessage", err)
	}
	noFrom := &didcomm.Message{ID: "1", Type: "t", To: []string{p.bob.DID}, Body: []byte(`{}`)}
	_, err := p.client.Pack(ctx, noFrom, didcomm.WithProfile(didcomm.ProfileSigned))
	if !errors.Is(err, didcomm.ErrNoSender) {
		t.Fatalf("missing from err = %v, want ErrNoSender", err)
	}
}

// TestUnpackRejectsSenderSpoof confirms a validly-signed message whose "from"
// differs from the signer is rejected — the signed-message spoofing variant the
// original library missed.
func TestUnpackRejectsSenderSpoof(t *testing.T) {
	p := newParties(t)
	ctx := context.Background()

	// Alice signs a message that claims to be from Bob.
	spoof := signAs(t, p.alice, &didcomm.Message{
		ID: "spoof-1", Type: "t", From: p.bob.DID, Body: json.RawMessage(`{}`),
	})

	if _, _, err := p.client.Unpack(ctx, spoof); !errors.Is(err, didcomm.ErrSenderMismatch) {
		t.Fatalf("Unpack(spoof) err = %v, want ErrSenderMismatch", err)
	}
}

// TestUnpackRejectsTamperedSignature confirms a broken signature fails with the
// opaque verification error.
func TestUnpackRejectsTamperedSignature(t *testing.T) {
	p := newParties(t)
	ctx := context.Background()

	good := signAs(t, p.alice, &didcomm.Message{
		ID: "s", Type: "t", From: p.alice.DID, Body: json.RawMessage(`{}`),
	})
	var jws map[string]string
	if err := json.Unmarshal(good, &jws); err != nil {
		t.Fatal(err)
	}
	sig, err := b64.DecodeString(jws["signature"])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xFF
	jws["signature"] = b64.EncodeToString(sig)
	tampered, err := json.Marshal(jws)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.client.Unpack(ctx, tampered); !errors.Is(err, didcomm.ErrDecryptFailed) {
		t.Fatalf("Unpack(tampered) err = %v, want ErrDecryptFailed", err)
	}
}

// signAs builds a flattened JSON JWS over msg signed by the party's Ed25519 key,
// simulating a wire message an attacker (or peer) could send.
func signAs(t *testing.T, km *didcomm.KeyMaterial, msg *didcomm.Message) []byte {
	t.Helper()
	payload, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]string{
		"typ": "application/didcomm-signed+json", "alg": "EdDSA", "kid": km.SigningKID,
	})
	if err != nil {
		t.Fatal(err)
	}
	protectedB64 := b64.EncodeToString(header)
	payloadB64 := b64.EncodeToString(payload)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(km.Ed25519Seed), []byte(protectedB64+"."+payloadB64))

	out, err := json.Marshal(map[string]string{
		"payload": payloadB64, "protected": protectedB64, "signature": b64.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
