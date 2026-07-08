package softkey_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"testing"

	didcomm "github.com/notabene-id/go-didcomm"
	"github.com/notabene-id/go-didcomm/softkey"
)

func TestStoreSignAndDiffieHellman(t *testing.T) {
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
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()

	sig, err := store.Sign(ctx, alice.SigningKID, []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub := ed25519.NewKeyFromSeed(alice.Ed25519Seed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte("payload"), sig) {
		t.Fatal("signature did not verify")
	}

	// Diffie-Hellman is symmetric across the two parties' keys.
	bobPub := mustX25519Public(t, bob.X25519Private)
	alicePub := mustX25519Public(t, alice.X25519Private)
	ab, err := store.DiffieHellman(ctx, alice.KeyAgreementKID, bobPub)
	if err != nil {
		t.Fatalf("dh ab: %v", err)
	}
	ba, err := store.DiffieHellman(ctx, bob.KeyAgreementKID, alicePub)
	if err != nil {
		t.Fatalf("dh ba: %v", err)
	}
	if string(ab) != string(ba) {
		t.Fatal("shared secrets differ")
	}
}

func TestStoreUnknownKey(t *testing.T) {
	store, err := softkey.New()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := store.Sign(ctx, "did:x#missing", nil); !errors.Is(err, didcomm.ErrKeyNotFound) {
		t.Fatalf("sign err = %v, want ErrKeyNotFound", err)
	}
	if _, err := store.DiffieHellman(ctx, "did:x#missing", make([]byte, 32)); !errors.Is(err, didcomm.ErrKeyNotFound) {
		t.Fatalf("dh err = %v, want ErrKeyNotFound", err)
	}
}

func TestStoreRejectsBadMaterial(t *testing.T) {
	if _, err := softkey.New(&didcomm.KeyMaterial{DID: "x", Ed25519Seed: []byte("short")}); err == nil {
		t.Fatal("expected error for short seed")
	}
}

func mustX25519Public(t *testing.T, priv []byte) []byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}
