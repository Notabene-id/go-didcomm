package convert

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEd25519PublicToX25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x25519Pub, err := Ed25519PublicToX25519(pub)
	if err != nil {
		t.Fatal(err)
	}

	if len(x25519Pub) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(x25519Pub))
	}
}

func TestEd25519PublicToX25519_Deterministic(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x1, err := Ed25519PublicToX25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	x2, err := Ed25519PublicToX25519(pub)
	if err != nil {
		t.Fatal(err)
	}

	if string(x1) != string(x2) {
		t.Fatal("conversion should be deterministic")
	}
}

func TestEd25519PublicToX25519_InvalidKey(t *testing.T) {
	_, err := Ed25519PublicToX25519([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestEd25519PrivateToX25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x25519Priv, err := Ed25519PrivateToX25519(priv)
	if err != nil {
		t.Fatal(err)
	}

	if len(x25519Priv) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(x25519Priv))
	}

	// Verify clamping
	if x25519Priv[0]&7 != 0 {
		t.Fatal("low 3 bits should be cleared")
	}
	if x25519Priv[31]&128 != 0 {
		t.Fatal("high bit should be cleared")
	}
	if x25519Priv[31]&64 == 0 {
		t.Fatal("bit 254 should be set")
	}
}

func TestEd25519PrivateToX25519_InvalidLength(t *testing.T) {
	_, err := Ed25519PrivateToX25519([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestEd25519PrivateToX25519_Deterministic(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x1, err := Ed25519PrivateToX25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	x2, err := Ed25519PrivateToX25519(priv)
	if err != nil {
		t.Fatal(err)
	}

	if string(x1) != string(x2) {
		t.Fatal("conversion should be deterministic")
	}
}
