package didcomm

import (
	"context"
	"errors"
	"testing"
)

func TestDIDKeyResolver_RoundTrip(t *testing.T) {
	// Generate a did:key, then resolve it and compare
	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	resolver := &DIDKeyResolver{}
	resolved, err := resolver.Resolve(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("resolve %s: %v", doc.ID, err)
	}

	if resolved.ID != doc.ID {
		t.Fatalf("ID mismatch: %s != %s", resolved.ID, doc.ID)
	}
	if len(resolved.Authentication) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(resolved.Authentication))
	}
	if len(resolved.KeyAgreement) != 1 {
		t.Fatalf("expected 1 key agreement method, got %d", len(resolved.KeyAgreement))
	}

	// Key IDs should match
	if resolved.Authentication[0].ID != doc.Authentication[0].ID {
		t.Fatalf("auth key ID mismatch: %s != %s", resolved.Authentication[0].ID, doc.Authentication[0].ID)
	}
	if resolved.KeyAgreement[0].ID != doc.KeyAgreement[0].ID {
		t.Fatalf("key agreement key ID mismatch: %s != %s", resolved.KeyAgreement[0].ID, doc.KeyAgreement[0].ID)
	}

	// Public keys should not be nil
	if resolved.Authentication[0].PublicKey == nil {
		t.Fatal("auth public key is nil")
	}
	if resolved.KeyAgreement[0].PublicKey == nil {
		t.Fatal("key agreement public key is nil")
	}
}

func TestDIDKeyResolver_NotDIDKey(t *testing.T) {
	resolver := &DIDKeyResolver{}
	_, err := resolver.Resolve(context.Background(), "did:web:example.com")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

func TestDIDKeyResolver_InvalidBase58(t *testing.T) {
	resolver := &DIDKeyResolver{}
	_, err := resolver.Resolve(context.Background(), "did:key:z!!!invalid")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

func TestDIDKeyResolver_TooShort(t *testing.T) {
	resolver := &DIDKeyResolver{}
	_, err := resolver.Resolve(context.Background(), "did:key")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}
