package didcomm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestGenerateDIDKey(t *testing.T) {
	doc, kp, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	// DID should start with did:key:z
	if !strings.HasPrefix(doc.ID, "did:key:z") {
		t.Fatalf("DID should start with did:key:z, got %s", doc.ID)
	}

	// Should have one authentication method
	if len(doc.Authentication) != 1 {
		t.Fatalf("expected 1 authentication method, got %d", len(doc.Authentication))
	}

	// Should have one key agreement method
	if len(doc.KeyAgreement) != 1 {
		t.Fatalf("expected 1 key agreement method, got %d", len(doc.KeyAgreement))
	}

	// Authentication key ID should be DID#fragment
	authVM := doc.Authentication[0]
	if !strings.HasPrefix(authVM.ID, doc.ID+"#") {
		t.Fatalf("auth key ID should start with DID#, got %s", authVM.ID)
	}
	if authVM.Type != "Ed25519VerificationKey2020" {
		t.Fatalf("expected Ed25519VerificationKey2020, got %s", authVM.Type)
	}
	if authVM.Controller != doc.ID {
		t.Fatalf("controller should be DID, got %s", authVM.Controller)
	}

	// Key agreement key ID
	kaVM := doc.KeyAgreement[0]
	if !strings.HasPrefix(kaVM.ID, doc.ID+"#") {
		t.Fatalf("key agreement key ID should start with DID#, got %s", kaVM.ID)
	}
	if kaVM.Type != "X25519KeyAgreementKey2020" {
		t.Fatalf("expected X25519KeyAgreementKey2020, got %s", kaVM.Type)
	}

	// KeyPair should not be nil
	if kp == nil {
		t.Fatal("key pair should not be nil")
	}

	// Signing JWK should have KID set
	if kid, ok := kp.SigningJWK.KeyID(); !ok || kid == "" {
		t.Fatal("signing JWK should have KID set")
	}

	// Encryption JWK should have KID set
	if kid, ok := kp.EncryptionJWK.KeyID(); !ok || kid == "" {
		t.Fatal("encryption JWK should have KID set")
	}
}

func TestGenerateDIDKey_Unique(t *testing.T) {
	doc1, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	doc2, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	if doc1.ID == doc2.ID {
		t.Fatal("generated DIDs should be unique")
	}
}

func TestGenerateDIDWeb(t *testing.T) {
	doc, kp, err := GenerateDIDWeb("example.com", "/alice")
	if err != nil {
		t.Fatal(err)
	}

	if doc.ID != "did:web:example.com:alice" {
		t.Fatalf("expected did:web:example.com:alice, got %s", doc.ID)
	}

	if len(doc.Authentication) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(doc.Authentication))
	}
	if len(doc.KeyAgreement) != 1 {
		t.Fatalf("expected 1 key agreement method, got %d", len(doc.KeyAgreement))
	}

	if doc.Authentication[0].ID != "did:web:example.com:alice#key-1" {
		t.Fatalf("unexpected auth key ID: %s", doc.Authentication[0].ID)
	}
	if doc.KeyAgreement[0].ID != "did:web:example.com:alice#key-2" {
		t.Fatalf("unexpected ka key ID: %s", doc.KeyAgreement[0].ID)
	}

	if kp == nil {
		t.Fatal("key pair should not be nil")
	}
}

func TestGenerateDIDWeb_NoPath(t *testing.T) {
	doc, _, err := GenerateDIDWeb("example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	if doc.ID != "did:web:example.com" {
		t.Fatalf("expected did:web:example.com, got %s", doc.ID)
	}
}

func TestGenerateDIDWeb_NestedPath(t *testing.T) {
	doc, _, err := GenerateDIDWeb("example.com", "/org/dept/alice")
	if err != nil {
		t.Fatal(err)
	}

	if doc.ID != "did:web:example.com:org:dept:alice" {
		t.Fatalf("expected did:web:example.com:org:dept:alice, got %s", doc.ID)
	}
}

func TestGenerateDIDWeb_PortInDomain(t *testing.T) {
	doc, _, err := GenerateDIDWeb("localhost:8080", "/alice")
	if err != nil {
		t.Fatal(err)
	}

	if doc.ID != "did:web:localhost%3A8080:alice" {
		t.Fatalf("expected did:web:localhost%%3A8080:alice, got %s", doc.ID)
	}
}

func TestResolver_StoreAndResolve(t *testing.T) {
	resolver := NewResolver()
	ctx := context.Background()

	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	resolver.Store(doc)

	resolved, err := resolver.Resolve(ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}

	if resolved.ID != doc.ID {
		t.Fatalf("expected %s, got %s", doc.ID, resolved.ID)
	}
}

func TestResolver_NotFound(t *testing.T) {
	resolver := NewResolver()
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "did:key:nonexistent")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

func TestDIDDocument_FindEncryptionKey(t *testing.T) {
	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	vm, err := doc.FindEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if vm.PublicKey == nil {
		t.Fatal("encryption key should not be nil")
	}
}

func TestDIDDocument_FindSigningKey(t *testing.T) {
	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	vm, err := doc.FindSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if vm.PublicKey == nil {
		t.Fatal("signing key should not be nil")
	}
}

func TestDIDDocument_FindEncryptionKey_Empty(t *testing.T) {
	doc := &DIDDocument{ID: "did:key:test"}
	_, err := doc.FindEncryptionKey()
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestDIDDocument_FindSigningKey_Empty(t *testing.T) {
	doc := &DIDDocument{ID: "did:key:test"}
	_, err := doc.FindSigningKey()
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}
