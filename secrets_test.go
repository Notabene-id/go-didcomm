package didcomm

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestInMemorySecretsStore_StoreAndGetKey(t *testing.T) {
	store := NewInMemorySecretsStore()
	ctx := context.Background()

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Set KIDs on keys
	_ = kp.SigningJWK.Set(jwk.KeyIDKey, "sig-key-1")
	_ = kp.EncryptionJWK.Set(jwk.KeyIDKey, "enc-key-1")

	store.Store(kp)

	// Retrieve signing key
	sigKey, err := store.GetKey(ctx, "sig-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := sigKey.KeyID(); kid != "sig-key-1" {
		t.Fatalf("expected kid=sig-key-1, got %s", kid)
	}

	// Retrieve encryption key
	encKey, err := store.GetKey(ctx, "enc-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := encKey.KeyID(); kid != "enc-key-1" {
		t.Fatalf("expected kid=enc-key-1, got %s", kid)
	}
}

func TestInMemorySecretsStore_KeyNotFound(t *testing.T) {
	store := NewInMemorySecretsStore()
	ctx := context.Background()

	_, err := store.GetKey(ctx, "nonexistent")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestInMemorySecretsStore_StoreKey(t *testing.T) {
	store := NewInMemorySecretsStore()
	ctx := context.Background()

	key, err := jwk.Import([]byte("test-symmetric-key-32-bytes!!!!"))
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.KeyIDKey, "my-key")

	store.StoreKey(key)

	got, err := store.GetKey(ctx, "my-key")
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := got.KeyID(); kid != "my-key" {
		t.Fatalf("expected kid=my-key, got %s", kid)
	}
}

func TestInMemorySecretsStore_ConcurrentAccess(t *testing.T) {
	store := NewInMemorySecretsStore()
	ctx := context.Background()

	// Store keys concurrently
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			kp, err := GenerateKeyPair()
			if err != nil {
				t.Error(err)
				return
			}
			_ = kp.SigningJWK.Set(jwk.KeyIDKey, "concurrent-key")
			store.Store(kp)
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should be able to retrieve
	_, err := store.GetKey(ctx, "concurrent-key")
	if err != nil {
		t.Fatal(err)
	}
}

// Verify InMemorySecretsStore implements SecretsResolver.
var _ SecretsResolver = (*InMemorySecretsStore)(nil)
