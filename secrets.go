package didcomm

import (
	"context"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// SecretsResolver provides access to private keys by key ID.
type SecretsResolver interface {
	GetKey(ctx context.Context, kid string) (jwk.Key, error)
}

// InMemorySecretsStore is a simple in-memory implementation of SecretsResolver.
type InMemorySecretsStore struct {
	mu   sync.RWMutex
	keys map[string]jwk.Key
}

// NewInMemorySecretsStore creates a new empty in-memory secrets store.
func NewInMemorySecretsStore() *InMemorySecretsStore {
	return &InMemorySecretsStore{
		keys: make(map[string]jwk.Key),
	}
}

// Store adds a key pair's private keys to the store, indexed by their key IDs.
func (s *InMemorySecretsStore) Store(kp *KeyPair) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if kid, ok := kp.SigningJWK.KeyID(); ok && kid != "" {
		s.keys[kid] = kp.SigningJWK
	}
	if kid, ok := kp.EncryptionJWK.KeyID(); ok && kid != "" {
		s.keys[kid] = kp.EncryptionJWK
	}
}

// StoreKey adds a single JWK to the store indexed by its key ID.
func (s *InMemorySecretsStore) StoreKey(key jwk.Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if kid, ok := key.KeyID(); ok && kid != "" {
		s.keys[kid] = key
	}
}

// GetKey retrieves a private key by its key ID.
func (s *InMemorySecretsStore) GetKey(_ context.Context, kid string) (jwk.Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}
