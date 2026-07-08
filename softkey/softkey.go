// Package softkey provides an in-memory KeyStore for tests and local
// development. It holds private keys in process memory and performs signing and
// key agreement in software. Production deployments should back the
// didcomm.KeyStore interface with an HSM or KMS instead, so that key material
// never resides in the application's address space.
package softkey

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
	"sync"

	didcomm "github.com/notabene-id/go-didcomm"
)

// Store is an in-memory KeyStore keyed by verification-method id.
type Store struct {
	mu        sync.RWMutex
	signing   map[string]ed25519.PrivateKey
	agreement map[string]*ecdh.PrivateKey
}

var _ didcomm.KeyStore = (*Store)(nil)

// New builds a Store seeded with the given key material.
func New(materials ...*didcomm.KeyMaterial) (*Store, error) {
	s := &Store{
		signing:   make(map[string]ed25519.PrivateKey),
		agreement: make(map[string]*ecdh.PrivateKey),
	}
	for _, km := range materials {
		if err := s.Add(km); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Add loads one DID's key material into the store.
func (s *Store) Add(km *didcomm.KeyMaterial) error {
	if len(km.Ed25519Seed) != ed25519.SeedSize {
		return fmt.Errorf("softkey: ed25519 seed for %s must be %d bytes", km.DID, ed25519.SeedSize)
	}
	agreement, err := ecdh.X25519().NewPrivateKey(km.X25519Private)
	if err != nil {
		return fmt.Errorf("softkey: x25519 key for %s: %w", km.DID, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.signing[km.SigningKID] = ed25519.NewKeyFromSeed(km.Ed25519Seed)
	s.agreement[km.KeyAgreementKID] = agreement
	return nil
}

// Sign implements didcomm.KeyStore.
func (s *Store) Sign(_ context.Context, kid string, data []byte) ([]byte, error) {
	s.mu.RLock()
	key, ok := s.signing[kid]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("softkey: no signing key for %s: %w", kid, didcomm.ErrKeyNotFound)
	}
	return ed25519.Sign(key, data), nil
}

// DiffieHellman implements didcomm.KeyStore.
func (s *Store) DiffieHellman(_ context.Context, kid string, peerPublicKey []byte) ([]byte, error) {
	s.mu.RLock()
	key, ok := s.agreement[kid]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("softkey: no key-agreement key for %s: %w", kid, didcomm.ErrKeyNotFound)
	}
	peer, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("softkey: peer public key: %w", err)
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("softkey: ecdh: %w", err)
	}
	return shared, nil
}
