package didcomm

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/Notabene-id/go-didcomm/internal/convert"
)

// KeyPair holds a signing (Ed25519) and encryption (X25519) key pair with their JWK representations.
type KeyPair struct {
	// Ed25519 signing keys (unexported — use JWK accessors)
	signingPrivate ed25519.PrivateKey
	signingPublic  ed25519.PublicKey

	// X25519 encryption keys (unexported — use JWK accessors)
	encryptionPrivate *ecdh.PrivateKey
	encryptionPublic  *ecdh.PublicKey

	// JWK representations
	SigningJWK    jwk.Key // OKP Ed25519 private key
	EncryptionJWK jwk.Key // OKP X25519 private key
}

// jwkSetter is implemented by jwk.Key and JWE/JWS header types.
type jwkSetter interface {
	Set(string, interface{}) error
}

// mustSet sets a JWK/header field and returns an error if it fails.
func mustSet(setter jwkSetter, key string, value interface{}) error {
	if err := setter.Set(key, value); err != nil {
		return fmt.Errorf("set %s: %w", key, err)
	}
	return nil
}

// GenerateKeyPair generates a new Ed25519 signing key pair and derives the corresponding X25519 encryption key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	return keyPairFromEd25519(pub, priv)
}

// keyPairFromEd25519 creates a KeyPair from existing Ed25519 keys.
func keyPairFromEd25519(pub ed25519.PublicKey, priv ed25519.PrivateKey) (*KeyPair, error) {
	// Convert to X25519
	x25519PubBytes, err := convert.Ed25519PublicToX25519(pub)
	if err != nil {
		return nil, fmt.Errorf("convert public key: %w", err)
	}

	x25519PrivBytes, err := convert.Ed25519PrivateToX25519(priv)
	if err != nil {
		return nil, fmt.Errorf("convert private key: %w", err)
	}

	x25519Priv, err := ecdh.X25519().NewPrivateKey(x25519PrivBytes)
	if err != nil {
		return nil, fmt.Errorf("create X25519 private key: %w", err)
	}

	x25519Pub, err := ecdh.X25519().NewPublicKey(x25519PubBytes)
	if err != nil {
		return nil, fmt.Errorf("create X25519 public key: %w", err)
	}

	// Build JWK for signing key
	sigJWK, err := jwk.Import(priv)
	if err != nil {
		return nil, fmt.Errorf("import signing key to JWK: %w", err)
	}
	err = mustSet(sigJWK, jwk.AlgorithmKey, jwa.EdDSA())
	if err != nil {
		return nil, err
	}

	// Build JWK for encryption key
	encJWK, err := jwk.Import(x25519Priv)
	if err != nil {
		return nil, fmt.Errorf("import encryption key to JWK: %w", err)
	}
	err = mustSet(encJWK, jwk.AlgorithmKey, jwa.ECDH_ES_A256KW())
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		signingPrivate:    priv,
		signingPublic:     pub,
		encryptionPrivate: x25519Priv,
		encryptionPublic:  x25519Pub,
		SigningJWK:        sigJWK,
		EncryptionJWK:     encJWK,
	}, nil
}

// SigningPublicJWK returns the public JWK for the signing key.
func (kp *KeyPair) SigningPublicJWK() (jwk.Key, error) {
	return jwk.PublicKeyOf(kp.SigningJWK)
}

// EncryptionPublicJWK returns the public JWK for the encryption key.
func (kp *KeyPair) EncryptionPublicJWK() (jwk.Key, error) {
	return jwk.PublicKeyOf(kp.EncryptionJWK)
}
