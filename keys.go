package didcomm

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/notabene-id/go-didcomm/internal/convert"
)

// KeyMaterial is the private key material for a generated DID. It is returned to
// the caller, who loads it into a KeyStore (see the softkey package for a
// development store, or a KMS/HSM adapter in production). It is never passed
// back into the library — the library operates only through the sealed KeyStore.
type KeyMaterial struct {
	DID             string `json:"did"`
	SigningKID      string `json:"signingKid"`      // Ed25519 signing verification-method id
	KeyAgreementKID string `json:"keyAgreementKid"` // X25519 key-agreement verification-method id
	Ed25519Seed     []byte `json:"ed25519Seed"`     // 32-byte Ed25519 private seed
	X25519Private   []byte `json:"x25519Private"`   // 32-byte X25519 private scalar
}

// generatedKeys is the raw output of key generation.
type generatedKeys struct {
	ed25519Seed   []byte
	ed25519Public ed25519.PublicKey
	x25519Private []byte
	x25519Public  []byte
}

// generateKeys creates an Ed25519 signing key and derives its X25519
// key-agreement counterpart (RFC 8032 / RFC 7748).
func generateKeys() (*generatedKeys, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	xPriv, err := convert.Ed25519PrivateToX25519(priv)
	if err != nil {
		return nil, fmt.Errorf("derive x25519 private key: %w", err)
	}
	xPub, err := convert.Ed25519PublicToX25519(pub)
	if err != nil {
		return nil, fmt.Errorf("derive x25519 public key: %w", err)
	}
	return &generatedKeys{
		ed25519Seed:   priv.Seed(),
		ed25519Public: pub,
		x25519Private: xPriv,
		x25519Public:  xPub,
	}, nil
}

// signingPublicJWK builds the public Ed25519 JWK for a DID document.
func signingPublicJWK(pub ed25519.PublicKey, kid string) (jwk.Key, error) {
	key, err := jwk.Import(pub)
	if err != nil {
		return nil, fmt.Errorf("import ed25519 public key: %w", err)
	}
	if err := setKeyFields(key, kid, jwa.EdDSA()); err != nil {
		return nil, err
	}
	return key, nil
}

// encryptionPublicJWK builds the public X25519 JWK for a DID document.
func encryptionPublicJWK(x25519Public []byte, kid string) (jwk.Key, error) {
	pub, err := ecdh.X25519().NewPublicKey(x25519Public)
	if err != nil {
		return nil, fmt.Errorf("parse x25519 public key: %w", err)
	}
	key, err := jwk.Import(pub)
	if err != nil {
		return nil, fmt.Errorf("import x25519 public key: %w", err)
	}
	if err := setKeyFields(key, kid, jwa.ECDH_ES_A256KW()); err != nil {
		return nil, err
	}
	return key, nil
}

// setKeyFields sets the kid and alg on a JWK.
func setKeyFields(key jwk.Key, kid string, alg jwa.KeyAlgorithm) error {
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return fmt.Errorf("set kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		return fmt.Errorf("set alg: %w", err)
	}
	return nil
}
