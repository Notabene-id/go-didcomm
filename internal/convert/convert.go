// Package convert provides Ed25519 to X25519 key conversion utilities.
package convert

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
)

// Ed25519PublicToX25519 converts an Ed25519 public key to an X25519 public key.
func Ed25519PublicToX25519(pub ed25519.PublicKey) ([]byte, error) {
	p, err := (&edwards25519.Point{}).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("convert: invalid Ed25519 public key: %w", err)
	}
	return p.BytesMontgomery(), nil
}

// Ed25519PrivateToX25519 converts an Ed25519 private key to an X25519 private key.
// This uses the RFC 7748 clamping procedure on the SHA-512 hash of the seed.
func Ed25519PrivateToX25519(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("convert: invalid Ed25519 private key length: %d", len(priv))
	}
	h := sha512.New()
	h.Write(priv.Seed())
	digest := h.Sum(nil)

	// Clamp per RFC 7748
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	return digest[:32], nil
}
