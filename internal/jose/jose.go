// Package jose implements the JOSE primitives DIDComm v2 needs that are not
// available from the standard library or the jwx JWS layer: NIST SP 800-56A
// Concat KDF, RFC 3394 AES key wrap, RFC 7518 content encryption, and the
// ECDH-ES / ECDH-1PU key-agreement key derivation used to build JWE envelopes.
//
// The package is deliberately key-agnostic: it never holds a private key. The
// ECDH shared secrets are computed by the caller (from a sealed key store) and
// passed in as raw bytes, so this layer is pure, testable cryptography.
package jose

import "errors"

// KeyWrapAlgorithm identifies a JWE "alg" key-management value.
type KeyWrapAlgorithm string

// ContentEncryption identifies a JWE "enc" content-encryption value.
type ContentEncryption string

// Serialization selects how a JWE is rendered on the wire.
type Serialization uint8

// JWE key-management ("alg") values supported by this package. XC20PKW
// (draft-amringer-jose-chacha-02) is accepted on unpack for interoperability
// with DIDComm implementations that use XChaCha20-Poly1305; this package only
// ever emits A256KW.
const (
	AlgECDH1PUA256KW  KeyWrapAlgorithm = "ECDH-1PU+A256KW"
	AlgECDH1PUXC20PKW KeyWrapAlgorithm = "ECDH-1PU+XC20PKW"
	AlgECDHESA256KW   KeyWrapAlgorithm = "ECDH-ES+A256KW"
)

// JWE content-encryption ("enc") values supported by this package. XC20P
// (XChaCha20-Poly1305) is accepted on unpack for the same interoperability; this
// package only ever emits A256GCM.
const (
	EncA256CBCHS512 ContentEncryption = "A256CBC-HS512"
	EncA256GCM      ContentEncryption = "A256GCM"
	EncXC20P        ContentEncryption = "XC20P"
)

// JWE serialization forms (RFC 7516 §3).
const (
	// GeneralJSON is the multi-recipient JSON serialization.
	GeneralJSON Serialization = iota
	// Compact is the single-recipient compact serialization.
	Compact
)

// Errors returned by the jose package. Decryption failures are intentionally
// indistinguishable: a caller must not be able to tell an unwrap failure from a
// MAC failure from a padding failure, so no oracle leaks through the error.
var (
	// ErrDecrypt is the single, opaque failure for every decryption error.
	ErrDecrypt = errors.New("jose: decryption failed")
	// ErrInvalidKeySize reports a key whose length does not match the algorithm.
	ErrInvalidKeySize = errors.New("jose: invalid key size")
	// ErrMalformed reports a structurally invalid JWE or input.
	ErrMalformed = errors.New("jose: malformed JWE")
)

// cekSize returns the content-encryption key length in bytes for enc.
func (enc ContentEncryption) cekSize() (int, bool) {
	switch enc {
	case EncA256CBCHS512:
		return 64, true
	case EncA256GCM, EncXC20P:
		return 32, true
	default:
		return 0, false
	}
}

// IsAuthcrypt reports whether alg is an ECDH-1PU (authenticated-sender) key
// agreement, regardless of the key-wrap it is paired with.
func IsAuthcrypt(alg KeyWrapAlgorithm) bool {
	return alg == AlgECDH1PUA256KW || alg == AlgECDH1PUXC20PKW
}
