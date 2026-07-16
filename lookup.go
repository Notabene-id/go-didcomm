package didcomm

import (
	"encoding/json"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/notabene-id/go-didcomm/internal/convert"
)

// didFromKID returns the DID portion of a verification-method id
// ("did:web:x#key-1" -> "did:web:x"), or "" if there is no fragment.
func didFromKID(kid string) string {
	if i := strings.LastIndex(kid, "#"); i >= 0 {
		return kid[:i]
	}
	return ""
}

// signingKey returns the authentication verification method matching kid, or the
// first one when kid is empty. Signature verification draws only from
// authentication, never from keyAgreement, so an encryption key can never be
// mistaken for a signing key.
func (doc *DIDDocument) signingKey(kid string) (*VerificationMethod, error) {
	return findVerificationMethod(doc.Authentication, kid)
}

// keyAgreementKey returns the keyAgreement verification method matching kid. When
// kid is empty it returns the first key usable for X25519 ECDH, skipping keys of
// other curves — a DID document may list a non-transport key (e.g. a P-256 PII
// key) first in keyAgreement, which must not be chosen for DIDComm encryption.
func (doc *DIDDocument) keyAgreementKey(kid string) (*VerificationMethod, error) {
	if kid != "" {
		return findVerificationMethod(doc.KeyAgreement, kid)
	}
	return firstX25519(doc.KeyAgreement)
}

// allX25519 returns every keyAgreement verification method usable for X25519
// ECDH, in document order, skipping nil and other-curve entries. An Ed25519 key
// counts — its Montgomery (X25519) form is used, as is conventional for Ed25519
// keys published for key agreement.
func allX25519(vms []VerificationMethod) []*VerificationMethod {
	var out []*VerificationMethod
	for i := range vms {
		if vms[i].PublicKey == nil {
			continue
		}
		if _, err := x25519FromKey(vms[i].PublicKey); err == nil {
			out = append(out, &vms[i])
		}
	}
	return out
}

// x25519FromKey returns the raw 32-byte X25519 public key for a key-agreement
// verification method: the key itself when it is X25519, or its Montgomery
// conversion when it is Ed25519 (RFC 7748). Other key types are unsupported.
func x25519FromKey(key jwk.Key) ([]byte, error) {
	if raw, err := x25519PublicBytes(key); err == nil {
		return raw, nil
	}
	edPub, err := ed25519PublicBytes(key)
	if err != nil {
		return nil, ErrUnsupportedKeyType
	}
	x, err := convert.Ed25519PublicToX25519(edPub)
	if err != nil {
		return nil, ErrUnsupportedKeyType
	}
	return x, nil
}

// ed25519PublicBytes extracts the raw 32-byte Ed25519 public key from an OKP JWK.
func ed25519PublicBytes(key jwk.Key) ([]byte, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, ErrUnsupportedKeyType
	}
	var j struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err = json.Unmarshal(data, &j); err != nil {
		return nil, ErrUnsupportedKeyType
	}
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, ErrUnsupportedKeyType
	}
	raw, err := b64.DecodeString(j.X)
	if err != nil || len(raw) != 32 {
		return nil, ErrUnsupportedKeyType
	}
	return raw, nil
}

// firstX25519 returns the first usable X25519 key agreement verification method.
func firstX25519(vms []VerificationMethod) (*VerificationMethod, error) {
	if x := allX25519(vms); len(x) > 0 {
		return x[0], nil
	}
	return nil, ErrKeyNotFound
}

func findVerificationMethod(vms []VerificationMethod, kid string) (*VerificationMethod, error) {
	for i := range vms {
		if vms[i].PublicKey == nil {
			continue
		}
		if kid == "" || vms[i].ID == kid {
			return &vms[i], nil
		}
	}
	return nil, ErrKeyNotFound
}

// x25519PublicBytes extracts the raw 32-byte X25519 public key from an OKP JWK.
// It reads the standard JWK JSON so it does not depend on jwx internals.
func x25519PublicBytes(key jwk.Key) ([]byte, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, ErrUnsupportedKeyType
	}
	var j struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err = json.Unmarshal(data, &j); err != nil {
		return nil, ErrUnsupportedKeyType
	}
	if j.Kty != "OKP" || j.Crv != "X25519" {
		return nil, ErrUnsupportedKeyType
	}
	raw, err := b64.DecodeString(j.X)
	if err != nil || len(raw) != 32 {
		return nil, ErrUnsupportedKeyType
	}
	return raw, nil
}
