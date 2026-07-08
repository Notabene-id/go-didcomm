package didcomm

import (
	"encoding/json"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
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

// keyAgreementKey returns the keyAgreement verification method matching kid, or
// the first when kid is empty.
func (doc *DIDDocument) keyAgreementKey(kid string) (*VerificationMethod, error) {
	return findVerificationMethod(doc.KeyAgreement, kid)
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
