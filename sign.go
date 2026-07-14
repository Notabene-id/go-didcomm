package didcomm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// signedMediaType is the JWS "typ" for a DIDComm signed message.
const signedMediaType = "application/didcomm-signed+json"

// b64 is the JOSE base64url (unpadded) encoding.
var b64 = base64.RawURLEncoding

// jwsHeader is the protected header of a DIDComm JWS.
type jwsHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// jwsFlattened is the flattened JSON JWS serialization DIDComm mandates
// (RFC 7515 §7.2.2); some DIDComm v2 implementations reject compact input.
type jwsFlattened struct {
	Payload   string `json:"payload"`
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

// signJWS builds a flattened JSON JWS over payload, signed by kid via the sealed
// key store. The private key never enters this process.
func signJWS(ctx context.Context, keys KeyStore, kid string, payload []byte) ([]byte, error) {
	protected, err := json.Marshal(jwsHeader{Typ: signedMediaType, Alg: "EdDSA", Kid: kid})
	if err != nil {
		return nil, fmt.Errorf("marshal JWS header: %w", err)
	}
	protectedB64 := b64.EncodeToString(protected)
	payloadB64 := b64.EncodeToString(payload)

	signature, err := keys.Sign(ctx, kid, []byte(protectedB64+"."+payloadB64))
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return json.Marshal(jwsFlattened{
		Payload:   payloadB64,
		Protected: protectedB64,
		Signature: b64.EncodeToString(signature),
	})
}

// verifyJWS verifies a JWS (JSON or compact) against a public key and returns the
// signed payload. The algorithm is pinned to EdDSA, so "alg":"none" and key-type
// confusion are rejected.
func verifyJWS(signed []byte, publicKey jwk.Key) ([]byte, error) {
	payload, err := jws.Verify(signed, jws.WithKey(jwa.EdDSA(), publicKey))
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return payload, nil
}

// jwsSignerKID extracts the "kid" from a JWS protected header without verifying.
func jwsSignerKID(signed []byte) (string, error) {
	msg, err := jws.Parse(signed)
	if err != nil {
		return "", ErrDecryptFailed
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return "", ErrDecryptFailed
	}
	kid, ok := sigs[0].ProtectedHeaders().KeyID()
	if !ok {
		return "", ErrDecryptFailed
	}
	return kid, nil
}
