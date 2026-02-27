package didcomm

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// signMessage creates a JWS compact serialization of the payload using EdDSA.
func signMessage(payload []byte, signingKey jwk.Key) ([]byte, error) {
	hdrs := jws.NewHeaders()
	if kid, ok := signingKey.KeyID(); ok && kid != "" {
		if err := mustSet(hdrs, jws.KeyIDKey, kid); err != nil {
			return nil, err
		}
	}
	if err := mustSet(hdrs, jws.TypeKey, "application/didcomm-signed+json"); err != nil {
		return nil, err
	}

	signed, err := jws.Sign(
		payload,
		jws.WithKey(jwa.EdDSA(), signingKey, jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigningFailed, err)
	}
	return signed, nil
}

// verifySignature verifies a JWS compact serialization and returns the payload.
func verifySignature(signed []byte, publicKey jwk.Key) ([]byte, error) {
	payload, err := jws.Verify(
		signed,
		jws.WithKey(jwa.EdDSA(), publicKey),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}
	return payload, nil
}

// parseJWSHeaders extracts the protected headers from a JWS message without verifying.
func parseJWSHeaders(signed []byte) (jws.Headers, error) {
	msg, err := jws.Parse(signed)
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %w", err)
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no signatures in JWS")
	}

	return sigs[0].ProtectedHeaders(), nil
}
