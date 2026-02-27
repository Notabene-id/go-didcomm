package didcomm

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// authcrypt performs sign-then-encrypt: signs the payload with the sender's Ed25519 key,
// then encrypts the JWS for the recipients using ECDH-ES+A256KW / A256CBC-HS512.
// The sender's key ID is included in the JWE protected headers via the "skid" field.
func authcrypt(payload []byte, signingKey jwk.Key, recipientKeys []jwk.Key) ([]byte, error) {
	if len(recipientKeys) == 0 {
		return nil, ErrNoRecipients
	}

	// Step 1: Sign the payload
	signed, err := signMessage(payload, signingKey)
	if err != nil {
		return nil, fmt.Errorf("authcrypt sign: %w", err)
	}

	// Step 2: Encrypt the JWS for recipients
	opts := []jwe.EncryptOption{
		jwe.WithContentEncryption(jwa.A256CBC_HS512()),
	}

	for _, rk := range recipientKeys {
		per := jwe.NewHeaders()
		if kid, ok := rk.KeyID(); ok && kid != "" {
			_ = per.Set(jwe.KeyIDKey, kid)
		}
		opts = append(opts, jwe.WithKey(jwa.ECDH_ES_A256KW(), rk, jwe.WithPerRecipientHeaders(per)))
	}

	// Set protected headers with sender identification
	hdrs := jwe.NewHeaders()
	_ = hdrs.Set(jwe.TypeKey, "application/didcomm-encrypted+json")

	// skid (sender key ID) identifies the sender per DIDComm v2 spec
	if kid, ok := signingKey.KeyID(); ok && kid != "" {
		_ = hdrs.Set("skid", kid)
	}
	opts = append(opts, jwe.WithProtectedHeaders(hdrs))

	// Use JSON serialization for multiple recipients
	if len(recipientKeys) > 1 {
		opts = append(opts, jwe.WithJSON())
	}

	encrypted, err := jwe.Encrypt(signed, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}
	return encrypted, nil
}

// authDecrypt decrypts and verifies an authcrypt message.
// Returns the inner payload, the sender's key ID (from skid header), and whether it was signed.
func authDecrypt(encrypted []byte, privateKey jwk.Key, senderPublicKey jwk.Key) ([]byte, string, error) {
	// Step 1: Decrypt the JWE
	signed, err := jwe.Decrypt(
		encrypted,
		jwe.WithKey(jwa.ECDH_ES_A256KW(), privateKey),
	)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Step 2: Extract skid from headers
	hdrs, err := parseJWEHeaders(encrypted)
	if err != nil {
		return nil, "", fmt.Errorf("parse JWE headers: %w", err)
	}
	var skid string
	_ = hdrs.Get("skid", &skid)

	// Step 3: Verify the JWS signature
	payload, err := verifySignature(signed, senderPublicKey)
	if err != nil {
		return nil, skid, fmt.Errorf("authcrypt verify: %w", err)
	}

	return payload, skid, nil
}
