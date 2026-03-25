package didcomm

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// anoncrypt encrypts a payload for one or more recipients using ECDH-ES+A256KW / A256CBC-HS512.
// This is anonymous encryption — the sender is not identified.
func anoncrypt(payload []byte, recipientKeys []jwk.Key) ([]byte, error) {
	if len(recipientKeys) == 0 {
		return nil, ErrNoRecipients
	}

	// Build recipient list for JWE
	opts := []jwe.EncryptOption{
		jwe.WithContentEncryption(jwa.A256CBC_HS512()),
	}

	for _, rk := range recipientKeys {
		per := jwe.NewHeaders()
		if kid, ok := rk.KeyID(); ok && kid != "" {
			if err := mustSet(per, jwe.KeyIDKey, kid); err != nil {
				return nil, err
			}
		}
		opts = append(opts, jwe.WithKey(jwa.ECDH_ES_A256KW(), rk, jwe.WithPerRecipientHeaders(per)))
	}

	// Set protected headers
	hdrs := jwe.NewHeaders()
	if err := mustSet(hdrs, jwe.TypeKey, "application/didcomm-encrypted+json"); err != nil {
		return nil, err
	}

	// NOTE: DIDComm v2 recommends APV (Agreement PartyVInfo) in the protected headers.
	// However, jwx v3 has a bug where X25519 encryption ignores apu/apv in the Concat KDF
	// while decryption uses them, causing a mismatch. APV is omitted until this is fixed.
	// See: https://github.com/lestrrat-go/jwx/issues — X25519 ECDH-ES KDF ignores apu/apv.

	opts = append(opts, jwe.WithProtectedHeaders(hdrs))

	// Always use JSON serialization (required for multiple recipients, preferred for consistency)
	opts = append(opts, jwe.WithJSON())

	encrypted, err := jwe.Encrypt(payload, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
	}
	return encrypted, nil
}

// anonDecrypt decrypts a JWE message using the recipient's private key.
func anonDecrypt(encrypted []byte, privateKey jwk.Key) ([]byte, error) {
	payload, err := jwe.Decrypt(
		encrypted,
		jwe.WithKey(jwa.ECDH_ES_A256KW(), privateKey),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	return payload, nil
}
