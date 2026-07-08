package didcomm

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/notabene-id/go-didcomm/internal/jose"
)

// encryptedMediaType is the JWE "typ" for a DIDComm encrypted message.
const encryptedMediaType = "application/didcomm-encrypted+json"

// Pack serializes and protects a message according to the chosen profile
// (default ProfileSignedAnoncrypt). See the Profile constants for the security
// properties of each.
func (c *Client) Pack(ctx context.Context, msg *Message, opts ...PackOption) ([]byte, error) {
	cfg := defaultPackConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	spec := cfg.profile.spec(cfg.contentEnc)
	if !spec.sign && !spec.encrypt {
		return nil, ErrUnsupportedProfile
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}

	if spec.sign {
		if msg.From == "" {
			return nil, ErrNoSender
		}
		kid, err := c.signingKID(ctx, msg.From)
		if err != nil {
			return nil, err
		}
		signed, err := signJWS(ctx, c.keys, kid, payload)
		if err != nil {
			return nil, err
		}
		if !spec.encrypt {
			return signed, nil
		}
		payload = signed
	}

	return c.encrypt(ctx, msg, payload, spec, cfg.joseSerialization())
}

// encrypt builds the JWE envelope for the (already signed, if applicable)
// payload.
func (c *Client) encrypt(
	ctx context.Context, msg *Message, payload []byte, spec packSpec, serialization jose.Serialization,
) ([]byte, error) {
	if len(msg.To) == 0 {
		return nil, ErrNoRecipients
	}

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	var senderKID string
	if spec.authcrypt {
		if msg.From == "" {
			return nil, ErrNoSender
		}
		if senderKID, err = c.keyAgreementKID(ctx, msg.From); err != nil {
			return nil, err
		}
	}

	recipients := make([]jose.Recipient, 0, len(msg.To))
	kids := make([]string, 0, len(msg.To))
	for _, to := range msg.To {
		z, kid, rErr := c.recipientSecret(ctx, ephemeral, senderKID, spec.authcrypt, to)
		if rErr != nil {
			return nil, rErr
		}
		recipients = append(recipients, jose.Recipient{KID: kid, Z: z})
		kids = append(kids, kid)
	}

	// DIDComm v2 binds the key derivation to the sender (apu) and the full
	// recipient set (apv). apv is required for both anoncrypt and authcrypt; apu
	// carries the skid and is set for authcrypt only. Both go in the shared
	// protected header and feed the Concat KDF (aries-rfc 0334, DIDComm v2 §5).
	var apu []byte
	if spec.authcrypt {
		apu = []byte(senderKID)
	}

	env, err := jose.Encrypt(&jose.EncryptRequest{
		Enc:           spec.enc,
		Alg:           spec.alg,
		Serialization: serialization,
		Typ:           encryptedMediaType,
		SenderKID:     senderKID,
		EphemeralPub:  ephemeral.PublicKey().Bytes(),
		APU:           apu,
		APV:           didcommAPV(kids),
		BindTag:       spec.bindTag,
		Plaintext:     payload,
		Recipients:    recipients,
	})
	if err != nil {
		return nil, fmt.Errorf("build JWE: %w", err)
	}
	return env, nil
}

// recipientSecret resolves one recipient's key-agreement key and derives the
// ECDH shared secret: Ze for ECDH-ES, or Ze||Zs for ECDH-1PU (Zs computed
// through the sealed key store from the sender's static key).
func (c *Client) recipientSecret(
	ctx context.Context, ephemeral *ecdh.PrivateKey, senderKID string, authcrypt bool, to string,
) (z []byte, kid string, err error) {
	doc, err := c.resolve(ctx, to)
	if err != nil {
		return nil, "", fmt.Errorf("resolve recipient %s: %w", to, err)
	}
	vm, err := doc.keyAgreementKey("")
	if err != nil {
		return nil, "", fmt.Errorf("recipient %s key agreement: %w", to, err)
	}
	recipientPub, err := x25519PublicBytes(vm.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("recipient %s public key: %w", to, err)
	}
	peer, err := ecdh.X25519().NewPublicKey(recipientPub)
	if err != nil {
		return nil, "", fmt.Errorf("recipient %s public key: %w", to, err)
	}

	ze, err := ephemeral.ECDH(peer)
	if err != nil {
		return nil, "", fmt.Errorf("ephemeral ECDH for %s: %w", to, err)
	}
	if !authcrypt {
		return ze, vm.ID, nil
	}

	zs, err := c.keys.DiffieHellman(ctx, senderKID, recipientPub)
	if err != nil {
		return nil, "", fmt.Errorf("sender ECDH for %s: %w", to, err)
	}
	z = make([]byte, 0, len(ze)+len(zs))
	z = append(z, ze...)
	z = append(z, zs...)
	return z, vm.ID, nil
}

// didcommAPV computes the DIDComm v2 "apv" PartyVInfo: the SHA-256 hash of the
// recipient key IDs sorted alphanumerically and joined with ".". The digest is
// returned raw — the JOSE layer base64url-encodes it for the protected header and
// feeds the raw bytes to the Concat KDF (aries-rfc 0334 §"apv").
func didcommAPV(kids []string) []byte {
	sorted := make([]string, len(kids))
	copy(sorted, kids)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, ".")))
	return sum[:]
}

// signingKID resolves the sender's signing verification-method id.
func (c *Client) signingKID(ctx context.Context, did string) (string, error) {
	doc, err := c.resolve(ctx, did)
	if err != nil {
		return "", err
	}
	vm, err := doc.signingKey("")
	if err != nil {
		return "", err
	}
	return vm.ID, nil
}

// keyAgreementKID resolves the sender's key-agreement verification-method id.
func (c *Client) keyAgreementKID(ctx context.Context, did string) (string, error) {
	doc, err := c.resolve(ctx, did)
	if err != nil {
		return "", err
	}
	vm, err := doc.keyAgreementKey("")
	if err != nil {
		return "", err
	}
	return vm.ID, nil
}
