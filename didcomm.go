package didcomm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// UnpackResult contains the result of unpacking a DIDComm v2 message.
type UnpackResult struct {
	Message   *Message
	Encrypted bool
	Signed    bool
	Anonymous bool // true if anoncrypt (no skid), false if authcrypt
}

// Client provides DIDComm v2 pack and unpack operations.
type Client struct {
	resolver *Resolver
	secrets  SecretsResolver
}

// NewClient creates a new DIDComm client with the given DID resolver and secrets resolver.
func NewClient(resolver *Resolver, secrets SecretsResolver) *Client {
	return &Client{
		resolver: resolver,
		secrets:  secrets,
	}
}

// PackSigned creates a JWS-signed DIDComm message.
// The message must have a From field to identify the signing key.
func (c *Client) PackSigned(ctx context.Context, msg *Message) ([]byte, error) {
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	if msg.From == "" {
		return nil, ErrNoSender
	}

	signingKey, err := c.getSenderSigningKey(ctx, msg.From)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}

	return signMessage(payload, signingKey)
}

// PackAnoncrypt creates an anonymous encrypted JWE DIDComm message.
// No sender identification is included.
func (c *Client) PackAnoncrypt(ctx context.Context, msg *Message) ([]byte, error) {
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	if len(msg.To) == 0 {
		return nil, ErrNoRecipients
	}

	recipientKeys, err := c.getRecipientEncryptionKeys(ctx, msg.To)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}

	return anoncrypt(payload, recipientKeys)
}

// PackAuthcrypt creates an authenticated encrypted DIDComm message (sign-then-encrypt).
// The message must have From and To fields.
func (c *Client) PackAuthcrypt(ctx context.Context, msg *Message) ([]byte, error) {
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	if msg.From == "" {
		return nil, ErrNoSender
	}
	if len(msg.To) == 0 {
		return nil, ErrNoRecipients
	}

	signingKey, err := c.getSenderSigningKey(ctx, msg.From)
	if err != nil {
		return nil, err
	}

	recipientKeys, err := c.getRecipientEncryptionKeys(ctx, msg.To)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}

	return authcrypt(payload, signingKey, recipientKeys)
}

// Unpack auto-detects the format (JWE, JWS, or plain JSON) and unpacks accordingly.
func (c *Client) Unpack(ctx context.Context, envelope []byte) (*UnpackResult, error) {
	envelope = bytes.TrimSpace(envelope)

	// Try JWE first (compact: starts with "eyJ", JSON: starts with "{")
	if isJWE(envelope) {
		return c.unpackEncrypted(ctx, envelope)
	}

	// Try JWS
	if isJWS(envelope) {
		return c.unpackSigned(ctx, envelope)
	}

	// Try plain JSON
	return c.unpackPlain(envelope)
}

func (c *Client) unpackEncrypted(ctx context.Context, encrypted []byte) (*UnpackResult, error) {
	// Parse JWE to find recipient key IDs and check for skid
	msg, err := jwe.Parse(encrypted)
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}

	// Try to find a matching recipient key
	var decrypted []byte
	for _, r := range msg.Recipients() {
		hdr := r.Headers()
		kid, ok := hdr.KeyID()
		if !ok {
			continue
		}

		privKey, err := c.secrets.GetKey(ctx, kid)
		if err != nil {
			continue
		}

		decrypted, err = anonDecrypt(encrypted, privKey)
		if err != nil {
			continue
		}
		break
	}

	// If no recipient matched by KID, try with all encryption keys from secrets
	if decrypted == nil {
		// Try the protected header KID (single-recipient compact JWE)
		if hdrs := msg.ProtectedHeaders(); hdrs != nil {
			if kid, ok := hdrs.KeyID(); ok {
				if privKey, err := c.secrets.GetKey(ctx, kid); err == nil {
					decrypted, _ = anonDecrypt(encrypted, privKey)
				}
			}
		}
	}

	if decrypted == nil {
		return nil, fmt.Errorf("%w: no matching recipient key found", ErrDecryptionFailed)
	}

	// Check for skid (sender key ID) — indicates authcrypt
	hdrs := msg.ProtectedHeaders()
	var skid string
	if hdrs != nil {
		_ = hdrs.Get("skid", &skid)
	}

	result := &UnpackResult{
		Encrypted: true,
		Anonymous: skid == "",
	}

	// If authcrypt (has skid), the decrypted content is a JWS — verify it
	if skid != "" {
		result.Signed = true

		// Find sender's public signing key via skid
		senderPubKey, err := c.resolveKeyByKID(ctx, skid)
		if err != nil {
			return nil, fmt.Errorf("resolve sender key %s: %w", skid, err)
		}

		payload, err := verifySignature(decrypted, senderPubKey)
		if err != nil {
			return nil, err
		}

		var m Message
		if err := json.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
		}
		result.Message = &m
	} else {
		// Anoncrypt — decrypted content is plain JSON
		var m Message
		if err := json.Unmarshal(decrypted, &m); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
		}
		result.Message = &m
	}

	return result, nil
}

func (c *Client) unpackSigned(ctx context.Context, signed []byte) (*UnpackResult, error) {
	// Parse JWS to find the signer's key ID
	hdrs, err := parseJWSHeaders(signed)
	if err != nil {
		return nil, err
	}

	kid, ok := hdrs.KeyID()
	if !ok || kid == "" {
		return nil, fmt.Errorf("%w: JWS missing kid header", ErrVerificationFailed)
	}

	pubKey, err := c.resolveKeyByKID(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("resolve signing key %s: %w", kid, err)
	}

	payload, err := verifySignature(signed, pubKey)
	if err != nil {
		return nil, err
	}

	var m Message
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}

	return &UnpackResult{
		Message:   &m,
		Signed:    true,
		Encrypted: false,
		Anonymous: false,
	}, nil
}

func (c *Client) unpackPlain(data []byte) (*UnpackResult, error) {
	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &UnpackResult{
		Message:   &m,
		Signed:    false,
		Encrypted: false,
		Anonymous: false,
	}, nil
}

// getSenderSigningKey retrieves the sender's private signing key from the secrets store.
func (c *Client) getSenderSigningKey(ctx context.Context, did string) (jwk.Key, error) {
	doc, err := c.resolver.Resolve(ctx, did)
	if err != nil {
		return nil, err
	}

	vm, err := doc.FindSigningKey()
	if err != nil {
		return nil, err
	}

	return c.secrets.GetKey(ctx, vm.ID)
}

// getRecipientEncryptionKeys resolves public encryption keys for all recipients.
func (c *Client) getRecipientEncryptionKeys(ctx context.Context, dids []string) ([]jwk.Key, error) {
	var keys []jwk.Key
	for _, did := range dids {
		doc, err := c.resolver.Resolve(ctx, did)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", did, err)
		}

		vm, err := doc.FindEncryptionKey()
		if err != nil {
			return nil, fmt.Errorf("find encryption key for %s: %w", did, err)
		}

		keys = append(keys, vm.PublicKey)
	}
	return keys, nil
}

// resolveKeyByKID finds a public key by its key ID across all stored DID documents.
func (c *Client) resolveKeyByKID(ctx context.Context, kid string) (jwk.Key, error) {
	// Extract the DID from the KID (KID format: did#fragment)
	did := extractDIDFromKID(kid)
	if did == "" {
		return nil, fmt.Errorf("%w: cannot extract DID from kid %s", ErrKeyNotFound, kid)
	}

	doc, err := c.resolver.Resolve(ctx, did)
	if err != nil {
		return nil, err
	}

	// Search authentication keys
	for _, vm := range doc.Authentication {
		if vm.ID == kid {
			return vm.PublicKey, nil
		}
	}

	// Search key agreement keys
	for _, vm := range doc.KeyAgreement {
		if vm.ID == kid {
			return vm.PublicKey, nil
		}
	}

	return nil, fmt.Errorf("%w: kid %s not found in DID document %s", ErrKeyNotFound, kid, did)
}

// extractDIDFromKID extracts the DID portion from a key ID (did:method:id#fragment -> did:method:id).
func extractDIDFromKID(kid string) string {
	for i := len(kid) - 1; i >= 0; i-- {
		if kid[i] == '#' {
			return kid[:i]
		}
	}
	return ""
}

// isJWE checks if the data looks like a JWE (compact or JSON serialization).
func isJWE(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// JSON serialization
	if data[0] == '{' {
		// Check for JWE JSON fields
		var peek struct {
			Recipients json.RawMessage `json:"recipients"`
			Ciphertext string          `json:"ciphertext"`
		}
		if err := json.Unmarshal(data, &peek); err == nil {
			return peek.Ciphertext != ""
		}
		return false
	}
	// Compact serialization: 5 base64url parts separated by dots
	parts := bytes.Count(data, []byte("."))
	return parts == 4
}

// isJWS checks if the data looks like a JWS (compact serialization).
func isJWS(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Compact: 3 base64url parts separated by dots
	parts := bytes.Count(data, []byte("."))
	return parts == 2
}
