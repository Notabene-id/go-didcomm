package didcomm

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/notabene-id/go-didcomm/internal/jose"
)

// envClass is the structurally detected wire form of an envelope.
type envClass uint8

const (
	classPlain envClass = iota
	classJWS
	classJWE
)

// Unpack decrypts and/or verifies an envelope and REQUIRES an authenticated
// sender. On success Metadata.SenderDID is cryptographically verified and equals
// Message.From. Plain and anonymously-encrypted messages are rejected with
// ErrUnauthenticated; use UnpackUnverified to accept them.
func (c *Client) Unpack(ctx context.Context, envelope []byte) (*Message, *Metadata, error) {
	return c.unpack(ctx, envelope, false)
}

// UnpackUnverified decrypts where it can but does NOT require an authenticated
// sender. For a returned message with an empty Metadata.SenderDID, Message.From
// is attacker-controlled and must not be trusted. Use it only for diagnostics,
// relaying, or anonymous intake.
func (c *Client) UnpackUnverified(ctx context.Context, envelope []byte) (*Message, *Metadata, error) {
	return c.unpack(ctx, envelope, true)
}

func (c *Client) unpack(ctx context.Context, envelope []byte, allowUnauthenticated bool) (*Message, *Metadata, error) {
	msg, meta, err := c.unpackClassified(ctx, bytes.TrimSpace(envelope), allowUnauthenticated)
	if err != nil {
		return nil, nil, err
	}
	if err := checkNotExpired(msg); err != nil {
		return nil, nil, err
	}
	return msg, meta, nil
}

func (c *Client) unpackClassified(
	ctx context.Context, envelope []byte, allowUnauthenticated bool,
) (*Message, *Metadata, error) {
	switch classify(envelope) {
	case classJWE:
		return c.unpackEncrypted(ctx, envelope, allowUnauthenticated)
	case classJWS:
		return c.unpackSigned(ctx, envelope)
	default:
		if !allowUnauthenticated {
			return nil, nil, ErrUnauthenticated
		}
		msg, err := parseMessage(envelope)
		if err != nil {
			return nil, nil, err
		}
		return msg, &Metadata{Mode: ModePlain}, nil
	}
}

// checkNotExpired rejects a message whose expires_time has passed. DIDComm
// leaves enforcement to the recipient; doing it here means a stale or replayed
// envelope never reaches application code as if it were fresh.
func checkNotExpired(msg *Message) error {
	if msg.ExpiresAt != nil && time.Now().After(*msg.ExpiresAt) {
		return ErrMessageExpired
	}
	return nil
}

// unpackSigned verifies a standalone JWS and binds the signer to the message's
// declared sender.
func (c *Client) unpackSigned(ctx context.Context, signed []byte) (*Message, *Metadata, error) {
	kid, err := jwsSignerKID(signed)
	if err != nil {
		return nil, nil, err
	}
	senderDID := didFromKID(kid)
	if senderDID == "" {
		return nil, nil, ErrDecryptFailed
	}
	pub, err := c.signingKey(ctx, kid)
	if err != nil {
		return nil, nil, ErrDecryptFailed
	}
	payload, err := verifyJWS(signed, pub)
	if err != nil {
		return nil, nil, err
	}
	msg, err := parseMessage(payload)
	if err != nil {
		return nil, nil, err
	}
	if err := bindSender(msg, senderDID); err != nil {
		return nil, nil, err
	}
	return msg, &Metadata{Mode: ModeSigned, SenderDID: senderDID}, nil
}

// unpackEncrypted decrypts a JWE, then authenticates the sender according to the
// envelope's key-management algorithm.
func (c *Client) unpackEncrypted(
	ctx context.Context, envelope []byte, allowUnauthenticated bool,
) (*Message, *Metadata, error) {
	p, err := jose.Parse(envelope)
	if err != nil || p.Header.EPK == nil {
		return nil, nil, ErrDecryptFailed
	}
	ephemeralPub, err := b64.DecodeString(p.Header.EPK.X)
	if err != nil || len(ephemeralPub) != 32 {
		return nil, nil, ErrDecryptFailed
	}

	authcrypt := p.Header.Alg == jose.AlgECDH1PUA256KW
	if !validKDFHeaders(p, authcrypt) {
		return nil, nil, ErrDecryptFailed
	}

	var senderStaticPub []byte
	if authcrypt {
		if p.Header.SKID == "" {
			return nil, nil, ErrDecryptFailed
		}
		if senderStaticPub, err = c.keyAgreementPublic(ctx, p.Header.SKID); err != nil {
			return nil, nil, ErrDecryptFailed
		}
	}

	for _, r := range p.Recipients {
		z, ok := c.recipientSharedSecret(ctx, r.KID, ephemeralPub, senderStaticPub, authcrypt)
		if !ok {
			continue
		}
		plaintext, profile, ok := openTrial(p, r.EncryptedKey, z, authcrypt)
		if !ok {
			continue
		}
		return c.authenticate(ctx, plaintext, authenticateInput{
			authcrypt:            authcrypt,
			senderKID:            p.Header.SKID,
			recipientDID:         didFromKID(r.KID),
			profile:              profile,
			allowUnauthenticated: allowUnauthenticated,
		})
	}
	return nil, nil, ErrDecryptFailed
}

// authenticateInput carries the post-decryption authentication context.
type authenticateInput struct {
	authcrypt            bool
	senderKID            string
	recipientDID         string
	profile              Profile
	allowUnauthenticated bool
}

// authenticate establishes and binds the sender of a decrypted payload. For
// ECDH-1PU the successful decryption already authenticates the skid; for ECDH-ES
// the payload is either an inner JWS (sign-then-encrypt) or an anonymous message.
func (c *Client) authenticate(
	ctx context.Context, plaintext []byte, in authenticateInput,
) (*Message, *Metadata, error) {
	if in.authcrypt {
		senderDID := didFromKID(in.senderKID)
		msg, err := parseMessage(plaintext)
		if err != nil {
			return nil, nil, err
		}
		if err := bindSender(msg, senderDID); err != nil {
			return nil, nil, err
		}
		if err := bindRecipient(msg, in.recipientDID); err != nil {
			return nil, nil, err
		}
		return msg, &Metadata{Mode: ModeAuthcrypt, SenderDID: senderDID, Encrypted: true, Profile: in.profile}, nil
	}

	if classify(plaintext) == classJWS {
		return c.verifyInnerJWS(ctx, plaintext, in.recipientDID)
	}

	// Anonymous encryption: no sender authentication is possible.
	if !in.allowUnauthenticated {
		return nil, nil, ErrUnauthenticated
	}
	msg, err := parseMessage(plaintext)
	if err != nil {
		return nil, nil, err
	}
	return msg, &Metadata{Mode: ModeAnoncrypt, Encrypted: true, Profile: ProfileAnoncrypt}, nil
}

// verifyInnerJWS verifies the inner signature of a sign-then-encrypt message and
// binds both the signer and this recipient.
func (c *Client) verifyInnerJWS(ctx context.Context, signed []byte, recipientDID string) (*Message, *Metadata, error) {
	kid, err := jwsSignerKID(signed)
	if err != nil {
		return nil, nil, err
	}
	senderDID := didFromKID(kid)
	if senderDID == "" {
		return nil, nil, ErrDecryptFailed
	}
	pub, err := c.signingKey(ctx, kid)
	if err != nil {
		return nil, nil, ErrDecryptFailed
	}
	payload, err := verifyJWS(signed, pub)
	if err != nil {
		return nil, nil, err
	}
	msg, err := parseMessage(payload)
	if err != nil {
		return nil, nil, err
	}
	if err := bindSender(msg, senderDID); err != nil {
		return nil, nil, err
	}
	if err := bindRecipient(msg, recipientDID); err != nil {
		return nil, nil, err
	}
	return msg, &Metadata{
		Mode: ModeSigned, SenderDID: senderDID, Encrypted: true, Profile: ProfileSignedAnoncrypt,
	}, nil
}

// recipientSharedSecret derives our ECDH shared secret for a recipient entry
// through the sealed key store. It returns ok=false when we do not hold that kid.
func (c *Client) recipientSharedSecret(
	ctx context.Context, kid string, ephemeralPub, senderStaticPub []byte, authcrypt bool,
) ([]byte, bool) {
	ze, err := c.keys.DiffieHellman(ctx, kid, ephemeralPub)
	if err != nil {
		return nil, false
	}
	if !authcrypt {
		return ze, true
	}
	zs, err := c.keys.DiffieHellman(ctx, kid, senderStaticPub)
	if err != nil {
		return nil, false
	}
	z := make([]byte, 0, len(ze)+len(zs))
	z = append(z, ze...)
	z = append(z, zs...)
	return z, true
}

// openTrial decrypts a recipient entry, selecting the ECDH-1PU draft when the
// content encryption permits either. Draft-03 and draft-04 share an "alg" value,
// so an A256CBC-HS512 authcrypt is tried without the tag binding (draft-03) then
// with it (draft-04); both failures are indistinguishable to a caller.
func openTrial(p *jose.ParsedJWE, encryptedKey, z []byte, authcrypt bool) ([]byte, Profile, bool) {
	if !authcrypt {
		if pt, err := jose.OpenRecipient(p, encryptedKey, z, false); err == nil {
			return pt, ProfileSignedAnoncrypt, true
		}
		return nil, 0, false
	}
	if pt, err := jose.OpenRecipient(p, encryptedKey, z, false); err == nil {
		return pt, ProfileAuthcrypt1PUv3, true
	}
	if p.Header.Enc == jose.EncA256CBCHS512 {
		if pt, err := jose.OpenRecipient(p, encryptedKey, z, true); err == nil {
			return pt, ProfileAuthcrypt1PUv4, true
		}
	}
	return nil, 0, false
}

// validKDFHeaders enforces the DIDComm v2 key-derivation binding headers. The
// "apv" MUST hash the exact recipient set present in the envelope, and for
// authcrypt "apu" MUST carry the skid. Both fields are also covered by the
// content AAD, but the spec requires them to be present and correct, so a
// mismatch (including a peer that omits them) is rejected. Anoncrypt omits apu.
func validKDFHeaders(p *jose.ParsedJWE, authcrypt bool) bool {
	kids := make([]string, len(p.Recipients))
	for i, r := range p.Recipients {
		kids[i] = r.KID
	}
	if p.Header.APV != b64.EncodeToString(didcommAPV(kids)) {
		return false
	}
	if authcrypt && p.Header.APU != b64.EncodeToString([]byte(p.Header.SKID)) {
		return false
	}
	return true
}

// keyAgreementPublic resolves the X25519 public key for a key-agreement kid.
func (c *Client) keyAgreementPublic(ctx context.Context, kid string) ([]byte, error) {
	did := didFromKID(kid)
	if did == "" {
		return nil, ErrKeyNotFound
	}
	doc, err := c.resolve(ctx, did)
	if err != nil {
		return nil, err
	}
	vm, err := doc.keyAgreementKey(kid)
	if err != nil {
		return nil, err
	}
	return x25519PublicBytes(vm.PublicKey)
}

// signingKey resolves the public signing key for a kid, from the authentication
// section only.
func (c *Client) signingKey(ctx context.Context, kid string) (jwk.Key, error) {
	did := didFromKID(kid)
	if did == "" {
		return nil, ErrKeyNotFound
	}
	doc, err := c.resolve(ctx, did)
	if err != nil {
		return nil, err
	}
	vm, err := doc.signingKey(kid)
	if err != nil {
		return nil, err
	}
	return vm.PublicKey, nil
}

// bindSender requires the message's declared "from" to match the verified signer.
func bindSender(msg *Message, senderDID string) error {
	if msg.From == "" || msg.From != senderDID {
		return ErrSenderMismatch
	}
	return nil
}

// bindRecipient guards against surreptitious forwarding: if the message lists
// addressees, this recipient must be among them.
func bindRecipient(msg *Message, recipientDID string) error {
	if len(msg.To) == 0 || recipientDID == "" {
		return nil
	}
	if slices.Contains(msg.To, recipientDID) {
		return nil
	}
	return ErrRecipientMismatch
}

// parseMessage unmarshals and validates a DIDComm message.
func parseMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, ErrInvalidMessage
	}
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	return &msg, nil
}

// classify structurally detects the wire form of an envelope.
func classify(env []byte) envClass {
	if len(env) == 0 {
		return classPlain
	}
	if env[0] == '{' {
		var probe map[string]json.RawMessage
		if json.Unmarshal(env, &probe) != nil {
			return classPlain
		}
		if _, ok := probe["ciphertext"]; ok {
			return classJWE
		}
		_, hasProtected := probe["protected"]
		_, hasSig := probe["signature"]
		_, hasSigs := probe["signatures"]
		if hasSigs || (hasProtected && hasSig) {
			return classJWS
		}
		return classPlain
	}
	switch bytes.Count(env, []byte(".")) {
	case 4:
		return classJWE
	case 2:
		return classJWS
	default:
		return classPlain
	}
}
