package jose

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// kekSize is the AES-256 key-wrapping key length in bytes (A256KW).
const kekSize = 32

// EphemeralKey is the "epk" JWK: an OKP X25519 public key.
type EphemeralKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// Header is the JWE protected header this package emits and understands.
type Header struct {
	Typ  string            `json:"typ,omitempty"`
	Alg  KeyWrapAlgorithm  `json:"alg"`
	Enc  ContentEncryption `json:"enc"`
	EPK  *EphemeralKey     `json:"epk,omitempty"`
	SKID string            `json:"skid,omitempty"`
	APU  string            `json:"apu,omitempty"`
	APV  string            `json:"apv,omitempty"`
	KID  string            `json:"kid,omitempty"` // compact serialization only
}

// Recipient is one recipient's key-agreement input for Encrypt. Z is the raw
// ECDH shared secret: Ze for ECDH-ES, or Ze||Zs for ECDH-1PU. The caller
// computes it from a sealed key store; this package never sees a private key.
type Recipient struct {
	KID string
	Z   []byte
}

// EncryptRequest fully specifies a JWE to build.
type EncryptRequest struct {
	Enc           ContentEncryption
	Alg           KeyWrapAlgorithm
	Serialization Serialization
	Typ           string
	SenderKID     string // "skid"; empty for ECDH-ES (anonymous sender)
	EphemeralPub  []byte // X25519 "epk" public key, shared across recipients
	APU           []byte // optional PartyUInfo (raw); omitted from header when nil
	APV           []byte // optional PartyVInfo (raw)
	BindTag       bool   // fold the content-encryption tag into the KDF (ECDH-1PU draft-04)
	Plaintext     []byte
	Recipients    []Recipient
}

// ParsedRecipient is one recipient entry from a parsed JWE.
type ParsedRecipient struct {
	KID          string
	EncryptedKey []byte
}

// ParsedJWE is the decoded wire form. RawProtected is retained verbatim because
// it is the AAD the content tag was computed over.
type ParsedJWE struct {
	Header       Header
	RawProtected string
	Recipients   []ParsedRecipient
	IV           []byte
	Ciphertext   []byte
	Tag          []byte
}

// jweJSON is the general JSON serialization wire shape.
type jweJSON struct {
	Protected  string          `json:"protected"`
	Recipients []recipientJSON `json:"recipients,omitempty"`
	IV         string          `json:"iv"`
	Ciphertext string          `json:"ciphertext"`
	Tag        string          `json:"tag"`
	// Flattened single-recipient fields (accepted on parse for interoperability).
	EncryptedKey string        `json:"encrypted_key,omitempty"`
	RecipHeader  *recipientHdr `json:"header,omitempty"`
}

type recipientJSON struct {
	Header       recipientHdr `json:"header"`
	EncryptedKey string       `json:"encrypted_key"`
}

type recipientHdr struct {
	KID string `json:"kid,omitempty"`
}

var b64 = base64.RawURLEncoding

// NewCEK returns a fresh random content-encryption key of the size enc needs.
func NewCEK(enc ContentEncryption) ([]byte, error) {
	size, ok := enc.cekSize()
	if !ok {
		return nil, ErrMalformed
	}
	cek := make([]byte, size)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}
	return cek, nil
}

// DeriveKEK computes the A256KW key-wrapping key from an ECDH shared secret via
// the Concat KDF (RFC 7518 §4.6). tag folds the content-encryption tag into the
// derivation for ECDH-1PU draft-04; pass nil for ECDH-ES and ECDH-1PU draft-03.
func DeriveKEK(z []byte, alg KeyWrapAlgorithm, apu, apv, tag []byte) []byte {
	return concatKDF(z, otherInfo(string(alg), apu, apv, kekSize*8, tag), kekSize)
}

// Encrypt builds a JWE per req. It generates the CEK, encrypts the content
// (binding the base64url protected header as AAD), then derives a KEK and wraps
// the CEK for each recipient. For ECDH-1PU draft-04 (BindTag) the wrap happens
// after content encryption so the tag can enter the KDF.
func Encrypt(req *EncryptRequest) ([]byte, error) {
	if len(req.Recipients) == 0 {
		return nil, ErrMalformed
	}
	if req.Serialization == Compact && len(req.Recipients) != 1 {
		return nil, ErrMalformed
	}

	cek, err := NewCEK(req.Enc)
	if err != nil {
		return nil, err
	}

	hdr := Header{
		Typ:  req.Typ,
		Alg:  req.Alg,
		Enc:  req.Enc,
		SKID: req.SenderKID,
		APU:  encodeOptional(req.APU),
		APV:  encodeOptional(req.APV),
	}
	if req.EphemeralPub != nil {
		hdr.EPK = &EphemeralKey{Kty: "OKP", Crv: "X25519", X: b64.EncodeToString(req.EphemeralPub)}
	}
	if req.Serialization == Compact {
		hdr.KID = req.Recipients[0].KID
	}

	protectedJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	protectedB64 := b64.EncodeToString(protectedJSON)

	s, err := encryptContent(req.Enc, cek, req.Plaintext, []byte(protectedB64))
	if err != nil {
		return nil, err
	}

	tag := s.tag
	kdfTag := []byte(nil)
	if req.BindTag {
		kdfTag = tag
	}

	wrapped := make([][]byte, len(req.Recipients))
	for i, r := range req.Recipients {
		kek := DeriveKEK(r.Z, req.Alg, req.APU, req.APV, kdfTag)
		w, err := aesKeyWrap(kek, cek)
		if err != nil {
			return nil, err
		}
		wrapped[i] = w
	}

	if req.Serialization == Compact {
		return serializeCompact(protectedB64, wrapped[0], s), nil
	}
	return serializeGeneral(protectedB64, req.Recipients, wrapped, s)
}

// OpenRecipient decrypts a parsed JWE for the recipient whose wrapped key and
// ECDH shared secret z are supplied. bindTag must match how the envelope was
// produced (ECDH-1PU draft-04). Every failure returns ErrDecrypt.
func OpenRecipient(p *ParsedJWE, encryptedKey, z []byte, bindTag bool) ([]byte, error) {
	apu, err := decodeOptional(p.Header.APU)
	if err != nil {
		return nil, ErrDecrypt
	}
	apv, err := decodeOptional(p.Header.APV)
	if err != nil {
		return nil, ErrDecrypt
	}

	kdfTag := []byte(nil)
	if bindTag {
		kdfTag = p.Tag
	}
	kek := DeriveKEK(z, p.Header.Alg, apu, apv, kdfTag)

	cek, err := aesKeyUnwrap(kek, encryptedKey)
	if err != nil {
		return nil, ErrDecrypt
	}
	return decryptContent(p.Header.Enc, cek, p.IV, p.Ciphertext, p.Tag, []byte(p.RawProtected))
}

// Parse decodes a general-JSON, flattened-JSON, or compact JWE.
func Parse(data []byte) (*ParsedJWE, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		return parseJSON([]byte(trimmed))
	}
	return parseCompact(trimmed)
}

func parseJSON(data []byte) (*ParsedJWE, error) {
	var w jweJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, ErrMalformed
	}
	hdr, err := decodeHeader(w.Protected)
	if err != nil {
		return nil, err
	}
	p := &ParsedJWE{Header: hdr, RawProtected: w.Protected}

	switch {
	case len(w.Recipients) > 0:
		for _, r := range w.Recipients {
			ek, err := b64.DecodeString(r.EncryptedKey)
			if err != nil {
				return nil, ErrMalformed
			}
			p.Recipients = append(p.Recipients, ParsedRecipient{KID: r.Header.KID, EncryptedKey: ek})
		}
	case w.EncryptedKey != "":
		ek, err := b64.DecodeString(w.EncryptedKey)
		if err != nil {
			return nil, ErrMalformed
		}
		kid := hdr.KID
		if w.RecipHeader != nil && w.RecipHeader.KID != "" {
			kid = w.RecipHeader.KID
		}
		p.Recipients = append(p.Recipients, ParsedRecipient{KID: kid, EncryptedKey: ek})
	default:
		return nil, ErrMalformed
	}

	if err := decodeBody(p, w.IV, w.Ciphertext, w.Tag); err != nil {
		return nil, err
	}
	return p, nil
}

func parseCompact(data string) (*ParsedJWE, error) {
	parts := strings.Split(data, ".")
	if len(parts) != 5 {
		return nil, ErrMalformed
	}
	hdr, err := decodeHeader(parts[0])
	if err != nil {
		return nil, err
	}
	ek, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	p := &ParsedJWE{
		Header:       hdr,
		RawProtected: parts[0],
		Recipients:   []ParsedRecipient{{KID: hdr.KID, EncryptedKey: ek}},
	}
	if err := decodeBody(p, parts[2], parts[3], parts[4]); err != nil {
		return nil, err
	}
	return p, nil
}

func decodeHeader(protectedB64 string) (Header, error) {
	raw, err := b64.DecodeString(protectedB64)
	if err != nil {
		return Header{}, ErrMalformed
	}
	var hdr Header
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return Header{}, ErrMalformed
	}
	return hdr, nil
}

func decodeBody(p *ParsedJWE, iv, ciphertext, tag string) error {
	var err error
	if p.IV, err = b64.DecodeString(iv); err != nil {
		return ErrMalformed
	}
	if p.Ciphertext, err = b64.DecodeString(ciphertext); err != nil {
		return ErrMalformed
	}
	if p.Tag, err = b64.DecodeString(tag); err != nil {
		return ErrMalformed
	}
	return nil
}

func serializeGeneral(protectedB64 string, recipients []Recipient, wrapped [][]byte, s sealed) ([]byte, error) {
	w := jweJSON{
		Protected:  protectedB64,
		IV:         b64.EncodeToString(s.iv),
		Ciphertext: b64.EncodeToString(s.ciphertext),
		Tag:        b64.EncodeToString(s.tag),
	}
	for i, r := range recipients {
		w.Recipients = append(w.Recipients, recipientJSON{
			Header:       recipientHdr{KID: r.KID},
			EncryptedKey: b64.EncodeToString(wrapped[i]),
		})
	}
	return json.Marshal(w)
}

func serializeCompact(protectedB64 string, wrapped []byte, s sealed) []byte {
	parts := []string{
		protectedB64,
		b64.EncodeToString(wrapped),
		b64.EncodeToString(s.iv),
		b64.EncodeToString(s.ciphertext),
		b64.EncodeToString(s.tag),
	}
	return []byte(strings.Join(parts, "."))
}

func encodeOptional(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return b64.EncodeToString(b)
}

func decodeOptional(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return b64.DecodeString(s)
}
