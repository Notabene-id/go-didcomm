package didcomm

import "github.com/notabene-id/go-didcomm/internal/jose"

// Profile selects the DIDComm envelope a message is packed into. The choice is
// a security and interoperability decision; see each constant.
type Profile uint8

// Mode reports how an unpacked message was protected on the wire.
type Mode uint8

// Serialization selects the JWE serialization for encrypted profiles.
type Serialization uint8

const (
	// ProfileSignedAnoncrypt is sign-then-encrypt: an inner EdDSA JWS wrapped in
	// an ECDH-ES anonymous-sender JWE. Authentication is the inner signature, so
	// it is NON-repudiable (provable to third parties) — the recommended default
	// where a message's origin must stand up to later audit. RFC 7515 (JWS) +
	// RFC 7518 §4.6 (ECDH-ES).
	ProfileSignedAnoncrypt Profile = iota

	// ProfileAuthcrypt1PUv3 is authenticated encryption via ECDH-1PU key
	// agreement, draft-madden-jose-ecdh-1pu-03: the sender's static key enters
	// the KDF, authenticating the sender at the envelope with no inner signature.
	// Repudiable. Interoperates with implementations that predate the draft-04
	// tag binding.
	ProfileAuthcrypt1PUv3

	// ProfileAuthcrypt1PUv4 is ECDH-1PU authcrypt per draft-madden-jose-ecdh-1pu-04,
	// which folds the content-encryption tag into the key derivation (§2.3) and
	// requires the AES-CBC-HMAC content-encryption family.
	ProfileAuthcrypt1PUv4

	// ProfileAnoncrypt is anonymous encryption (ECDH-ES) with no sender
	// authentication. A message packed this way carries no verifiable sender and
	// is only readable through Client.UnpackUnverified.
	ProfileAnoncrypt

	// ProfileSigned is a signed-only JWS with no encryption. The body is
	// authenticated and non-repudiable but travels in the clear; use it only for
	// content that is not confidential (e.g. out-of-band invitations).
	ProfileSigned
)

// Unpacked message modes.
const (
	ModeSigned Mode = iota
	ModeAuthcrypt
	ModeAnoncrypt
	ModePlain
)

// JWE serialization forms.
const (
	GeneralJSON Serialization = iota
	Compact
)

// packSpec is the resolved wire configuration for a profile.
type packSpec struct {
	encrypt   bool
	sign      bool // inner (or standalone) JWS
	authcrypt bool // ECDH-1PU envelope authentication
	alg       jose.KeyWrapAlgorithm
	enc       jose.ContentEncryption
	bindTag   bool // ECDH-1PU draft-04
}

// spec resolves a profile and options into a wire configuration.
func (p Profile) spec(enc jose.ContentEncryption) packSpec {
	switch p {
	case ProfileSignedAnoncrypt:
		return packSpec{encrypt: true, sign: true, alg: jose.AlgECDHESA256KW, enc: enc}
	case ProfileAuthcrypt1PUv3:
		return packSpec{encrypt: true, authcrypt: true, alg: jose.AlgECDH1PUA256KW, enc: enc}
	case ProfileAuthcrypt1PUv4:
		return packSpec{encrypt: true, authcrypt: true, alg: jose.AlgECDH1PUA256KW, enc: jose.EncA256CBCHS512, bindTag: true}
	case ProfileAnoncrypt:
		return packSpec{encrypt: true, alg: jose.AlgECDHESA256KW, enc: enc}
	case ProfileSigned:
		return packSpec{sign: true}
	default:
		return packSpec{}
	}
}
