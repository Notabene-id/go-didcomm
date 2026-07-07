package didcomm

import "github.com/notabene-id/go-didcomm/internal/jose"

// packConfig holds resolved pack options.
type packConfig struct {
	profile       Profile
	contentEnc    jose.ContentEncryption
	serialization Serialization
}

// PackOption configures a Pack call.
type PackOption func(*packConfig)

// defaultPackConfig is sign-then-encrypt with A256GCM content encryption in the
// general JSON serialization: non-repudiable, and interoperable with the widest
// set of peers.
func defaultPackConfig() packConfig {
	return packConfig{
		profile:       ProfileSignedAnoncrypt,
		contentEnc:    jose.EncA256GCM,
		serialization: GeneralJSON,
	}
}

// WithProfile selects the envelope profile (default ProfileSignedAnoncrypt).
func WithProfile(p Profile) PackOption {
	return func(c *packConfig) { c.profile = p }
}

// WithContentEncryption overrides the JWE content-encryption algorithm. Ignored
// where a profile fixes it (ProfileAuthcrypt1PUv4 requires A256CBC-HS512).
func WithContentEncryption(enc ContentEncryption) PackOption {
	return func(c *packConfig) {
		switch enc {
		case ContentA256GCM:
			c.contentEnc = jose.EncA256GCM
		case ContentA256CBCHS512:
			c.contentEnc = jose.EncA256CBCHS512
		}
	}
}

// WithSerialization selects the JWE serialization (default GeneralJSON). Compact
// supports a single recipient only.
func WithSerialization(s Serialization) PackOption {
	return func(c *packConfig) { c.serialization = s }
}

// ContentEncryption identifies a content-encryption algorithm for
// WithContentEncryption.
type ContentEncryption uint8

// Content-encryption choices.
const (
	ContentA256GCM ContentEncryption = iota
	ContentA256CBCHS512
)

func (c packConfig) joseSerialization() jose.Serialization {
	if c.serialization == Compact {
		return jose.Compact
	}
	return jose.GeneralJSON
}
