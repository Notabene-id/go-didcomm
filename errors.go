package didcomm

import "errors"

var (
	// ErrKeyNotFound is returned when a key cannot be found in the secrets resolver.
	ErrKeyNotFound = errors.New("didcomm: key not found")

	// ErrDIDNotFound is returned when a DID document cannot be resolved.
	ErrDIDNotFound = errors.New("didcomm: DID not found")

	// ErrInvalidMessage is returned when a message is malformed or missing required fields.
	ErrInvalidMessage = errors.New("didcomm: invalid message")

	// ErrEncryptionFailed is returned when JWE encryption fails.
	ErrEncryptionFailed = errors.New("didcomm: encryption failed")

	// ErrDecryptionFailed is returned when JWE decryption fails.
	ErrDecryptionFailed = errors.New("didcomm: decryption failed")

	// ErrSigningFailed is returned when JWS signing fails.
	ErrSigningFailed = errors.New("didcomm: signing failed")

	// ErrVerificationFailed is returned when JWS signature verification fails.
	ErrVerificationFailed = errors.New("didcomm: verification failed")

	// ErrUnsupportedKeyType is returned when a key type is not supported.
	ErrUnsupportedKeyType = errors.New("didcomm: unsupported key type")

	// ErrNoRecipients is returned when no recipients are specified for encryption.
	ErrNoRecipients = errors.New("didcomm: no recipients")

	// ErrNoSender is returned when no sender is specified for operations that require one.
	ErrNoSender = errors.New("didcomm: no sender")
)
