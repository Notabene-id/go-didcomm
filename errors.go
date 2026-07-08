package didcomm

import "errors"

// Sentinel errors returned across the package boundary. Match with errors.Is.
var (
	// ErrKeyNotFound is returned when a key cannot be found for a kid.
	ErrKeyNotFound = errors.New("didcomm: key not found")

	// ErrDIDNotFound is returned when a DID document cannot be resolved.
	ErrDIDNotFound = errors.New("didcomm: DID not found")

	// ErrInvalidMessage is returned when a message is malformed or missing
	// required fields.
	ErrInvalidMessage = errors.New("didcomm: invalid message")

	// ErrUnsupportedKeyType is returned for an unsupported key or curve.
	ErrUnsupportedKeyType = errors.New("didcomm: unsupported key type")

	// ErrUnsupportedProfile is returned when a profile cannot be packed or a wire
	// envelope uses an algorithm this library does not implement.
	ErrUnsupportedProfile = errors.New("didcomm: unsupported profile")

	// ErrNoRecipients is returned when encryption is requested with no recipients.
	ErrNoRecipients = errors.New("didcomm: no recipients")

	// ErrNoSender is returned when an operation requires a sender and none is set.
	ErrNoSender = errors.New("didcomm: no sender")

	// ErrNoServiceEndpoint is returned when a DID document exposes no
	// DIDCommMessaging service endpoint.
	ErrNoServiceEndpoint = errors.New("didcomm: no service endpoint")

	// ErrBlockedAddress is returned when did:web resolution is refused because the
	// target resolves to a non-public (loopback, private, link-local, or
	// metadata) address.
	ErrBlockedAddress = errors.New("didcomm: blocked non-public address")

	// ErrDecryptFailed is the single, opaque failure for any decryption or
	// signature-verification error. It never reveals which stage failed, so it
	// cannot be used as a decryption oracle.
	ErrDecryptFailed = errors.New("didcomm: decryption or verification failed")

	// ErrUnauthenticated is returned by Unpack for a message with no verifiable
	// sender (plain or anonymous encryption). Use UnpackUnverified to accept such
	// messages, understanding that the sender is not authenticated.
	ErrUnauthenticated = errors.New("didcomm: message has no authenticated sender")

	// ErrSenderMismatch is returned when the cryptographically verified sender
	// does not match the message's declared "from".
	ErrSenderMismatch = errors.New("didcomm: signer does not match message sender")

	// ErrRecipientMismatch is returned when this recipient is not listed in the
	// message's "to", which would indicate a forwarded or misdirected message.
	ErrRecipientMismatch = errors.New("didcomm: recipient not in message addressees")

	// ErrMessageExpired is returned by Unpack when a message's expires_time has
	// already passed.
	ErrMessageExpired = errors.New("didcomm: message has expired")
)
