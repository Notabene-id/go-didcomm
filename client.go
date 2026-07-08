package didcomm

import "context"

// Client packs and unpacks DIDComm v2 messages. It resolves DIDs through a
// Resolver and performs every private-key operation through a KeyStore, so it
// never holds key material itself.
type Client struct {
	resolver DIDResolver
	keys     KeyStore
}

// Metadata describes how an unpacked message was protected.
type Metadata struct {
	// Mode is the wire protection that was applied.
	Mode Mode
	// SenderDID is the cryptographically verified sender. For messages returned
	// by Unpack it always equals Message.From. It is empty only for anonymous or
	// plain messages, which Unpack rejects and only UnpackUnverified returns.
	SenderDID string
	// Encrypted reports whether the message was encrypted on the wire.
	Encrypted bool
	// Profile is the encrypted profile that was detected, when Encrypted.
	Profile Profile
}

// NewClient creates a Client backed by the given resolver and key store.
func NewClient(resolver DIDResolver, keys KeyStore) *Client {
	return &Client{resolver: resolver, keys: keys}
}

// resolve looks up a DID document.
func (c *Client) resolve(ctx context.Context, did string) (*DIDDocument, error) {
	return c.resolver.Resolve(ctx, did)
}
