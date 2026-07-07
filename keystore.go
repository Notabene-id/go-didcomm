package didcomm

import "context"

// KeyStore is the sole channel for private-key material: implementations hold
// the keys and return only operation results, so a compromised build of this
// library cannot exfiltrate a key. Back it with an HSM or KMS. Keys are named by
// their DID verification-method id (kid, e.g. "did:web:example.com#key-1").
type KeyStore interface {
	// Sign returns the raw EdDSA signature over data for signing key kid.
	Sign(ctx context.Context, kid string, data []byte) ([]byte, error)

	// DiffieHellman returns the X25519 shared secret between key kid and
	// peerPublicKey. The long-term private key is not recoverable from it.
	DiffieHellman(ctx context.Context, kid string, peerPublicKey []byte) ([]byte, error)
}
