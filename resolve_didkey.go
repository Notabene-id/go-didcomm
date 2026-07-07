package didcomm

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/notabene-id/go-didcomm/internal/convert"
)

// DIDKeyResolver resolves did:key DIDs locally by decoding the multicodec-encoded public key.
type DIDKeyResolver struct{}

// Resolve parses a did:key DID and returns a DIDDocument with authentication and key agreement keys.
func (r *DIDKeyResolver) Resolve(_ context.Context, did string) (*DIDDocument, error) {
	if len(did) < len("did:key:z") || did[:8] != "did:key:" {
		return nil, fmt.Errorf("%w: not a did:key DID: %s", ErrDIDNotFound, did)
	}

	fragment := did[8:] // everything after "did:key:"
	if fragment[0] != 'z' {
		return nil, fmt.Errorf("%w: did:key missing multibase 'z' prefix: %s", ErrDIDNotFound, did)
	}

	decoded, err := base58.Decode(fragment[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: decode base58: %w", ErrDIDNotFound, err)
	}

	codec, n := binary.Uvarint(decoded)
	if n <= 0 {
		return nil, fmt.Errorf("%w: invalid multicodec varint in %s", ErrDIDNotFound, did)
	}

	pubKeyBytes := decoded[n:]

	switch codec {
	case multicodecEd25519:
		return buildDIDKeyDoc(did, fragment, pubKeyBytes)
	default:
		return nil, fmt.Errorf("%w: unsupported multicodec 0x%x in %s", ErrUnsupportedKeyType, codec, did)
	}
}

// buildDIDKeyDoc constructs a DIDDocument from an Ed25519 public key embedded in a did:key.
func buildDIDKeyDoc(did, sigFragment string, ed25519PubBytes []byte) (*DIDDocument, error) {
	if len(ed25519PubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid Ed25519 key length %d", ErrDIDNotFound, len(ed25519PubBytes))
	}

	sigKID := did + "#" + sigFragment

	x25519PubBytes, err := convert.Ed25519PublicToX25519(ed25519PubBytes)
	if err != nil {
		return nil, fmt.Errorf("convert ed25519 to x25519: %w", err)
	}
	encKID := did + "#" + encodeDIDKeyFragment(multicodecX25519, x25519PubBytes)

	sigPubJWK, err := signingPublicJWK(ed25519PubBytes, sigKID)
	if err != nil {
		return nil, err
	}
	encPubJWK, err := encryptionPublicJWK(x25519PubBytes, encKID)
	if err != nil {
		return nil, err
	}

	return &DIDDocument{
		ID: did,
		Authentication: []VerificationMethod{
			{ID: sigKID, Type: vmTypeEd25519, Controller: did, PublicKey: sigPubJWK},
		},
		KeyAgreement: []VerificationMethod{
			{ID: encKID, Type: vmTypeX25519, Controller: did, PublicKey: encPubJWK},
		},
	}, nil
}
