package didcomm

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/mr-tron/base58"
)

// Multicodec prefixes for did:key
const (
	multicodecEd25519 = 0xed
	multicodecX25519  = 0xec
)

// VerificationMethod represents a DID document verification method.
type VerificationMethod struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Controller string  `json:"controller"`
	PublicKey  jwk.Key `json:"-"`
}

// DIDDocument is a thin DID document with only DIDComm-relevant fields.
type DIDDocument struct {
	ID                   string               `json:"id"`
	Authentication       []VerificationMethod  `json:"authentication,omitempty"`
	KeyAgreement         []VerificationMethod  `json:"keyAgreement,omitempty"`
	Service              []Service             `json:"service,omitempty"`
}

// Service represents a DID document service entry.
type Service struct {
	ID              string   `json:"id"`
	Type            string   `json:"type"`
	ServiceEndpoint string   `json:"serviceEndpoint"`
}

// GenerateDIDKey generates a new did:key with Ed25519 signing and X25519 encryption keys.
func GenerateDIDKey() (*DIDDocument, *KeyPair, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Encode Ed25519 public key with multicodec prefix
	did := encodeDIDKey(multicodecEd25519, kp.SigningPublic)

	// Build signing verification method key ID
	sigFragment := did[len("did:key:"):]
	sigKID := did + "#" + sigFragment

	// Build encryption key fragment from X25519 public key
	encFragment := encodeDIDKeyFragment(multicodecX25519, kp.EncryptionPublic.Bytes())
	encKID := did + "#" + encFragment

	// Set KIDs on JWK keys
	_ = kp.SigningJWK.Set(jwk.KeyIDKey, sigKID)
	_ = kp.EncryptionJWK.Set(jwk.KeyIDKey, encKID)

	sigPubJWK, err := kp.SigningPublicJWK()
	if err != nil {
		return nil, nil, fmt.Errorf("derive signing public JWK: %w", err)
	}
	_ = sigPubJWK.Set(jwk.KeyIDKey, sigKID)
	_ = sigPubJWK.Set(jwk.AlgorithmKey, jwa.EdDSA())

	encPubJWK, err := kp.EncryptionPublicJWK()
	if err != nil {
		return nil, nil, fmt.Errorf("derive encryption public JWK: %w", err)
	}
	_ = encPubJWK.Set(jwk.KeyIDKey, encKID)
	_ = encPubJWK.Set(jwk.AlgorithmKey, jwa.ECDH_ES_A256KW())

	doc := &DIDDocument{
		ID: did,
		Authentication: []VerificationMethod{
			{
				ID:         sigKID,
				Type:       "Ed25519VerificationKey2020",
				Controller: did,
				PublicKey:  sigPubJWK,
			},
		},
		KeyAgreement: []VerificationMethod{
			{
				ID:         encKID,
				Type:       "X25519KeyAgreementKey2020",
				Controller: did,
				PublicKey:  encPubJWK,
			},
		},
	}

	return doc, kp, nil
}

// GenerateDIDWeb generates a did:web with Ed25519/X25519 keys.
// The caller is responsible for hosting the returned DID document at the appropriate URL.
func GenerateDIDWeb(domain string, path string) (*DIDDocument, *KeyPair, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Build did:web identifier
	did := "did:web:" + strings.ReplaceAll(domain, ":", "%3A")
	if path != "" {
		// Replace / with : in path (per did:web spec)
		cleaned := strings.TrimPrefix(path, "/")
		parts := strings.Split(cleaned, "/")
		did += ":" + strings.Join(parts, ":")
	}

	sigKID := did + "#key-1"
	encKID := did + "#key-2"

	_ = kp.SigningJWK.Set(jwk.KeyIDKey, sigKID)
	_ = kp.EncryptionJWK.Set(jwk.KeyIDKey, encKID)

	sigPubJWK, err := kp.SigningPublicJWK()
	if err != nil {
		return nil, nil, fmt.Errorf("derive signing public JWK: %w", err)
	}
	_ = sigPubJWK.Set(jwk.KeyIDKey, sigKID)
	_ = sigPubJWK.Set(jwk.AlgorithmKey, jwa.EdDSA())

	encPubJWK, err := kp.EncryptionPublicJWK()
	if err != nil {
		return nil, nil, fmt.Errorf("derive encryption public JWK: %w", err)
	}
	_ = encPubJWK.Set(jwk.KeyIDKey, encKID)
	_ = encPubJWK.Set(jwk.AlgorithmKey, jwa.ECDH_ES_A256KW())

	doc := &DIDDocument{
		ID: did,
		Authentication: []VerificationMethod{
			{
				ID:         sigKID,
				Type:       "Ed25519VerificationKey2020",
				Controller: did,
				PublicKey:  sigPubJWK,
			},
		},
		KeyAgreement: []VerificationMethod{
			{
				ID:         encKID,
				Type:       "X25519KeyAgreementKey2020",
				Controller: did,
				PublicKey:  encPubJWK,
			},
		},
	}

	return doc, kp, nil
}

// encodeDIDKey creates a did:key identifier from a multicodec prefix and public key bytes.
func encodeDIDKey(codec uint64, pubKeyBytes []byte) string {
	return "did:key:" + encodeDIDKeyFragment(codec, pubKeyBytes)
}

// encodeDIDKeyFragment creates a multibase-encoded fragment from a multicodec prefix and key bytes.
func encodeDIDKeyFragment(codec uint64, pubKeyBytes []byte) string {
	// Encode multicodec as unsigned varint
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, codec)
	multicodecBytes := append(buf[:n], pubKeyBytes...)
	return "z" + base58.Encode(multicodecBytes)
}

// Resolver resolves DIDs to DID documents.
type Resolver struct {
	mu   sync.RWMutex
	docs map[string]*DIDDocument
}

// NewResolver creates a new DID resolver.
func NewResolver() *Resolver {
	return &Resolver{
		docs: make(map[string]*DIDDocument),
	}
}

// Store registers a DID document with the resolver.
func (r *Resolver) Store(doc *DIDDocument) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docs[doc.ID] = doc
}

// Resolve looks up a DID document by DID.
func (r *Resolver) Resolve(_ context.Context, did string) (*DIDDocument, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	doc, ok := r.docs[did]
	if !ok {
		return nil, ErrDIDNotFound
	}
	return doc, nil
}

// FindEncryptionKey returns the first key agreement key from a DID document.
func (doc *DIDDocument) FindEncryptionKey() (*VerificationMethod, error) {
	if len(doc.KeyAgreement) == 0 {
		return nil, fmt.Errorf("%w: no key agreement keys in DID document %s", ErrKeyNotFound, doc.ID)
	}
	return &doc.KeyAgreement[0], nil
}

// FindSigningKey returns the first authentication key from a DID document.
func (doc *DIDDocument) FindSigningKey() (*VerificationMethod, error) {
	if len(doc.Authentication) == 0 {
		return nil, fmt.Errorf("%w: no authentication keys in DID document %s", ErrKeyNotFound, doc.ID)
	}
	return &doc.Authentication[0], nil
}
