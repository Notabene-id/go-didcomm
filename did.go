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
	ID             string               `json:"id"`
	Authentication []VerificationMethod `json:"authentication,omitempty"`
	KeyAgreement   []VerificationMethod `json:"keyAgreement,omitempty"`
	Service        []Service            `json:"service,omitempty"`
}

// Service represents a DID document service entry.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// GenerateDIDKey generates a new did:key with Ed25519 signing and X25519 encryption keys.
func GenerateDIDKey() (*DIDDocument, *KeyPair, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Encode Ed25519 public key with multicodec prefix
	did := encodeDIDKey(multicodecEd25519, kp.signingPublic)

	// Build signing verification method key ID
	sigFragment := did[len("did:key:"):]
	sigKID := did + "#" + sigFragment

	// Build encryption key fragment from X25519 public key
	encFragment := encodeDIDKeyFragment(multicodecX25519, kp.encryptionPublic.Bytes())
	encKID := did + "#" + encFragment

	return buildDIDDocument(did, sigKID, encKID, kp)
}

// GenerateDIDWeb generates a did:web with Ed25519/X25519 keys.
// The caller is responsible for hosting the returned DID document at the appropriate URL.
func GenerateDIDWeb(domain, path string) (*DIDDocument, *KeyPair, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("%w: empty domain", ErrInvalidMessage)
	}
	if strings.ContainsAny(domain, " \t\n\r") {
		return nil, nil, fmt.Errorf("%w: domain contains whitespace", ErrInvalidMessage)
	}

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

	return buildDIDDocument(did, sigKID, encKID, kp)
}

// buildDIDDocument constructs a DIDDocument from a DID string, key IDs, and key pair.
func buildDIDDocument(did, sigKID, encKID string, kp *KeyPair) (*DIDDocument, *KeyPair, error) {
	err := mustSet(kp.SigningJWK, jwk.KeyIDKey, sigKID)
	if err != nil {
		return nil, nil, err
	}
	err = mustSet(kp.EncryptionJWK, jwk.KeyIDKey, encKID)
	if err != nil {
		return nil, nil, err
	}

	sigPubJWK, err := kp.SigningPublicJWK()
	if err != nil {
		return nil, nil, fmt.Errorf("derive signing public JWK: %w", err)
	}
	err = mustSet(sigPubJWK, jwk.KeyIDKey, sigKID)
	if err != nil {
		return nil, nil, err
	}
	err = mustSet(sigPubJWK, jwk.AlgorithmKey, jwa.EdDSA())
	if err != nil {
		return nil, nil, err
	}

	encPubJWK, err := kp.EncryptionPublicJWK()
	if err != nil {
		return nil, nil, fmt.Errorf("derive encryption public JWK: %w", err)
	}
	err = mustSet(encPubJWK, jwk.KeyIDKey, encKID)
	if err != nil {
		return nil, nil, err
	}
	err = mustSet(encPubJWK, jwk.AlgorithmKey, jwa.ECDH_ES_A256KW())
	if err != nil {
		return nil, nil, err
	}

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
	prefixed := make([]byte, 0, n+len(pubKeyBytes))
	prefixed = append(prefixed, buf[:n]...)
	prefixed = append(prefixed, pubKeyBytes...)
	return "z" + base58.Encode(prefixed)
}

// DIDResolver resolves DIDs to DID documents.
type DIDResolver interface {
	Resolve(ctx context.Context, did string) (*DIDDocument, error)
}

// InMemoryResolver is a simple in-memory implementation of DIDResolver.
type InMemoryResolver struct {
	mu   sync.RWMutex
	docs map[string]*DIDDocument
}

// NewInMemoryResolver creates a new in-memory DID resolver.
func NewInMemoryResolver() *InMemoryResolver {
	return &InMemoryResolver{
		docs: make(map[string]*DIDDocument),
	}
}

// Store registers a DID document with the resolver.
func (r *InMemoryResolver) Store(doc *DIDDocument) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docs[doc.ID] = doc
}

// Resolve looks up a DID document by DID.
func (r *InMemoryResolver) Resolve(_ context.Context, did string) (*DIDDocument, error) {
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
