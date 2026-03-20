package didcomm

import (
	"context"
	"encoding/binary"
	"encoding/json"
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

// verificationMethodJSON is the JSON wire format with publicKeyJwk.
type verificationMethodJSON struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	Controller   string          `json:"controller"`
	PublicKeyJWK json.RawMessage `json:"publicKeyJwk,omitempty"`
}

// MarshalJSON serializes a VerificationMethod including publicKeyJwk.
func (vm VerificationMethod) MarshalJSON() ([]byte, error) {
	out := verificationMethodJSON{
		ID:         vm.ID,
		Type:       vm.Type,
		Controller: vm.Controller,
	}
	if vm.PublicKey != nil {
		jwkBytes, err := json.Marshal(vm.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("marshal publicKeyJwk for %s: %w", vm.ID, err)
		}
		out.PublicKeyJWK = jwkBytes
	}
	return json.Marshal(out)
}

// UnmarshalJSON deserializes a VerificationMethod restoring publicKeyJwk into PublicKey.
func (vm *VerificationMethod) UnmarshalJSON(data []byte) error {
	var raw verificationMethodJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	vm.ID = raw.ID
	vm.Type = raw.Type
	vm.Controller = raw.Controller
	if len(raw.PublicKeyJWK) > 0 {
		key, err := jwk.ParseKey(raw.PublicKeyJWK)
		if err != nil {
			return fmt.Errorf("parse publicKeyJwk for %s: %w", raw.ID, err)
		}
		vm.PublicKey = key
	}
	return nil
}

// DIDDocument is a thin DID document with only DIDComm-relevant fields.
type DIDDocument struct {
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []VerificationMethod `json:"authentication,omitempty"`
	KeyAgreement       []VerificationMethod `json:"keyAgreement,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

// didDocumentJSON is the JSON wire format for DIDDocument.
type didDocumentJSON struct {
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []json.RawMessage    `json:"authentication,omitempty"`
	KeyAgreement       []json.RawMessage    `json:"keyAgreement,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

// UnmarshalJSON handles DID document fields where authentication and keyAgreement
// can contain either inline verification method objects or string references
// to entries in the verificationMethod array.
func (doc *DIDDocument) UnmarshalJSON(data []byte) error {
	var raw didDocumentJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	doc.ID = raw.ID
	doc.VerificationMethod = raw.VerificationMethod
	doc.Service = raw.Service

	var err error
	doc.Authentication, err = resolveVerificationMethods(raw.Authentication, raw.VerificationMethod)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	doc.KeyAgreement, err = resolveVerificationMethods(raw.KeyAgreement, raw.VerificationMethod)
	if err != nil {
		return fmt.Errorf("keyAgreement: %w", err)
	}

	return nil
}

// resolveVerificationMethods converts a mixed array of string references and inline
// verification method objects into a slice of VerificationMethod values.
// String references are resolved against the provided verification methods.
func resolveVerificationMethods(raw []json.RawMessage, vms []VerificationMethod) ([]VerificationMethod, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	// Build lookup map for string references
	vmByID := make(map[string]*VerificationMethod, len(vms))
	for i := range vms {
		vmByID[vms[i].ID] = &vms[i]
	}

	result := make([]VerificationMethod, 0, len(raw))
	for _, entry := range raw {
		trimmed := strings.TrimSpace(string(entry))
		if trimmed != "" && trimmed[0] == '"' {
			// String reference — dereference against verificationMethod array
			var ref string
			if err := json.Unmarshal(entry, &ref); err != nil {
				return nil, fmt.Errorf("parse reference: %w", err)
			}
			vm, ok := vmByID[ref]
			if !ok {
				// Keep as a stub with just the ID so callers can see the reference
				result = append(result, VerificationMethod{ID: ref})
			} else {
				result = append(result, *vm)
			}
		} else {
			// Inline verification method object
			var vm VerificationMethod
			if err := json.Unmarshal(entry, &vm); err != nil {
				return nil, fmt.Errorf("parse verification method: %w", err)
			}
			result = append(result, vm)
		}
	}
	return result, nil
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

// FindDIDCommEndpoint returns the first DIDCommMessaging service endpoint URL from the document.
func (doc *DIDDocument) FindDIDCommEndpoint() (string, error) {
	for _, svc := range doc.Service {
		if svc.Type == "DIDCommMessaging" && svc.ServiceEndpoint != "" {
			return svc.ServiceEndpoint, nil
		}
	}
	return "", fmt.Errorf("%w: no DIDCommMessaging service in DID document %s", ErrNoServiceEndpoint, doc.ID)
}
