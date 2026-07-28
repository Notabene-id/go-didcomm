package didcomm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/mr-tron/base58"
)

// ServiceTypeDIDCommMessaging is the service type for DIDComm v2 endpoints.
const ServiceTypeDIDCommMessaging = "DIDCommMessaging"

// Multicodec prefixes for did:key.
const (
	multicodecEd25519 = 0xed
	multicodecX25519  = 0xec
)

// VMTypeJSONWebKey is the verification-method type this library emits: the one
// type whose material pairing, publicKeyJwk, every mainstream consumer
// supports.
const VMTypeJSONWebKey = "JsonWebKey2020"

// Verification-method types still accepted when parsing documents from older
// peers (W3C DID registry).
const (
	vmTypeEd25519       = "Ed25519VerificationKey2020"
	vmTypeX25519        = "X25519KeyAgreementKey2020"
	vmTypeEd25519Legacy = "Ed25519VerificationKey2018"
	vmTypeX25519Legacy  = "X25519KeyAgreementKey2019"
)

// JSON-LD contexts for emitted documents: DID Core 1.0 plus the JWS-2020 suite
// that defines JsonWebKey2020.
const (
	contextDIDCore = "https://www.w3.org/ns/did/v1"
	contextJWS2020 = "https://w3id.org/security/suites/jws-2020/v1"
)

// VerificationMethod represents a DID document verification method.
type VerificationMethod struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Controller string  `json:"controller"`
	PublicKey  jwk.Key `json:"-"`
}

// verificationMethodJSON is the JSON wire format. It accepts publicKeyJwk,
// publicKeyBase58, and publicKeyMultibase key encodings.
type verificationMethodJSON struct {
	ID                 string          `json:"id"`
	Type               string          `json:"type"`
	Controller         string          `json:"controller"`
	PublicKeyJWK       json.RawMessage `json:"publicKeyJwk,omitempty"`
	PublicKeyBase58    string          `json:"publicKeyBase58,omitempty"`
	PublicKeyMultibase string          `json:"publicKeyMultibase,omitempty"`
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

	// A verification method may legitimately carry no inline key (e.g. a bare
	// reference), in which case PublicKey stays nil.
	if !raw.hasKeyMaterial() {
		return nil
	}
	key, err := raw.publicKey()
	if err != nil {
		// An unsupported key type (a curve/method this library doesn't use) must
		// not fail the whole document: leave PublicKey nil so this method is
		// skipped while the rest of the document — including usable keys —
		// remains available. Malformed key material of a known type still errors.
		if errors.Is(err, ErrUnsupportedKeyType) {
			return nil
		}
		return fmt.Errorf("verification method %s: %w", raw.ID, err)
	}
	vm.PublicKey = key
	return nil
}

// hasKeyMaterial reports whether any public-key encoding is present.
func (raw *verificationMethodJSON) hasKeyMaterial() bool {
	return len(raw.PublicKeyJWK) > 0 || raw.PublicKeyBase58 != "" || raw.PublicKeyMultibase != ""
}

// publicKey decodes the verification method's public key. The caller must first
// confirm key material is present via hasKeyMaterial.
func (raw *verificationMethodJSON) publicKey() (jwk.Key, error) {
	switch {
	case len(raw.PublicKeyJWK) > 0:
		return jwk.ParseKey(raw.PublicKeyJWK)
	case raw.PublicKeyBase58 != "":
		decoded, err := base58.Decode(raw.PublicKeyBase58)
		if err != nil {
			return nil, fmt.Errorf("decode publicKeyBase58: %w", err)
		}
		return publicKeyFromBytes(raw.Type, decoded, raw.ID)
	default:
		return publicKeyFromMultibase(raw.PublicKeyMultibase, raw.ID)
	}
}

// publicKeyFromBytes builds a JWK from raw key bytes, choosing the curve from
// the verification-method type.
func publicKeyFromBytes(vmType string, raw []byte, kid string) (jwk.Key, error) {
	switch vmType {
	case vmTypeEd25519, vmTypeEd25519Legacy:
		if len(raw) != ed25519.PublicKeySize {
			return nil, ErrUnsupportedKeyType
		}
		return signingPublicJWK(ed25519.PublicKey(raw), kid)
	case vmTypeX25519, vmTypeX25519Legacy:
		if len(raw) != 32 {
			return nil, ErrUnsupportedKeyType
		}
		return encryptionPublicJWK(raw, kid)
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// publicKeyFromMultibase decodes a base58-btc multibase multicodec key.
func publicKeyFromMultibase(multibase, kid string) (jwk.Key, error) {
	if len(multibase) < 2 || multibase[0] != 'z' {
		return nil, ErrUnsupportedKeyType
	}
	decoded, err := base58.Decode(multibase[1:])
	if err != nil {
		return nil, fmt.Errorf("decode publicKeyMultibase: %w", err)
	}
	codec, n := binary.Uvarint(decoded)
	if n <= 0 {
		return nil, ErrUnsupportedKeyType
	}
	switch codec {
	case multicodecEd25519:
		if len(decoded[n:]) != ed25519.PublicKeySize {
			return nil, ErrUnsupportedKeyType
		}
		return signingPublicJWK(ed25519.PublicKey(decoded[n:]), kid)
	case multicodecX25519:
		return encryptionPublicJWK(decoded[n:], kid)
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// DIDDocument is a DID document covering the fields DIDComm and did:web
// hosting need.
type DIDDocument struct {
	// Context is the JSON-LD @context, kept raw so string, array, and mixed
	// forms all round-trip. Build one with [DocumentContext].
	Context            json.RawMessage      `json:"@context,omitempty"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []VerificationMethod `json:"authentication,omitempty"`
	AssertionMethod    []VerificationMethod `json:"assertionMethod,omitempty"`
	KeyAgreement       []VerificationMethod `json:"keyAgreement,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

// didDocumentJSON is the JSON wire format for parsing a DIDDocument, where
// relationship entries may be inline objects or string references.
type didDocumentJSON struct {
	Context            json.RawMessage      `json:"@context,omitempty"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []json.RawMessage    `json:"authentication,omitempty"`
	AssertionMethod    []json.RawMessage    `json:"assertionMethod,omitempty"`
	KeyAgreement       []json.RawMessage    `json:"keyAgreement,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

// didDocumentRefsJSON is the JSON wire format for emitting a DIDDocument:
// relationship entries are DID URL references into verificationMethod.
type didDocumentRefsJSON struct {
	Context            json.RawMessage      `json:"@context,omitempty"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	KeyAgreement       []string             `json:"keyAgreement,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

// DocumentContext builds a JSON-LD @context value from the given URIs, for
// assignment to [DIDDocument.Context].
func DocumentContext(uris ...string) json.RawMessage {
	data, err := json.Marshal(uris)
	if err != nil {
		panic(err) // marshaling []string cannot fail
	}
	return data
}

// UnmarshalJSON handles DID document fields where the verification
// relationships can contain either inline verification method objects or
// string references to entries in the verificationMethod array.
func (doc *DIDDocument) UnmarshalJSON(data []byte) error {
	var raw didDocumentJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	doc.Context = raw.Context
	doc.ID = raw.ID
	doc.VerificationMethod = raw.VerificationMethod
	doc.Service = raw.Service

	var err error
	doc.Authentication, err = resolveVerificationMethods(raw.Authentication, raw.VerificationMethod)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	doc.AssertionMethod, err = resolveVerificationMethods(raw.AssertionMethod, raw.VerificationMethod)
	if err != nil {
		return fmt.Errorf("assertionMethod: %w", err)
	}
	doc.KeyAgreement, err = resolveVerificationMethods(raw.KeyAgreement, raw.VerificationMethod)
	if err != nil {
		return fmt.Errorf("keyAgreement: %w", err)
	}

	return nil
}

// MarshalJSON emits the canonical wire form: every verification method is
// hoisted into the top-level verificationMethod array and the relationship
// sections carry DID URL references. Several ecosystem consumers dereference
// relationship entries only against the top-level array, so embedded-only
// documents break them even though both forms are spec-legal.
//
//nolint:gocritic // hugeParam: value receiver so DIDDocument and *DIDDocument marshal identically
func (doc DIDDocument) MarshalJSON() ([]byte, error) {
	out := didDocumentRefsJSON{
		Context: doc.Context,
		ID:      doc.ID,
		Service: doc.Service,
	}

	methods := make([]VerificationMethod, 0, len(doc.VerificationMethod))
	seen := make(map[string]bool, len(doc.VerificationMethod))
	for _, vm := range doc.VerificationMethod {
		if seen[vm.ID] {
			continue
		}
		seen[vm.ID] = true
		methods = append(methods, vm)
	}
	hoist := func(vms []VerificationMethod) []string {
		if len(vms) == 0 {
			return nil
		}
		refs := make([]string, 0, len(vms))
		for _, vm := range vms {
			refs = append(refs, vm.ID)
			// A bare reference (no type, no key material) has nothing to hoist.
			if seen[vm.ID] || (vm.Type == "" && vm.PublicKey == nil) {
				continue
			}
			seen[vm.ID] = true
			methods = append(methods, vm)
		}
		return refs
	}
	out.Authentication = hoist(doc.Authentication)
	out.AssertionMethod = hoist(doc.AssertionMethod)
	out.KeyAgreement = hoist(doc.KeyAgreement)
	out.VerificationMethod = methods

	return json.Marshal(out)
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
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	ServiceEndpoint ServiceEndpoint `json:"serviceEndpoint"`
}

// ServiceEndpoint is a service endpoint. DIDComm v2 requires the object form
// ({"uri": …}) for DIDCommMessaging services; legacy peers publish a bare URI
// string and some publish an array of either. All three parse — the first
// entry carrying a URI wins — and marshaling always emits one object.
type ServiceEndpoint struct {
	URI         string   `json:"uri"`
	Accept      []string `json:"accept,omitempty"`
	RoutingKeys []string `json:"routingKeys"`
}

// serviceEndpointJSON is ServiceEndpoint without its marshal methods, for
// recursion-free encoding of the object form.
type serviceEndpointJSON ServiceEndpoint

// MarshalJSON emits routingKeys as [] rather than null — at least one
// mainstream consumer requires the key to be present on DIDCommMessaging
// endpoints.
func (se ServiceEndpoint) MarshalJSON() ([]byte, error) {
	w := serviceEndpointJSON(se)
	if w.RoutingKeys == nil {
		w.RoutingKeys = []string{}
	}
	return json.Marshal(w) //nolint:wrapcheck // thin alias marshal, nothing to add
}

// UnmarshalJSON accepts the object form, a bare URI string, or an array of
// either (first entry with a URI wins). Unusable values parse to a zero
// endpoint rather than failing the document, mirroring how unsupported key
// types are tolerated: a service we cannot read must not make the rest of the
// document unavailable.
func (se *ServiceEndpoint) UnmarshalJSON(data []byte) error {
	*se = ServiceEndpoint{}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] != '[' {
		se.setFromSingle(trimmed)
		return nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		return nil //nolint:nilerr // tolerated: malformed endpoint, see doc comment
	}
	for _, entry := range entries {
		var candidate ServiceEndpoint
		candidate.setFromSingle(bytes.TrimSpace(entry))
		if candidate.URI != "" {
			*se = candidate
			return nil
		}
	}
	return nil
}

// setFromSingle parses one endpoint value (URI string or object); anything
// else leaves the endpoint zero.
func (se *ServiceEndpoint) setFromSingle(data []byte) {
	if len(data) == 0 {
		return
	}
	if data[0] == '"' {
		var uri string
		if json.Unmarshal(data, &uri) == nil {
			se.URI = uri
		}
		return
	}
	var w serviceEndpointJSON
	if json.Unmarshal(data, &w) == nil {
		*se = ServiceEndpoint(w)
	}
}

// GenerateDIDKey generates a new did:key with an Ed25519 signing key and its
// derived X25519 key-agreement key. It returns the public DID document and the
// private KeyMaterial for the caller to load into a KeyStore.
func GenerateDIDKey() (*DIDDocument, *KeyMaterial, error) {
	gk, err := generateKeys()
	if err != nil {
		return nil, nil, err
	}

	did := encodeDIDKey(multicodecEd25519, gk.ed25519Public)
	sigKID := did + "#" + did[len("did:key:"):]
	encKID := did + "#" + encodeDIDKeyFragment(multicodecX25519, gk.x25519Public)

	return buildDIDDocument(did, sigKID, encKID, gk)
}

// GenerateDIDWeb generates a did:web with an Ed25519 signing key and its derived
// X25519 key-agreement key. The caller hosts the returned document at the
// resolved URL and loads the KeyMaterial into a KeyStore.
func GenerateDIDWeb(domain, path string) (*DIDDocument, *KeyMaterial, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("%w: empty domain", ErrInvalidMessage)
	}
	if strings.ContainsAny(domain, " \t\n\r") {
		return nil, nil, fmt.Errorf("%w: domain contains whitespace", ErrInvalidMessage)
	}

	gk, err := generateKeys()
	if err != nil {
		return nil, nil, err
	}

	did := "did:web:" + strings.ReplaceAll(domain, ":", "%3A")
	if path != "" {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		did += ":" + strings.Join(parts, ":")
	}

	return buildDIDDocument(did, did+"#key-1", did+"#key-2", gk)
}

// buildDIDDocument assembles a DID document and the matching KeyMaterial from
// generated keys and the chosen verification-method ids.
func buildDIDDocument(did, sigKID, encKID string, gk *generatedKeys) (*DIDDocument, *KeyMaterial, error) {
	sigPubJWK, err := signingPublicJWK(gk.ed25519Public, sigKID)
	if err != nil {
		return nil, nil, err
	}
	encPubJWK, err := encryptionPublicJWK(gk.x25519Public, encKID)
	if err != nil {
		return nil, nil, err
	}

	signing := VerificationMethod{ID: sigKID, Type: VMTypeJSONWebKey, Controller: did, PublicKey: sigPubJWK}
	doc := &DIDDocument{
		Context:         DocumentContext(contextDIDCore, contextJWS2020),
		ID:              did,
		Authentication:  []VerificationMethod{signing},
		AssertionMethod: []VerificationMethod{signing},
		KeyAgreement: []VerificationMethod{
			{ID: encKID, Type: VMTypeJSONWebKey, Controller: did, PublicKey: encPubJWK},
		},
	}
	km := &KeyMaterial{
		DID:             did,
		SigningKID:      sigKID,
		KeyAgreementKID: encKID,
		Ed25519Seed:     gk.ed25519Seed,
		X25519Private:   gk.x25519Private,
	}
	return doc, km, nil
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

// FindEncryptionKey returns the first X25519 key agreement key from a DID
// document, skipping keys of other curves (e.g. a P-256 PII key).
func (doc *DIDDocument) FindEncryptionKey() (*VerificationMethod, error) {
	vm, err := firstX25519(doc.KeyAgreement)
	if err != nil {
		return nil, fmt.Errorf("%w: no X25519 key agreement key in DID document %s", ErrKeyNotFound, doc.ID)
	}
	return vm, nil
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
		if svc.Type == ServiceTypeDIDCommMessaging && svc.ServiceEndpoint.URI != "" {
			return svc.ServiceEndpoint.URI, nil
		}
	}
	return "", fmt.Errorf("%w: no DIDCommMessaging service in DID document %s", ErrNoServiceEndpoint, doc.ID)
}
