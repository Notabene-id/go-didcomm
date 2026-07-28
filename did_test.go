package didcomm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestGenerateDIDKey(t *testing.T) {
	doc, km, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	// DID should start with did:key:z
	if !strings.HasPrefix(doc.ID, "did:key:z") {
		t.Fatalf("DID should start with did:key:z, got %s", doc.ID)
	}

	// Should have one authentication method
	if len(doc.Authentication) != 1 {
		t.Fatalf("expected 1 authentication method, got %d", len(doc.Authentication))
	}

	// Should have one key agreement method
	if len(doc.KeyAgreement) != 1 {
		t.Fatalf("expected 1 key agreement method, got %d", len(doc.KeyAgreement))
	}

	// Authentication key ID should be DID#fragment
	authVM := doc.Authentication[0]
	if !strings.HasPrefix(authVM.ID, doc.ID+"#") {
		t.Fatalf("auth key ID should start with DID#, got %s", authVM.ID)
	}
	if authVM.Type != VMTypeJSONWebKey {
		t.Fatalf("expected VMTypeJSONWebKey, got %s", authVM.Type)
	}
	if authVM.Controller != doc.ID {
		t.Fatalf("controller should be DID, got %s", authVM.Controller)
	}

	// Key agreement key ID
	kaVM := doc.KeyAgreement[0]
	if !strings.HasPrefix(kaVM.ID, doc.ID+"#") {
		t.Fatalf("key agreement key ID should start with DID#, got %s", kaVM.ID)
	}
	if kaVM.Type != VMTypeJSONWebKey {
		t.Fatalf("expected VMTypeJSONWebKey, got %s", kaVM.Type)
	}
	if len(doc.Context) == 0 {
		t.Fatal("generated document should carry @context")
	}
	if len(doc.AssertionMethod) != 1 || doc.AssertionMethod[0].ID != authVM.ID {
		t.Fatalf("assertionMethod should reference the signing key, got %+v", doc.AssertionMethod)
	}

	if km == nil {
		t.Fatal("key material should not be nil")
	}
	if km.SigningKID != authVM.ID {
		t.Fatalf("signing kid %q should match authentication VM %q", km.SigningKID, authVM.ID)
	}
	if km.KeyAgreementKID != kaVM.ID {
		t.Fatalf("key-agreement kid %q should match keyAgreement VM %q", km.KeyAgreementKID, kaVM.ID)
	}
	if len(km.Ed25519Seed) != 32 || len(km.X25519Private) != 32 {
		t.Fatal("key material should carry 32-byte private keys")
	}
}

func TestGenerateDIDKey_Unique(t *testing.T) {
	doc1, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	doc2, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	if doc1.ID == doc2.ID {
		t.Fatal("generated DIDs should be unique")
	}
}

func TestGenerateDIDWeb(t *testing.T) {
	doc, km, err := GenerateDIDWeb("example.com", "/alice")
	if err != nil {
		t.Fatal(err)
	}

	if doc.ID != "did:web:example.com:alice" {
		t.Fatalf("expected did:web:example.com:alice, got %s", doc.ID)
	}

	if len(doc.Authentication) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(doc.Authentication))
	}
	if len(doc.KeyAgreement) != 1 {
		t.Fatalf("expected 1 key agreement method, got %d", len(doc.KeyAgreement))
	}

	if doc.Authentication[0].ID != "did:web:example.com:alice#key-1" {
		t.Fatalf("unexpected auth key ID: %s", doc.Authentication[0].ID)
	}
	if doc.KeyAgreement[0].ID != "did:web:example.com:alice#key-2" {
		t.Fatalf("unexpected ka key ID: %s", doc.KeyAgreement[0].ID)
	}

	if km == nil || km.DID != doc.ID {
		t.Fatal("key material should not be nil and should carry the DID")
	}
}

func TestGenerateDIDWeb_NoPath(t *testing.T) {
	doc, _, err := GenerateDIDWeb("example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	if doc.ID != "did:web:example.com" {
		t.Fatalf("expected did:web:example.com, got %s", doc.ID)
	}
}

func TestGenerateDIDWeb_NestedPath(t *testing.T) {
	doc, _, err := GenerateDIDWeb("example.com", "/org/dept/alice")
	if err != nil {
		t.Fatal(err)
	}

	if doc.ID != "did:web:example.com:org:dept:alice" {
		t.Fatalf("expected did:web:example.com:org:dept:alice, got %s", doc.ID)
	}
}

func TestGenerateDIDWeb_PortInDomain(t *testing.T) {
	doc, _, err := GenerateDIDWeb("localhost:8080", "/alice")
	if err != nil {
		t.Fatal(err)
	}

	if doc.ID != "did:web:localhost%3A8080:alice" {
		t.Fatalf("expected did:web:localhost%%3A8080:alice, got %s", doc.ID)
	}
}

func TestGenerateDIDWeb_EmptyDomain(t *testing.T) {
	_, _, err := GenerateDIDWeb("", "/alice")
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("expected ErrInvalidMessage, got %v", err)
	}
}

func TestGenerateDIDWeb_WhitespaceDomain(t *testing.T) {
	_, _, err := GenerateDIDWeb("example .com", "/alice")
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("expected ErrInvalidMessage, got %v", err)
	}

	_, _, err = GenerateDIDWeb("example\t.com", "/alice")
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("expected ErrInvalidMessage for tab, got %v", err)
	}

	_, _, err = GenerateDIDWeb("example\n.com", "/alice")
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("expected ErrInvalidMessage for newline, got %v", err)
	}
}

func TestResolver_StoreAndResolve(t *testing.T) {
	resolver := NewInMemoryResolver()
	ctx := context.Background()

	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	resolver.Store(doc)

	resolved, err := resolver.Resolve(ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}

	if resolved.ID != doc.ID {
		t.Fatalf("expected %s, got %s", doc.ID, resolved.ID)
	}
}

func TestResolver_NotFound(t *testing.T) {
	resolver := NewInMemoryResolver()
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "did:key:nonexistent")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

func TestDIDDocument_FindEncryptionKey(t *testing.T) {
	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	vm, err := doc.FindEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if vm.PublicKey == nil {
		t.Fatal("encryption key should not be nil")
	}
}

func TestDIDDocument_FindSigningKey(t *testing.T) {
	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	vm, err := doc.FindSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if vm.PublicKey == nil {
		t.Fatal("signing key should not be nil")
	}
}

func TestDIDDocument_FindEncryptionKey_Empty(t *testing.T) {
	doc := &DIDDocument{ID: "did:key:test"}
	_, err := doc.FindEncryptionKey()
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestDIDDocument_FindSigningKey_Empty(t *testing.T) {
	doc := &DIDDocument{ID: "did:key:test"}
	_, err := doc.FindSigningKey()
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestDIDDocument_FindDIDCommEndpoint(t *testing.T) {
	doc := &DIDDocument{
		ID: "did:web:example.com",
		Service: []Service{
			{ID: "#didcomm", Type: "DIDCommMessaging", ServiceEndpoint: ServiceEndpoint{URI: "https://example.com/didcomm"}},
		},
	}

	endpoint, err := doc.FindDIDCommEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://example.com/didcomm" {
		t.Fatalf("expected https://example.com/didcomm, got %s", endpoint)
	}
}

func TestDIDDocument_FindDIDCommEndpoint_NoService(t *testing.T) {
	doc := &DIDDocument{ID: "did:key:test"}
	_, err := doc.FindDIDCommEndpoint()
	if !errors.Is(err, ErrNoServiceEndpoint) {
		t.Fatalf("expected ErrNoServiceEndpoint, got %v", err)
	}
}

func TestDIDDocument_FindDIDCommEndpoint_WrongType(t *testing.T) {
	doc := &DIDDocument{
		ID: "did:web:example.com",
		Service: []Service{
			{ID: "#other", Type: "OtherService", ServiceEndpoint: ServiceEndpoint{URI: "https://example.com/other"}},
		},
	}
	_, err := doc.FindDIDCommEndpoint()
	if !errors.Is(err, ErrNoServiceEndpoint) {
		t.Fatalf("expected ErrNoServiceEndpoint, got %v", err)
	}
}

func TestVerificationMethod_JSON_RoundTrip(t *testing.T) {
	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	// Marshal the entire DIDDocument (uses VerificationMethod.MarshalJSON)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal back
	var doc2 DIDDocument
	if err := json.Unmarshal(data, &doc2); err != nil {
		t.Fatal(err)
	}

	if doc2.ID != doc.ID {
		t.Fatalf("ID mismatch: %s != %s", doc2.ID, doc.ID)
	}
	if len(doc2.Authentication) != 1 {
		t.Fatalf("expected 1 auth, got %d", len(doc2.Authentication))
	}
	if len(doc2.KeyAgreement) != 1 {
		t.Fatalf("expected 1 ka, got %d", len(doc2.KeyAgreement))
	}
	if doc2.Authentication[0].PublicKey == nil {
		t.Fatal("auth public key nil after round-trip")
	}
	if doc2.KeyAgreement[0].PublicKey == nil {
		t.Fatal("ka public key nil after round-trip")
	}
	if doc2.Authentication[0].ID != doc.Authentication[0].ID {
		t.Fatalf("auth key ID mismatch")
	}
}

func TestDIDDocument_UnmarshalJSON_StringReferences(t *testing.T) {
	// Simulates a real-world DID document where authentication and keyAgreement
	// contain string references to entries in the verificationMethod array.
	input := `{
		"id": "did:web:example.com",
		"verificationMethod": [
			{
				"id": "did:web:example.com#key-1",
				"type": "Ed25519VerificationKey2018",
				"controller": "did:web:example.com"
			},
			{
				"id": "did:web:example.com#key-2",
				"type": "X25519KeyAgreementKey2019",
				"controller": "did:web:example.com"
			}
		],
		"authentication": [
			"did:web:example.com#key-1"
		],
		"keyAgreement": [
			"did:web:example.com#key-2"
		]
	}`

	var doc DIDDocument
	if err := json.Unmarshal([]byte(input), &doc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(doc.VerificationMethod) != 2 {
		t.Fatalf("expected 2 verification methods, got %d", len(doc.VerificationMethod))
	}
	if len(doc.Authentication) != 1 {
		t.Fatalf("expected 1 authentication, got %d", len(doc.Authentication))
	}
	if doc.Authentication[0].ID != "did:web:example.com#key-1" {
		t.Fatalf("expected key-1, got %s", doc.Authentication[0].ID)
	}
	if doc.Authentication[0].Type != "Ed25519VerificationKey2018" {
		t.Fatalf("expected dereferenced type, got %s", doc.Authentication[0].Type)
	}
	if len(doc.KeyAgreement) != 1 {
		t.Fatalf("expected 1 key agreement, got %d", len(doc.KeyAgreement))
	}
	if doc.KeyAgreement[0].ID != "did:web:example.com#key-2" {
		t.Fatalf("expected key-2, got %s", doc.KeyAgreement[0].ID)
	}
}

func TestDIDDocument_UnmarshalJSON_MixedReferencesAndInline(t *testing.T) {
	input := `{
		"id": "did:web:example.com",
		"verificationMethod": [
			{
				"id": "did:web:example.com#key-1",
				"type": "Ed25519VerificationKey2018",
				"controller": "did:web:example.com"
			}
		],
		"authentication": [
			"did:web:example.com#key-1",
			{
				"id": "did:web:example.com#key-3",
				"type": "Ed25519VerificationKey2020",
				"controller": "did:web:example.com"
			}
		]
	}`

	var doc DIDDocument
	if err := json.Unmarshal([]byte(input), &doc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(doc.Authentication) != 2 {
		t.Fatalf("expected 2 authentication entries, got %d", len(doc.Authentication))
	}
	// First is dereferenced from verificationMethod
	if doc.Authentication[0].Type != "Ed25519VerificationKey2018" {
		t.Fatalf("expected dereferenced type, got %s", doc.Authentication[0].Type)
	}
	// Second is inline
	if doc.Authentication[1].Type != "Ed25519VerificationKey2020" {
		t.Fatalf("expected inline type, got %s", doc.Authentication[1].Type)
	}
}

// TestDIDDocument_MarshalJSON_HoistsEmbeddedMethods verifies the canonical
// emission: embedded relationship methods land in verificationMethod and the
// relationships become DID URL references.
func TestDIDDocument_MarshalJSON_HoistsEmbeddedMethods(t *testing.T) {
	generated, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	signing := generated.Authentication[0]
	ka := generated.KeyAgreement[0]

	doc := DIDDocument{
		Context:         DocumentContext("https://www.w3.org/ns/did/v1"),
		ID:              "did:web:example.com",
		Authentication:  []VerificationMethod{signing},
		AssertionMethod: []VerificationMethod{signing},
		KeyAgreement:    []VerificationMethod{ka},
		Service: []Service{{
			ID: "did:web:example.com#didcomm", Type: "DIDCommMessaging",
			ServiceEndpoint: ServiceEndpoint{URI: "https://example.com/didcomm", Accept: []string{"didcomm/v2"}},
		}},
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	var wire struct {
		Context            []string `json:"@context"`
		VerificationMethod []struct {
			ID           string          `json:"id"`
			Type         string          `json:"type"`
			PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
		Authentication  []string `json:"authentication"`
		AssertionMethod []string `json:"assertionMethod"`
		KeyAgreement    []string `json:"keyAgreement"`
		Service         []struct {
			ServiceEndpoint struct {
				URI         string   `json:"uri"`
				Accept      []string `json:"accept"`
				RoutingKeys []string `json:"routingKeys"`
			} `json:"serviceEndpoint"`
		} `json:"service"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("emitted document does not match the reference wire shape: %v\n%s", err, data)
	}

	if len(wire.Context) != 1 || wire.Context[0] != "https://www.w3.org/ns/did/v1" {
		t.Fatalf("@context = %v", wire.Context)
	}
	if len(wire.VerificationMethod) != 2 {
		t.Fatalf("expected 2 hoisted methods, got %d\n%s", len(wire.VerificationMethod), data)
	}
	for _, vm := range wire.VerificationMethod {
		if len(vm.PublicKeyJWK) == 0 {
			t.Fatalf("hoisted method %s lost its key material", vm.ID)
		}
	}
	if len(wire.Authentication) != 1 || wire.Authentication[0] != signing.ID {
		t.Fatalf("authentication = %v, want [%s]", wire.Authentication, signing.ID)
	}
	if len(wire.AssertionMethod) != 1 || wire.AssertionMethod[0] != signing.ID {
		t.Fatalf("assertionMethod = %v, want [%s]", wire.AssertionMethod, signing.ID)
	}
	if len(wire.KeyAgreement) != 1 || wire.KeyAgreement[0] != ka.ID {
		t.Fatalf("keyAgreement = %v, want [%s]", wire.KeyAgreement, ka.ID)
	}
	ep := wire.Service[0].ServiceEndpoint
	if ep.URI != "https://example.com/didcomm" {
		t.Fatalf("service endpoint uri = %q", ep.URI)
	}
	if len(ep.Accept) != 1 || ep.Accept[0] != "didcomm/v2" {
		t.Fatalf("service endpoint accept = %v", ep.Accept)
	}
	if ep.RoutingKeys == nil {
		t.Fatal("routingKeys must be emitted as [], not omitted")
	}

	// The emission must resolve back into usable keys.
	var back DIDDocument
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.AssertionMethod) != 1 || back.AssertionMethod[0].PublicKey == nil {
		t.Fatal("assertionMethod reference did not resolve on re-parse")
	}
	if back.KeyAgreement[0].PublicKey == nil {
		t.Fatal("keyAgreement reference did not resolve on re-parse")
	}
}

// TestDIDDocument_MarshalJSON_DoesNotDuplicateHoistedMethods verifies a method
// present in both verificationMethod and a relationship is emitted once.
func TestDIDDocument_MarshalJSON_DoesNotDuplicateHoistedMethods(t *testing.T) {
	generated, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	signing := generated.Authentication[0]

	doc := DIDDocument{
		ID:                 "did:web:example.com",
		VerificationMethod: []VerificationMethod{signing},
		Authentication:     []VerificationMethod{signing},
		AssertionMethod:    []VerificationMethod{signing},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		VerificationMethod []json.RawMessage `json:"verificationMethod"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.VerificationMethod) != 1 {
		t.Fatalf("expected 1 method, got %d\n%s", len(wire.VerificationMethod), data)
	}
}

func TestServiceEndpoint_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantURI string
	}{
		{"bare string", `"https://a.example/didcomm"`, "https://a.example/didcomm"},
		{"object", `{"uri":"https://b.example/didcomm","accept":["didcomm/v2"]}`, "https://b.example/didcomm"},
		{"array of strings", `["https://c.example/didcomm","https://c2.example"]`, "https://c.example/didcomm"},
		{"array of objects", `[{"uri":"https://d.example/didcomm"}]`, "https://d.example/didcomm"},
		{"array skips unusable entries", `[{"origins":["x"]},"https://e.example/didcomm"]`, "https://e.example/didcomm"},
		{"unusable object tolerated", `{"origins":["https://f.example"]}`, ""},
		{"unusable scalar tolerated", `42`, ""},
		{"null tolerated", `null`, ""},
		{"empty array tolerated", `[]`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := `{"id":"did:web:x#s","type":"DIDCommMessaging","serviceEndpoint":` + tt.input + `}`
			var svc Service
			if err := json.Unmarshal([]byte(raw), &svc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if svc.ServiceEndpoint.URI != tt.wantURI {
				t.Fatalf("URI = %q, want %q", svc.ServiceEndpoint.URI, tt.wantURI)
			}
		})
	}
}

// TestServiceEndpoint_ObjectRoundTrip verifies accept and routingKeys survive
// a parse/emit cycle.
func TestServiceEndpoint_ObjectRoundTrip(t *testing.T) {
	in := `{"uri":"https://x.example/didcomm","accept":["didcomm/v2"],"routingKeys":["did:web:m#k"]}`
	var se ServiceEndpoint
	if err := json.Unmarshal([]byte(in), &se); err != nil {
		t.Fatal(err)
	}
	if len(se.Accept) != 1 || len(se.RoutingKeys) != 1 {
		t.Fatalf("accept=%v routingKeys=%v", se.Accept, se.RoutingKeys)
	}
	out, err := json.Marshal(se)
	if err != nil {
		t.Fatal(err)
	}
	var back ServiceEndpoint
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back.URI != se.URI || len(back.Accept) != 1 || len(back.RoutingKeys) != 1 {
		t.Fatalf("round-trip mismatch: %s", out)
	}
}

// TestDIDDocument_UnmarshalJSON_AssertionMethodReference verifies
// assertionMethod resolves string references like the other relationships.
func TestDIDDocument_UnmarshalJSON_AssertionMethodReference(t *testing.T) {
	generated, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	signing := generated.Authentication[0]
	vmJSON, err := json.Marshal(signing)
	if err != nil {
		t.Fatal(err)
	}

	input := `{
		"id": "did:web:example.com",
		"verificationMethod": [` + string(vmJSON) + `],
		"assertionMethod": ["` + signing.ID + `"]
	}`
	var doc DIDDocument
	if err := json.Unmarshal([]byte(input), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.AssertionMethod) != 1 || doc.AssertionMethod[0].PublicKey == nil {
		t.Fatal("assertionMethod reference did not resolve")
	}
}
