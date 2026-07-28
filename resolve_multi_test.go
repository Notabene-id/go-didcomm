package didcomm

import (
	"context"
	"errors"
	"testing"
)

func TestMultiResolver_DIDKey(t *testing.T) {
	multi, _ := DefaultResolver()

	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := multi.Resolve(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("resolve did:key: %v", err)
	}
	if resolved.ID != doc.ID {
		t.Fatalf("ID mismatch: %s != %s", resolved.ID, doc.ID)
	}
}

func TestMultiResolver_Fallback(t *testing.T) {
	multi, mem := DefaultResolver()

	// Store a custom document
	doc := &DIDDocument{
		ID: "did:example:custom",
	}
	mem.Store(doc)

	resolved, err := multi.Resolve(context.Background(), "did:example:custom")
	if err != nil {
		t.Fatalf("resolve custom: %v", err)
	}
	if resolved.ID != "did:example:custom" {
		t.Fatalf("ID mismatch: %s", resolved.ID)
	}
}

func TestMultiResolver_FallbackOverride(t *testing.T) {
	multi, mem := DefaultResolver()

	// Store a did:key document manually — it should take priority over DIDKeyResolver
	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	doc.Service = []Service{{ID: "custom", Type: "test", ServiceEndpoint: ServiceEndpoint{URI: "http://test"}}}
	mem.Store(doc)

	resolved, err := multi.Resolve(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("resolve override: %v", err)
	}
	// Should have the custom service from our override, not the bare DIDKeyResolver result
	if len(resolved.Service) != 1 {
		t.Fatalf("expected 1 service from override, got %d", len(resolved.Service))
	}
}

func TestMultiResolver_UnknownMethod(t *testing.T) {
	multi, _ := DefaultResolver()

	_, err := multi.Resolve(context.Background(), "did:unknown:something")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

func TestMultiResolver_InvalidDID(t *testing.T) {
	multi, _ := DefaultResolver()

	_, err := multi.Resolve(context.Background(), "not-a-did")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got %v", err)
	}
}

func TestExtractDIDMethod(t *testing.T) {
	tests := []struct {
		did    string
		method string
	}{
		{"did:key:z6Mk...", "did:key"},
		{"did:web:example.com", "did:web"},
		{"did:web:example.com:path", "did:web"},
		{"did:example:123", "did:example"},
		{"not-a-did", ""},
		{"did:nocolon", ""},
	}

	for _, tt := range tests {
		t.Run(tt.did, func(t *testing.T) {
			got := extractDIDMethod(tt.did)
			if got != tt.method {
				t.Fatalf("got %q, want %q", got, tt.method)
			}
		})
	}
}

// Full pack/unpack round-trips live in the external client_test.go, which can
// import the softkey KeyStore without an import cycle.
