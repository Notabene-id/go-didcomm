package didcomm

import (
	"context"
	"fmt"
	"strings"
)

// DID method prefixes routed by DefaultResolver.
const (
	methodDIDKey = "did:key"
	methodDIDWeb = "did:web"
)

// MultiResolver routes DID resolution to method-specific resolvers based on the DID prefix.
type MultiResolver struct {
	resolvers map[string]DIDResolver
	fallback  DIDResolver
}

// NewMultiResolver creates a MultiResolver with the given method resolvers and optional fallback.
// The methods map keys should be DID method prefixes like "did:key" or "did:web".
func NewMultiResolver(methods map[string]DIDResolver, fallback DIDResolver) *MultiResolver {
	return &MultiResolver{
		resolvers: methods,
		fallback:  fallback,
	}
}

// DefaultResolver creates a MultiResolver pre-configured with did:key and did:web resolvers,
// and an InMemoryResolver as fallback for manually stored documents.
// Returns both the MultiResolver (for use with Client) and the InMemoryResolver (for Store calls).
func DefaultResolver() (*MultiResolver, *InMemoryResolver) {
	mem := NewInMemoryResolver()
	multi := NewMultiResolver(map[string]DIDResolver{
		methodDIDKey: &DIDKeyResolver{},
		methodDIDWeb: &DIDWebResolver{},
	}, mem)
	return multi, mem
}

// Resolve routes the DID to the appropriate method-specific resolver.
func (r *MultiResolver) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
	// Try fallback first for explicit overrides
	if r.fallback != nil {
		doc, err := r.fallback.Resolve(ctx, did)
		if err == nil {
			return doc, nil
		}
	}

	// Route by method prefix
	method := extractDIDMethod(did)
	if method != "" {
		if resolver, ok := r.resolvers[method]; ok {
			return resolver.Resolve(ctx, did)
		}
	}

	return nil, fmt.Errorf("%w: no resolver for %s", ErrDIDNotFound, did)
}

// extractDIDMethod returns the DID method prefix (e.g. "did:key" from "did:key:z6Mk...").
func extractDIDMethod(did string) string {
	if !strings.HasPrefix(did, "did:") {
		return ""
	}
	// Find the second ":"
	idx := strings.Index(did[4:], ":")
	if idx < 0 {
		return ""
	}
	return did[:4+idx]
}
