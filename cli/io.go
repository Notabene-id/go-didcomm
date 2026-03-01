package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"

	didcomm "github.com/Notabene-id/go-didcomm"
)

// ReadMessageInput reads message data based on the flag value:
//   - "-" or empty: read from stdin
//   - "@filename": read from file
//   - otherwise: treat as inline JSON string
func ReadMessageInput(flag string) ([]byte, error) {
	if flag == "" || flag == "-" {
		return io.ReadAll(os.Stdin)
	}
	if strings.HasPrefix(flag, "@") {
		return os.ReadFile(flag[1:])
	}
	return []byte(flag), nil
}

// MarshalDIDDoc serializes a DIDDocument to JSON including public keys as publicKeyJwk.
func MarshalDIDDoc(doc *didcomm.DIDDocument) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}

// UnmarshalDIDDoc deserializes a DIDDocument from JSON.
func UnmarshalDIDDoc(data []byte) (*didcomm.DIDDocument, error) {
	var doc didcomm.DIDDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse DID document: %w", err)
	}
	return &doc, nil
}

// MarshalKeyPair serializes a KeyPair's private keys as a JWK Set.
func MarshalKeyPair(kp *didcomm.KeyPair) ([]byte, error) {
	set := jwk.NewSet()
	if err := set.AddKey(kp.SigningJWK); err != nil {
		return nil, fmt.Errorf("add signing key to set: %w", err)
	}
	if err := set.AddKey(kp.EncryptionJWK); err != nil {
		return nil, fmt.Errorf("add encryption key to set: %w", err)
	}
	return json.MarshalIndent(set, "", "  ")
}

// LoadKeyFile loads a JWK Set from a file and stores all keys in an InMemorySecretsStore.
func LoadKeyFile(path string) (*didcomm.InMemorySecretsStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}

	set, err := jwk.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", path, err)
	}

	store := didcomm.NewInMemorySecretsStore()
	for i := range set.Len() {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		store.StoreKey(key)
	}
	return store, nil
}

// LoadDIDDocs loads DID documents from a comma-separated list of file paths into an InMemoryResolver.
func LoadDIDDocs(paths string) (*didcomm.InMemoryResolver, error) {
	resolver := didcomm.NewInMemoryResolver()
	if paths == "" {
		return resolver, nil
	}

	for _, p := range strings.Split(paths, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read DID document %s: %w", p, err)
		}
		doc, err := UnmarshalDIDDoc(data)
		if err != nil {
			return nil, fmt.Errorf("parse DID document %s: %w", p, err)
		}
		resolver.Store(doc)
	}
	return resolver, nil
}

// BuildResolverWithOverrides creates a MultiResolver with optional DID doc file overrides
// loaded into the fallback InMemoryResolver.
func BuildResolverWithOverrides(didDocPaths string) (*didcomm.MultiResolver, error) {
	multi, mem := didcomm.DefaultResolver()

	if didDocPaths != "" {
		for _, p := range strings.Split(didDocPaths, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("read DID document %s: %w", p, err)
			}
			doc, err := UnmarshalDIDDoc(data)
			if err != nil {
				return nil, fmt.Errorf("parse DID document %s: %w", p, err)
			}
			mem.Store(doc)
		}
	}

	return multi, nil
}

// BuildClient creates a Client with DefaultResolver (did:key + did:web auto-resolution),
// optional --did-doc overrides, and secrets from the key file.
func BuildClient(keyFile, didDocPaths string) (*didcomm.Client, error) {
	secrets, err := LoadKeyFile(keyFile)
	if err != nil {
		return nil, err
	}

	resolver, err := BuildResolverWithOverrides(didDocPaths)
	if err != nil {
		return nil, err
	}

	return didcomm.NewClient(resolver, secrets), nil
}

const (
	ContentTypeEncrypted = "application/didcomm-encrypted+json"
	ContentTypeSigned    = "application/didcomm-signed+json"
	ContentTypePlain     = "application/didcomm-plain+json"
)

// DetectContentType returns the DIDComm media type based on the envelope format.
func DetectContentType(data []byte) string {
	data = []byte(strings.TrimSpace(string(data)))
	dots := strings.Count(string(data), ".")

	switch dots {
	case 4:
		return ContentTypeEncrypted
	case 2:
		return ContentTypeSigned
	default:
		// JSON serialization JWE or plain
		if len(data) > 0 && data[0] == '{' {
			var peek struct {
				Ciphertext string `json:"ciphertext"`
			}
			if err := json.Unmarshal(data, &peek); err == nil && peek.Ciphertext != "" {
				return ContentTypeEncrypted
			}
		}
		return ContentTypePlain
	}
}

// ParseMessage parses raw JSON bytes into a didcomm.Message.
func ParseMessage(data []byte) (*didcomm.Message, error) {
	var msg didcomm.Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("parse message JSON: %w", err)
	}
	return &msg, nil
}

// HTTPClient is the HTTP client used for sending messages, replaceable for testing.
var HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
} = http.DefaultClient
