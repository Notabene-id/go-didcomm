# go-didcomm

A Go library for [DIDComm v2](https://identity.foundation/didcomm-messaging/spec/v2.1/) messaging with support for signed, anonymous encrypted, and authenticated encrypted messages.

## Features

- **Signed messages** (JWS) using Ed25519/EdDSA
- **Anonymous encryption** (anoncrypt) using ECDH-ES+A256KW / A256CBC-HS512
- **Authenticated encryption** (authcrypt) using sign-then-encrypt
- **Auto-detection** of message format on unpack (JWE, JWS, or plain JSON)
- **did:key** and **did:web** generation with Ed25519 signing and X25519 key agreement keys
- Pluggable DID resolver and secrets store interfaces

## Install

```bash
go get github.com/Notabene-id/go-didcomm
```

## Usage

### Generate DIDs and set up a client

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	didcomm "github.com/Notabene-id/go-didcomm"
)

func main() {
	ctx := context.Background()

	// Generate did:key identities for Alice and Bob
	aliceDoc, aliceKeys, _ := didcomm.GenerateDIDKey()
	bobDoc, bobKeys, _ := didcomm.GenerateDIDKey()

	// Set up resolver and secrets store
	resolver := didcomm.NewResolver()
	resolver.Store(aliceDoc)
	resolver.Store(bobDoc)

	secrets := didcomm.NewInMemorySecretsStore()
	secrets.Store(aliceKeys)
	secrets.Store(bobKeys)

	client := didcomm.NewClient(resolver, secrets)

	// Create a message from Alice to Bob
	msg := &didcomm.Message{
		ID:   "msg-1",
		Type: "https://example.com/hello",
		From: aliceDoc.ID,
		To:   []string{bobDoc.ID},
		Body: json.RawMessage(`{"text": "Hello Bob!"}`),
	}

	// Pack as authenticated encrypted message
	packed, err := client.PackAuthcrypt(ctx, msg)
	if err != nil {
		log.Fatal(err)
	}

	// Unpack (auto-detects format)
	result, err := client.Unpack(ctx, packed)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Message type: %s\n", result.Message.Type)
	fmt.Printf("Encrypted: %v, Signed: %v\n", result.Encrypted, result.Signed)
}
```

### Packing modes

```go
// Signed (JWS) — sender is authenticated, message is not encrypted
packed, err := client.PackSigned(ctx, msg)

// Anonymous encryption — encrypted for recipients, sender is anonymous
packed, err := client.PackAnoncrypt(ctx, msg)

// Authenticated encryption — signed then encrypted
packed, err := client.PackAuthcrypt(ctx, msg)
```

### Custom secrets resolver

Implement the `SecretsResolver` interface to integrate with your key management system:

```go
type SecretsResolver interface {
	GetKey(ctx context.Context, kid string) (jwk.Key, error)
}
```

## Development

### Prerequisites

- Go 1.25 or later

### Running tests

```bash
go test ./...
```

With verbose output:

```bash
go test -v ./...
```

With coverage:

```bash
go test -cover ./...
```

### Project structure

```
.
├── didcomm.go        # Client with Pack*/Unpack operations
├── message.go        # DIDComm v2 Message type and JSON marshaling
├── did.go            # DID document types, did:key/did:web generation, Resolver
├── keys.go           # Ed25519/X25519 key pair generation
├── secrets.go        # SecretsResolver interface and in-memory implementation
├── encrypt.go        # Anonymous encryption (anoncrypt) using JWE
├── authcrypt.go      # Authenticated encryption (sign-then-encrypt)
├── sign.go           # JWS signing and verification
├── errors.go         # Sentinel errors
└── internal/
    └── convert/      # Ed25519 ↔ X25519 key conversion
```

## License

[MIT](LICENSE)
