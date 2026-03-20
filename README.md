# go-didcomm

A Go library for [DIDComm v2](https://identity.foundation/didcomm-messaging/spec/v2.1/) messaging with support for signed, anonymous encrypted, and authenticated encrypted messages.

## Features

- **Signed messages** (JWS) using Ed25519/EdDSA
- **Anonymous encryption** (anoncrypt) using ECDH-ES+A256KW / A256CBC-HS512
- **Authenticated encryption** (authcrypt) using sign-then-encrypt
- **Auto-detection** of message format on unpack (JWE, JWS, or plain JSON)
- **did:key** and **did:web** generation with Ed25519 signing and X25519 key agreement keys
- **Automatic DID resolution** for did:key (local) and did:web (HTTPS fetch)
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

	// Set up resolver (auto-resolves did:key and did:web) and secrets store
	resolver, _ := didcomm.DefaultResolver()

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

### Custom resolver

Implement the `Resolver` interface to integrate with your DID resolution infrastructure:

```go
type Resolver interface {
	Resolve(ctx context.Context, did string) (*DIDDocument, error)
}
```

Built-in resolvers: `DIDKeyResolver` (local), `DIDWebResolver` (HTTPS), `MultiResolver` (routes by method), `InMemoryResolver` (manual). Use `DefaultResolver()` for a pre-configured setup.

### Custom secrets resolver

Implement the `SecretsResolver` interface to integrate with your key management system:

```go
type SecretsResolver interface {
	GetKey(ctx context.Context, kid string) (jwk.Key, error)
}
```

## CLI

A command-line tool for DIDComm v2 operations: generate identities, pack/unpack messages, and send to endpoints.

### Install

```bash
go install github.com/Notabene-id/go-didcomm/cmd/didcomm@latest
```

### Commands

```
didcomm did generate-key [--output-dir <dir>]
didcomm did generate-web --domain <d> [--path <p>] [--service-endpoint <url>] [--output-dir <dir>]
didcomm did resolve <did> [--did-doc <f>]
didcomm pack signed    --key-file <f> [--send] [--did-doc <f>] [--message <m>]
didcomm pack anoncrypt [--send] [--did-doc <f>] [--message <m>]
didcomm pack authcrypt --key-file <f> [--send] [--did-doc <f>] [--message <m>]
didcomm unpack         --key-file <f> [--did-doc <f>] [--message <m>]
didcomm send           --to <url> [--message <m>]
```

DID resolution is automatic for `did:key` (decoded locally) and `did:web` (fetched over HTTPS). The `--did-doc` flag is only needed to override or supplement auto-resolved documents.

The `--send` flag on pack commands resolves the first recipient's DIDCommMessaging service endpoint and POSTs the packed message to it.

The `--message` flag accepts `-` for stdin (default), `@filename` to read from a file, or an inline JSON string.

### Walkthrough

Generate identities for Alice and Bob:

```bash
didcomm did generate-key --output-dir alice
didcomm did generate-key --output-dir bob
```

This creates `did-doc.json` (public DID document) and `keys.json` (private JWK Set) in each directory.

Resolve a DID document (auto-resolves `did:key` and `did:web`):

```bash
didcomm did resolve did:web:notabene.id:bq
```

Create a message and pack it with authenticated encryption (did:key auto-resolves — no `--did-doc` needed):

```bash
ALICE=$(jq -r .id alice/did-doc.json)
BOB=$(jq -r .id bob/did-doc.json)

echo '{"id":"1","type":"https://example.com/hello","from":"'$ALICE'","to":["'$BOB'"],"body":{"text":"hi"}}' | \
  didcomm pack authcrypt --key-file alice/keys.json > packed.json
```

Unpack with Bob's keys:

```bash
didcomm unpack --key-file bob/keys.json --message @packed.json
```

Send a packed message to an endpoint:

```bash
didcomm send --to https://example.com/didcomm --message @packed.json
```

The content type is auto-detected (`application/didcomm-encrypted+json`, `application/didcomm-signed+json`, or `application/didcomm-plain+json`).

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
├── didcomm.go           # Client with Pack*/Unpack operations
├── message.go           # DIDComm v2 Message type and JSON marshaling
├── did.go               # DID document types, did:key/did:web generation, Resolver interface
├── resolve_didkey.go    # DIDKeyResolver — local did:key resolution
├── resolve_didweb.go    # DIDWebResolver — HTTPS did:web resolution
├── resolve_multi.go     # MultiResolver — routes by DID method, DefaultResolver()
├── keys.go              # Ed25519/X25519 key pair generation
├── secrets.go           # SecretsResolver interface and in-memory implementation
├── encrypt.go           # Anonymous encryption (anoncrypt) using JWE
├── authcrypt.go         # Authenticated encryption (sign-then-encrypt)
├── sign.go              # JWS signing and verification
├── errors.go            # Sentinel errors
├── cli/                # Exported CLI utilities (shared with tap-go)
├── cmd/
│   └── didcomm/         # CLI tool
└── internal/
    └── convert/         # Ed25519 ↔ X25519 key conversion
```

## License

[MIT](LICENSE)
