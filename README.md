# go-didcomm

DIDComm v2 messaging for Go — signed, anonymous-encrypted, and
authenticated-encrypted (ECDH-1PU) messages, with sender authentication that is
on by default and bound to the message's declared sender.

## Why this library

- **Private keys never enter the library.** You implement a `KeyStore` (sign +
  Diffie-Hellman); the library only ever receives operation results, never a
  private key. Back it with an HSM/KMS and key material never leaves it.
- **Authenticated sender, returned as a value.** `Unpack` verifies the sender
  and checks it against the message's `from`, returning the verified DID.
  Unsigned and sender-anonymous messages are rejected unless you explicitly opt
  out with `UnpackUnverified`.
- **Interoperable.** Selectable per message: sign-then-encrypt (non-repudiable),
  ECDH-1PU authcrypt draft-03 and draft-04, and anoncrypt.
- **No decryption oracles.** A self-contained JWE codec does constant-time
  MAC-then-decrypt and returns a single opaque error for every failure.

## Install

```bash
go get github.com/notabene-id/go-didcomm
```

## Quickstart

```go
ctx := context.Background()

// Public DID documents plus private key material. In production the material
// goes into your KMS; softkey is an in-memory store for tests and local dev.
aliceDoc, aliceKeys, _ := didcomm.GenerateDIDKey()
bobDoc, bobKeys, _ := didcomm.GenerateDIDKey()

resolver, overrides := didcomm.DefaultResolver()
overrides.Store(aliceDoc)
overrides.Store(bobDoc)

store, _ := softkey.New(aliceKeys, bobKeys)
client := didcomm.NewClient(resolver, store)

msg := &didcomm.Message{
    ID: "1", Type: "https://example.com/hello",
    From: aliceDoc.ID, To: []string{bobDoc.ID},
    Body: json.RawMessage(`{"text":"Hello Bob!"}`),
}

packed, _ := client.Pack(ctx, msg, didcomm.WithProfile(didcomm.ProfileAuthcrypt1PUv3))

got, meta, err := client.Unpack(ctx, packed)
// err is non-nil for an unauthenticated, spoofed, or undecryptable message.
fmt.Println(meta.SenderDID) // == got.From, cryptographically verified
```

## Profiles

Pick per message with `WithProfile`. The default is `ProfileSignedAnoncrypt`.

| Profile | Wire form | Sender auth | Repudiation |
| --- | --- | --- | --- |
| `ProfileSignedAnoncrypt` | inner EdDSA JWS + ECDH-ES JWE | inner signature | non-repudiable |
| `ProfileAuthcrypt1PUv3` | ECDH-1PU JWE (draft-03) | envelope (1PU) | repudiable |
| `ProfileAuthcrypt1PUv4` | ECDH-1PU JWE (draft-04) | envelope (1PU) | repudiable |
| `ProfileAnoncrypt` | ECDH-ES JWE | none | — |
| `ProfileSigned` | EdDSA JWS, no encryption | signature | non-repudiable |

`WithContentEncryption` (A256GCM or A256CBC-HS512) and `WithSerialization`
(general JSON or compact) refine the encrypted profiles; `ProfileAuthcrypt1PUv4`
fixes A256CBC-HS512 per the draft.

## Unpacking

```go
// Default: requires authentication; guarantees meta.SenderDID == msg.From.
// Rejects plain and anonymous messages. Use this wherever you trust `from`.
msg, meta, err := client.Unpack(ctx, envelope)

// Opt-out: decrypts where possible but does NOT authenticate the sender —
// msg.From is attacker-controlled. For diagnostics or anonymous intake only.
msg, meta, err := client.UnpackUnverified(ctx, envelope)
```

## Interfaces you implement

```go
// The only channel for private-key material. Keys never leave your implementation.
type KeyStore interface {
    Sign(ctx context.Context, kid string, data []byte) ([]byte, error)
    DiffieHellman(ctx context.Context, kid string, peerPublicKey []byte) ([]byte, error)
}

// DID resolution.
type DIDResolver interface {
    Resolve(ctx context.Context, did string) (*DIDDocument, error)
}
```

Built-in resolvers: `DIDKeyResolver` (local), `DIDWebResolver` (HTTPS),
`MultiResolver`, and `DefaultResolver()`. did:web resolution enforces a timeout,
caps the response size, refuses redirects, and blocks private, loopback, and
cloud-metadata addresses at dial time (`DIDWebResolver.AllowLoopback` re-enables
loopback for local dev). Verification methods are read from `publicKeyJwk`,
`publicKeyBase58`, or `publicKeyMultibase`.

## CLI

```bash
go install github.com/notabene-id/go-didcomm/cmd/didcomm@latest

didcomm generate --dir alice                          # did:key identity + keys.json
didcomm pack   --keys alice/keys.json --profile 1pu-v3 < msg.json
didcomm unpack --keys bob/keys.json   < packed.json
```

`generate` writes keys `0600` and prints only the public document unless
`--print-private` is given. `pack --send` and `send --to` accept http(s) URLs
only.

## Security

Sender authentication is bound to `from`; unauthenticated intake is a named
opt-out. The JWE codec is constant-time and returns one opaque decryption error.
Report vulnerabilities to security@notabene.id.

## License

[MIT](LICENSE)
