# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
go test ./...

# Run tests with race detector and coverage (matches CI)
go test -race -coverprofile=coverage.out ./...

# Run a single test
go test -run TestClient_PackAuthcrypt_Unpack ./...

# Lint (requires golangci-lint v2)
golangci-lint run ./...

# Auto-fix formatting
golangci-lint fmt ./...
```

## Architecture

This is a DIDComm v2 messaging library. The central type is `Client`, which provides `Pack*` and `Unpack` operations for three message formats:

- **PackSigned** — JWS (EdDSA/Ed25519), sender authenticated, not encrypted
- **PackAnoncrypt** — JWE (ECDH-ES+A256KW / A256CBC-HS512), encrypted, sender anonymous
- **PackAuthcrypt** — sign-then-encrypt (JWS inside JWE), sender identified via `skid` header

`Unpack` auto-detects the format (JWE by dot count or JSON fields, JWS by dot count, else plain JSON) and returns an `UnpackResult` with `Encrypted`/`Signed`/`Anonymous` flags.

### Key resolution flow

`Client` depends on two pluggable components:
- **`Resolver`** — maps DIDs to `DIDDocument`s (which contain public keys in `Authentication` and `KeyAgreement` verification methods)
- **`SecretsResolver`** (interface) — maps key IDs (kid) to private JWK keys. `InMemorySecretsStore` is the built-in implementation.

Pack operations resolve the sender's private key via `Resolver` → `DIDDocument.FindSigningKey()` → `SecretsResolver.GetKey()`, and recipients' public keys via `Resolver` → `DIDDocument.FindEncryptionKey()`.

### Key pairs

`GenerateKeyPair()` creates an Ed25519 signing key and derives an X25519 encryption key from it (via `internal/convert`). Both are stored as JWKs in `KeyPair`. DID generation (`GenerateDIDKey`, `GenerateDIDWeb`) wraps this into a `DIDDocument` with proper key IDs.

### Known limitation

APV (Agreement PartyVInfo) is omitted from JWE headers due to a jwx v3 bug where X25519 ECDH-ES KDF ignores apu/apv during encryption but uses them during decryption. See `encrypt.go`.

## Lint rules

The `.golangci.yml` uses golangci-lint v2 format (`version: "2"`). Key rules:
- All `%v` in `fmt.Errorf` with errors must use `%w` (errorlint)
- Use `errors.Is()` not `==` for sentinel error checks (errorlint)
- Max cyclomatic complexity: 15 (gocyclo)
- `nolint` directives require explanation and specific linter name
- Test files are excluded from gosec, errcheck, gocritic, gocyclo, goconst, unparam
