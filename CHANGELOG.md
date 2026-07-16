## Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-07-16

### Fixed
- **keyAgreement key selection.** Packing now selects the recipient's X25519
  key(s), skipping keyAgreement entries of other curves — some DID documents
  list a non-transport key (e.g. a P-256 PII key) first. Previously the first
  entry was used unconditionally, so packing to such a recipient failed with
  "unsupported key type".

### Changed
- **Encrypt to every X25519 keyAgreement key.** A message is now encrypted to
  all of a recipient's X25519 keyAgreement keys, so the recipient can decrypt
  with whichever it holds rather than only the first.

## [0.6.0] - 2026-07-14

### Added
- **Decrypt ECDH-1PU authcrypt sealed with XChaCha20-Poly1305** on unpack: `alg`
  `ECDH-1PU+XC20PKW` and `enc` `XC20P` (draft-amringer-jose-chacha-02), for
  interoperability with DIDComm implementations that use XChaCha20. `alg`, `epk`,
  and the XC20PKW key-wrap `iv`/`tag` are read from the per-recipient header as
  well as the protected header. Output is unchanged — this package still emits
  A256GCM / A256KW.

## [0.5.0] - 2026-07-07

A security-driven rewrite. **Breaking**: the module path, the key interface, and
the pack/unpack API all changed. There is no in-place upgrade from 0.4.x.

### Security
- **Sender authentication is now bound to the message's `from`.** `Unpack`
  verifies the signer (JWS) or the ECDH-1PU `skid`, requires it to equal
  `message.from`, and returns it as `Metadata.SenderDID`. Previously any
  resolvable DID holder could forge `from` on signed and authcrypt messages, and
  unsigned plain messages were accepted outright — both are now rejected.
- **Plain and anonymous messages are rejected by `Unpack`.** Accepting them is a
  deliberate opt-in via `UnpackUnverified`, which never reports a trusted sender.
- **Anti-forwarding binding**: for encrypted messages the local recipient must
  appear in `to`, closing surreptitious-forwarding of a validly-signed payload.
- **did:web resolution is SSRF-hardened**: a timeout, a 1 MiB response cap, no
  redirects, and a dial-time block on loopback, private, link-local, and
  cloud-metadata addresses (defeating DNS rebinding).
- **Decryption is oracle-free**: a self-contained JWE codec verifies the content
  MAC in constant time before decrypting and returns a single opaque error.

### Added
- **`KeyStore` interface** (`Sign` + `DiffieHellman`) as the sole channel for
  private-key material — the library never receives a private key. HSM/KMS-ready.
- **`softkey` package**: an in-memory `KeyStore` for tests and local development;
  the only place raw keys are handled, kept out of the core.
- **Real ECDH-1PU authcrypt**, draft-03 and draft-04, interoperable with
  DIDComm v2 peers. Selectable per message via `Profile`
  (`ProfileSignedAnoncrypt`, `ProfileAuthcrypt1PUv3`, `ProfileAuthcrypt1PUv4`,
  `ProfileAnoncrypt`, `ProfileSigned`) with `WithContentEncryption` and
  `WithSerialization` options.
- Verification-method parsing for `publicKeyBase58` and `publicKeyMultibase`
  (`Ed25519VerificationKey2018` / `X25519KeyAgreementKey2019` and the 2020 types),
  not just `publicKeyJwk`.
- `created_time` / `expires_time` are accepted as either a JSON number or string
  on the wire.

### Changed
- Module path is now `github.com/notabene-id/go-didcomm` (lowercase org).
- `Pack` takes functional options; `Unpack` returns `(*Message, *Metadata, error)`.
- `internal/jose` implements ConcatKDF (RFC 7518 §4.6), AES key wrap (RFC 3394),
  and A256CBC-HS512 / A256GCM content encryption (RFC 7518 §5), verified against
  RFC test vectors and a captured cross-implementation interop fixture.
- The CLI is a single hardened `cmd/didcomm` command; private keys are written
  `0600` and only printed with `--print-private`.

### Removed
- `PackSigned` / `PackAnoncrypt` / `PackAuthcrypt` (use `Pack` + `WithProfile`),
  the `SecretsResolver` / `InMemorySecretsStore` types (use `KeyStore` /
  `softkey`), the sign-then-anoncrypt mislabeling of "authcrypt", and the
  exported `cli/` package.

## [0.4.0] - 2026-05-05

### Fixed
- **JWS serialization now conforms to DIDComm v2.** The spec ([signature.md](https://github.com/decentralized-identity/didcomm-messaging/blob/master/docs/spec-files/signature.md)) states: "When transmitted in a normal JWM fashion, the JSON Serialization MUST be used … Message recipients MUST be able to process both [general and flattened] forms." Pre-v0.4.0 emitted JWS in compact serialization (non-conforming) and refused JSON-serialized JWS on `Unpack` (also non-conforming).
- `cli.DetectContentType` no longer mislabels compact JWS/JWE as `application/didcomm-*+json`. The `+json` suffix per RFC 6839 §3.1 specifically signals JSON serialization, so compact data now returns `application/jose` (the RFC 7515/7516 media type for compact JOSE). DIDComm v2 mandates JSON serialization for transmission, so this only affects users feeding compact JOSE through the CLI's `--send` flag.

### Added
- `cli.ContentTypeJOSE = "application/jose"` constant for compact JOSE.
- `Unpack` and `DetectContentType` recognize JWS JSON serialization in both flattened (`payload`+`signature`) and general (`payload`+`signatures[]`) forms.

### Changed
- `PackSigned` and the inner JWS of `PackAuthcrypt` now emit JSON serialization by default (jwx flattened form for the single-signer case, valid per spec). Compact-serialized JWS produced by other implementations continues to verify on the unpack side — only the pack-side default changed.
- `cmd/didcomm` CLI version bumped to `0.4.0`.

## [0.3.0] - 2026-03-25

### Added
- `did resolve` CLI command and support for string references in DID documents.
- Pre-push checklist in `CLAUDE.md`.

### Changed
- JWE pack output now defaults to JSON serialization (required for multi-recipient, preferred for consistency).
- HTTP error logging improved on `--send`.

## [0.2.0] - 2026-03-01

### Added
- Exported `cli/` package so external tools (e.g. `tap-go`) can reuse the CLI utilities.

### Removed
- Unused wrappers flagged by the linter.

## [0.1.0] - 2026-02-27

### Added
- Initial DIDComm v2 messaging library: `PackSigned` (JWS), `PackAnoncrypt` (JWE), `PackAuthcrypt` (sign-then-encrypt), and `Unpack` with auto-detection.
- `did:key` and `did:web` generation and resolution; `MultiResolver` and `DefaultResolver()`.
- `cmd/didcomm` CLI with `did generate-key`, `did generate-web`, `pack`, `unpack`, and `send` commands; `--send` flag resolves the recipient's `DIDCommMessaging` service endpoint.
- `SecretsResolver` interface and in-memory implementation.
- GitHub Actions CI with linting and tests.

[0.6.1]: https://github.com/notabene-id/go-didcomm/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/notabene-id/go-didcomm/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/notabene-id/go-didcomm/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Notabene-id/go-didcomm/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Notabene-id/go-didcomm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Notabene-id/go-didcomm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Notabene-id/go-didcomm/releases/tag/v0.1.0
