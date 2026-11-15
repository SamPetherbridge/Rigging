# ``RiggingUnixPass``

GPG-backed Unix `pass` (`pass://`) and Mozilla SOPS (`sops://`) encrypted-file secret providers.

## Overview

`RiggingUnixPass` provides two complementary secret providers tailored for Unix workstations, GitOps repositories, and Linux servers:

1. ``UnixPassProvider`` (`pass://`): Resolves entries from the standard Unix Password Store (`~/.password-store` or `PASSWORD_STORE_DIR`), supporting first-line passwords, `#full` multiline payloads, `#line:<N>` line selectors, and `#<key>` metadata extraction (`username: alice`).
2. ``SOPSProvider`` (`sops://`): Decrypts age-, PGP-, or cloud-KMS-encrypted YAML, JSON, ENV, and INI files into memory via `sops --decrypt --output-type json` and extracts nested values in-process using RFC 6901 JSON Pointers (`#/database/password`) or dotted key paths.

Both providers deduplicate underlying CLI invocations within each batch: referencing five fields from the same `pass` entry or encrypted SOPS file executes `pass show` or `sops --decrypt` **only once**.

### Supported `pass://` and `sops://` URI Syntax

```text
# Standard pass convention: line 1 of ~/.password-store/prod/postgres.gpg
pass://prod/postgres

# Extract "username: ..." metadata line from the same entry
pass://prod/postgres#username

# Specific 1-based line number or full multiline file (e.g. SSH / PEM key)
pass://prod/postgres#line:2
pass://infra/signing-key#full

# Custom password store directory per reference
pass://team/api-token?store=/etc/company-pass

# Mozilla SOPS with RFC 6901 JSON Pointer (supports ~0 for '~' and ~1 for '/')
sops://config/secrets.enc.yaml#/database/password
sops://config/secrets.enc.json#/webhooks/0/signingSecret

# Mozilla SOPS raw whole-file decryption (e.g. encrypted binary or PEM file)
sops://keys/AuthKey.enc.p8?raw=true
```

### Usage Example

```swift
import Rigging
import RiggingUnixPass

@Settings(envPrefix: "INFRA_")
public struct InfraSettings: Sendable {
    @SecretSetting
    public var dbPassword: Secret<String>

    @SecretSetting
    public var dbUser: Secret<String>

    @SecretSetting
    public var jwtPrivateKey: Secret<String>
}

let settings = try await InfraSettings.load(
    secretProviders: [
        FileSecretProvider(),
        IndirectEnvProvider(),
        .unixPass(),
        .sops(),
    ]
)
```

### Security Notes

- **In-Memory RFC 6901 Pointer Traversal**: ``SOPSProvider`` intentionally avoids SOPS's `--extract` CLI flag (which interprets Python-style slice syntax) and instead parses JSON in-memory after `sops --decrypt --output-type json` over `stdout`, eliminating key-injection vectors and writing zero plaintext files to disk.
- **Path Traversal & Option Injection Guards**: ``UnixPassProvider`` rejects `.` and `..` path traversal segments, empty segments, and leading `-` flags; ``SOPSProvider`` validates both raw and home-expanded file paths against leading `-` option injection, NUL bytes, and control characters.
- **Trusted Executables & Redaction**: Both `pass` and `sops` are verified against `ProcessSubprocessRunner.verifyExecutableTrust`, and `SOPS_AGE_KEY` plus all decrypted secret values are registered in `DiagnosticRedactor`.

## Topics

### Secret Providers

- ``UnixPassProvider``
- ``SOPSProvider``
