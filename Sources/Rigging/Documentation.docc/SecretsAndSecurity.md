# Secrets and Security Hygiene

@Metadata {
    @PageKind(article)
}

Resolve credentials in minimal biometric batches, prevent accidental plaintext commits, materialize mode-`0600` ephemeral files, and scrub secrets from logs.

## Overview

Configuration libraries frequently treat secrets as ordinary `String` properties—making it trivial to leak an API token or PKCS#8 private key through string interpolation, `dump()`, `Codable` snapshots, or validation stack traces, or to trigger a storm of sequential macOS Touch ID prompts when resolving multiple vault items.

Rigging treats secret management as a first-class architectural pillar through five coordinated mechanisms:

1. **Leak-proof `Secret<Value>` containers** that redact formatting, reflection, and default serialization.
2. **Two-phase batched secret resolution** across the entire root and `@NestedSettings` graph.
3. **Repo-committed plaintext guards** (`allowLiteralInProjectConfig: false`) and POSIX `0600` file permission checks.
4. **Hardened `withEphemeralFile` materialization** for external tools that require a file path.
5. **Thread-safe `DiagnosticRedactor` scrubbing** across all error messages and CLI output.

## Leak-Proof `Secret<Value>` Wrapper

Every `@SecretSetting` property must wrap its payload in `Secret<Value>` (or `Secret<Value>?`), such as `Secret<String>`, `Secret<Data>`, or `Secret<[UInt8]>`:

```swift
@Settings(envPrefix: "ASC_")
public struct Credentials {
    @SecretSetting
    public var privateKey: Secret<String>

    @SecretSetting
    public var distributionCertificate: Secret<Data>?
}
```

`Secret<Value>` always renders `"**********"` in `String(describing:)`, `debugDescription`, string interpolation, `Mirror` / `dump()`, and `JSONEncoder` (unless you explicitly opt into `encoder.userInfo[.secretEncodingPolicy] = SecretEncodingPolicy.exposePlaintext`).

To access the underlying value at the call site that genuinely needs it, use scoped closures or byte buffers:

```swift
// Scoped closure unwrap
let bearerHeader = credentials.privateKey.expose { pem in
    signJWT(pemKey: pem)
}

// Contiguous UTF-8 buffer access
credentials.privateKey.withExposedUTF8 { utf8Bytes in
    // Pass raw UnsafeBufferPointer<UInt8> to a C or CryptoKit API
}
```

## Two-Phase Batched Secret Resolution

When `load(...)` runs on a `@Settings` model, Rigging executes secret resolution in two distinct phases before typed decoding:

1. **Phase 1 — Discovery & Grouping**: Rigging walks the root struct and every `@NestedSettings` group (`enqueueSecrets`), inspects the winning raw node for each `@SecretSetting` (and any `@Setting(resolveSecrets: true)`), parses URI schemes into typed `SecretReference` values, deduplicates identical URIs, and groups requests by `(scheme, accountHint)`.
2. **Phase 2 — Single-Batch Provider Dispatch**: Each registered `SecretProvider` receives its entire batch in a single `resolveBatch(_:context:)` call.

For example, if a parent struct and two nested structs reference four `op://` items in the same 1Password account, `OnePasswordProvider` resolves all four secrets in **one `op inject` subprocess invocation** over in-memory `stdin`/`stdout` pipes—prompting for Touch ID once and writing zero bytes to disk.

### Supported Secret Reference Schemes

| Syntax | Provider | Module | Description |
| :--- | :--- | :--- | :--- |
| `op://<vault>/<item>[/<section>]/<field>` | `OnePasswordProvider` | `RiggingOnePassword` | Batched `op inject` CLI or 1Password Connect REST API |
| `keychain://<service>/<account>` | `KeychainProvider` | `RiggingKeychain` | In-process Apple `Security.framework` lookup |
| `bws://<secret-uuid>` | `BitwardenProvider` | `RiggingBitwarden` | Bitwarden Secrets Manager CLI (`BWS_ACCESS_TOKEN`) |
| `bw://<item-id>/<field>` | `BitwardenProvider` | `RiggingBitwarden` | Bitwarden Vault CLI (`BW_SESSION`) |
| `pass://<entry-path>[#fragment]` | `UnixPassProvider` | `RiggingUnixPass` | Unix `pass` GPG store (`#full`, `#line:2`, `#username`) |
| `sops://<file-path>#<json-pointer>` | `SOPSProvider` | `RiggingUnixPass` | Mozilla SOPS encrypted YAML/JSON/ENV + RFC 6901 pointer |
| `file:///abs/path` or `@~/path` | `FileSecretProvider` | `RiggingCore` (Built-in) | Local secret file enforcing `0600` permissions |
| `env://VAR_NAME` | `IndirectEnvProvider` | `RiggingCore` (Built-in) | Indirect lookup from another environment variable |

## Blocking Plaintext Secrets in Committed Config Files

Team repositories often check in a shared project configuration file (such as `.asc.json`) referencing `op://` or `@~/.asc/AuthKey.p8` URIs. To prevent a developer from accidentally pasting a live credential into a tracked file, `@SecretSetting` defaults to `allowLiteralInProjectConfig: false`.

- **Allowed in `.asc.json`**: `"op://Eng/ASC/private_key"`, `"keychain://com.example.asc/key"`, `"sops://secrets.enc.yaml#/asc/key"`, or `"@~/.asc/AuthKey.p8"` (when paired with `.expandFileReference`).
- **Rejected with Exit Code `4` (`unsafeSecret`)**: Any literal string in `projectConfigFiles` that is not a secret reference URI.
- **Allowed in Local Sources**: Plaintext values in process environment variables, gitignored `.env` files, `/run/secrets`, or mode-`0600` user config (`~/.config/<app>/config.json`).

## Transforming Secret Payloads

Many credentials—especially PEM keys and binary certificates—arrive Base64-encoded, carry trailing newlines, or have literal `\n` escape sequences from CI secret variables. Declare composable `SecretTransform` pipelines directly on `@SecretSetting`:

```swift
@SecretSetting(
    transforms: [
        .expandFileReference(requirePermissions: 0o600),
        .decodeBase64IfPrefixed,
        .normalizePEM,
    ]
)
public var signingKey: Secret<String>
```

## Materializing Hardened Ephemeral Files

Legacy CLI tools (`codesign`, `openssl`, `ssh -i`) occasionally require a filesystem path rather than `stdin`. Use `withEphemeralFile` on `Secret<String>`, `Secret<Data>`, or `Secret<[UInt8]>`:

```swift
try await credentials.privateKey.withEphemeralFile(suffix: ".p8") { keyURL in
    // keyURL points to a mode-0600 file inside a private mode-0700 mkdtemp directory.
    try await invokeExternalTool(keyPath: keyURL.path(percentEncoded: false))
}
// On scope exit (normal return or thrown error), the file is overwritten with zero bytes,
// fsynced, unlinked, and its private 0700 directory is removed.
```

## Automatic Diagnostic Redaction and Subprocess Hardening

Every `SettingsContext` carries a thread-safe `DiagnosticRedactor`. As soon as a secret (or ambient auth token like `OP_SERVICE_ACCOUNT_TOKEN`, `BWS_ACCESS_TOKEN`, or `SOPS_AGE_KEY`) is observed—even if validation later fails—its full value and any multiline body lines (such as PEM key lines, excluding public `-----BEGIN ...-----` armor headers) are registered. Longest-match-first scrubbing guarantees that neither validation errors nor `config show` / `config doctor` outputs ever leak secret material.

All CLI-backed secret providers also enforce `ProcessSubprocessRunner.verifyExecutableTrust`:

- Commands execute directly via `Foundation.Process` argument arrays (`executableURL` + `arguments`), **never** via `/bin/sh -c`.
- Binaries are resolved strictly from absolute paths or trusted system directories (`/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`), rejecting relative `PATH` entries and world-writable executables (`mode & 0o002 != 0`).
- Every URI segment is validated against leading `-` option injection, NUL bytes, and ASCII control characters.
