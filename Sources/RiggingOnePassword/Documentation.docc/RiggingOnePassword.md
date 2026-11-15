# ``RiggingOnePassword``

Batched 1Password secret resolution (`op://`) via single-pass `op inject` pipes or 1Password Connect REST APIs.

## Overview

`RiggingOnePassword` provides ``OnePasswordProvider``, a production-hardened `SecretProvider` for resolving `op://` secret reference URIs across local macOS developer workstations, CI runners (1Password Service Accounts), and containerized Linux servers (1Password Connect Server).

### Single-Prompt Biometric Batching

When your `@Settings` model declares multiple `@SecretSetting` properties (across root and `@NestedSettings` structs), Rigging's two-phase resolver collects all `op://` references up front and dispatches them to ``OnePasswordProvider/resolveBatch(_:context:)`` in a single batch:

- **Standard Vault Fields**: Rendered into an in-memory template guarded by a fresh 128-bit random boundary nonce and piped through **one** `op inject` invocation over `stdin`/`stdout`—unlocking Touch ID once and writing zero temporary files to disk.
- **OTP & Binary Documents**: `?attribute=otp` and `?document=true` references are resolved concurrently immediately after the initial batch unlock.
- **1Password Connect REST Mode**: When ``OnePasswordConnectConfiguration`` is supplied (or `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` are set in the environment), `OnePasswordProvider` resolves vaults, items, fields, OTPs, and document files directly over HTTPS via `URLSession` (`FoundationNetworking` on Linux) with **no `op` CLI binary required**.

### Supported `op://` URI Syntax

```text
# Standard item field
op://Engineering/AppStoreConnect/private_key

# Section-scoped item field
op://Engineering/Postgres/Credentials/password

# Explicit account selector (shorthand, sign-in address, or account UUID)
op://Engineering/Stripe/webhook_secret?account=myteam.1password.com

# Time-based one-time password (TOTP)
op://Engineering/GitHubBot/one-time-password?attribute=otp

# Binary or PEM document attachment
op://Engineering/AppleSigningCert/dist.p12?document=true
```

### Usage Example

```swift
import Rigging
import RiggingOnePassword

@Settings(envPrefix: "APP_", projectConfigFiles: [".app.json"])
public struct AppSettings: Sendable {
    @SecretSetting
    public var databasePassword: Secret<String>

    @SecretSetting
    public var signingCert: Secret<Data>?
}

let settings = try await AppSettings.load(
    secretProviders: [
        FileSecretProvider(),
        IndirectEnvProvider(),
        .onePassword(),
    ]
)
```

### Security Notes

- The `op` binary is resolved strictly from an explicit absolute path or trusted system directories (`/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`) and verified non-world-writable (`mode & 0o002 == 0`) prior to execution.
- All URI path segments and account selectors reject leading `-` option injection, NUL bytes, and ASCII control characters.
- Ambient tokens (`OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_TOKEN`) and all resolved secret payloads are automatically registered in `DiagnosticRedactor` so diagnostic output never echoes sensitive material.

## Topics

### Secret Provider

- ``OnePasswordProvider``

### 1Password Connect REST Mode

- ``OnePasswordConnectConfiguration``
- ``OnePasswordHTTPTransport``
- ``URLSessionOnePasswordHTTPTransport``
- ``ClosureOnePasswordHTTPTransport``
