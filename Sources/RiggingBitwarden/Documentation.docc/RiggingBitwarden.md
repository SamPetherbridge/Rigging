# ``RiggingBitwarden``

Bitwarden Secrets Manager (`bws://`) and Bitwarden Vault CLI (`bw://`) secret resolution.

## Overview

`RiggingBitwarden` provides ``BitwardenProvider``, a unified `SecretProvider` supporting both machine-oriented CI/server secrets in **Bitwarden Secrets Manager** (`bws://`) and developer vault items in **Bitwarden Password Manager CLI** (`bw://`).

When multiple `bw://` fields reference the same vault item (for example `bw://<item-id>/username` and `bw://<item-id>/password`), ``BitwardenProvider`` caches the decoded item payload within the batch so `bw get item` executes only once per unique item ID.

### Supported `bws://` and `bw://` URI Syntax

```text
# Bitwarden Secrets Manager (requires BWS_ACCESS_TOKEN or explicit bwsAccessToken)
bws://be8e0ad8-d545-4017-a55a-b02f014d4158

# Bitwarden Vault login fields (requires BW_SESSION or explicit bwSession)
bw://7b226964-1111-2222-3333-444455556666/password
bw://7b226964-1111-2222-3333-444455556666/username
bw://7b226964-1111-2222-3333-444455556666/totp
bw://7b226964-1111-2222-3333-444455556666/uri
bw://7b226964-1111-2222-3333-444455556666/notes

# Bitwarden Vault custom field lookup (case-insensitive fallback)
bw://7b226964-1111-2222-3333-444455556666/api_signing_key
```

### Usage Example

```swift
import Rigging
import RiggingBitwarden

@Settings(envPrefix: "DEPLOY_")
public struct DeploySettings: Sendable {
    @SecretSetting
    public var registryToken: Secret<String>

    @SecretSetting
    public var webhookSecret: Secret<String>
}

let settings = try await DeploySettings.load(
    secretProviders: [
        FileSecretProvider(),
        IndirectEnvProvider(),
        .bitwarden(),
    ]
)
```

### Security Notes

- Both `bws` and `bw` binaries are resolved exclusively from explicit absolute paths or trusted system directories (`/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`) and verified non-world-writable (`mode & 0o002 == 0`).
- Subprocesses are invoked directly via argument arrays (`["secret", "get", secretID, "--output", "json"]` and `["get", "item", itemID]`) with zero shell interpolation.
- Every `secretID`, `itemID`, and `field` segment rejects leading `-` option injection, NUL bytes, and control characters.
- Ambient `BWS_ACCESS_TOKEN` and `BW_SESSION` credentials—along with every resolved secret—are registered in `DiagnosticRedactor` prior to subprocess execution so errors never leak tokens.

## Topics

### Secret Provider

- ``BitwardenProvider``
