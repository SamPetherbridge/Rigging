# ``RiggingKeychain``

Native, in-process Apple `Security.framework` Keychain secret resolution (`keychain://`).

## Overview

`RiggingKeychain` provides ``KeychainProvider``, an in-process `SecretProvider` that resolves `keychain://<service>/<account>` secret references on macOS, iOS, tvOS, watchOS, and visionOS using `SecItemCopyMatching` directly—with zero `/usr/bin/security` subprocess spawning.

On non-Apple platforms such as Linux, `RiggingKeychain` compiles cleanly without conditional imports in consumer code and surfaces a structured `SecretResolutionError.providerFailed` (`exitCode = 6`) with actionable remediation guidance if a `keychain://` URI is encountered at runtime.

### Supported `keychain://` URI Syntax

```text
# Generic password item (kSecClassGenericPassword) — the default
keychain://com.example.asc/private-key

# Internet password item (kSecClassInternetPassword)
keychain://api.example.com/deploy-bot?kind=internet

# Explicit Keychain access group and iCloud Keychain synchronizable filter
keychain://com.example.asc/api-token?accessGroup=TEAMID1234.com.example.shared&synchronizable=true
```

### Usage Example

```swift
import Rigging
import RiggingKeychain

@Rigged(envPrefix: "ASC_")
public struct Credentials: Sendable {
    /// Reads kSecClassGenericPassword where service="com.example.asc" and account="issuer-key"
    @SecretSetting
    public var privateKey: Secret<String>
}

let credentials = try await Credentials.load(
    secretProviders: [
        FileSecretProvider(),
        IndirectEnvProvider(),
        .keychain(synchronizable: false),
    ]
)
```

### Security Notes

- Lookups execute strictly in-process via `Security.SecItemCopyMatching` (`kSecReturnData: true`, `kSecMatchLimitOne`), avoiding CLI argument exposure in `ps` process listings.
- Service, account, and access group segments reject empty strings, leading `-` characters, NUL bytes, and ASCII control characters.
- Locked keychain or user-canceled biometric prompts (`errSecAuthFailed`, `errSecUserCanceled`, `errSecInteractionNotAllowed`) map deterministically to `SecretResolutionError.authenticationFailed` (`exitCode = 6`), while resolved bytes are registered immediately in `DiagnosticRedactor`.
- Unit tests can inject a custom ``KeychainProvider/Backend`` closure via ``KeychainProvider/init(accessGroup:synchronizable:backend:)`` to test every `OSStatus` edge case hermetically without touching the macOS login Keychain.

## Topics

### Secret Provider

- ``KeychainProvider``
- ``KeychainPasswordKind``
- ``KeychainBackendResponse``
