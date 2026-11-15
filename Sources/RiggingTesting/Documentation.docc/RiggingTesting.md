# ``RiggingTesting``

Hermetic, zero-I/O test doubles, in-memory filesystems, and mock secret providers for testing `@Settings` models in parallel.

## Overview

`RiggingTesting` lets unit and integration tests exercise every layer of Rigging—CLI overrides, environment variables, `.env` files, upward `.git`-bounded project config discovery, POSIX permission checks, and batched `op://` / `keychain://` / `bws://` / `pass://` secret resolution—100% in memory without touching `ProcessInfo.processInfo.environment`, disk, macOS Keychain, or external CLI binaries.

### One-Line Hermetic Settings Tests

Use `SettingsContext.inMemory(...)` or `RiggedSettings.loadInMemory(...)` to run deterministic parallel tests with Swift Testing:

```swift
import Rigging
import RiggingTesting
import Testing

@Test("Loads project config, resolves 1Password secret in 1 batch, and tracks provenance")
func loadSettingsHermetically() async throws {
    let mockOP = MockOnePasswordProvider(secrets: [
        "op://Eng/App/private_key": TestFixtures.sampleP8PEM,
    ])

    let settings = try await AppSettings.loadInMemory(
        environment: ["APP_READ_ONLY": "true"],
        files: [
            "/repo/.app.json": """
            {
                "keyId": "ABC1234567",
                "privateKey": "op://Eng/App/private_key"
            }
            """,
        ],
        directories: ["/repo/.git"],
        secretProviders: [mockOP]
    )

    #expect(settings.readOnly == true)
    #expect(settings.$readOnly.source == .environment(variable: "APP_READ_ONLY"))
    #expect(await mockOP.invocationCount == 1)
}
```

## Topics

### Hermetic Execution & Filesystem

- ``InMemoryFileSystem``

### Mock Secret Providers

- ``MockOnePasswordProvider``
- ``MockKeychainProvider``
- ``MockSecretProvider``

### Mock Subprocess Execution & Fixtures

- ``MockSubprocessRunner``
- ``TestFixtures``
