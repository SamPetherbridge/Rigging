# Getting Started with Rigging

@Metadata {
    @PageKind(article)
}

Define strongly typed `@Settings` models, layer environment and repository configuration files, and validate startup configuration in Swift 6.

## Overview

Rigging turns plain Swift structs into multi-source, self-documenting configuration schemas. Instead of scattering `ProcessInfo.processInfo.environment` lookups and ad-hoc JSON decoding across your application, you declare a single struct annotated with ``Settings(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)`` (or ``Rigged(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)`` in SwiftUI targets).

At load time, Rigging merges up to eight configuration layers, resolves external secret references in minimal batches, validates every field and cross-field invariant without failing on the first error, and records exact source provenance on every property.

## Adding Rigging to Your Package

Add `Rigging` to your `Package.swift` dependencies, along with any optional secret provider, file format, or CLI integration modules your target needs:

```swift
dependencies: [
    .package(url: "https://github.com/SamPetherbridge/Rigging.git", from: "0.4.1"),
],
targets: [
    .executableTarget(
        name: "my-service",
        dependencies: [
            .product(name: "Rigging", package: "Rigging"),
            .product(name: "RiggingOnePassword", package: "Rigging"),
            .product(name: "RiggingKeychain", package: "Rigging"),
            .product(name: "RiggingArgumentParser", package: "Rigging"),
        ]
    ),
]
```

## Declaring Your First Settings Model

Annotate a `struct` with `@Settings` and mark stored properties with `@Setting`, `@SecretSetting`, or `@NestedSettings`:

```swift
import Foundation
import Rigging

public enum LogLevel: String, CaseIterable, Sendable, Equatable {
    case debug, info, warn, error
}

@Settings
public struct DatabaseSettings: Sendable, Equatable {
    /// PostgreSQL server hostname.
    @Setting(validate: .nonEmpty)
    public var host: String = "localhost"

    /// PostgreSQL TCP port.
    @Setting(validate: .range(1...65535))
    public var port: Int = 5432

    /// Database role password (`op://`, `keychain://`, or `.env`).
    @SecretSetting
    public var password: Secret<String>
}

@Settings(
    envPrefix: "SERVICE_",
    envNestedDelimiter: "__",
    dotEnvFiles: [".env", ".env.local"],
    projectConfigFiles: [".service.json"],
    xdgAppName: "my-service",
    secretsDirectory: "/run/secrets",
    extraKeys: .forbid
)
public struct ServiceSettings: Sendable, Equatable {
    /// Public base URL advertised in callbacks.
    @Setting(validate: .url(allowedSchemes: ["https"]))
    public var publicURL: URL

    /// Minimum structured log level.
    @Setting
    public var logLevel: LogLevel = .info

    /// Allowed CORS origins parsed from JSON arrays or comma-separated strings.
    @Setting(envListStrategy: .jsonOrCommaSeparated)
    public var corsOrigins: [String] = []

    /// Request timeout (supports `"30s"`, `"500ms"`, `"2m"`).
    @Setting
    public var requestTimeout: Duration = .seconds(30)

    /// Nested PostgreSQL connection settings.
    @NestedSettings
    public var database: DatabaseSettings
}
```

> Tip: In macOS or iOS application targets that `import SwiftUI`, use `@Rigged` instead of `@Settings` to avoid colliding with `SwiftUI.Settings`. Both macros synthesize identical conformances and APIs.

## Understanding the 8-Layer Precedence Cascade

When you call `ServiceSettings.load(...)`, Rigging evaluates sources from highest priority to lowest priority:

| Priority | Layer | Example Origin |
| :--- | :--- | :--- |
| **1 (Highest)** | Explicit Init & CLI Overrides | `--database-port 5433` or `SettingOverride` |
| **2** | Process Environment | `SERVICE_DATABASE__PORT=5433` |
| **3** | `.env` File Cascade | `.env`, overridden by `.env.local` |
| **4** | Secrets Directory | `/run/secrets/service_database__password` |
| **5** | Project Configuration File | `.service.json` discovered upward to `.git` |
| **6** | User Configuration File | `~/.config/my-service/config.json` |
| **7** | Managed Policy (macOS MDM) | `CFPreferencesCopyAppValue` managed domain |
| **8 (Lowest)** | Swift Default Value | `public var port: Int = 5432` |

### Upward Repository Discovery and Profiles

When `projectConfigFiles: [".service.json"]` is configured, Rigging walks upward from `workingDirectory` toward the nearest `.git` directory boundary (or filesystem root) so invoking a CLI from a nested subdirectory (`ios-app/Sources`) automatically discovers the repository root configuration.

Configuration files can also define named `profiles` overlays:

```json
{
  "logLevel": "info",
  "database": {
    "host": "db.internal",
    "password": "op://Infra/Postgres/password"
  },
  "profiles": {
    "staging": {
      "logLevel": "debug",
      "database": {
        "host": "staging-db.internal"
      }
    }
  }
}
```

## Loading Settings and Handling Validation Errors

Register external secret providers once on your settings type via `defaultSecretProviders` (so `load()`, `load(cliArguments:)`, and `ConfigSubcommand` all share them), or pass `secretProviders:` directly to `load(...)`:

```swift
import Rigging
import RiggingKeychain
import RiggingOnePassword

extension ServiceSettings {
    public static var defaultSecretProviders: [any SecretProvider] {
        [.file(), .env(), .onePassword(), .keychain()]
    }
}

do {
    let settings = try await ServiceSettings.load()
    print("Connected to \(settings.database.host):\(settings.database.port)")
} catch let error as SettingsValidationError {
    FileHandle.standardError.write(Data((error.description + "\n").utf8))
    exit(error.exitCode)
}
```

Rigging accumulates *every* missing key, invalid value, forbidden extra key, secret provider failure, and cross-field check into a single `SettingsValidationError` with deterministic process exit codes:

- **`2`**: Missing required setting, type decoding failure, validator rejection, or cross-field error.
- **`4`**: Unsafe secret hygiene (for example plaintext secret committed in project config or world-readable `0644` key file).
- **`6`**: External secret provider authentication, missing vault item, or binary execution failure.

## Cross-Field Model Validation

Implement `static func validate(_ settings: Self) -> [ValidationIssue]` on any `@Settings` struct to enforce invariants spanning multiple properties or nested groups:

```swift
extension ServiceSettings {
    public static func validate(_ settings: Self) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        if settings.publicURL.host() == "localhost" && settings.logLevel == .error {
            issues.append(
                ValidationIssue(
                    path: ["logLevel"],
                    message: "Localhost deployments must use debug, info, or warn logging."
                )
            )
        }
        return issues
    }
}
```
