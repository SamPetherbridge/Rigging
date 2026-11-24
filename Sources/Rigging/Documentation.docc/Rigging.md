# ``Rigging``

Strongly typed, multi-source configuration, batched leak-proof secrets, and per-field provenance for Swift 6.

## Overview

`Rigging` is the declarative application-level settings and secret-hygiene layer for **Swift CLIs, macOS developer & automation tools, and Swift Server services** (with full Apple-platform, SwiftUI `@Rigged`, and macOS MDM support). Inspired by Python's `pydantic-settings` and built to complement `apple/swift-configuration` and `swift-argument-parser`, Rigging turns plain Swift structs annotated with ``Settings(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)`` (or ``Rigged(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)`` in SwiftUI targets) into compile-time multi-layer configuration models with batched secret resolution, `$field` provenance inspection, and JSON Schema / `.env` documentation generation.

`Rigging` automatically re-exports `RiggingCore`, so a single `import Rigging` provides every macro, configuration source, validator, secret container, and provenance type needed to define and load configuration models.

### Architecture & 8-Layer Cascade

```text
  Highest Priority
  ┌─────────────────────────────────────────────────────────────────────┐
  │ 1. CLI Flags & Init Overrides  (--port, SettingOverride)            │
  │ 2. Process Environment         (APP_DATABASE__PORT)                 │
  │ 3. .env File Cascade           (.env → .env.local, 1-based lines)   │
  │ 4. Secrets Directory           (/run/secrets/*)                     │
  │ 5. Project Config              (.app.json upward to .git + profile) │
  │ 6. User Config                 (~/.config/app/config.* + profile)   │
  │ 7. Managed Policy              (macOS MDM CFPreferences)            │
  │ 8. Swift Default Values        (var port: Int = 8080)               │
  └──────────────────────────────────┬──────────────────────────────────┘
                                     ▼
          Merged RawConfigTree (Winning Origin + Shadowed Origins)
                                     │
                                     ▼
        Phase 1: Collect & Deduplicate @SecretSetting URIs Across Tree
                                     │
                                     ▼
        Phase 2: Single-Batch SecretProvider Dispatch (1 Biometric Unlock)
                 (op://, keychain://, bws://, bw://, pass://, sops://)
                                     │
                                     ▼
      Typed Decoding + Transforms + Exhaustive Validation + $field Provenance
```

### Quick Example

```swift
import Foundation
import Rigging

@Settings(
    envPrefix: "ASC_",
    dotEnvFiles: [".env", ".env.local"],
    projectConfigFiles: [".asc.json"],
    xdgAppName: "asc",
    extraKeys: .forbid
)
public struct ASCSettings: Sendable, Equatable {
    /// 10-character App Store Connect Key ID.
    @Setting(
        aliases: [.configPath(["auth", "keyId"])],
        validate: .regex(#"^[A-Z0-9]{10}$"#)
    )
    public var keyId: String

    /// App Store Connect Issuer UUID.
    @Setting(aliases: [.configPath(["auth", "issuerId"])])
    public var issuerId: UUID

    /// PKCS#8 `.p8` private key (`op://`, `keychain://`, or `@~/.asc/AuthKey.p8`).
    @SecretSetting(
        aliases: [.configPath(["auth", "privateKey"])],
        transforms: [
            .expandFileReference(requirePermissions: 0o600),
            .decodeBase64IfPrefixed,
            .normalizePEM,
        ]
    )
    public var privateKey: Secret<String>

    /// Request timeout duration.
    @Setting
    public var timeout: Duration = .seconds(30)
}
```

### Ecosystem Modules

Keep binary size and dependency graphs minimal by importing only the adapter targets your executable needs:

- **`Rigging`** *(this module)*: Re-exports `RiggingCore` and provides `@Settings`, `@Rigged`, `@Setting`, `@SecretSetting`, `@NestedSettings`, and ``SettingTransform``.
- **`RiggingOnePassword`**: Batched `op inject` CLI and 1Password Connect REST secret provider (`op://`).
- **`RiggingKeychain`**: In-process Apple `Security.framework` Keychain provider (`keychain://`).
- **`RiggingBitwarden`**: Bitwarden Secrets Manager (`bws://`) and Vault CLI (`bw://`) provider.
- **`RiggingUnixPass`**: GPG-backed Unix `pass` (`pass://`) and Mozilla SOPS (`sops://`) providers.
- **`RiggingTOML`** & **`RiggingYAML`**: Zero-dependency TOML 1.0 and Yams-backed YAML file sources.
- **`RiggingArgumentParser`**: `@OptionGroup` CLI override binding and turnkey `ConfigSubcommand` (`show`, `doctor`, `schema`, `init`).
- **`RiggingSwiftConfiguration`**: Bidirectional adapters for Apple's `swift-configuration` (`ConfigReader` / `ConfigProvider`).
- **`RiggingTesting`**: Hermetic `InMemoryFileSystem`, `MockSubprocessRunner`, and mock secret providers.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:SecretsAndSecurity>
- <doc:ProvenanceAndDebugging>
- <doc:MigratingFromPydanticSettings>

### Model Macros

- ``Settings(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)``
- ``Settings(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:extraKeys:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:)``
- ``Rigged(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)``
- ``Rigged(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:extraKeys:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:)``

### Field & Nested Group Macros

- ``Setting(aliases:envListStrategy:resolveSecrets:help:deprecated:examples:)``
- ``Setting(aliases:envListStrategy:resolveSecrets:deprecated:help:examples:)``
- ``Setting(aliases:validate:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,SettingValidator<String>,_,_,_,_,_)``
- ``Setting(aliases:validate:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,SettingValidator<T>,_,_,_,_,_)``
- ``Setting(aliases:validate:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,[SettingValidator<String>],_,_,_,_,_)``
- ``Setting(aliases:validate:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,[SettingValidator<T>],_,_,_,_,_)``
- ``Setting(aliases:transforms:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,[SettingTransform<String>],_,_,_,_,_)``
- ``Setting(aliases:transforms:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,[SettingTransform<T>],_,_,_,_,_)``
- ``Setting(aliases:transforms:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,SettingTransform<String>,_,_,_,_,_)``
- ``Setting(aliases:transforms:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,SettingTransform<T>,_,_,_,_,_)``
- ``Setting(aliases:validate:transforms:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,SettingValidator<String>,_,_,_,_,_,_)``
- ``Setting(aliases:validate:transforms:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,SettingValidator<T>,_,_,_,_,_,_)``
- ``Setting(aliases:validate:transforms:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,[SettingValidator<String>],_,_,_,_,_,_)``
- ``Setting(aliases:validate:transforms:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,[SettingValidator<T>],_,_,_,_,_,_)``
- ``Setting(aliases:transforms:validate:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,_,SettingValidator<String>,_,_,_,_,_)``
- ``Setting(aliases:transforms:validate:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,_,SettingValidator<T>,_,_,_,_,_)``
- ``Setting(aliases:transforms:validate:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,_,[SettingValidator<String>],_,_,_,_,_)``
- ``Setting(aliases:transforms:validate:envListStrategy:resolveSecrets:help:deprecated:examples:)-(_,_,[SettingValidator<T>],_,_,_,_,_)``
- ``SecretSetting(aliases:transforms:allowLiteralInProjectConfig:help:deprecated:examples:)``
- ``SecretSetting(aliases:transforms:validate:allowLiteralInProjectConfig:help:deprecated:examples:)-(_,_,SettingValidator<String>,_,_,_,_)``
- ``SecretSetting(aliases:transforms:validate:allowLiteralInProjectConfig:help:deprecated:examples:)-(_,_,SettingValidator<T>,_,_,_,_)``
- ``SecretSetting(aliases:transforms:validate:allowLiteralInProjectConfig:help:deprecated:examples:)-(_,_,[SettingValidator<String>],_,_,_,_)``
- ``SecretSetting(aliases:transforms:validate:allowLiteralInProjectConfig:help:deprecated:examples:)-(_,_,[SettingValidator<T>],_,_,_,_)``
- ``SecretSetting(aliases:validate:transforms:allowLiteralInProjectConfig:help:deprecated:examples:)-(_,SettingValidator<String>,_,_,_,_,_)``
- ``SecretSetting(aliases:validate:transforms:allowLiteralInProjectConfig:help:deprecated:examples:)-(_,SettingValidator<T>,_,_,_,_,_)``
- ``SecretSetting(aliases:validate:transforms:allowLiteralInProjectConfig:help:deprecated:examples:)-(_,[SettingValidator<String>],_,_,_,_,_)``
- ``SecretSetting(aliases:validate:transforms:allowLiteralInProjectConfig:help:deprecated:examples:)-(_,[SettingValidator<T>],_,_,_,_,_)``
- ``NestedSettings()``

### Value Transforms

- ``SettingTransform``
