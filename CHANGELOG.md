# Changelog

All notable changes to `Rigging` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-11-24

### Added

- **`RiggingCore`, `Rigging`, & `RiggingArgumentParser`:** Add `RiggedSettings.defaultSecretProviders` and `RiggedSettings.makeDefaultContext()` so `@Settings` / `@Rigged` models can register external secret providers (such as `.onePassword()` and `.keychain()`) once and have `load()`, `load(cliArguments:)`, `SettingsWatcher`, and turnkey `ConfigSubcommand` (`config show`, `config doctor`) use them automatically.

### Changed

- **Licensing & Governance:** Update `LICENSE` copyright to Peth Pty Ltd, add a direct maintainer contact to `CODE_OF_CONDUCT.md`, and update `SECURITY.md` supported versions to `0.3.x`.
- **Documentation & Positioning:** Refine positioning across `README.md`, DocC catalogs, and `docs/SPECIFICATION.md` to emphasize Rigging's primary role for Swift CLIs, macOS developer/automation tools, and Swift Server services alongside `apple/swift-configuration` and `swift-argument-parser`; fix exit-code and API references in `RiggingCore.md`, `CONTRIBUTING.md`, and `SettingsProtocol.swift`; replace raw Mermaid syntax in `Rigging.md` with a DocC-native diagram for Swift Package Index hosting.

## [0.2.0] - 2026-11-20

### Added

- **`RiggingCore`:** Add `SecretResolutionError.rateLimited(scheme:message:retryAfter:remediation:)` (`exitCode == 6`) and structured `ValidationIssue.isRateLimited` / `ValidationIssue.retryAfter` metadata (also surfaced in `SettingsValidationError.jsonPayload()`) ([#4](https://github.com/SamPetherbridge/Rigging/issues/4)).

### Fixed

- **`RiggingOnePassword`:** Classify 1Password CLI rate-limit responses (`op inject` / `op` stderr) and 1Password Connect HTTP `429` responses (`Retry-After` delta-seconds) as `SecretResolutionError.rateLimited` without echoing `stderr` or response bodies ([#4](https://github.com/SamPetherbridge/Rigging/issues/4)).
- **`RiggingCore` & `RiggingOnePassword`:** Preserve literal spaces in `OnePasswordSecretReference.opReadURI` so `op inject` and `op read` accept space-containing vault, item, section, and field names without `%20` percent-encoding errors, while keeping 1Password Connect HTTP path encoding separate and rejecting CLI delimiter/template-breaking characters ([#5](https://github.com/SamPetherbridge/Rigging/issues/5)).

## [0.1.0] - 2026-11-16

### Added

- **`Rigging` & `RiggingMacros`:**
  - `@Settings` and `@Rigged` (SwiftUI-safe alias) attached macros synthesizing multi-source loading, nested `@NestedSettings` composition, `$field` `SettingMetadata<Value>` provenance projections, `ProvenanceReport` generation, and Draft 2020-12 JSON Schema / `.env` / Markdown exporters with zero runtime `Mirror` reflection.
  - `@Setting` and `@SecretSetting` peer macros supporting `aliases` (`.env`, `.configPath`, `.cli`), typed `SettingValidator<T>` rules, `SettingTransform<T>` and `SecretTransform` pipelines, doc-comment extraction, and compile-time diagnostics.
- **`RiggingCore` (Zero External Dependencies):**
  - Deterministic 8-layer configuration cascade (`InitSource`, `EnvironmentSource`, `DotEnvSource`, `SecretsDirSource`, `ProjectConfigSource`, `UserConfigSource`, `ManagedPreferencesSource`, and Swift defaults) with full winning and shadowed `SettingOrigin` provenance.
  - RFC-compatible `.env` parser supporting `export`, single/double/unquoted strings, multiline PEM blocks, `#` comments, `${VAR}` / `${VAR:-default}` / `${VAR-default}` interpolation, and exact 1-based line tracking.
  - Upward project config discovery (stopping inclusively at `.git` or `$HOME`), XDG / Application Support user config lookup, named `"profiles"` overlays, and `ExtraKeysPolicy` (`.ignore`, `.warn`, `.forbid`, `.allow`).
  - Rich `SettingValueDecodable` support for scalars, flexible `Bool` literals, fixed-width integers, floating-point types, `Decimal`, `UUID`, `URL`, ISO-8601 `Date`, `Data`, `Duration` (`30s`, `500ms`, `5m`, `1h`), `ByteCount` (`512KB`, `10MB`, `2GiB`), case-insensitive `RawRepresentable` enums, and `EnvCollectionStrategy` collections.
  - Leak-proof `Secret<Value>` (`"**********"` across descriptions, `Mirror`, and default `Encodable`), `Synchronization.Mutex`-backed `DiagnosticRedactor`, atomic `0700`/`0600` `withEphemeralFile` materializer with zero-overwrite cleanup, two-phase batched `SecretResolver` with TTL `SecretResolutionCache`, `FileSecretProvider` (`0600` check), and `IndirectEnvProvider`.
  - Multi-issue `SettingsValidationError` aggregation (`LocalizedError` + deterministic JSON payload) with exit code taxonomy (`2` validation/missing, `4` unsafe secret storage, `6` external provider failure) and `SettingsWatcher` live reloader (`SIGHUP` + file polling).
- **Secret Provider Modules:**
  - `RiggingOnePassword`: Single-pass `op inject` batch resolution over in-memory pipes with 128-bit cryptographic boundary nonces, OTP & document support, Service Account & `--account` routing, and 1Password Connect REST API support (`FoundationNetworking` compatible on Linux).
  - `RiggingKeychain`: Direct in-process `Security.framework` `SecItemCopyMatching` lookups for generic and internet passwords (`accessGroup`, `synchronizable`).
  - `RiggingBitwarden`: Bitwarden Secrets Manager (`bws://`) and Vault CLI (`bw://`) batch resolution.
  - `RiggingUnixPass`: `pass` (`pass://` line, `#full`, `#line:N`, and `#key` metadata extraction) and `sops` (`sops://` in-memory RFC 6901 JSON Pointer resolution).
- **Ecosystem & Format Modules:**
  - `RiggingArgumentParser`: Non-clobbering `ParsableArguments` / `RiggingCLIOptions` bridge (omitting unset `nil` optionals) and turnkey `ConfigSubcommand<Settings>` (`config show`, `config doctor`, `config schema`, `config init`).
  - `RiggingSwiftConfiguration`: Bidirectional adapter (`SwiftConfigurationSource` and `asConfigProvider()` / `asConfigReader()`) for `apple/swift-configuration` preserving `isSecret: true` on all `@SecretSetting` fields.
  - `RiggingTOML`: Zero-dependency pure-Swift TOML v1.0 parser and `TOMLProjectConfigSource` / `TOMLUserConfigSource`.
  - `RiggingYAML`: `Yams`-backed `YAMLFileSource`, `YAMLProjectConfigSource`, and `YAMLUserConfigSource` with `<<` merge-key and `profiles` support.
  - `RiggingTesting`: Hermetic `SettingsContext.inMemory(...)`, `InMemoryFileSystem`, `MockOnePasswordProvider`, `MockKeychainProvider`, `MockSubprocessRunner`, and `TestFixtures`.
- **Documentation & Tooling:**
  - Multi-module Apple DocC catalogs across all 11 library products with Swift Package Index (`.spi.yml`) configuration and `swift-docc-plugin` integration.

[Unreleased]: https://github.com/SamPetherbridge/Rigging/compare/0.3.0...HEAD
[0.3.0]: https://github.com/SamPetherbridge/Rigging/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/SamPetherbridge/Rigging/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/SamPetherbridge/Rigging/releases/tag/0.1.0
