# ``RiggingCore``

Load, merge, resolve secrets, validate, and audit typed Swift settings with zero external dependencies.

## Overview

`RiggingCore` is the zero-dependency runtime engine underlying Rigging. While applications typically declare models with the `@Settings`, `@Setting`, `@SecretSetting`, and `@NestedSettings` macros from the `Rigging` umbrella module, `RiggingCore` provides every protocol, configuration source, secret URI parser, redactor, validator, schema exporter, and live-reload coordinator.

### Deterministic Source Precedence & Provenance

``SettingsLoader`` merges configuration layers from highest to lowest priority using ``DefaultSources``:

1. ``InitSource`` — explicit CLI flag and programmatic ``SettingOverride`` values
2. ``EnvironmentSource`` — prefixed and nested process environment variables
3. ``DotEnvSource`` — multi-file `.env` cascading with `${VAR}` interpolation
4. ``SecretsDirSource`` — `/run/secrets` container-mounted secret files
5. ``ProjectConfigSource`` — workspace JSON and Apple plist files with `profiles.<name>` overlays
6. ``UserConfigSource`` — XDG (`~/.config/<app>/`) and `~/Library/Application Support/<app>/` files
7. ``ManagedPreferencesSource`` — Apple `CFPreferences` / MDM managed policies

Every winning leaf value preserves its exact ``SettingOrigin`` alongside any lower-precedence origins it shadowed inside ``ProvenanceReport``.

### Batched Secret Resolution & Leak-Proof Redaction

Secret fields are wrapped in ``Secret``, which redacts `description`, `debugDescription`, `Mirror` reflection, and default `Encodable` output while exposing raw material only through explicit ``Secret/expose()``, ``Secret/withExposedUTF8(_:)``, or `withExposedBytes(_:)` calls. During loading, ``SettingsLoader`` gathers every secret reference across root and nested groups and executes a single deduplicated ``SecretResolver`` batch pass per ``SecretProvider``. Resolved payloads are automatically registered with ``DiagnosticRedactor`` so validation errors and logs never leak sensitive bytes, and `Secret.withEphemeralFile(prefix:suffix:permissions:_:)` materializes `0600` files for legacy CLIs before zero-wiping and unlinking them on scope exit.

### Exhaustive Validation & Schema Export

Rather than failing on the first missing variable, ``SettingsLoader`` collects every missing, malformed, unknown-key, and secret-provider failure into a single ``SettingsValidationError`` with `sysexits.h`-compatible exit codes (`78` for configuration errors, `69` for unavailable external providers) and `LocalizedError` formatting. Static ``SettingFieldDescriptor`` trees also drive ``JSONSchemaExporter`` and ``DotEnvExporter`` without runtime reflection.

## Topics

### Core Protocols & Context

- ``RiggedSettings``
- ``RiggedNestedSettings``
- ``SettingsConfiguration``
- ``SettingsContext``
- ``SettingsLoader``
- ``SettingOrigin``
- ``SettingAlias``
- ``SettingOverride``
- ``ExtraKeysPolicy``
- ``EnvCollectionStrategy``
- ``SettingMetadata``
- ``ProvenanceEntry``
- ``ProvenanceReport``
- ``FileSystem``
- ``LocalFileSystem``
- ``SubprocessRunner``
- ``ProcessSubprocessRunner``
- ``SubprocessResult``
- ``SubprocessSecurityError``

### Configuration Tree & Value Decoding

- ``RawConfigTree``
- ``RawNode``
- ``RawValue``
- ``SettingValueDecodable``
- ``ValueDecodingContext``
- ``ValueDecodingError``
- ``ByteCount``

### Built-In Configuration Sources

- ``SettingsSource``
- ``DefaultSources``
- ``InitSource``
- ``EnvironmentSource``
- ``DotEnvSource``
- ``DotEnvParser``
- ``DotEnvEntry``
- ``DotEnvParseError``
- ``SecretsDirSource``
- ``JSONFileSource``
- ``JSONSourceOriginStyle``
- ``ProjectConfigSource``
- ``UserConfigSource``
- ``PlistFileSource``
- ``ConfigFileParseError``
- ``ManagedPreferencesSource``

### Secrets & Redaction

- ``Secret``
- ``SecretEncodingPolicy``
- ``DiagnosticRedactor``
- ``SecretProvider``
- ``SecretResolver``
- ``SecretResolutionCache``
- ``SecretResolutionRequest``
- ``ResolvedSecret``
- ``SecretBatchResolutionResult``
- ``SecretBatchPartialFailureError``
- ``SecretResolutionError``
- ``SecretTransform``
- ``FileSecretProvider``
- ``IndirectEnvProvider``

### Secret URI References

- ``SecretReference``
- ``SecretReferenceError``
- ``SecretQueryItem``
- ``OnePasswordSecretReference``
- ``KeychainSecretReference``
- ``BitwardenSecretsManagerReference``
- ``BitwardenVaultReference``
- ``PassSecretReference``
- ``SopsSecretReference``
- ``FileSecretReference``
- ``EnvSecretReference``
- ``CustomSecretReference``

### Ephemeral Secret Files

- ``EphemeralSecretFileError``

### Validation & Diagnostics

- ``SettingValidator``
- ``ValidationIssue``
- ``ValidationIssueKind``
- ``SettingsValidationError``

### Schema & Template Exporters

- ``SettingFieldDescriptor``
- ``JSONSchemaFieldType``
- ``JSONSchemaExporter``
- ``DotEnvExporter``

### Live Reloading

- ``SettingsWatcher``
