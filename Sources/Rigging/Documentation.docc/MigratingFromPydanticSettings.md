# Migrating from Python pydantic-settings

@Metadata {
    @PageKind(article)
}

Translate Python `pydantic-settings` models, `SettingsConfigDict` options, `AliasChoices`, `SecretStr`, and custom source hooks into idiomatic Swift 6 `Rigging`.

## Overview

If your team builds Python services or CLIs with [`pydantic-settings`](https://docs.pydantic.dev/latest/concepts/pydantic_settings/), Rigging's mental model will feel immediately familiar—while taking full advantage of Swift 6 compile-time macros, `Sendable` value types, native Apple Keychain integration, batched secret manager URIs, and line-level `$field` provenance.

## Concept Mapping Reference

| Python `pydantic-settings` | Swift 6 `Rigging` |
| :--- | :--- |
| `class Settings(BaseSettings):` | `@Settings struct AppSettings: Sendable` (or `@Rigged` in SwiftUI targets) |
| `BaseModel` nested group | `@Settings struct DBSettings` + `@NestedSettings var db: DBSettings` |
| `model_config = SettingsConfigDict(...)` | `@Settings(envPrefix: ..., dotEnvFiles: ..., extraKeys: ...)` |
| `env_prefix="APP_"` | `envPrefix: "APP_"` |
| `env_nested_delimiter="__"` | `envNestedDelimiter: "__"` |
| `env_nested_max_split=1` | `envNestedMaxSplit: 1` |
| `case_sensitive=False` | `caseSensitive: false` |
| `env_ignore_empty=True` | `envIgnoreEmpty: true` |
| `env_parse_none_str="null"` | `envNullStrings: ["null", "none", "~"]` |
| `env_file=(".env", ".env.prod")` | `dotEnvFiles: [".env", ".env.prod"]` |
| `secrets_dir="/run/secrets"` | `secretsDirectory: "/run/secrets"` |
| `secrets_nested_subdir=True` | `secretsNestedSubdir: true` |
| `extra="forbid"` / `"ignore"` / `"allow"` | `extraKeys: .forbid` / `.ignore` / `.allow` / `.warn` |
| `Field(validation_alias=AliasChoices("KEY", AliasPath("a", "b")))` | `@Setting(aliases: [.env("KEY"), .configPath(["a", "b"])])` |
| `SecretStr` / `SecretBytes` | `@SecretSetting var apiKey: Secret<String>` / `Secret<Data>` |
| `secret.get_secret_value()` | `secret.expose()` or `secret.expose { plaintext in ... }` |
| `enable_decoding=False` (`NoDecode`) | `@Setting(envListStrategy: .noDecode)` |
| `@field_validator("host", mode="before")` | `@Setting(transforms: [.trimWhitespace, .lowercased])` |
| `Field(ge=1, le=65535, pattern=r"...")` | `@Setting(validate: .range(1...65535))` / `.regex(#"..."#)` |
| `@model_validator(mode="after")` | `public static func validate(_ settings: Self) -> [ValidationIssue]` |
| `settings_customise_sources(...)` | `public static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource]` |
| `Settings.model_json_schema()` | `AppSettings.jsonSchema()` |
| `CliApp.run(Settings)` | `RiggingArgumentParser` (`@OptionGroup` + `ConfigSubcommand<AppSettings>`) |

## Side-by-Side Example

### Python (`pydantic-settings`)

```python
from pydantic import AliasChoices, AliasPath, BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class DatabaseConfig(BaseModel):
    host: str = "localhost"
    port: int = Field(default=5432, ge=1, le=65535)
    password: SecretStr

class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_nested_delimiter="__",
        env_file=(".env", ".env.local"),
        secrets_dir="/run/secrets",
        extra="forbid",
    )

    api_key: SecretStr = Field(
        validation_alias=AliasChoices("LEGACY_API_KEY", AliasPath("auth", "apiKey"))
    )
    workers: int = Field(default=4, ge=1, le=64)
    tls_enabled: bool = False
    tls_cert_path: str | None = None
    database: DatabaseConfig

    @model_validator(mode="after")
    def verify_tls(self) -> "AppSettings":
        if self.tls_enabled and not self.tls_cert_path:
            raise ValueError("tls_cert_path is required when tls_enabled is True")
        return self
```

### Swift 6 (`Rigging`)

```swift
import Rigging

@Settings
public struct DatabaseConfig: Sendable, Equatable {
    @Setting
    public var host: String = "localhost"

    @Setting(validate: .range(1...65535))
    public var port: Int = 5432

    @SecretSetting
    public var password: Secret<String>
}

@Settings(
    envPrefix: "APP_",
    envNestedDelimiter: "__",
    dotEnvFiles: [".env", ".env.local"],
    secretsDirectory: "/run/secrets",
    extraKeys: .forbid
)
public struct AppSettings: Sendable, Equatable {
    @SecretSetting(
        aliases: [.env("LEGACY_API_KEY"), .configPath(["auth", "apiKey"])]
    )
    public var apiKey: Secret<String>

    @Setting(validate: .range(1...64))
    public var workers: Int = 4

    @Setting
    public var tlsEnabled: Bool = false

    @Setting(transforms: .expandTilde)
    public var tlsCertPath: String?

    @NestedSettings
    public var database: DatabaseConfig

    public static func validate(_ settings: Self) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        if settings.tlsEnabled && settings.tlsCertPath == nil {
            issues.append(
                ValidationIssue(
                    path: ["tlsCertPath"],
                    message: "tlsCertPath is required when tlsEnabled is true"
                )
            )
        }
        return issues
    }
}
```

## Customizing Source Precedence (`settings_customise_sources`)

In `pydantic-settings`, overriding `settings_customise_sources` reorders or injects configuration sources (such as placing TOML or YAML files ahead of `.env`). In Rigging, implement `customizeSources(_:)` on your `@Settings` struct:

```swift
import Rigging
import RiggingTOML
import RiggingYAML

extension AppSettings {
    public static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        [
            defaults.initOverrides,
            defaults.environment,
            defaults.dotEnv,
            defaults.secretsDirectory,
            TOMLFileSource(paths: ["config.toml"]),
            YAMLFileSource(paths: ["config.yaml"]),
            defaults.userConfig,
            defaults.managedPreferences,
        ]
    }
}
```

## Key Differences to Keep in Mind

1. **CamelCase Properties Map Automatically to `SCREAMING_SNAKE_CASE`**: A Swift property named `tlsCertPath` under `envPrefix: "APP_"` automatically reads `APP_TLS_CERT_PATH` in the environment and `"tlsCertPath"` (case-insensitively by default) in JSON/TOML/YAML files.
2. **Asynchronous Loading (`async throws`)**: Unlike `AppSettings()` in Python, `try await AppSettings.load(...)` is `async throws` so external secret managers (`1Password`, `Bitwarden`, `SOPS`, `swift-configuration`) execute cleanly under Swift 6 structured concurrency without blocking thread pools.
3. **Value Semantics (`var` for Defaulted Fields)**: Use `var` (not `let`) on `@Setting` properties that declare an inline default (`public var port: Int = 5432`) so loaded configuration layers can override the default value, and so test suites can mutate copies cleanly with value semantics.
4. **Native External Secret URIs & Provenance**: Any `@SecretSetting` natively understands `op://`, `keychain://`, `bws://`, `bw://`, `pass://`, `sops://`, `file://`, and `env://` references out of the box, and every field exposes `$field.source` and `$field.overriddenSources` at zero runtime reflection cost.
