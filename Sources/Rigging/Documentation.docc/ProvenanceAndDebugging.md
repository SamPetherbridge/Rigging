# Provenance and Operational Debugging

@Metadata {
    @PageKind(article)
}

Inspect exact source origins and shadowed overrides with `$field` projections, `provenanceReport()`, and the turnkey `ConfigSubcommand` CLI suite.

## Overview

When a service misbehaves in staging or on a developer's laptop, the hardest question is rarely *what* a setting's value is—it is **where that value came from** and **which lower-priority configuration file it shadowed**.

Rigging tracks provenance natively across every layer of the configuration tree, preserving line numbers for `.env` entries, JSON/TOML/YAML key paths and active profile names for config files, CLI flag names, and chained `via` origins when a secret URI inside a config file is resolved through an external secret manager.

## Inspecting `$field` Provenance in Swift

Every `@Setting` and `@SecretSetting` property on a `@Settings` or `@Rigged` struct synthesizes a `$property` accessor returning `SettingMetadata<Value>`:

```swift
let settings = try await ServiceSettings.load(
    secretProviders: [FileSecretProvider(), IndirectEnvProvider(), .onePassword()]
)

// Winning source for a scalar field:
print(settings.$logLevel.source)
// e.g. "CLI flag --log-level" or ".env.local:4 (SERVICE_LOG_LEVEL)"

// Lower-priority sources shadowed by the winner:
for shadowed in settings.$logLevel.overriddenSources {
    print("Shadowed: \(shadowed)")
}

// Secret fields preserve full origin lineage while masking the value:
print(settings.database.$password.displayValue) // "**********"
print(settings.database.$password.source)
// "op://Infra/Postgres/password via project config /repo/.service.json → database.password"
```

### Structured `SettingOrigin` Cases

Because `SettingOrigin` is a `Sendable, Equatable, Hashable, Codable` enum, you can pattern-match on provenance programmatically in diagnostics, telemetry, or tests:

- `.cliArgument(flag: "--port")`
- `.initOverride(keyPath: ["port"])`
- `.environment(variable: "SERVICE_PORT")`
- `.dotEnv(path: "/work/.env", line: 12, variable: "SERVICE_PORT")`
- `.secretsDirectory(path: "/run/secrets/db_password")`
- `.projectConfig(path: "/work/.service.json", keyPath: ["database", "port"], profile: "staging")`
- `.userConfig(path: "/Users/alice/.config/my-service/config.json", keyPath: ["port"], profile: nil)`
- `.managedPolicy(domain: "com.example.service", key: "port")`
- `.secretProvider(scheme: "op", referenceRedacted: "op://Infra/DB/password", via: ...)`
- `.customSource(name: "Consul", detail: "kv/service/port")`
- `.defaultValue`

## Generating Full Provenance Reports

Call `provenanceReport()` (or access `.provenance`) on any loaded settings model to obtain a `ProvenanceReport` covering root and nested fields alike:

```swift
let report = settings.provenanceReport()

// Human-readable table (secrets automatically masked as **********)
print(report.formattedTable())

// Look up a specific nested key path
if let dbHost = report["database", "host"] {
    print("\(dbHost.displayValue) came from \(dbHost.source)")
}

// Deterministic sorted-key JSON payload for structured logging or support bundles
let jsonBytes = try report.jsonPayload(prettyPrinted: true)
```

## Turnkey CLI Debugging with `ConfigSubcommand`

If your executable uses `swift-argument-parser`, import `RiggingArgumentParser` and mount `ConfigSubcommand<MySettings>` as a subcommand:

```swift
import ArgumentParser
import Rigging
import RiggingArgumentParser

@main
struct MyServiceCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "my-service",
        subcommands: [
            ServeCommand.self,
            ConfigSubcommand<ServiceSettings>.self,
        ]
    )
}
```

Mounting `ConfigSubcommand<ServiceSettings>` gives operators and developers four production-ready subcommands out of the box:

### 1. `my-service config show`

Displays every resolved setting, its winning `SettingOrigin`, and any shadowed sources, while redacting all `@SecretSetting` values and scrubbing registered secrets via `DiagnosticRedactor`:

```text
$ my-service config show
publicURL = https://api.example.com  [environment SERVICE_PUBLIC_URL]
logLevel = debug  [CLI flag --log-level] (overrides: .env:2 (SERVICE_LOG_LEVEL), default value)
corsOrigins = []  [default value]
requestTimeout = 30.0 seconds  [default value]
database.host = db.internal  [project config /repo/.service.json → database.host] (overrides: default value)
database.port = 5432  [default value]
database.password = **********  [op://Infra/Postgres/password via project config /repo/.service.json → database.password]
```

Pass `--json` for deterministic machine-readable JSON output, or `--profile staging` to preview a specific profile overlay.

### 2. `my-service config doctor`

Performs an end-to-end health audit without exposing secret plaintext:

- Inspects `.env` and `~/.config/<app>/config.*` files for unsafe world-writable POSIX permissions (`0666` / `0664`).
- Verifies all required settings, type conversions, field validators, and cross-field `validate(_:)` rules.
- Verifies connectivity and authentication against configured secret providers (`1Password`, `Keychain`, `Bitwarden`, `pass`, `SOPS`).
- Flags active usage of `@Setting(deprecated: ...)` fields.
- Exits `0` when healthy, `2` on validation issues, `4` on unsafe secret storage, or `6` on secret provider failures (supports `--json` for CI preflight checks).

### 3. `my-service config schema`

Exports a Draft 2020-12 JSON Schema derived from your Swift types, `CaseIterable` enum cases, extracted `///` doc comments, defaults, `profiles` overlays, and `writeOnly: true` / `"x-secret": true` markers—ready to wire into `$schema` for VS Code autocomplete:

```text
$ my-service config schema > .service.schema.json
```

### 4. `my-service config init`

Scaffolds a commented `.env.example` (`--dotenv`, the default) or a starter JSON configuration file (`--json`) using safe secret URI placeholders (`op://Personal/<app>/<field>`) instead of secrets:

```text
$ my-service config init --dotenv > .env.example
$ my-service config init --json > .service.json
```
