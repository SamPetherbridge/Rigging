# Rigging

Declarative, multi-source settings, secret-reference resolution, and configuration provenance for Swift 6 — bringing full [`pydantic-settings`](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) ergonomics to Swift CLIs, macOS developer tools, and Swift Server services.

---

## Highlights

- **Declarative `@Settings` & `@Rigged` Macros:** Synthesizes async multi-source loading, nested models (`@NestedSettings`), exhaustive multi-issue validation, `$field` provenance accessors, Draft 2020-12 JSON Schema export, and commented `.env` templates (`@Rigged` avoids symbol collisions with `SwiftUI.Settings`).
- **Two-Phase Batched Secret Engine:** Resolves `op://` (1Password CLI & Connect), `keychain://` (native `Security.framework`), `bws://` / `bw://` (Bitwarden), `pass://`, `sops://`, `file://` / `@~/path`, and `env://` references in a single deduplicated pass — unlocking 1Password once over `stdin`/`stdout` pipes with zero plaintext temp files.
- **Defense-in-Depth `Secret<Value>`:** Redacts `"**********"` across `String(describing:)`, `debugDescription`, `Mirror`/`dump`, and `Encodable`; scrubs resolved secrets from subprocess error logs via `DiagnosticRedactor`; materializes `0700`/`0600` ephemeral files via `withEphemeralFile` and zeroes bytes on exit; and blocks accidental literal secrets in git-tracked project configs (exit code `4`).
- **First-Class Provenance (`$field`):** Inspect `settings.$readOnly.source` and `settings.$readOnly.overriddenSources` to see which CLI flag, environment variable, `.env` line, profile overlay, or secret provider won — and which lower-priority sources were shadowed.
- **Ecosystem Bridges:**
  - `RiggingArgumentParser`: Zero-boilerplate `ParsableArguments` binding (omitting unset `nil` optionals so CLI defaults never clobber env vars or config files) plus a drop-in `ConfigSubcommand<MySettings>` (`config show`, `config doctor`, `config schema`, `config init`).
  - `RiggingSwiftConfiguration`: Bidirectional adapter for [`apple/swift-configuration`](https://github.com/apple/swift-configuration) (`SwiftConfigurationSource` and `settings.asConfigReader()`, preserving `isSecret: true` for `AccessLogger` redaction).
  - `RiggingTOML` & `RiggingYAML`: Pure-Swift TOML v1.0 and `Yams`-backed YAML project/user config sources.
  - `RiggingTesting`: Hermetic, zero-I/O `SettingsContext.inMemory(...)`, `InMemoryFileSystem`, `MockOnePasswordProvider`, `MockKeychainProvider`, and `MockSubprocessRunner`.

---

## Installation

Add `Rigging` to your `Package.swift` (Swift 6.2+, macOS 15+ / iOS 18+ / Linux):

```swift
dependencies: [
    .package(url: "https://github.com/ppl/Rigging.git", from: "1.0.0"),
],
targets: [
    .executableTarget(
        name: "my-cli",
        dependencies: [
            .product(name: "Rigging", package: "Rigging"),
            .product(name: "RiggingOnePassword", package: "Rigging"),
            .product(name: "RiggingKeychain", package: "Rigging"),
            .product(name: "RiggingArgumentParser", package: "Rigging"),
        ]
    ),
    .testTarget(
        name: "MyCLITests",
        dependencies: [
            "my-cli",
            .product(name: "RiggingTesting", package: "Rigging"),
        ]
    ),
]
```

### Modular Products

| Product | Dependencies | Purpose |
|---|---|---|
| `Rigging` | `RiggingCore`, `RiggingMacros` | `@Settings`, `@Rigged`, `@Setting`, `@SecretSetting`, `@NestedSettings` |
| `RiggingCore` | Foundation only | Runtime cascade, `.env` / JSON / plist / MDM / secrets-dir sources, validators, exporters |
| `RiggingOnePassword` | `RiggingCore` | Batched `op://` resolution (`op inject` pipe & 1Password Connect REST API) |
| `RiggingKeychain` | `RiggingCore` | Direct `Security.framework` `keychain://` lookups (zero subprocesses) |
| `RiggingBitwarden` | `RiggingCore` | `bws://` (Secrets Manager) & `bw://` CLI secret resolution |
| `RiggingUnixPass` | `RiggingCore` | `pass://` (`~/.password-store`) & `sops://` (`age`/KMS JSON pointer) resolution |
| `RiggingTOML` | `RiggingCore` | Pure-Swift RFC-compliant TOML v1.0 parser & project/user sources |
| `RiggingYAML` | `RiggingCore`, `Yams` | YAML project/user config sources with `profiles` & merge-key support |
| `RiggingArgumentParser` | `RiggingCore`, `ArgumentParser` | `ParsableArguments` bridge & turnkey `ConfigSubcommand` |
| `RiggingSwiftConfiguration` | `RiggingCore`, `Configuration` | Bidirectional `apple/swift-configuration` provider & reader bridge |
| `RiggingTesting` | `RiggingCore` | Hermetic in-memory filesystem, context builders, and mock secret providers |

---

## Quick Start (`@Settings` & `@Rigged`)

```swift
import Foundation
import Rigging
import RiggingKeychain
import RiggingOnePassword

@Settings
struct SigningSettings: Sendable {
    @Setting(help: "Apple Developer Team ID", examples: ["ABCDE12345"])
    var teamId: String?

    @Setting(help: "Enable automatic signing")
    var automaticSigning: Bool = true
}

@Settings(
    envPrefix: "ASC_",
    envNestedDelimiter: "__",
    dotEnvFiles: [".env", ".env.local"],
    projectConfigFiles: [".asc.json"],
    xdgAppName: "asc",
    extraKeys: .forbid
)
struct ASCSettings: Sendable {
    @Setting(
        aliases: [.env("APP_STORE_CONNECT_KEY_ID")],
        validate: [.nonEmpty, .count(10)],
        help: "10-character App Store Connect Key ID"
    )
    var keyId: String

    @Setting(validate: .uuid, help: "App Store Connect Issuer ID")
    var issuerId: String

    @SecretSetting(
        transforms: [.expandFileReference, .decodeBase64IfPrefixed, .normalizePEM],
        help: "PKCS#8 (.p8) private key or secret URI (op://, keychain://, @~/AuthKey.p8)"
    )
    var privateKey: Secret<String>

    @Setting(help: "Enforce read-only API mode")
    var readOnly: Bool = false

    @NestedSettings
    var signing: SigningSettings = SigningSettings()

    static func validate(_ s: Self) -> [ValidationIssue] {
        if !s.readOnly && s.signing.teamId == nil {
            return [
                ValidationIssue(
                    path: ["signing", "teamId"],
                    message: "signing.teamId is required when readOnly is false."
                ),
            ]
        }
        return []
    }
}
```

> **SwiftUI Apps:** Import `Rigging` alongside `SwiftUI` and annotate models with `@Rigged(...)` instead of `@Settings(...)` to avoid colliding with `SwiftUI.Settings`.

Load settings asynchronously with batched secret resolution:

```swift
let settings = try await ASCSettings.load(
    secretProviders: [
        .onePassword(),
        .keychain(servicePrefix: "com.example.asc"),
    ]
)
```

---

## `pydantic-settings` Parity & Source Precedence

By default, `Rigging` merges sources from highest priority to lowest (customizable via `static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource]`):

1. **CLI & Programmatic Overrides (`InitSource` / `ArgumentParserSource`)** — Omitting `nil` optionals so unset flags never clobber lower layers.
2. **Environment Variables (`EnvironmentSource`)** — Honors `envPrefix`, `envNestedDelimiter` (`ASC_SIGNING__TEAM_ID`), `envIgnoreEmpty`, `envNullStrings` (`null`, `none`, `~`), aliases, and `EnvCollectionStrategy` (`.jsonOrCommaSeparated`, `.jsonOnly`, `.separator`, `.noDecode`).
3. **Dotenv Files (`DotEnvSource`)** — Supports `export`, single/double/unquoted multiline strings, `#` comments, `${VAR:-default}` variable expansion, and `.env` → `.env.local` layering with exact line numbers.
4. **Secrets Directory (`SecretsDirSource`)** — Docker/Kubernetes `/run/secrets` volume mounts (`secretsNestedSubdir`, dotfile skipping, trailing newline trimming).
5. **Project Config (`ProjectConfigSource`, `TOMLProjectConfigSource`, `YAMLProjectConfigSource`)** — Walks upward from `workingDirectory`, stopping inclusively at `.git` or `$HOME`, overlaying `"profiles": { "<active>": { ... } }` (`--profile` or `<PREFIX>PROFILE`), and stripping `"$schema"` and `"profiles"`.
6. **User Config (`UserConfigSource`, `TOMLUserConfigSource`, `YAMLUserConfigSource`)** — Reads `$XDG_CONFIG_HOME/<app>/config.{json,toml,yaml,yml}` (`~/.config/<app>/...`) with macOS `~/Library/Application Support/<app>/` fallback.
7. **Managed Preferences (`ManagedPreferencesSource`)** — macOS `CFPreferences` / MDM enterprise policy domains.
8. **Swift Property Defaults** — Declared inline on struct properties.

Unlike `Codable` (which halts on the first `DecodingError`), `Rigging` evaluates **all** fields, nested models, secret guards, and `validate(_:)` rules in one pass, throwing a single `SettingsValidationError` with deterministic CLI exit codes:
- **`2`**: Missing required setting, invalid value, unknown key (`extraKeys: .forbid`), or cross-field failure
- **`4`**: Unsafe secret permissions (`0644` key file, world-writable binary) or forbidden plaintext secret in a git-tracked project config
- **`6`**: External secret provider failure (missing Keychain item, expired 1Password session)

---

## Batched Secret References & Leak-Proof `Secret<T>`

Any `@SecretSetting` (or `@Setting(resolveSecrets: true)`) transparently dereferences secret URIs across all registered providers:

| Reference URI | Provider | Mechanism |
|---|---|---|
| `op://Vault/Item/[Section/]field` | `OnePasswordProvider` (`.onePassword()`) | Single batched `op inject` over in-memory pipes or Connect REST API |
| `keychain://service/account` | `KeychainProvider` (`.keychain()`) | In-process `SecItemCopyMatching` |
| `bws://<uuid>` / `bw://<id>/field` | `BitwardenProvider` (`.bitwarden()`) | Bitwarden Secrets Manager (`bws`) or `bw` CLI |
| `pass://team/prod/api-key` | `UnixPassProvider` (`.unixPass()`) | `pass show` (`~/.password-store`) |
| `sops://secrets.enc.json#/db/pass` | `SOPSProvider` (`.sops()`) | `sops --decrypt` + in-memory RFC 6901 JSON Pointer |
| `file:///abs/path` or `@~/.keys/Auth.p8` | `FileSecretProvider` (built-in) | Enforces `0600` POSIX permissions prior to reading |
| `env://PROD_API_KEY` | `IndirectEnvProvider` (built-in) | Indirection from safe config files to environment variables |

### Safe Secret Consumption & `withEphemeralFile`

```swift
// Explicit extraction (easy to audit in code review):
let rawPEM: String = settings.privateKey.expose()

// Scoped UTF-8 byte buffer access:
let token = try settings.privateKey.withExposedUTF8 { buffer in
    try signJWT(pemBytes: buffer)
}

// Atomic 0700 directory + 0600 file materialization for legacy CLI tools (xcodebuild, openssl, ssh):
// Automatically overwrites bytes with zeros and unlinks file + directory when scope exits!
try await settings.privateKey.withEphemeralFile(prefix: "authkey-", suffix: ".p8") { keyURL in
    try await runXcodebuild(authenticationKeyPath: keyURL.path(percentEncoded: false))
}

// Scrub subprocess stderr before logging so resolved secrets never leak to CI output:
let safeStderr = settings.redactor.scrub(rawProcessStderr)
```

---

## `$field` Provenance Inspection

Every `@Setting` and `@SecretSetting` synthesizes a `$field` projected `SettingMetadata<Value>`:

```swift
print(settings.$keyId.source)
// environment ASC_KEY_ID

print(settings.$keyId.overriddenSources)
// [project config /repo/.asc.json → keyId]

print(settings.$privateKey.valueSummary)
// **********

print(settings.provenanceReport().formattedTable())
```

---

## `RiggingArgumentParser`

Bind `swift-argument-parser` options directly to `@Settings` and mount a turnkey `config` subcommand group:

```swift
import ArgumentParser
import Rigging
import RiggingArgumentParser

struct GlobalCLIOptions: ParsableArguments {
    @Option(name: .long) var keyId: String?
    @Option(name: .long) var profile: String?
    @Flag(name: .long, inversion: .prefixedNo) var readOnly: Bool? // nil when omitted -> never clobbers env!
}

@main
struct MyCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "asc",
        subcommands: [
            StatusCommand.self,
            ConfigSubcommand<ASCSettings>.self,
        ]
    )
}

struct StatusCommand: AsyncParsableCommand {
    @OptionGroup var globals: GlobalCLIOptions

    mutating func run() async throws {
        let settings = try await ASCSettings.load(cliArguments: globals)
        print("Key ID: \(settings.keyId), read-only: \(settings.readOnly)")
    }
}
```

Mounting `ConfigSubcommand<ASCSettings>.self` provides four operational subcommands out of the box:
- `asc config show [--json] [--profile <name>]` — Displays resolved values (`**********` for secrets) with exact winning and overridden `SettingOrigin`s.
- `asc config doctor [--json] [--profile <name>]` — Validates config syntax, `0600` file permissions, secret provider connectivity, and unknown/deprecated keys with deterministic exit codes (`0`, `2`, `4`, `6`).
- `asc config schema [--compact]` — Exports Draft 2020-12 JSON Schema for editor `$schema` autocomplete.
- `asc config init [--dotenv | --json]` — Scaffolds a commented `.env` file or git-safe starter JSON config.

---

## `RiggingSwiftConfiguration` (`apple/swift-configuration`)

Bridge `Rigging` bidirectionally with `apple/swift-configuration` (`1.0+`):

```swift
import Configuration
import Rigging
import RiggingOnePassword
import RiggingSwiftConfiguration

// Direction B: Vend validated, secret-resolved Rigging settings as a standard Apple ConfigReader.
// Every @SecretSetting is flagged with `isSecret: true` so AccessLogger redacts secrets in traces!
let settings = try await ASCSettings.load(secretProviders: [.onePassword()])
let reader: ConfigReader = settings.asConfigReader()
let teamId = reader.scoped(to: "signing").string(forKey: "team-id")

// Direction A: Consume any upstream ConfigProvider / ConfigReader inside customizeSources(_:):
// SwiftConfigurationSource(provider: upstreamProvider, for: Self.self)
```

---

## Hermetic Testing with `RiggingTesting`

Write fast, deterministic, parallel `Swift Testing` suites with zero filesystem, Keychain, or subprocess side effects:

```swift
import Rigging
import RiggingTesting
import Testing

@Test func cliReadOnlyBeatsEnvironment() async throws {
    let mockOP = MockOnePasswordProvider(secrets: [
        "op://Personal/ASC/key": TestFixtures.sampleP8PEM,
    ])

    let context = SettingsContext.inMemory(
        cli: ["readOnly": true],
        environment: [
            "ASC_KEY_ID": "ABC1234567",
            "ASC_ISSUER_ID": "00000000-0000-0000-0000-000000000001",
            "ASC_READ_ONLY": "false",
        ],
        files: [
            "/repo/.asc.json": #"{"privateKey": "op://Personal/ASC/key"}"#,
        ],
        directories: ["/repo/.git"],
        secretProviders: [mockOP]
    )

    let settings = try await ASCSettings.load(context: context)
    #expect(settings.readOnly == true)
    #expect(settings.$readOnly.source == .cliArgument(flag: "--read-only"))
    #expect(await mockOP.invocationCount == 1)
}
```
