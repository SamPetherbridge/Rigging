# Rigging

**Declarative multi-source settings, batched secret references, and configuration provenance for Swift 6.**

`Rigging` brings [`pydantic-settings`](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) ergonomics and defense-in-depth secret hygiene to Swift CLIs, macOS developer tools, iOS/macOS apps, and Swift Server services.

---

## Why Rigging?

Swift already has two great building blocks in this space — [`swift-argument-parser`](https://github.com/apple/swift-argument-parser) for command-line flags and [`apple/swift-configuration`](https://github.com/apple/swift-configuration) for untyped runtime `ConfigReader` lookups — yet production CLIs, developer tools, and services still end up hand-rolling hundreds of lines of glue for the hardest parts of configuration:

| Capability | Manual `ProcessInfo` / `Codable` | `apple/swift-configuration` | **`Rigging`** |
|---|---|---|---|
| Declarative typed Swift structs (`@Settings` / `@Rigged`) | Manual decoding boilerplate | Imperative key-by-key `reader.string(forKey:)` | **Compile-time `swift-syntax` macro synthesis** |
| Non-clobbering CLI → Env → `.env` → Config cascade | Unset CLI defaults overwrite env/files | Provider ordering only | **8-layer cascade; `nil` CLI flags never clobber** |
| Password-manager secret URIs (`op://`, `keychain://`, `bws://`, `pass://`, `sops://`) | Custom shell scripts per app | Not built-in | **Deduplicated two-phase batch engine (1 unlock)** |
| Validation error reporting | `Codable` halts on the first error | Fails at individual read call sites | **Exhaustive single-pass multi-issue diagnostics (exit `2`/`4`/`6`)** |
| Per-field provenance & shadowed origins (`$field`) | None | Access logging only | **`settings.$keyId.source` + `overriddenSources`** |
| Secret redaction, `0600` checks & ephemeral `.p8`/PEM files | Easy to leak in `print`/`dump`/temp files | `isSecret` marker on reads | **`Secret<T>`, `DiagnosticRedactor`, git-config guard & `withEphemeralFile`** |
| Operational CLI tooling (`show`, `doctor`, `schema`, `init`) | Hand-built per tool | None | **Drop-in `ConfigSubcommand<MySettings>`** |
| External dependencies in core runtime | None | `swift-log`, `swift-service-lifecycle`, etc. | **`RiggingCore` & `RiggingTOML` have zero external deps** |

**Rigging composes directly with both ecosystems:**
- **`RiggingArgumentParser`** binds `ParsableArguments` into the cascade (omitting unset `nil` optionals) and mounts a turnkey `config` subcommand group.
- **`RiggingSwiftConfiguration`** bridges bidirectionally with `apple/swift-configuration` (`SwiftConfigurationSource` and `settings.asConfigReader()`), automatically flagging every `@SecretSetting` with `isSecret: true` so `AccessLogger` redacts secrets in traces.

---

## Installation

Add `Rigging` to your `Package.swift` (Swift 6.2+, macOS 15+ / iOS 18+ / tvOS 18+ / watchOS 11+ / visionOS 2+ / Linux):

```swift
dependencies: [
    .package(url: "https://github.com/SamPetherbridge/Rigging.git", from: "0.1.0"),
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

Link only what your binary needs — `RiggingCore` and `RiggingTOML` depend exclusively on `Foundation`:

| Product | External Dependencies | Purpose |
|---|---|---|
| `Rigging` | `swift-syntax` *(macro plugin)* | `@Settings`, `@Rigged`, `@Setting`, `@SecretSetting`, `@NestedSettings` |
| `RiggingCore` | **None** (`Foundation` only) | Cascade engine, `.env` / JSON / plist / MDM / secrets-dir sources, `Secret<T>`, validators, JSON Schema & `.env` exporters |
| `RiggingOnePassword` | **None** | Batched `op://` resolution (`op inject` pipe & 1Password Connect REST API) |
| `RiggingKeychain` | **None** (`Security.framework`) | Direct in-process `keychain://` lookups with zero subprocesses |
| `RiggingBitwarden` | **None** | `bws://` (Secrets Manager) & `bw://` (Vault CLI) secret resolution |
| `RiggingUnixPass` | **None** | `pass://` (`~/.password-store`) & `sops://` (RFC 6901 JSON Pointer) resolution |
| `RiggingTOML` | **None** | Pure-Swift TOML v1.0 parser & `TOMLProjectConfigSource` / `TOMLUserConfigSource` |
| `RiggingYAML` | `Yams` | YAML project/user config sources with `profiles` & `<<` merge-key support |
| `RiggingArgumentParser` | `swift-argument-parser` | Non-clobbering `ParsableArguments` bridge & turnkey `ConfigSubcommand` |
| `RiggingSwiftConfiguration` | `apple/swift-configuration` | Bidirectional `ConfigProvider` / `ConfigReader` adapter |
| `RiggingTesting` | **None** | Hermetic `SettingsContext.inMemory`, `InMemoryFileSystem`, and mock providers |

---

## Quick Start (`@Settings` & `@Rigged`)

```swift
import Foundation
import Rigging
import RiggingKeychain
import RiggingOnePassword

@Settings
public struct SigningSettings: Sendable, Equatable {
    /// Apple Developer Team ID
    @Setting(validate: .nonEmpty, examples: ["ABCDE12345"])
    public var teamId: String?

    /// Enable automatic code signing
    @Setting
    public var automaticSigning: Bool = true
}

@Settings(
    envPrefix: "ASC_",
    envNestedDelimiter: "__",
    dotEnvFiles: [".env", ".env.local"],
    projectConfigFiles: [".asc.json"],
    xdgAppName: "asc",
    extraKeys: .forbid
)
public struct ASCSettings: Sendable, Equatable {
    /// 10-character App Store Connect Key ID
    @Setting(
        aliases: [.env("APP_STORE_CONNECT_KEY_ID"), .configPath(["auth", "keyId"])],
        validate: .regex(#"^[A-Z0-9]{10}$"#, message: "Must be a 10-character alphanumeric Key ID")
    )
    public var keyId: String

    /// App Store Connect Issuer UUID
    @Setting(aliases: [.configPath(["auth", "issuerId"])])
    public var issuerId: UUID

    /// PKCS#8 (.p8) private key or secret URI (op://, keychain://, @~/.keys/AuthKey.p8)
    @SecretSetting(
        transforms: [
            .expandFileReference(requirePermissions: 0o600),
            .decodeBase64IfPrefixed,
            .normalizePEM,
        ]
    )
    public var privateKey: Secret<String>

    /// Enforce read-only API operations
    @Setting
    public var readOnly: Bool = false

    /// HTTP request timeout (`"30s"`, `"500ms"`, `"2m"`)
    @Setting
    public var timeout: Duration = .seconds(30)

    /// Nested signing configuration (`ASC_SIGNING__TEAM_ID` or `signing.teamId`)
    @NestedSettings
    public var signing: SigningSettings = .init()

    public static func validate(_ settings: Self) -> [ValidationIssue] {
        if !settings.readOnly && settings.signing.teamId == nil {
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

> **SwiftUI Apps:** When importing `Rigging` alongside `SwiftUI`, annotate models with `@Rigged(...)` instead of `@Settings(...)` to avoid colliding with `SwiftUI.Settings`.

Load settings asynchronously with deduplicated, single-batch secret resolution:

```swift
let settings = try await ASCSettings.load(
    secretProviders: [
        .onePassword(),
        .keychain(),
    ]
)
```

---

## Source Precedence & Exhaustive Validation

By default, `Rigging` merges configuration layers from highest to lowest priority (customizable per model via `static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource]`):

1. **CLI & Programmatic Overrides (`InitSource` / `ArgumentParserSource`)** — Unset `nil` optional flags are omitted so they never clobber lower layers.
2. **Environment Variables (`EnvironmentSource`)** — Honors `envPrefix`, `envNestedDelimiter` (`ASC_SIGNING__TEAM_ID`), `envIgnoreEmpty`, `envNullStrings` (`null`, `none`, `~`), `.env(...)` aliases, and `EnvCollectionStrategy` (`.jsonOrCommaSeparated`, `.jsonOnly`, `.separator`, `.noDecode`).
3. **Dotenv Files (`DotEnvSource`)** — Supports `export`, single/double/unquoted strings, multiline PEM blocks, `#` comments, `${VAR:-default}` interpolation, and `.env` → `.env.local` layering with exact 1-based line numbers.
4. **Secrets Directory (`SecretsDirSource`)** — Docker / Kubernetes `/run/secrets` mounts (`secretsNestedSubdir`, dotfile skipping, trailing newline trimming).
5. **Project Config (`ProjectConfigSource`, `TOMLProjectConfigSource`, `YAMLProjectConfigSource`)** — Walks upward from `workingDirectory`, stopping inclusively at `.git` or `$HOME`, overlaying `"profiles": { "<active>": { ... } }` (`--profile` or `<PREFIX>PROFILE`), and stripping `"$schema"` and `"profiles"` for `extraKeys: .forbid`.
6. **User Config (`UserConfigSource`, `TOMLUserConfigSource`, `YAMLUserConfigSource`)** — Reads `$XDG_CONFIG_HOME/<app>/config.{json,toml,yaml,yml}` (`~/.config/<app>/...`) with macOS `~/Library/Application Support/<app>/` fallback.
7. **Managed Preferences (`ManagedPreferencesSource`)** — macOS `CFPreferences` / enterprise MDM policy domains (e.g., `com.example.asc`).
8. **Swift Property Defaults** — Declared inline on struct properties.

Unlike `Codable` (which halts on the first `DecodingError`), `Rigging` evaluates **every** field, nested struct, secret safety rule, and cross-field `validate(_:)` check in one pass, throwing a `SettingsValidationError` (`LocalizedError`) with deterministic CLI exit codes:

- **`2`** — Missing required setting, type/validator mismatch, unknown key (`extraKeys: .forbid`), or cross-field failure
- **`4`** — Unsafe secret storage (`0644` key file, world-writable binary, or literal secret committed in a project config file)
- **`6`** — External secret provider failure (missing Keychain item, expired 1Password session, or unreachable Connect server)

---

## Batched Secret References & Leak-Proof `Secret<T>`

Any `@SecretSetting` (or `@Setting(resolveSecrets: true)`) transparently dereferences secret URIs across all registered providers, grouping by `(scheme, accountHint)` so 1Password prompts for biometric unlock **at most once**:

| Reference URI | Provider | Mechanism |
|---|---|---|
| `op://Vault/Item/[Section/]field` | `OnePasswordProvider` (`.onePassword()`) | Single batched `op inject` over in-memory pipes or Connect REST API |
| `keychain://service/account` | `KeychainProvider` (`.keychain()`) | In-process `SecItemCopyMatching` (generic & internet passwords) |
| `bws://<uuid>` / `bw://<id>/field` | `BitwardenProvider` (`.bitwarden()`) | Bitwarden Secrets Manager (`bws`) or Vault (`bw`) CLI |
| `pass://team/prod/api-key[#key]` | `UnixPassProvider` (`.unixPass()`) | `pass show` (`~/.password-store` line, `#full`, `#line:N`, or `#key`) |
| `sops://secrets.enc.json#/db/pass` | `SOPSProvider` (`.sops()`) | `sops --decrypt` + in-memory RFC 6901 JSON Pointer |
| `file:///abs/path` or `@~/.keys/Auth.p8` | `FileSecretProvider` *(built-in)* | Enforces `0600` POSIX permissions prior to reading |
| `env://PROD_API_KEY` | `IndirectEnvProvider` *(built-in)* | Safe config-file indirection to environment variables |

### Safe Secret Consumption & `withEphemeralFile`

```swift
// Explicit extraction (easy to grep in security review):
let rawPEM: String = settings.privateKey.expose()

// Scoped UTF-8 byte buffer access:
let jwt = try settings.privateKey.withExposedUTF8 { pemBytes in
    try signAppStoreJWT(pemBytes: pemBytes)
}

// Atomic 0700 directory + 0600 file materialization for legacy CLIs (xcodebuild, openssl, ssh):
// Guaranteed to overwrite bytes with zeros, fsync, unlink, and rmdir on return or throw!
try await settings.privateKey.withEphemeralFile(prefix: "authkey-", suffix: ".p8") { keyURL in
    try await runXcodebuild(authenticationKeyPath: keyURL.path(percentEncoded: false))
}

// Scrub subprocess stderr before logging so resolved secrets never leak to CI logs:
let safeStderr = settings.redactor.scrub(rawProcessStderr)
```

---

## `$field` Provenance Inspection

Every `@Setting` and `@SecretSetting` synthesizes a `$field` projected `SettingMetadata<Value>`:

```swift
print(settings.$keyId.source)
// environment ASC_KEY_ID

print(settings.$keyId.overriddenSources)
// [project config /repo/.asc.json (keyId)]

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

struct GlobalCLIOptions: RiggingCLIOptions {
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

Mounting `ConfigSubcommand<ASCSettings>.self` adds four operational subcommands out of the box:
- `asc config show [--json] [--profile <name>]` — Displays effective values (`**********` for secrets) with winning and shadowed `SettingOrigin`s.
- `asc config doctor [--json] [--profile <name>]` — Audits config syntax, `0600` file permissions, secret provider reachability, and unknown/deprecated keys (`0`, `2`, `4`, `6`).
- `asc config schema [--compact]` — Exports Draft 2020-12 JSON Schema for editor `$schema` autocomplete.
- `asc config init [--dotenv | --json]` — Scaffolds a commented `.env` template or git-safe starter JSON config.

---

## `RiggingSwiftConfiguration` (`apple/swift-configuration`)

Bridge `Rigging` bidirectionally with `apple/swift-configuration` (`1.0+`):

```swift
import Configuration
import Rigging
import RiggingOnePassword
import RiggingSwiftConfiguration

// Direction B: Vend validated, secret-resolved Rigging settings as a standard Apple ConfigReader.
// Every @SecretSetting is marked `isSecret: true` so AccessLogger automatically redacts secrets!
let settings = try await ASCSettings.load(secretProviders: [.onePassword()])
let reader: ConfigReader = settings.asConfigReader()
let teamId = reader.scoped(to: "signing").string(forKey: "team-id")

// Direction A: Consume any upstream ConfigProvider inside `customizeSources(_:)`:
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

---

## Documentation

Full multi-module **Apple DocC** reference documentation and conceptual guides (*Getting Started with Rigging*, *Secrets and Security Hygiene*, *Provenance and Operational Debugging*, and *Migrating from Python pydantic-settings*) are included across all 11 library targets:

- **In Xcode:** Open `Package.swift` and choose **Product → Build Documentation** (`⌃⇧⌘D`).
- **From the CLI:** Run `swift package generate-documentation --target Rigging` (configured for multi-target hosting via [`.spi.yml`](.spi.yml)).
- **Architecture & Threat Model:** See [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) and [`SECURITY.md`](SECURITY.md).

---

## Contributing & Security

- Run `./scripts/install-hooks.sh` after cloning to enable the local `.githooks/pre-push` verification gate (zero-warning Swift 6 build, parallel `Swift Testing` suite, and multi-module DocC `--warnings-as-errors` check), and read [`CONTRIBUTING.md`](CONTRIBUTING.md) for module dependency boundaries and extension guides.
- To report a security vulnerability privately, see [`SECURITY.md`](SECURITY.md).
- Please review our [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

Released under the [MIT License](LICENSE).
