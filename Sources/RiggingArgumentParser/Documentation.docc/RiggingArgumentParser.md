# ``RiggingArgumentParser``

Bridge `swift-argument-parser` options, flags, and operational `config` subcommands directly into Rigging settings models without clobbering lower-priority sources.

## Overview

`RiggingArgumentParser` solves the classic CLI configuration clobbering problem (`@Flag var readOnly = false` silently overriding `APP_READ_ONLY=true` or `"readOnly": true` in a config file). By declaring CLI options as `Optional` (such as `@Option var host: String?` or `@Flag(inversion: .prefixedNo) var readOnly: Bool?`), `RiggingArgumentParser` emits overrides **only** for flags explicitly supplied on the command line, preserving exact CLI flag provenance (such as `--no-read-only` or `--enable-telemetry`).

In addition, ``ConfigSubcommand`` (aliased as ``SettingsCommandGroup``) provides a turnkey `config` subcommand group (`show`, `doctor`, `schema`, and `init`) that you can mount in any `ParsableCommand` or `AsyncParsableCommand` in a single line. Both `RiggedSettings.load(cliArguments:)` and ``ConfigSubcommand`` automatically honor your model's `defaultSecretProviders` (such as `.onePassword()` and `.keychain()`).

### Explicit-Only CLI Overrides

Pass any `ParsableArguments` or ``RiggingCLIOptions`` value to `RiggedSettings.load(cliArguments:...)`:

```swift
import ArgumentParser
import Rigging
import RiggingArgumentParser

struct GlobalOptions: ParsableArguments, Sendable {
    @Option(name: .long, help: "Server bind host")
    var host: String?

    @Flag(name: .long, inversion: .prefixedNo, help: "Enforce read-only mode")
    var readOnly: Bool?

    @Option(name: .long, help: "Active configuration profile")
    var profile: String?
}

@main
struct MyCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "my-cli",
        subcommands: [
            ServeCommand.self,
            ConfigSubcommand<AppSettings>.self,
        ]
    )
}

struct ServeCommand: AsyncParsableCommand {
    @OptionGroup var globals: GlobalOptions

    mutating func run() async throws {
        let settings = try await AppSettings.load(cliArguments: globals)
        print("Listening on \(settings.host) (source: \(settings.$host.source))")
    }
}
```

### Operational `config` Subcommands

Mounting ``ConfigSubcommand`` adds four zero-secret-leak operational subcommands:

- `config show` (`--json`, `--profile`): Displays effective resolved settings, winning provenance origins, and displaced sources with all `@SecretSetting` values redacted (`**********`).
- `config doctor` (`--json`, `--profile`): Verifies configuration syntax, file permissions, deprecated settings, and secret provider connectivity with semantic exit codes (`0` healthy, `2` invalid configuration, `4` unsafe secret storage, `6` secret provider failure).
- `config schema` (`--compact`, `--title`): Exports JSON Schema (Draft 2020-12) for IDE autocomplete and CI validation.
- `config init` (`--dotenv`, `--json`): Scaffolds a commented `.env` template or starter JSON configuration file populated with safe `op://...` placeholders.

## Topics

### Argument & Flag Extraction

- ``ArgumentParserSource``
- ``RiggingCLIOptions``
- ``CLIOverridesConvertible``
- ``CLIFieldTarget``
- ``CLIOverridesBuilder``
- ``CLIRawValueRepresentable``

### Turnkey Operational Subcommands

- ``ConfigSubcommand``
- ``SettingsCommandGroup``
- ``ConfigSubcommandExecutable``
- ``ConfigCommandExecutionResult``
