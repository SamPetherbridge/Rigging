import ArgumentParser
import Foundation
import Rigging
import RiggingArgumentParser
import RiggingTesting
import RiggingTOML
import RiggingYAML
import Testing

// MARK: - Test Models & CLI Argument Types

@Settings
struct SigningOptions: Equatable, Sendable {
    @Setting(help: "Apple Developer Team ID", examples: ["TEAM123456"])
    var teamId: String = "DEFAULT_TEAM"

    @Setting(help: "Enable Xcode automatic code signing")
    var automaticSigning: Bool = true
}

@Settings(
    envPrefix: "ASC_",
    projectConfigFiles: [".asc.json"],
    xdgAppName: "asc",
    extraKeys: .warn
)
struct ASCIntegrationSettings: Sendable {
    @Setting(
        validate: .nonEmpty,
        help: "App Store Connect Key ID",
        examples: ["ABC1234567"]
    )
    var keyId: String

    @Setting(
        validate: .nonEmpty,
        help: "App Store Connect Issuer ID",
        examples: ["00000000-0000-0000-0000-000000000000"]
    )
    var issuerId: String = "00000000-0000-0000-0000-000000000001"

    @SecretSetting(
        transforms: [.normalizePEM],
        help: "PKCS#8 private key material or secret reference",
        examples: ["op://Personal/ASC/private_key"]
    )
    var privateKey: Secret<String>

    @Setting(help: "Enforce read-only API mode")
    var readOnly: Bool = false

    @Setting(
        help: "Legacy team identifier",
        deprecated: "Use signing.teamId instead."
    )
    var legacyTeam: String?

    @NestedSettings
    var signing: SigningOptions = SigningOptions()
}

struct GlobalCLIOptions: ParsableArguments, Sendable {
    @Option(name: .long, help: "App Store Connect Key ID")
    var keyId: String?

    @Option(name: .long, help: "Active configuration profile")
    var profile: String?

    @Flag(name: .long, inversion: .prefixedNo, help: "Enforce read-only API mode")
    var readOnly: Bool?
}

struct SigningCLIGroup: RiggingCLIOptions {
    static var cliKeyMap: [String: CLIFieldTarget] {
        [
            "team": .key("signing", "teamId", flag: "--team"),
        ]
    }

    @Option(name: .customLong("team"))
    var team: String?
}

struct RootCLIOptionsWithGroup: RiggingCLIOptions {
    @Option(name: .long)
    var keyId: String?

    @OptionGroup
    var signingGroup: SigningCLIGroup
}

@Settings(
    envPrefix: "TOMLAPP_",
    projectConfigFiles: [".tomlapp.toml"],
    xdgAppName: "tomlapp",
    extraKeys: .forbid
)
struct TOMLAppSettings: Sendable {
    @Setting
    var host: String = "127.0.0.1"

    @Setting
    var port: Int = 8080

    @Setting
    var debug: Bool = false

    @Setting
    var tags: [String] = []

    @SecretSetting
    var apiToken: Secret<String>

    @NestedSettings
    var signing: SigningOptions = SigningOptions()

    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        [
            defaults.initOverrides,
            defaults.environment,
            defaults.dotEnv,
            TOMLProjectConfigSource(),
            TOMLUserConfigSource(),
        ]
    }
}

@Settings(
    envPrefix: "YAMLAPP_",
    projectConfigFiles: [".yamlapp.yaml", ".yamlapp.yml"],
    xdgAppName: "yamlapp",
    extraKeys: .forbid
)
struct YAMLAppSettings: Sendable {
    @Setting
    var endpoint: String = "https://api.example.com"

    @Setting
    var maxRetries: Int = 3

    @Setting
    var enableMetrics: Bool = false

    @Setting
    var allowedRegions: [String] = []

    @SecretSetting
    var webhookSecret: Secret<String>

    @NestedSettings
    var signing: SigningOptions = SigningOptions()

    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        [
            defaults.initOverrides,
            defaults.environment,
            defaults.dotEnv,
            YAMLProjectConfigSource(),
            YAMLUserConfigSource(),
        ]
    }
}

// MARK: - CLI Binding & Non-Clobbering Precedence Suite

@Suite("ArgumentParser Explicit-vs-Default CLI Binding")
struct ArgumentParserCLIBindingTests {
    @Test("Explicit --read-only overrides ASC_READ_ONLY=false with exact CLI provenance")
    func explicitReadOnlyOverridesEnvironmentFalse() async throws {
        let parsed = try GlobalCLIOptions.parse(["--read-only", "--key-id", "CLIKEY9999"])
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Personal/ASC/private_key": TestFixtures.sampleP8PEM,
        ])
        let context = SettingsContext.inMemory(
            environment: [
                "ASC_READ_ONLY": "false",
                "ASC_KEY_ID": "ENVKEY1111",
                "ASC_PRIVATE_KEY": "op://Personal/ASC/private_key",
            ],
            secretProviders: [mockOP]
        )

        let settings = try await ASCIntegrationSettings.load(
            cliArguments: parsed,
            context: context
        )

        #expect(settings.readOnly == true)
        #expect(settings.keyId == "CLIKEY9999")
        #expect(settings.$readOnly.source == .cliArgument(flag: "--read-only"))
        #expect(settings.$readOnly.overriddenSources == [.environment(variable: "ASC_READ_ONLY")])
        #expect(settings.$keyId.source == .cliArgument(flag: "--key-id"))
        #expect(settings.$keyId.overriddenSources == [.environment(variable: "ASC_KEY_ID")])
    }

    @Test("Unset readOnly: Bool? and keyId: String? fall through to ASC_READ_ONLY=true and config file")
    func unsetOptionalFlagsNeverClobberEnvironmentOrConfig() async throws {
        let parsed = try GlobalCLIOptions.parse([])
        #expect(parsed.readOnly == nil)
        #expect(parsed.keyId == nil)
        #expect(parsed.riggingOverrides().isEmpty)

        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Personal/ASC/private_key": TestFixtures.sampleP8PEM,
        ])
        let context = SettingsContext.inMemory(
            environment: [
                "ASC_READ_ONLY": "true",
            ],
            files: [
                "/repo/.asc.json": """
                {
                    "keyId": "JSONKEY777",
                    "privateKey": "op://Personal/ASC/private_key"
                }
                """,
            ],
            directories: ["/repo/.git"],
            secretProviders: [mockOP]
        )

        let settings = try await ASCIntegrationSettings.load(
            cliArguments: parsed,
            context: context
        )

        #expect(settings.readOnly == true)
        #expect(settings.$readOnly.source == .environment(variable: "ASC_READ_ONLY"))
        #expect(settings.keyId == "JSONKEY777")
        #expect(
            settings.$keyId.source == .projectConfig(
                path: "/repo/.asc.json",
                keyPath: ["keyId"],
                profile: nil
            )
        )
    }

    @Test("Explicit --no-read-only overrides ASC_READ_ONLY=true with --no-read-only provenance")
    func explicitInvertedFlagOverridesEnvironmentTrue() async throws {
        let parsed = try GlobalCLIOptions.parse(["--no-read-only"])
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Personal/ASC/private_key": TestFixtures.sampleP8PEM,
        ])
        let context = SettingsContext.inMemory(
            environment: [
                "ASC_READ_ONLY": "true",
                "ASC_KEY_ID": "ENVKEY2222",
                "ASC_PRIVATE_KEY": "op://Personal/ASC/private_key",
            ],
            secretProviders: [mockOP]
        )

        let settings = try await ASCIntegrationSettings.load(
            cliArguments: parsed,
            context: context
        )

        #expect(settings.readOnly == false)
        #expect(settings.$readOnly.source == .cliArgument(flag: "--no-read-only"))
        #expect(settings.$readOnly.overriddenSources == [.environment(variable: "ASC_READ_ONLY")])
    }

    @Test("Nested @OptionGroup, custom cliKeyMap, and --profile selection work end-to-end")
    func optionGroupKeyMapAndProfileSelection() async throws {
        let groupParsed = try RootCLIOptionsWithGroup.parse(["--team", "CUSTOM_TEAM_42"])
        let profileParsed = try GlobalCLIOptions.parse(["--profile", "release"])

        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Personal/ASC/private_key": TestFixtures.sampleP8PEM,
        ])
        let context = SettingsContext.inMemory(
            files: [
                "/repo/.asc.json": """
                {
                    "$schema": "https://example.com/asc.schema.json",
                    "keyId": "BASE_KEY",
                    "privateKey": "op://Personal/ASC/private_key",
                    "profiles": {
                        "release": {
                            "keyId": "RELEASE_KEY",
                            "readOnly": true
                        }
                    }
                }
                """,
            ],
            directories: ["/repo/.git"],
            secretProviders: [mockOP]
        )

        let combinedOverrides = groupParsed.cliSettingOverrides() + profileParsed.riggingOverrides()
        let settings = try await ASCIntegrationSettings.load(
            context: context,
            overrides: combinedOverrides
        )

        #expect(settings.keyId == "RELEASE_KEY")
        #expect(settings.readOnly == true)
        #expect(settings.signing.teamId == "CUSTOM_TEAM_42")
        #expect(settings.provenance["signing", "teamId"]?.origin == .cliArgument(flag: "--team"))
        #expect(
            settings.$keyId.source == .projectConfig(
                path: "/repo/.asc.json",
                keyPath: ["keyId"],
                profile: "release"
            )
        )
    }
}

// MARK: - Operational `ConfigSubcommand` Suite

@Suite("ConfigSubcommand Operational Commands (show, doctor, schema, init)")
struct ConfigSubcommandIntegrationTests {
    @Test("config show and config show --json print provenance and never leak plaintext secrets")
    func configShowHumanAndJSONRedaction() async throws {
        let superSecretMaterial = "SUPER_SECRET_PRIVATE_KEY_MATERIAL_998877"
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Personal/ASC/private_key": superSecretMaterial,
        ])
        let context = SettingsContext.inMemory(
            environment: [
                "ASC_KEY_ID": "ENVKEY9000",
            ],
            files: [
                "/repo/.asc.json": """
                {
                    "keyId": "FILEKEY1000",
                    "privateKey": "op://Personal/ASC/private_key",
                    "readOnly": true
                }
                """,
            ],
            directories: ["/repo/.git"],
            secretProviders: [mockOP]
        )

        // Human table output
        let humanResult = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["show"],
            context: context
        )
        #expect(humanResult.exitCode == 0)
        #expect(humanResult.stdout.contains("keyId = ENVKEY9000"))
        #expect(humanResult.stdout.contains("overrides: project config /repo/.asc.json"))
        #expect(humanResult.stdout.contains("privateKey = **********"))
        #expect(!humanResult.stdout.contains(superSecretMaterial))
        #expect(!humanResult.stderr.contains(superSecretMaterial))

        // Deterministic --json output
        let jsonResult = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["show", "--json"],
            context: context
        )
        #expect(jsonResult.exitCode == 0)
        #expect(!jsonResult.stdout.contains(superSecretMaterial))

        let parsed = try JSONSerialization.jsonObject(
            with: Data(jsonResult.stdout.utf8)
        ) as? [String: Any]
        let values = parsed?["values"] as? [String: String]
        #expect(values?["keyId"] == "ENVKEY9000")
        #expect(values?["privateKey"] == "**********")
        #expect(values?["readOnly"] == "true")
    }

    @Test("config doctor reports healthy status, unknown/deprecated warnings, and exit codes 2 / 4 / 6")
    func configDoctorHealthWarningsAndExitCodes() async throws {
        let secretBody = "TOP_SECRET_PEM_BODY_ABCDEF123456"
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Personal/ASC/private_key": secretBody,
        ])

        // 1. Healthy + extraKeys warning + deprecated key warning -> exitCode 0
        let warningContext = SettingsContext.inMemory(
            files: [
                "/repo/.asc.json": """
                {
                    "keyId": "HEALTHYKEY1",
                    "privateKey": "op://Personal/ASC/private_key",
                    "legacyTeam": "OLD_TEAM",
                    "mysteryExtraKey": 123
                }
                """,
            ],
            directories: ["/repo/.git"],
            secretProviders: [mockOP]
        )

        let healthyJSON = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["doctor", "--json"],
            context: warningContext
        )
        #expect(healthyJSON.exitCode == 0)
        #expect(!healthyJSON.stdout.contains(secretBody))
        let healthyObj = try JSONSerialization.jsonObject(
            with: Data(healthyJSON.stdout.utf8)
        ) as? [String: Any]
        #expect(healthyObj?["healthy"] as? Bool == true)
        #expect(healthyObj?["status"] as? String == "warning")
        #expect((healthyObj?["warningCount"] as? Int ?? 0) >= 2)

        // 2. Missing required setting -> exitCode 2
        let missingContext = SettingsContext.inMemory(
            environment: [
                "ASC_PRIVATE_KEY": "op://Personal/ASC/private_key",
            ],
            secretProviders: [mockOP]
        )
        let exit2Result = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["doctor", "--json"],
            context: missingContext
        )
        #expect(exit2Result.exitCode == 2)

        // 3. Literal secret in git-tracked project config -> exitCode 4
        let unsafeRepoSecretContext = SettingsContext.inMemory(
            files: [
                "/repo/.asc.json": """
                {
                    "keyId": "UNSAFEKEY1",
                    "privateKey": "sk-live-committed-secret-value"
                }
                """,
            ],
            directories: ["/repo/.git"],
            secretProviders: [mockOP]
        )
        let exit4Result = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["doctor", "--json"],
            context: unsafeRepoSecretContext
        )
        #expect(exit4Result.exitCode == 4)
        #expect(!exit4Result.stdout.contains("sk-live-committed-secret-value"))

        // 4. Failing secret provider (missing op:// item) -> exitCode 6
        let failingOP = MockOnePasswordProvider(secrets: [:])
        let providerFailContext = SettingsContext.inMemory(
            files: [
                "/repo/.asc.json": """
                {
                    "keyId": "KEY_WITH_MISSING_OP",
                    "privateKey": "op://Personal/ASC/missing_field"
                }
                """,
            ],
            directories: ["/repo/.git"],
            secretProviders: [failingOP]
        )
        let exit6Result = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["doctor"],
            context: providerFailContext
        )
        #expect(exit6Result.exitCode == 6)
        #expect(exit6Result.stderr.contains("privateKey"))
    }

    @Test("config schema and config init (--dotenv / --json) generate valid Draft 2020-12 schema and templates")
    func configSchemaAndInitGenerators() async throws {
        // Schema
        let schemaResult = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["schema"]
        )
        #expect(schemaResult.exitCode == 0)
        let schemaJSON = try JSONSerialization.jsonObject(
            with: Data(schemaResult.stdout.utf8)
        ) as? [String: Any]
        #expect(schemaJSON?["$schema"] as? String == "https://json-schema.org/draft/2020-12/schema")
        let props = schemaJSON?["properties"] as? [String: Any]
        #expect(props?["keyId"] != nil)
        #expect(props?["signing"] != nil)

        // Init --dotenv
        let dotEnvResult = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["init", "--dotenv"]
        )
        #expect(dotEnvResult.exitCode == 0)
        #expect(dotEnvResult.stdout.contains("ASC_KEY_ID="))
        #expect(dotEnvResult.stdout.contains("ASC_PRIVATE_KEY="))

        // Init --json (uses safe op:// secret reference placeholder, never literal secret)
        let initJSONResult = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["init", "--json"]
        )
        #expect(initJSONResult.exitCode == 0)
        let starterObj = try JSONSerialization.jsonObject(
            with: Data(initJSONResult.stdout.utf8)
        ) as? [String: Any]
        #expect(starterObj?["privateKey"] as? String == "op://Personal/ASC/private_key")
        #expect(starterObj?["readOnly"] as? Bool == false)
        let signingStarter = starterObj?["signing"] as? [String: Any]
        #expect(signingStarter?["teamId"] as? String == "DEFAULT_TEAM")

        // Mutually exclusive --dotenv --json rejected
        await #expect(throws: (any Error).self) {
            _ = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
                arguments: ["init", "--dotenv", "--json"]
            )
        }
    }
}

// MARK: - RiggingTOML & RiggingYAML End-to-End Integration Suite

@Suite("TOML & YAML Project/User Config End-to-End Integration")
struct TOMLANDYAMLIntegrationTests {
    @Test("TOMLProjectConfigSource & TOMLUserConfigSource discover upward to .git, apply profiles, and resolve op:// secrets")
    func tomlProjectAndUserConfigEndToEnd() async throws {
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Engineering/TOMLApp/token": "toml-resolved-token-secret-xyz",
        ])

        let context = SettingsContext.inMemory(
            environment: [
                "TOMLAPP_PROFILE": "staging",
            ],
            files: [
                // Parent above .git should NOT be read because /repo/.git stops upward walk
                "/.tomlapp.toml": """
                host = "should-not-be-read.invalid"
                """,
                "/repo/.tomlapp.toml": """
                # Project TOML config with $schema and profiles
                "$schema" = "https://example.com/tomlapp.schema.json"
                host = "prod.internal"
                port = 8_443
                tags = ["api", "v2",]
                apiToken = "op://Engineering/TOMLApp/token"

                [signing]
                teamId = "TOML_TEAM_01"

                [profiles.staging]
                host = "staging.internal"
                debug = true
                """,
                "/Users/test/.config/tomlapp/config.toml": """
                host = "user-fallback.internal"
                port = 9000
                signing = { teamId = "USER_TEAM", automaticSigning = false }
                """,
            ],
            directories: ["/repo/.git", "/repo/Sources/Subdir"],
            workingDirectory: "/repo/Sources/Subdir",
            homeDirectory: "/Users/test",
            secretProviders: [mockOP]
        )

        let settings = try await TOMLAppSettings.load(context: context)

        #expect(settings.host == "staging.internal")
        #expect(settings.port == 8443)
        #expect(settings.debug == true)
        #expect(settings.tags == ["api", "v2"])
        #expect(settings.signing.teamId == "TOML_TEAM_01")
        #expect(settings.signing.automaticSigning == false)
        #expect(settings.apiToken.expose() == "toml-resolved-token-secret-xyz")
        #expect(
            settings.$host.source == .projectConfig(
                path: "/repo/.tomlapp.toml",
                keyPath: ["host"],
                profile: "staging"
            )
        )
        #expect(await mockOP.invocationCount == 1)
    }

    @Test("TOMLParser supports full v1.0 syntax: multiline strings, hex/oct/bin ints, inf/nan, datetimes, [[array_of_tables]], and inline tables")
    func tomlParserComprehensiveRFCFeatures() throws {
        let tomlInput = """
        # Full TOML v1.0 syntax verification
        title = "Rigging\\nTOML\\u0021"
        literalPath = 'C:\\Users\\nodejs\\templates'
        multilineBasic = \"\"\"
        Roses are red
        Violets are \\
          blue\"\"\"
        multilineLiteral = '''
        First newline stripped
        Second line intact'''

        hexInt = 0xDEAD_BEEF
        octInt = 0o755
        binInt = 0b1101_0110
        sciFloat = 6.022e23
        posInf = +inf
        notANumber = nan
        releaseDate = 2026-11-15 08:30:00Z
        dotted.a.b = 42
        inlineCfg = { enabled = true, retries = 3 }

        [[servers]]
        name = "alpha"
        ports = [8001, 8002]

        [[servers]]
        name = "beta"
        ports = [9001]
        """

        let parsed = try TOMLParser.parse(tomlInput)
        #expect(parsed["title"] == .string("Rigging\nTOML!"))
        #expect(parsed["literalPath"] == .string(#"C:\Users\nodejs\templates"#))
        #expect(parsed["multilineBasic"] == .string("Roses are red\nViolets are blue"))
        #expect(parsed["multilineLiteral"] == .string("First newline stripped\nSecond line intact"))
        #expect(parsed["hexInt"] == .int(0xDEADBEEF))
        #expect(parsed["octInt"] == .int(0o755))
        #expect(parsed["binInt"] == .int(0b11010110))
        #expect(parsed["releaseDate"] == .datetime("2026-11-15T08:30:00Z"))

        if case .float(let nanVal) = parsed["notANumber"] {
            #expect(nanVal.isNaN)
        } else {
            Issue.record("Expected .float(nan)")
        }

        if case .table(let dotted) = parsed["dotted"],
           case .table(let nestedA) = dotted["a"] {
            #expect(nestedA["b"] == .int(42))
        } else {
            Issue.record("Expected nested dotted table")
        }

        if case .array(let servers) = parsed["servers"] {
            #expect(servers.count == 2)
        } else {
            Issue.record("Expected [[servers]] array of tables")
        }

        // Duplicate key redefinition must throw TOMLParseError
        #expect(throws: TOMLParseError.self) {
            _ = try TOMLParser.parse("dup = 1\ndup = 2\n")
        }
    }

    @Test("YAMLProjectConfigSource & YAMLUserConfigSource support .yml/.yaml upward discovery, merge keys, profiles, and op:// secrets")
    func yamlProjectAndUserConfigEndToEnd() async throws {
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Engineering/YAMLApp/webhook": "yaml-webhook-secret-987654",
        ])

        let context = SettingsContext.inMemory(
            cli: [
                .cli(flag: "--profile", keyPath: ["profile"], value: .string("eu")),
            ],
            files: [
                "/repo/.yamlapp.yml": """
                $schema: https://example.com/yamlapp.schema.json
                endpoint: https://us.api.example.com
                maxRetries: 5
                enableMetrics: true
                allowedRegions:
                  - us-east-1
                  - eu-west-1
                webhookSecret: op://Engineering/YAMLApp/webhook
                signing:
                  teamId: YAML_TEAM_77
                profiles:
                  eu:
                    endpoint: https://eu.api.example.com
                """,
                "/Users/test/.config/yamlapp/config.yaml": """
                signing:
                  teamId: USER_FALLBACK_TEAM
                  automaticSigning: false
                """,
            ],
            directories: ["/repo/.git", "/repo/nested/dir"],
            workingDirectory: "/repo/nested/dir",
            homeDirectory: "/Users/test",
            secretProviders: [mockOP]
        )

        let settings = try await YAMLAppSettings.load(context: context)

        #expect(settings.endpoint == "https://eu.api.example.com")
        #expect(settings.maxRetries == 5)
        #expect(settings.enableMetrics == true)
        #expect(settings.allowedRegions == ["us-east-1", "eu-west-1"])
        #expect(settings.signing.teamId == "YAML_TEAM_77")
        #expect(settings.signing.automaticSigning == false)
        #expect(settings.webhookSecret.expose() == "yaml-webhook-secret-987654")
        #expect(
            settings.$endpoint.source == .projectConfig(
                path: "/repo/.yamlapp.yml",
                keyPath: ["endpoint"],
                profile: "eu"
            )
        )
    }
}
