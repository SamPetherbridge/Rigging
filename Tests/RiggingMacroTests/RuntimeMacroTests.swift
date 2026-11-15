import Foundation
import Rigging
import RiggingTesting
import Testing

// MARK: - Spec Section 3 Reference Models (`ASCSettings` & `SigningSettings`)

@Settings(
    envPrefix: "ASC_",
    envNestedDelimiter: "__",
    dotEnvFiles: [".env", ".env.local"],
    projectConfigFiles: [".asc.json"],
    xdgAppName: "asc",
    secretsDirectory: "/run/secrets",
    extraKeys: .forbid
)
public struct ASCSettings: Sendable, Equatable {
    /// App Store Connect API Key ID (e.g., "ABC1234567")
    @Setting(
        aliases: [.env("ASC_KEY_ID"), .configPath(["auth", "keyId"])],
        validate: .regex(#"^[A-Z0-9]{10}$"#, message: "Must be a 10-character alphanumeric Key ID"),
        resolveSecrets: true
    )
    public var keyId: String

    /// Issuer UUID from App Store Connect -> Users and Access -> Integrations
    @Setting(aliases: [.configPath(["auth", "issuerId"])])
    public var issuerId: UUID

    /// PKCS#8 `.p8` private key content (supports `op://`, `keychain://`, `@/path/to/AuthKey.p8`, or literal PEM)
    @SecretSetting(
        aliases: [.configPath(["auth", "privateKey"])],
        transforms: [
            .expandFileReference(requirePermissions: 0o600),
            .decodeBase64IfPrefixed,
            .normalizePEM,
        ],
        allowLiteralInProjectConfig: false
    )
    public var privateKey: Secret<String>

    /// Default App Store Connect App ID
    @Setting
    public var appId: String?

    /// Enforce read-only API operations
    @Setting
    public var readOnly: Bool = false

    /// HTTP request timeout
    @Setting
    public var timeout: Duration = .seconds(30)

    /// Nested signing configuration (`ASC_SIGNING__TEAM_ID`, `.asc.json` -> `signing.teamId`)
    @NestedSettings
    public var signing: SigningSettings = .init()

    /// Cross-field model validation
    public static func validate(_ settings: Self) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        if settings.signing.enabled && settings.signing.certificate == nil {
            issues.append(
                ValidationIssue(
                    path: ["signing", "certificate"],
                    message: "Signing certificate is required when signing.enabled is true"
                )
            )
        }
        return issues
    }
}

@Settings
public struct SigningSettings: Sendable, Equatable {
    /// Enable automatic code signing
    @Setting public var enabled: Bool = false

    /// Apple Developer Team ID
    @Setting(validate: .nonEmpty) public var teamId: String?

    /// PKCS#12 signing certificate data
    @SecretSetting public var certificate: Secret<Data>?

    /// Passphrase unlocking the signing certificate
    @SecretSetting public var certificatePassword: Secret<String>?
}

// MARK: - `@Rigged` Alias & Customization Reference Models

public enum RiggedLogLevel: String, CaseIterable, Sendable, Equatable {
    case debug
    case info
    case warn
    case error
}

@Rigged
public struct WebhookSettings: Sendable, Equatable {
    /// Target HTTPS webhook endpoint
    @Setting(validate: .url(allowedSchemes: ["https"]))
    public var endpoint: URL

    /// Shared HMAC signing secret
    @SecretSetting(validate: .minLength(8))
    public var signingSecret: Secret<String>
}

@Rigged(
    envPrefix: "APP_",
    envNestedDelimiter: "__",
    extraKeys: .forbid,
    dotEnvFiles: [".env"]
)
public struct SwiftUIAppSettings: Sendable, Equatable {
    /// Deployment environment name
    @Setting(transforms: [.trimWhitespace, .lowercased])
    public var environmentName: String = "production"

    /// Local cache directory path
    @Setting(transforms: .expandTilde)
    public var cacheDir: String = "~/.cache/app"

    /// Colon-delimited plugin search paths
    @Setting(envListStrategy: .separator(":"))
    public var searchPaths: [String] = []

    /// Arbitrary telemetry labels
    @Setting
    public var labels: [String: String] = [:]

    /// Minimum log level
    @Setting
    public var logLevel: RiggedLogLevel = .info

    /// Optional nested webhook settings
    @NestedSettings
    public var webhook: WebhookSettings?

    public static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        var sources = defaults.ordered
        sources.insert(
            InitSource(keyPathValues: [["labels", "managedBy"]: .string("rigging")]),
            at: 0
        )
        return sources
    }
}

// MARK: - Runtime End-to-End Tests

@Suite("Runtime @Settings & @Rigged Execution")
struct RuntimeMacroTests {
    @Test("Spec Section 8: Precedence, upward .asc.json discovery, single-batch op:// resolution, and $provenance")
    func ascPrecedenceAndBatchedSecrets() async throws {
        let mockOP = MockOnePasswordProvider(
            secrets: [
                "op://Eng/ASC/key_id": "ABC1234567",
                "op://Eng/ASC/private_key": TestFixtures.sampleP8PEM,
            ]
        )

        let context = SettingsContext.inMemory(
            cli: ["readOnly": true],
            environment: [
                "ASC_ISSUER_ID": "11111111-2222-3333-4444-555555555555",
                "ASC_READ_ONLY": "false",
            ],
            files: [
                "/repo/.asc.json": """
                {
                  "auth": {
                    "keyId": "op://Eng/ASC/key_id",
                    "privateKey": "op://Eng/ASC/private_key"
                  }
                }
                """
            ],
            directories: ["/repo/.git", "/repo/ios-app"],
            workingDirectory: "/repo/ios-app",
            secretProviders: [mockOP]
        )

        let settings = try await ASCSettings.load(context: context)

        // Single batch call across both @Setting(resolveSecrets: true) and @SecretSetting
        #expect(await mockOP.invocationCount == 1)
        #expect(await mockOP.batchHistory.first?.count == 2)

        #expect(settings.keyId == "ABC1234567")
        #expect(settings.issuerId == UUID(uuidString: "11111111-2222-3333-4444-555555555555"))
        #expect(settings.readOnly == true)
        #expect(settings.timeout == .seconds(30))
        #expect(settings.appId == nil)
        #expect(settings.signing == SigningSettings())
        #expect(settings.privateKey.expose { $0 == TestFixtures.sampleP8PEM })

        // Provenance assertions from Spec Section 8
        #expect(settings.$readOnly.source == .cliArgument(flag: "--read-only"))
        #expect(settings.$readOnly.overriddenSources.contains(.environment(variable: "ASC_READ_ONLY")))
        #expect(
            settings.$privateKey.source
                == .secretProvider(
                    scheme: "op",
                    referenceRedacted: "op://Eng/ASC/private_key",
                    via: .projectConfig(path: "/repo/.asc.json", keyPath: ["auth", "privateKey"], profile: nil)
                )
        )
        #expect(
            settings.$keyId.source
                == .secretProvider(
                    scheme: "op",
                    referenceRedacted: "op://Eng/ASC/key_id",
                    via: .projectConfig(path: "/repo/.asc.json", keyPath: ["auth", "keyId"], profile: nil)
                )
        )
    }

    @Test("Root + @NestedSettings enqueue all op:// secrets in Phase 1 and resolve in ONE single batch")
    func rootAndNestedSingleBatchSecretResolution() async throws {
        let p12Bytes = Data([0x30, 0x82, 0x04, 0xA0, 0xDE, 0xAD, 0xBE, 0xEF])
        let mockOP = MockOnePasswordProvider(
            secrets: [
                "op://Eng/ASC/key_id": "XYZ9876543",
                // Base64-prefixed PEM with escaped newlines to verify SecretTransform pipeline order
                "op://Eng/ASC/private_key": "base64:" + Data(TestFixtures.sampleEscapedP8PEM.utf8).base64EncodedString(),
                "op://Team/Signing/password": "super-secret-p12-passphrase",
            ]
        )
        await mockOP.setBinarySecret(p12Bytes, for: "op://Team/Signing/dist.p12")

        let context = SettingsContext.inMemory(
            environment: [
                "ASC_ISSUER_ID": "22222222-3333-4444-5555-666666666666",
                "ASC_SIGNING__ENABLED": "true",
                "ASC_SIGNING__TEAM_ID": "TEAM998877",
                "ASC_SIGNING__CERTIFICATE_PASSWORD": "op://Team/Signing/password",
            ],
            files: [
                "/repo/.asc.json": """
                {
                  "auth": {
                    "keyId": "op://Eng/ASC/key_id",
                    "privateKey": "op://Eng/ASC/private_key"
                  },
                  "signing": {
                    "certificate": "op://Team/Signing/dist.p12"
                  }
                }
                """
            ],
            directories: ["/repo/.git"],
            workingDirectory: "/repo",
            secretProviders: [mockOP]
        )

        let settings = try await ASCSettings.load(context: context)

        // All 4 op:// secrets (2 root + 2 nested) MUST resolve in 1 single batch invocation!
        #expect(await mockOP.invocationCount == 1)
        #expect(await mockOP.batchHistory.first?.count == 4)

        #expect(settings.keyId == "XYZ9876543")
        #expect(settings.privateKey.expose { $0 == TestFixtures.sampleP8PEM })
        #expect(settings.signing.enabled == true)
        #expect(settings.signing.teamId == "TEAM998877")
        #expect(settings.signing.certificate?.expose { $0 } == p12Bytes)
        #expect(settings.signing.certificatePassword?.expose { $0 } == "super-secret-p12-passphrase")

        #expect(
            settings.signing.$certificatePassword.source
                == .secretProvider(
                    scheme: "op",
                    referenceRedacted: "op://Team/Signing/password",
                    via: .environment(variable: "ASC_SIGNING__CERTIFICATE_PASSWORD")
                )
        )
    }

    @Test("Cross-field validate(_:) fires when signing.enabled == true && signing.certificate == nil")
    func crossFieldValidationAndMultiIssueAccumulation() async throws {
        let context = SettingsContext.inMemory(
            environment: [
                "ASC_KEY_ID": "ABC1234567",
                "ASC_ISSUER_ID": "11111111-2222-3333-4444-555555555555",
                "ASC_PRIVATE_KEY": TestFixtures.sampleP8PEM,
                "ASC_SIGNING__ENABLED": "true",
            ]
        )

        await #expect(throws: SettingsValidationError.self) {
            _ = try await ASCSettings.load(context: context)
        }

        do {
            _ = try await ASCSettings.load(context: context)
            Issue.record("Expected SettingsValidationError to be thrown")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 2)
            #expect(error.issues.count == 1)
            #expect(error.issues.first?.path == ["signing", "certificate"])
            #expect(error.issues.first?.kind == .crossField)
            #expect(
                error.issues.first?.message
                    == "Signing certificate is required when signing.enabled is true"
            )
        }

        // Verify exhaustive multi-issue accumulation (invalid regex + invalid UUID + forbidden extra key)
        let multiInvalidContext = SettingsContext.inMemory(
            environment: [
                "ASC_KEY_ID": "invalid-id",
                "ASC_ISSUER_ID": "not-a-uuid",
                "ASC_PRIVATE_KEY": TestFixtures.sampleP8PEM,
            ],
            files: [
                "/repo/.asc.json": """
                {
                  "unexpectedTopLevelKey": true
                }
                """
            ],
            directories: ["/repo/.git"],
            workingDirectory: "/repo"
        )

        do {
            _ = try await ASCSettings.load(context: multiInvalidContext)
            Issue.record("Expected multi-issue SettingsValidationError")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 2)
            #expect(error.issues.count == 3)
            let paths = Set(error.issues.map(\.keyPathString))
            #expect(paths.contains("keyId"))
            #expect(paths.contains("issuerId"))
            #expect(paths.contains("unexpectedTopLevelKey"))
        }
    }

    @Test("allowLiteralInProjectConfig: false blocks literal secrets in .asc.json while allowing @/path with 0600 permissions")
    func literalSecretProtectionAndFileReferencePermissions() async throws {
        // 1. Plaintext PEM inside .asc.json must fail with exitCode 4
        let literalInConfigContext = SettingsContext.inMemory(
            environment: [
                "ASC_KEY_ID": "ABC1234567",
                "ASC_ISSUER_ID": "11111111-2222-3333-4444-555555555555",
            ],
            files: [
                "/repo/.asc.json": """
                {
                  "auth": {
                    "privateKey": "-----BEGIN PRIVATE KEY-----\\nPLAINTEXT\\n-----END PRIVATE KEY-----"
                  }
                }
                """
            ],
            directories: ["/repo/.git"],
            workingDirectory: "/repo"
        )

        do {
            _ = try await ASCSettings.load(context: literalInConfigContext)
            Issue.record("Expected SettingsValidationError with exitCode 4 for literal secret in project config")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 4)
            #expect(error.issues.first?.kind == .unsafeSecret)
            #expect(error.issues.first?.keyPath == ["privateKey"])
            #expect(!error.description.contains("PLAINTEXT"))
        }

        // 2. `@/Users/test/.asc/AuthKey.p8` with world/group-readable 0644 permissions fails with exitCode 4
        let insecureFileContext = SettingsContext.inMemory(
            environment: [
                "ASC_KEY_ID": "ABC1234567",
                "ASC_ISSUER_ID": "11111111-2222-3333-4444-555555555555",
            ],
            files: [
                "/repo/.asc.json": """
                {
                  "auth": {
                    "privateKey": "@~/.asc/AuthKey.p8"
                  }
                }
                """,
                "/Users/test/.asc/AuthKey.p8": TestFixtures.sampleP8PEM,
            ],
            directories: ["/repo/.git"],
            filePermissions: ["/Users/test/.asc/AuthKey.p8": 0o644],
            workingDirectory: "/repo",
            homeDirectory: "/Users/test"
        )

        do {
            _ = try await ASCSettings.load(context: insecureFileContext)
            Issue.record("Expected SettingsValidationError with exitCode 4 for 0644 private key file")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 4)
            #expect(error.issues.first?.kind == .unsafeSecret)
            #expect(error.issues.first?.keyPath == ["privateKey"])
        }

        // 3. `@~/.asc/AuthKey.p8` with strict 0600 permissions succeeds
        let secureFileContext = SettingsContext.inMemory(
            environment: [
                "ASC_KEY_ID": "ABC1234567",
                "ASC_ISSUER_ID": "11111111-2222-3333-4444-555555555555",
            ],
            files: [
                "/repo/.asc.json": """
                {
                  "auth": {
                    "privateKey": "@~/.asc/AuthKey.p8"
                  }
                }
                """,
                "/Users/test/.asc/AuthKey.p8": TestFixtures.sampleP8PEM + "\r\n",
            ],
            directories: ["/repo/.git"],
            filePermissions: ["/Users/test/.asc/AuthKey.p8": 0o600],
            workingDirectory: "/repo",
            homeDirectory: "/Users/test"
        )

        let loaded = try await ASCSettings.load(context: secureFileContext)
        #expect(loaded.privateKey.expose { $0 == TestFixtures.sampleP8PEM })
    }

    @Test("Equatable conformance, direct memberwise init, Secret redaction, ephemeral file, and provenance export")
    func equatableDirectInitAndSecretHygiene() async throws {
        let issuer = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let context = SettingsContext.inMemory(
            environment: [
                "ASC_KEY_ID": "ABC1234567",
                "ASC_ISSUER_ID": issuer.uuidString,
                "ASC_PRIVATE_KEY": TestFixtures.sampleP8PEM,
            ]
        )

        let loaded = try await ASCSettings.load(context: context)
        let direct = ASCSettings(
            keyId: "ABC1234567",
            issuerId: issuer,
            privateKey: Secret(TestFixtures.sampleP8PEM)
        )

        // Loaded and directly constructed instances with identical values compare equal!
        #expect(loaded == direct)

        var modified = direct
        modified.readOnly = true
        #expect(modified != loaded)

        // Direct initialization defaults `$field` provenance to `.defaultValue` and registers secrets in `redactor`
        #expect(direct.$readOnly.source == .defaultValue)
        #expect(direct.$privateKey.valueSummary == "**********")
        #expect(String(describing: direct.privateKey) == "**********")
        #expect(!direct.redactor.scrub("Failure with \(TestFixtures.sampleP8PEM)").contains("BEGIN PRIVATE KEY"))

        // Provenance report & JSON serialization redact secret material
        let report = loaded.provenanceReport()
        #expect(report == loaded.provenance)
        let reportJSON = String(decoding: try report.jsonPayload(), as: UTF8.self)
        #expect(reportJSON.contains("**********"))
        #expect(!reportJSON.contains("SyntheticTestKey"))

        // Ephemeral file materializes 0600 file and securely deletes it on scope exit
        let (ephemeralPath, readBack) = try await loaded.privateKey.withEphemeralFile(suffix: ".p8") { url in
            let path = url.path(percentEncoded: false)
            let attrs = try FileManager.default.attributesOfItem(atPath: path)
            let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
            #expect((mode & 0o777) == 0o600)
            let contents = try String(contentsOf: url, encoding: .utf8)
            return (path, contents)
        }
        #expect(readBack == TestFixtures.sampleP8PEM)
        #expect(!FileManager.default.fileExists(atPath: ephemeralPath))
    }

    @Test("@Rigged alias supports transforms, custom envListStrategy, CaseIterable enums, dictionaries, optional @NestedSettings, customizeSources, and ergonomic load()")
    func riggedAliasAndErgonomicLoad() async throws {
        let fs = InMemoryFileSystem(
            files: [
                "/work/.env": """
                APP_ENVIRONMENT_NAME="  StAgInG  "
                APP_SEARCH_PATHS="/opt/plugins:/usr/local/plugins"
                APP_LOG_LEVEL="warn"
                APP_LABELS__REGION="ap-southeast-2"
                APP_WEBHOOK__ENDPOINT="https://hooks.example.com/events"
                APP_WEBHOOK__SIGNING_SECRET="hmac-signing-secret-1234"
                """
            ],
            directories: ["/work"]
        )

        let settings = try await SwiftUIAppSettings.load(
            cliOverrides: [.cli(flag: "--cache-dir", keyPath: ["cacheDir"], value: .string("~/Library/Caches/myapp"))],
            environment: [:],
            workingDirectory: "/work",
            homeDirectory: "/Users/alice",
            fileSystem: fs
        )

        #expect(settings.environmentName == "staging")
        #expect(settings.cacheDir == "/Users/alice/Library/Caches/myapp")
        #expect(settings.searchPaths == ["/opt/plugins", "/usr/local/plugins"])
        #expect(settings.logLevel == .warn)
        // Merged from both `customizeSources` InitSource and `.env` nested dictionary key!
        #expect(settings.labels == ["managedBy": "rigging", "REGION": "ap-southeast-2"])
        #expect(settings.webhook?.endpoint == URL(string: "https://hooks.example.com/events"))
        #expect(settings.webhook?.signingSecret.expose { $0 } == "hmac-signing-secret-1234")
        #expect(settings.$cacheDir.source == .cliArgument(flag: "--cache-dir"))
    }

    @Test("jsonSchema(), dotEnvTemplate(), and markdownDocs() export extracted doc comments, defaults, and redacted secrets")
    func schemaAndDocumentationExporters() throws {
        // 1. Draft 2020-12 JSON Schema
        let schemaJSON = ASCSettings.jsonSchema()
        let root = try #require(
            JSONSerialization.jsonObject(with: Data(schemaJSON.utf8)) as? [String: Any]
        )

        #expect(root["$schema"] as? String == "https://json-schema.org/draft/2020-12/schema")
        #expect(root["title"] as? String == "ASCSettings")
        #expect(root["additionalProperties"] as? Bool == false)

        let properties = try #require(root["properties"] as? [String: Any])
        #expect(properties["profiles"] != nil)

        let keyIdProp = try #require(properties["keyId"] as? [String: Any])
        #expect(keyIdProp["description"] as? String == #"App Store Connect API Key ID (e.g., "ABC1234567")"#)

        let issuerProp = try #require(properties["issuerId"] as? [String: Any])
        #expect(issuerProp["format"] as? String == "uuid")

        let privateKeyProp = try #require(properties["privateKey"] as? [String: Any])
        #expect(privateKeyProp["writeOnly"] as? Bool == true)
        #expect(privateKeyProp["x-secret"] as? Bool == true)
        #expect(privateKeyProp["default"] == nil)

        let readOnlyProp = try #require(properties["readOnly"] as? [String: Any])
        #expect(readOnlyProp["default"] as? Bool == false)

        let signingProp = try #require(properties["signing"] as? [String: Any])
        let signingNestedProps = try #require(signingProp["properties"] as? [String: Any])
        let teamIdProp = try #require(signingNestedProps["teamId"] as? [String: Any])
        #expect(teamIdProp["description"] as? String == "Apple Developer Team ID")

        // Also check CaseIterable enum schema export on SwiftUIAppSettings
        let riggedSchema = try #require(
            JSONSerialization.jsonObject(with: Data(SwiftUIAppSettings.jsonSchema().utf8)) as? [String: Any]
        )
        let riggedProps = try #require(riggedSchema["properties"] as? [String: Any])
        let logLevelProp = try #require(riggedProps["logLevel"] as? [String: Any])
        #expect(logLevelProp["enum"] as? [String] == ["debug", "info", "warn", "error"])

        // 2. .env.example Template
        let dotEnv = ASCSettings.dotEnvTemplate()
        #expect(dotEnv.contains("# App Store Connect API Key ID (e.g., \"ABC1234567\")"))
        #expect(dotEnv.contains("ASC_KEY_ID="))
        #expect(dotEnv.contains("ASC_READ_ONLY=false"))
        #expect(dotEnv.contains("ASC_TIMEOUT=30s"))
        #expect(dotEnv.contains("ASC_SIGNING__ENABLED=false"))
        #expect(dotEnv.contains("# ASC_SIGNING__CERTIFICATE="))

        // 3. Markdown Reference Table
        let markdown = ASCSettings.markdownDocs()
        #expect(markdown.contains("# ASCSettings"))
        #expect(markdown.contains("| `keyId` | `ASC_KEY_ID` | `String` | Yes |"))
        #expect(markdown.contains("| `privateKey` | `ASC_PRIVATE_KEY` | `Secret<String>` | Yes | — |"))
        #expect(markdown.contains("*(Secret)*"))
        #expect(markdown.contains("| `signing.certificate` | `ASC_SIGNING__CERTIFICATE` | `Secret<Data>?` | No |"))
    }
}
