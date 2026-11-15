import Foundation
import RiggingCore
import RiggingTesting
import Testing

// MARK: - Hand-Wired RiggedSettings Fixture for Core Cascade Verification

private struct CascadeNestedSettings: RiggedNestedSettings, Equatable, Sendable {
    let enabled: Bool
    let enabledMeta: SettingMetadata<Bool>

    static func fieldDescriptors(
        prefix: [String],
        configuration: SettingsConfiguration
    ) -> [SettingFieldDescriptor] {
        [
            SettingFieldDescriptor(
                name: "enabled",
                keyPath: prefix + ["enabled"],
                typeName: "Bool",
                schemaType: .boolean,
                hasDefault: true,
                defaultDisplay: "false"
            )
        ]
    }

    static func enqueueSecrets(into loader: inout SettingsLoader, prefix: [String]) {}

    static func decodeNested(from loader: inout SettingsLoader, prefix: [String]) -> CascadeNestedSettings? {
        guard let meta = loader.decodeDefaulted(
            Bool.self,
            default: false,
            keyPath: prefix + ["enabled"]
        ) else {
            return nil
        }
        return CascadeNestedSettings(enabled: meta.value, enabledMeta: meta)
    }
}

private struct EightLayerSettings: RiggedSettings, Equatable, Sendable {
    static let configuration = SettingsConfiguration(
        envPrefix: "APP_",
        envNestedDelimiter: "__",
        dotEnvFiles: [".env", ".env.local"],
        projectConfigFiles: [".app.json"],
        xdgAppName: "riggingapp",
        secretsDirectory: "/run/secrets",
        managedPreferencesDomain: "com.example.riggingapp"
    )

    static let fieldDescriptors: [SettingFieldDescriptor] = [
        SettingFieldDescriptor(
            name: "endpoint",
            keyPath: ["endpoint"],
            typeName: "String",
            schemaType: .string(),
            hasDefault: true,
            defaultDisplay: "https://default.example.com"
        ),
        SettingFieldDescriptor(
            name: "readOnly",
            keyPath: ["readOnly"],
            typeName: "Bool",
            schemaType: .boolean,
            hasDefault: true,
            defaultDisplay: "false"
        ),
        SettingFieldDescriptor(
            name: "feature",
            keyPath: ["feature"],
            typeName: "CascadeNestedSettings",
            schemaType: .object(
                fields: CascadeNestedSettings.fieldDescriptors(
                    prefix: ["feature"],
                    configuration: configuration
                )
            ),
            hasDefault: true
        ),
    ]

    let endpoint: String
    let endpointMeta: SettingMetadata<String>
    let readOnly: Bool
    let readOnlyMeta: SettingMetadata<Bool>
    let feature: CascadeNestedSettings
    let provenance: ProvenanceReport

    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        // Inject deterministic mock managed preferences at the standard 7th slot
        [
            defaults.initOverrides,
            defaults.environment,
            defaults.dotEnv,
            defaults.secretsDirectory,
            defaults.projectConfig,
            defaults.userConfig,
            ManagedPreferencesSource(
                domain: "com.example.riggingapp",
                mockValues: ["endpoint": .string("https://mdm.example.com")]
            ),
        ]
    }

    static func load(context: SettingsContext, overrides: [SettingOverride]) async throws -> EightLayerSettings {
        var loader = try await SettingsLoader.prepare(for: Self.self, context: context, overrides: overrides)
        CascadeNestedSettings.enqueueSecrets(into: &loader, prefix: ["feature"])
        await loader.resolveEnqueuedSecrets()

        let endpointMeta = loader.decodeDefaulted(
            String.self,
            default: "https://default.example.com",
            keyPath: ["endpoint"]
        )
        let readOnlyMeta = loader.decodeDefaulted(
            Bool.self,
            default: false,
            keyPath: ["readOnly"]
        )
        let featureVal = loader.decodeNested(CascadeNestedSettings.self, keyPath: ["feature"])

        try loader.throwIfInvalid()
        let resolvedEndpoint = endpointMeta!
        let resolvedReadOnly = readOnlyMeta!
        let resolvedFeature = featureVal!

        let model = EightLayerSettings(
            endpoint: resolvedEndpoint.value,
            endpointMeta: resolvedEndpoint,
            readOnly: resolvedReadOnly.value,
            readOnlyMeta: resolvedReadOnly,
            feature: resolvedFeature,
            provenance: loader.buildProvenanceReport()
        )
        return try loader.finalize(model)
    }
}

private struct DefaultOnlySettings: RiggedSettings, Sendable {
    static let configuration = SettingsConfiguration(envPrefix: "DEF_")
    static let fieldDescriptors: [SettingFieldDescriptor] = [
        SettingFieldDescriptor(
            name: "endpoint",
            keyPath: ["endpoint"],
            typeName: "String",
            schemaType: .string(),
            hasDefault: true,
            defaultDisplay: "https://default.example.com"
        )
    ]

    let endpoint: String
    let endpointMeta: SettingMetadata<String>
    let provenance: ProvenanceReport

    static func load(context: SettingsContext, overrides: [SettingOverride]) async throws -> DefaultOnlySettings {
        var loader = try await SettingsLoader.prepare(for: Self.self, context: context, overrides: overrides)
        let meta = loader.decodeDefaulted(
            String.self,
            default: "https://default.example.com",
            keyPath: ["endpoint"]
        )
        try loader.throwIfInvalid()
        let unwrapped = meta!
        return try loader.finalize(
            DefaultOnlySettings(
                endpoint: unwrapped.value,
                endpointMeta: unwrapped,
                provenance: loader.buildProvenanceReport()
            )
        )
    }
}

private struct EnforcedMDMSettings: RiggedSettings, Sendable {
    static let configuration = SettingsConfiguration(envPrefix: "MDM_")
    static let fieldDescriptors: [SettingFieldDescriptor] = [
        SettingFieldDescriptor(name: "readOnly", keyPath: ["readOnly"], typeName: "Bool", schemaType: .boolean, hasDefault: true)
    ]

    let readOnly: Bool
    let readOnlyMeta: SettingMetadata<Bool>
    let provenance: ProvenanceReport

    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        [
            ManagedPreferencesSource(
                domain: "com.corp.policy",
                mockValues: ["readOnly": .bool(true)]
            ),
            defaults.initOverrides,
            defaults.environment,
        ]
    }

    static func load(context: SettingsContext, overrides: [SettingOverride]) async throws -> EnforcedMDMSettings {
        var loader = try await SettingsLoader.prepare(for: Self.self, context: context, overrides: overrides)
        let meta = loader.decodeDefaulted(Bool.self, default: false, keyPath: ["readOnly"])
        try loader.throwIfInvalid()
        return try loader.finalize(
            EnforcedMDMSettings(
                readOnly: meta!.value,
                readOnlyMeta: meta!,
                provenance: loader.buildProvenanceReport()
            )
        )
    }
}

// MARK: - Tests

@Suite("8-Layer Source Precedence Cascade & Provenance")
struct PrecedenceCascadeTests {

    @Test("Full 8-layer precedence cascade and overriddenOrigins tracking")
    func fullEightLayerPrecedenceAndOverriddenOrigins() async throws {
        let baseFiles: [String: String] = [
            "/repo/.env": "APP_ENDPOINT=https://dotenv1.example.com\n",
            "/repo/.env.local": "APP_ENDPOINT=https://dotenv2.example.com\n",
            "/run/secrets/APP_ENDPOINT": "https://secretsdir.example.com\n",
            "/repo/.app.json": #"{"endpoint": "https://project.example.com"}"#,
            "/Users/test/.config/riggingapp/config.json": #"{"endpoint": "https://user.example.com"}"#,
        ]

        // 1. CLI argument beats initOverride, environment, .env.local, .env, secretsDir, projectConfig, userConfig, managedPolicy
        let cliContext = SettingsContext.inMemory(
            cli: ["endpoint": "https://cli.example.com"],
            environment: ["APP_ENDPOINT": "https://env.example.com"],
            files: baseFiles,
            directories: ["/repo/.git"]
        )
        let fromCLI = try await EightLayerSettings.load(
            context: cliContext,
            overrides: [.initValue(keyPath: ["endpoint"], value: .string("https://init.example.com"))]
        )
        #expect(fromCLI.endpoint == "https://cli.example.com")
        #expect(fromCLI.endpointMeta.source == .cliArgument(flag: "--endpoint"))
        #expect(
            fromCLI.endpointMeta.overriddenSources == [
                .initOverride(keyPath: ["endpoint"]),
                .environment(variable: "APP_ENDPOINT"),
                .dotEnv(path: "/repo/.env.local", line: 1, variable: "APP_ENDPOINT"),
                .dotEnv(path: "/repo/.env", line: 1, variable: "APP_ENDPOINT"),
                .secretsDirectory(path: "/run/secrets/APP_ENDPOINT"),
                .projectConfig(path: "/repo/.app.json", keyPath: ["endpoint"], profile: nil),
                .userConfig(path: "/Users/test/.config/riggingapp/config.json", keyPath: ["endpoint"], profile: nil),
                .managedPolicy(domain: "com.example.riggingapp", key: "endpoint"),
            ]
        )

        // 2. Programmatic initOverride beats environment when no CLI flag is set
        let initContext = SettingsContext.inMemory(
            environment: ["APP_ENDPOINT": "https://env.example.com"],
            files: baseFiles,
            directories: ["/repo/.git"]
        )
        let fromInit = try await EightLayerSettings.load(
            context: initContext,
            overrides: [.initValue(keyPath: ["endpoint"], value: .string("https://init.example.com"))]
        )
        #expect(fromInit.endpoint == "https://init.example.com")
        #expect(fromInit.endpointMeta.origin == .initOverride(keyPath: ["endpoint"]))
        #expect(fromInit.endpointMeta.overriddenOrigins.first == .environment(variable: "APP_ENDPOINT"))

        // 3. Environment beats .env.local & .env
        let fromEnv = try await EightLayerSettings.load(context: initContext)
        #expect(fromEnv.endpoint == "https://env.example.com")
        #expect(fromEnv.endpointMeta.origin == .environment(variable: "APP_ENDPOINT"))

        // 4. .env.local beats .env, which beats secretsDir
        let dotEnvContext = SettingsContext.inMemory(
            files: baseFiles,
            directories: ["/repo/.git"]
        )
        let fromDotEnv = try await EightLayerSettings.load(context: dotEnvContext)
        #expect(fromDotEnv.endpoint == "https://dotenv2.example.com")
        #expect(fromDotEnv.endpointMeta.origin == .dotEnv(path: "/repo/.env.local", line: 1, variable: "APP_ENDPOINT"))
        #expect(fromDotEnv.endpointMeta.overriddenOrigins.first == .dotEnv(path: "/repo/.env", line: 1, variable: "APP_ENDPOINT"))

        // 5. secretsDirectory beats projectConfig
        var withoutDotEnv = baseFiles
        withoutDotEnv.removeValue(forKey: "/repo/.env")
        withoutDotEnv.removeValue(forKey: "/repo/.env.local")
        let fromSecretsDir = try await EightLayerSettings.load(
            context: .inMemory(files: withoutDotEnv, directories: ["/repo/.git"])
        )
        #expect(fromSecretsDir.endpoint == "https://secretsdir.example.com")
        #expect(fromSecretsDir.endpointMeta.origin == .secretsDirectory(path: "/run/secrets/APP_ENDPOINT"))

        // 6. projectConfig beats userConfig
        var withoutSecretsDir = withoutDotEnv
        withoutSecretsDir.removeValue(forKey: "/run/secrets/APP_ENDPOINT")
        let fromProject = try await EightLayerSettings.load(
            context: .inMemory(files: withoutSecretsDir, directories: ["/repo/.git"])
        )
        #expect(fromProject.endpoint == "https://project.example.com")
        #expect(fromProject.endpointMeta.origin == .projectConfig(path: "/repo/.app.json", keyPath: ["endpoint"], profile: nil))

        // 7. userConfig beats managedPolicy
        var withoutProject = withoutSecretsDir
        withoutProject.removeValue(forKey: "/repo/.app.json")
        let fromUser = try await EightLayerSettings.load(
            context: .inMemory(files: withoutProject, directories: ["/repo/.git"])
        )
        #expect(fromUser.endpoint == "https://user.example.com")
        #expect(
            fromUser.endpointMeta.origin
                == .userConfig(path: "/Users/test/.config/riggingapp/config.json", keyPath: ["endpoint"], profile: nil)
        )

        // 8. managedPolicy beats defaultValue
        let fromManaged = try await EightLayerSettings.load(context: .inMemory())
        #expect(fromManaged.endpoint == "https://mdm.example.com")
        #expect(fromManaged.endpointMeta.origin == .managedPolicy(domain: "com.example.riggingapp", key: "endpoint"))

        // 9. defaultValue when no source supplies the key
        let fromDefault = try await DefaultOnlySettings.load(context: .inMemory())
        #expect(fromDefault.endpoint == "https://default.example.com")
        #expect(fromDefault.endpointMeta.origin == .defaultValue)
        #expect(fromDefault.endpointMeta.overriddenOrigins.isEmpty)
    }

    @Test("Unset nil CLI optionals do not clobber environment or config files")
    func nilCLIOptionalsDoNotClobberLowerLayers() async throws {
        let unsetFlag: Bool? = nil
        let context = SettingsContext.inMemory(
            cli: ["readOnly": unsetFlag as Any],
            environment: [
                "APP_READ_ONLY": "true",
                "APP_FEATURE__ENABLED": "true",
            ]
        )

        let settings = try await EightLayerSettings.load(context: context)
        #expect(settings.readOnly == true)
        #expect(settings.readOnlyMeta.origin == .environment(variable: "APP_READ_ONLY"))
        #expect(settings.feature.enabled == true)
        #expect(settings.feature.enabledMeta.origin == .environment(variable: "APP_FEATURE__ENABLED"))

        // Explicit false CLI flag DOES override environment true
        let explicitFalse = try await EightLayerSettings.load(
            context: .inMemory(
                cli: ["readOnly": false],
                environment: ["APP_READ_ONLY": "true"]
            )
        )
        #expect(explicitFalse.readOnly == false)
        #expect(explicitFalse.readOnlyMeta.origin == .cliArgument(flag: "--read-only"))
        #expect(explicitFalse.readOnlyMeta.overriddenOrigins == [.environment(variable: "APP_READ_ONLY")])
    }

    @Test("customizeSources allows enterprise MDM policy to override environment and CLI")
    func customSourceOrderingOverridesEnvironment() async throws {
        let settings = try await EnforcedMDMSettings.load(
            context: .inMemory(
                cli: ["readOnly": false],
                environment: ["MDM_READ_ONLY": "false"]
            )
        )
        #expect(settings.readOnly == true)
        #expect(settings.readOnlyMeta.origin == .managedPolicy(domain: "com.corp.policy", key: "readOnly"))
        #expect(settings.readOnlyMeta.overriddenOrigins.contains(.cliArgument(flag: "--read-only")))
        #expect(settings.readOnlyMeta.overriddenOrigins.contains(.environment(variable: "MDM_READ_ONLY")))
    }

    @Test("ProvenanceReport formats human table and deterministic JSON")
    func provenanceReportFormatting() async throws {
        let settings = try await EightLayerSettings.load(
            context: .inMemory(
                cli: ["readOnly": true],
                environment: ["APP_READ_ONLY": "false"]
            )
        )
        let table = settings.provenanceReport().formattedTable()
        #expect(table.contains("readOnly = true  [CLI flag --read-only] (overrides: environment APP_READ_ONLY)"))

        let jsonData = try settings.provenance.jsonPayload(prettyPrinted: false)
        let decoded = try JSONDecoder().decode(ProvenanceReport.self, from: jsonData)
        #expect(decoded["readOnly"]?.origin == .cliArgument(flag: "--read-only"))
    }
}
