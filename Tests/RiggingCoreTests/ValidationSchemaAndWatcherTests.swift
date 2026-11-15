import Foundation
import RiggingCore
import RiggingTesting
import Synchronization
import Testing

// MARK: - Reloadable RiggedSettings Fixture for SettingsWatcher & Schema Tests

private struct ReloadableServerSettings: RiggedSettings, Equatable, Sendable {
    static let configuration = SettingsConfiguration(
        envPrefix: "SRV_",
        envNestedDelimiter: "__",
        extraKeys: .forbid,
        projectConfigFiles: [".srv.json"],
        xdgAppName: "srv"
    )

    static let fieldDescriptors: [SettingFieldDescriptor] = [
        SettingFieldDescriptor(
            name: "host",
            keyPath: ["host"],
            typeName: "String",
            schemaType: .string(),
            hasDefault: true,
            defaultDisplay: "127.0.0.1",
            help: "Bind address for HTTP server"
        ),
        SettingFieldDescriptor(
            name: "port",
            keyPath: ["port"],
            typeName: "Int",
            schemaType: .integer,
            hasDefault: true,
            defaultDisplay: "8080",
            help: "TCP listen port"
        ),
        SettingFieldDescriptor(
            name: "apiSecret",
            keyPath: ["apiSecret"],
            typeName: "Secret<String>",
            schemaType: .string(),
            isSecret: true,
            help: "API signing secret",
            deprecated: "Migrate to mTLS client certificates"
        ),
        SettingFieldDescriptor(
            name: "corsOrigins",
            keyPath: ["corsOrigins"],
            typeName: "[String]?",
            schemaType: .array(items: .string()),
            isOptional: true,
            help: "Allowed CORS origins | comma-separated"
        ),
    ]

    let host: String
    let port: Int
    let apiSecret: Secret<String>
    let corsOrigins: [String]?
    let provenance: ProvenanceReport

    static func validate(_ settings: ReloadableServerSettings) -> [ValidationIssue] {
        if settings.host == "0.0.0.0" && settings.port == 80 {
            return [
                ValidationIssue(
                    path: ["port"],
                    kind: .crossField,
                    message: "Unencrypted port 80 is forbidden when bound to 0.0.0.0."
                )
            ]
        }
        return []
    }

    static func load(context: SettingsContext, overrides: [SettingOverride]) async throws -> ReloadableServerSettings {
        var loader = try await SettingsLoader.prepare(for: Self.self, context: context, overrides: overrides)
        loader.enqueueSecret(keyPath: ["apiSecret"])
        await loader.resolveEnqueuedSecrets()

        let hostMeta = loader.decodeDefaulted(
            String.self,
            default: "127.0.0.1",
            keyPath: ["host"],
            validators: [.nonEmpty]
        )
        let portMeta = loader.decodeDefaulted(
            Int.self,
            default: 8080,
            keyPath: ["port"],
            validators: [.range(1...65535)]
        )
        let secretMeta = loader.decodeRequiredSecret(
            String.self,
            keyPath: ["apiSecret"],
            validators: [.minLength(8)]
        )
        let corsMeta = loader.decodeOptional([String].self, keyPath: ["corsOrigins"])

        try loader.throwIfInvalid()
        let model = ReloadableServerSettings(
            host: hostMeta!.value,
            port: portMeta!.value,
            apiSecret: secretMeta!.value,
            corsOrigins: corsMeta!.value,
            provenance: loader.buildProvenanceReport()
        )
        return try loader.finalize(model)
    }
}

@Suite("Validators, Multi-Issue ValidationError, Exporters & SettingsWatcher")
struct ValidationSchemaAndWatcherTests {

    @Test("Built-in SettingValidator rules (.nonEmpty, .range, .regex, .url, .oneOf, .fileExists, .forSecret)")
    func builtInValidators() {
        let context = SettingsContext.inMemory(
            files: ["/Users/test/cert.pem": "CERT"],
            directories: ["/Users/test/certs"],
            homeDirectory: "/Users/test"
        )

        #expect(SettingValidator<String>.nonEmpty.validate("ok", context: context) == nil)
        #expect(SettingValidator<String>.nonEmpty.validate("   ", context: context) != nil)

        #expect(SettingValidator<Int>.range(1...10).validate(5, context: context) == nil)
        #expect(SettingValidator<Int>.range(1...10).validate(11, context: context) != nil)
        #expect(SettingValidator<Int>.range(1..<10).validate(10, context: context) != nil)

        let keyIdRegex = SettingValidator<String>.regex(#"^[A-Z0-9]{10}$"#, message: "Must be 10 uppercase chars")
        #expect(keyIdRegex.validate("ABC1234567", context: context) == nil)
        #expect(keyIdRegex.validate("bad", context: context) == "Must be 10 uppercase chars")

        let urlRule = SettingValidator<String>.url(allowedSchemes: ["https"])
        #expect(urlRule.validate("https://example.com/api", context: context) == nil)
        #expect(urlRule.validate("http://example.com/api", context: context) != nil)

        #expect(SettingValidator<String>.oneOf(["dev", "prod"]).validate("prod", context: context) == nil)
        #expect(SettingValidator<String>.oneOf(["dev", "prod"]).validate("qa", context: context) != nil)

        let fileCheck = SettingValidator<String>.fileExists(mustBeDirectory: false)
        #expect(fileCheck.validate("~/cert.pem", context: context) == nil)
        #expect(fileCheck.validate("~/certs", context: context) != nil)
        #expect(fileCheck.validate("~/missing.pem", context: context) != nil)

        // Secret validator scrubs plaintext from error reason
        let leakedValue = "bad-secret-value-12345"
        context.redactor.register(leakedValue)
        let secretValidator = SettingValidator<String>.custom { val in
            "Rejected secret '\(val)'"
        }.forSecret()
        let failure = secretValidator.validate(Secret(leakedValue), context: context)
        #expect(failure == "Rejected secret '**********'")
    }

    @Test("SettingsValidationError aggregates multiple issues, computes exit codes 2/4/6, and emits deterministic JSON")
    func validationErrorAggregationExitCodesAndJSON() throws {
        let redactor = DiagnosticRedactor()
        redactor.register("super-secret-inline")

        let issue2a = ValidationIssue(
            keyPath: ["issuerId"],
            kind: .missingRequired,
            message: "Missing required setting 'issuerId'.",
            envVariableHint: "ASC_ISSUER_ID"
        )
        let issue2b = ValidationIssue(
            keyPath: ["port"],
            kind: .invalidValue,
            message: "Port out of range."
        )
        let errExit2 = SettingsValidationError(issues: [issue2a, issue2b], redactor: redactor)
        #expect(errExit2.exitCode == 2)
        #expect(errExit2.issues.count == 2)

        let issue4 = ValidationIssue(
            keyPath: ["privateKey"],
            kind: .unsafeSecret,
            message: "Committed secret super-secret-inline in config.",
            remediation: "Fix: chmod 600 /path/key.p8"
        )
        let errExit4 = SettingsValidationError(issues: [issue2a, issue4], redactor: redactor)
        #expect(errExit4.exitCode == 4)
        #expect(!errExit4.description.contains("super-secret-inline"))
        #expect(errExit4.description.contains("**********"))

        let issue6 = ValidationIssue(
            keyPath: ["vaultToken"],
            kind: .providerFailure,
            message: "1Password session locked."
        )
        let errExit6 = SettingsValidationError(issues: [issue2a, issue4, issue6], redactor: redactor)
        #expect(errExit6.exitCode == 6)

        let jsonBytes = errExit6.jsonPayload(prettyPrinted: true, redactor: redactor)
        let jsonText = String(decoding: jsonBytes, as: UTF8.self)
        #expect(!jsonText.contains("super-secret-inline"))

        let parsed = try #require(try JSONSerialization.jsonObject(with: jsonBytes) as? [String: Any])
        #expect(parsed["errorCount"] as? Int == 3)
        #expect(parsed["exitCode"] as? Int == 6)
        let jsonIssues = try #require(parsed["issues"] as? [[String: Any]])
        #expect(jsonIssues.count == 3)
    }

    @Test("JSONSchemaExporter emits valid Draft 2020-12 schema with secret writeOnly markers and profiles")
    func jsonSchemaExporterDraft202012() throws {
        let schemaText = ReloadableServerSettings.jsonSchema(prettyPrinted: true)
        let data = try #require(schemaText.data(using: .utf8))
        let root = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])

        #expect(root["$schema"] as? String == JSONSchemaExporter.draft202012URI)
        #expect(root["title"] as? String == "ReloadableServerSettings")
        #expect(root["additionalProperties"] as? Bool == false)
        #expect(root["required"] as? [String] == ["apiSecret"])

        let properties = try #require(root["properties"] as? [String: Any])
        #expect(properties["$schema"] != nil)
        #expect(properties["profiles"] != nil)

        let secretProp = try #require(properties["apiSecret"] as? [String: Any])
        #expect(secretProp["writeOnly"] as? Bool == true)
        #expect(secretProp["x-secret"] as? Bool == true)
        #expect(secretProp["deprecated"] as? Bool == true)
        #expect(secretProp["default"] == nil)

        let portProp = try #require(properties["port"] as? [String: Any])
        #expect(portProp["type"] as? String == "integer")
        #expect(portProp["default"] as? Int == 8080)

        let corsProp = try #require(properties["corsOrigins"] as? [String: Any])
        #expect(corsProp["type"] as? [String] == ["array", "null"])
    }

    @Test("DotEnvExporter generates .env.example template and escaped GFM Markdown docs")
    func dotEnvAndMarkdownExporters() {
        let dotEnvExample = ReloadableServerSettings.dotEnvTemplate(includeDefaults: true)
        #expect(dotEnvExample.contains("# Bind address for HTTP server"))
        #expect(dotEnvExample.contains("SRV_HOST=127.0.0.1"))
        #expect(dotEnvExample.contains("SRV_PORT=8080"))
        #expect(dotEnvExample.contains("# DEPRECATED: Migrate to mTLS client certificates"))
        #expect(dotEnvExample.contains("SRV_API_SECRET="))
        #expect(dotEnvExample.contains("# SRV_CORS_ORIGINS="))

        let markdown = ReloadableServerSettings.markdownDocs()
        #expect(markdown.contains("# ReloadableServerSettings"))
        #expect(markdown.contains("| `apiSecret` | `SRV_API_SECRET` | `Secret<String>` | Yes | — |"))
        // Pipe inside description is properly escaped so table columns never break
        #expect(markdown.contains(#"Allowed CORS origins \| comma-separated"#))
    }

    @Test("SettingsWatcher reloads valid file edits atomically and preserves current snapshot on invalid edits")
    func settingsWatcherLiveReloadAndRollbackOnInvalidEdit() async throws {
        let fs = InMemoryFileSystem(
            files: [
                "/repo/.srv.json": #"{"host": "127.0.0.1", "port": 8080}"#
            ],
            directories: ["/repo/.git"]
        )
        let context = SettingsContext.inMemory(
            environment: ["SRV_API_SECRET": "initial-valid-secret"],
            fileSystem: fs
        )

        let observedErrors = Mutex<[String]>([])
        let watcher = try await SettingsWatcher<ReloadableServerSettings>.start(
            context: context,
            watchedPaths: ["/repo/.srv.json"],
            pollInterval: .milliseconds(30),
            debounce: .milliseconds(10),
            onError: { err in
                observedErrors.withLock { $0.append(String(describing: err)) }
            }
        )

        #expect(await watcher.current.port == 8080)

        let stream = await watcher.updates()
        let firstUpdateTask = Task { () -> ReloadableServerSettings? in
            for await updated in stream {
                return updated
            }
            return nil
        }

        // Write a valid update -> watcher reloads and yields new snapshot
        fs.writeString(#"{"host": "127.0.0.1", "port": 9090}"#, atPath: "/repo/.srv.json")
        let emitted = try #require(await firstUpdateTask.value)
        #expect(emitted.port == 9090)
        #expect(await watcher.current.port == 9090)

        // Write an invalid cross-field update (0.0.0.0:80) -> reloadNow throws, current stays 9090!
        fs.writeString(#"{"host": "0.0.0.0", "port": 80}"#, atPath: "/repo/.srv.json")
        await #expect(throws: SettingsValidationError.self) {
            try await watcher.reloadNow()
        }
        #expect(await watcher.current.port == 9090)
        #expect(await watcher.current.host == "127.0.0.1")

        await watcher.stop()
    }
}
