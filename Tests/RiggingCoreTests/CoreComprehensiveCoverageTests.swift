import Foundation
import RiggingCore
import RiggingTesting
import Synchronization
import Testing

// MARK: - Helper Types for Comprehensive Core Coverage

private enum SampleIntEnum: Int, SettingValueDecodable {
    case zero = 0
    case one = 1
}

private enum NonCaseIterableStringEnum: String, SettingValueDecodable {
    case alpha
    case beta
}

private enum CaseIterableEnvMode: String, CaseIterable, SettingValueDecodable {
    case development
    case production
}

private struct ThrowingValidationSource: SettingsSource {
    let throwError: any Error
    func load(configuration: SettingsConfiguration, context: SettingsContext) async throws -> RawConfigTree {
        throw throwError
    }
}

private struct ValidatedNestedConfig: RiggedNestedSettings, Equatable, Sendable {
    var minThreads: Int
    var maxThreads: Int

    static func fieldDescriptors(
        prefix: [String],
        configuration: SettingsConfiguration
    ) -> [SettingFieldDescriptor] {
        [
            SettingFieldDescriptor(
                name: "minThreads",
                keyPath: prefix + ["minThreads"],
                typeName: "Int",
                schemaType: .integer,
                hasDefault: true,
                defaultDisplay: "1"
            ),
            SettingFieldDescriptor(
                name: "maxThreads",
                keyPath: prefix + ["maxThreads"],
                typeName: "Int",
                schemaType: .integer,
                hasDefault: true,
                defaultDisplay: "4"
            ),
        ]
    }

    static func enqueueSecrets(into loader: inout SettingsLoader, prefix: [String]) {}

    static func decodeNested(from loader: inout SettingsLoader, prefix: [String]) -> ValidatedNestedConfig? {
        let minMeta = loader.decodeDefaulted(Int.self, default: 1, keyPath: prefix + ["minThreads"])
        let maxMeta = loader.decodeDefaulted(Int.self, default: 4, keyPath: prefix + ["maxThreads"])
        guard let minVal = minMeta?.value, let maxVal = maxMeta?.value else { return nil }
        return ValidatedNestedConfig(minThreads: minVal, maxThreads: maxVal)
    }

    static func validate(_ settings: ValidatedNestedConfig, prefix: [String]) -> [ValidationIssue] {
        if settings.minThreads > settings.maxThreads {
            return [
                ValidationIssue(
                    keyPath: prefix,
                    kind: .invalidValue,
                    message: "minThreads (\(settings.minThreads)) must not exceed maxThreads (\(settings.maxThreads))."
                ),
            ]
        }
        return []
    }
}

private struct ManualLoaderSettings: RiggedSettings, Equatable, Sendable {
    static let configuration = SettingsConfiguration(
        envPrefix: "MANUAL_",
        extraKeys: .warn,
        projectConfigFiles: [".manual.json"],
        xdgAppName: "manualapp"
    )

    static let fieldDescriptors: [SettingFieldDescriptor] = [
        SettingFieldDescriptor(
            name: "host",
            keyPath: ["host"],
            envVariable: "MANUAL_HOST_OVERRIDE",
            aliases: [.env("LEGACY_MANUAL_HOST"), .configPath(["legacy", "host"]), .cli("--custom-host")],
            typeName: "String",
            schemaType: .string(),
            hasDefault: true,
            defaultDisplay: "localhost",
            documentation: "Primary hostname"
        ),
        SettingFieldDescriptor(
            name: "labels",
            keyPath: ["labels"],
            aliases: [.configPath(["altLabels"]), .env("MANUAL_ALT_LABELS"), .cli("--alt-labels")],
            typeName: "[String: String]",
            schemaType: .dictionary(values: .string()),
            hasDefault: true,
            allowsArbitraryChildKeys: true
        ),
        SettingFieldDescriptor(
            name: "pool",
            keyPath: ["pool"],
            typeName: "ValidatedNestedConfig",
            schemaType: .object(
                fields: ValidatedNestedConfig.fieldDescriptors(
                    prefix: [],
                    configuration: SettingsConfiguration(envPrefix: "MANUAL_")
                )
            ),
            hasDefault: true
        ),
    ]

    var host: String
    var labels: [String: String]
    var pool: ValidatedNestedConfig
    var provenance: ProvenanceReport

    static func load(context: SettingsContext, overrides: [SettingOverride]) async throws -> ManualLoaderSettings {
        var loader = try await SettingsLoader.prepare(for: Self.self, context: context, overrides: overrides)
        let hostMeta = loader.decodeDefaulted(
            String.self,
            default: "localhost",
            keyPath: ["host"],
            aliases: [.env("LEGACY_MANUAL_HOST"), .configPath(["legacy", "host"]), .cli("--custom-host")]
        )
        let labelsMeta = loader.decodeDefaulted(
            [String: String].self,
            default: [:],
            keyPath: ["labels"],
            aliases: [.configPath(["altLabels"])]
        )
        let poolVal = loader.decodeNested(ValidatedNestedConfig.self, keyPath: ["pool"])
        try loader.throwIfInvalid()
        let built = ManualLoaderSettings(
            host: hostMeta!.value,
            labels: labelsMeta!.value,
            pool: poolVal!,
            provenance: loader.buildProvenanceReport()
        )
        return try loader.finalize(built)
    }

    static func validate(_ settings: ManualLoaderSettings) -> [ValidationIssue] {
        if settings.host == "forbidden.internal" {
            return [
                ValidationIssue(
                    keyPath: ["host"],
                    kind: .invalidValue,
                    message: "Host 'forbidden.internal' is disallowed."
                ),
            ]
        }
        return []
    }
}

// MARK: - Suite 1: SettingsProtocol, Origins, LocalFileSystem & ProcessSubprocessRunner

@Suite("SettingsProtocol, LocalFileSystem & ProcessSubprocessRunner Coverage")
struct SettingsProtocolCoverageTests {
    @Test("SettingOrigin descriptions, SettingOverride, EnvCollectionStrategy Codable, and ProvenanceReport helpers")
    func originDescriptionsAndCodableRoundTrips() throws {
        let origins: [(SettingOrigin, String)] = [
            (.initOverride(keyPath: ["db", "port"]), "init override (db.port)"),
            (.cliArgument(flag: "--port"), "CLI flag --port"),
            (.environment(variable: "APP_PORT"), "environment APP_PORT"),
            (.dotEnv(path: ".env", line: 7, variable: "APP_PORT"), ".env:7 (APP_PORT)"),
            (.secretsDirectory(path: "/run/secrets/db_pass"), "secrets file /run/secrets/db_pass"),
            (.projectConfig(path: "/repo/.app.json", keyPath: ["db", "port"], profile: nil), "project config /repo/.app.json → db.port"),
            (.projectConfig(path: "/repo/.app.json", keyPath: ["db", "port"], profile: "prod"), "project config /repo/.app.json [profile: prod] → db.port"),
            (.userConfig(path: "/Users/jane/.config/app/config.json", keyPath: ["theme"], profile: nil), "user config /Users/jane/.config/app/config.json → theme"),
            (.userConfig(path: "/Users/jane/.config/app/config.json", keyPath: ["theme"], profile: "dark"), "user config /Users/jane/.config/app/config.json [profile: dark] → theme"),
            (.managedPolicy(domain: "com.example.asc", key: "readOnly"), "managed policy com.example.asc (readOnly)"),
            (.customSource(name: "Vault", detail: ""), "Vault"),
            (.customSource(name: "Vault", detail: "kv/prod"), "Vault (kv/prod)"),
            (.secretProvider(scheme: "op", referenceRedacted: "op://Vault/Item/field", via: .environment(variable: "TOKEN")), "op://Vault/Item/field via environment TOKEN"),
            (.defaultValue, "default value"),
        ]

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        for (origin, expectedText) in origins {
            #expect(origin.description == expectedText)
            let encoded = try encoder.encode(origin)
            let roundTripped = try decoder.decode(SettingOrigin.self, from: encoded)
            #expect(roundTripped == origin)
        }

        // EnvCollectionStrategy Codable round-trip + invalid JSON errors
        let strategies: [EnvCollectionStrategy] = [
            .jsonOrCommaSeparated,
            .jsonOnly,
            .separator(":"),
            .noDecode,
        ]
        for strategy in strategies {
            let data = try encoder.encode(strategy)
            let decoded = try decoder.decode(EnvCollectionStrategy.self, from: data)
            #expect(decoded == strategy)
        }
        #expect(throws: DecodingError.self) {
            _ = try decoder.decode(
                EnvCollectionStrategy.self,
                from: Data(#"{"kind":"separator","separator":""}"#.utf8)
            )
        }
        #expect(throws: DecodingError.self) {
            _ = try decoder.decode(
                EnvCollectionStrategy.self,
                from: Data(#"{"kind":"unknownStrategy"}"#.utf8)
            )
        }

        // SettingOverride helpers
        let cliOv = SettingOverride.cli(flag: "--host", keyPath: ["host"], value: .string("example.com"))
        let initOv = SettingOverride.initValue(keyPath: ["port"], value: .int(9000))
        #expect(cliOv.origin == .cliArgument(flag: "--host"))
        #expect(initOv.origin == .initOverride(keyPath: ["port"]))

        // SettingMetadata, ProvenanceEntry, ProvenanceReport empty & compact JSON
        let meta = SettingMetadata(
            keyPath: ["apiKey"],
            value: "secret-val",
            isSecret: true,
            origin: .environment(variable: "API_KEY"),
            overriddenOrigins: [.defaultValue]
        )
        #expect(meta.source == .environment(variable: "API_KEY"))
        #expect(meta.overriddenSources == [.defaultValue])
        #expect(meta.displayValue == "**********")
        #expect(meta.valueSummary == "**********")
        var setOfMeta = Set<SettingMetadata<String>>()
        setOfMeta.insert(meta)
        #expect(setOfMeta.contains(meta))
        let encodedMeta = try String(decoding: encoder.encode(meta), as: UTF8.self)
        #expect(encodedMeta.contains("**********"))
        #expect(!encodedMeta.contains("secret-val"))

        let emptyReport = ProvenanceReport()
        #expect(emptyReport.formattedTable() == "(no settings)")
        #expect(emptyReport.description == "(no settings)")
        #expect(emptyReport["missing"] == nil)

        let entry = ProvenanceEntry(
            keyPath: ["token"],
            typeName: "Secret<String>",
            isSecret: true,
            displayValue: "should-be-masked",
            origin: .environment(variable: "TOKEN"),
            overriddenOrigins: [.defaultValue]
        )
        #expect(entry.source == .environment(variable: "TOKEN"))
        #expect(entry.overriddenSources == [.defaultValue])
        #expect(entry.valueSummary == "**********")

        let populatedReport = ProvenanceReport(entries: [entry])
        let compactJSON = try populatedReport.jsonPayload(prettyPrinted: false)
        #expect(!compactJSON.isEmpty)

        // SettingFieldDescriptor secret default masking & documentation fallback
        let secretDesc = SettingFieldDescriptor(
            name: "secretField",
            keyPath: ["secretField"],
            typeName: "Secret<String>",
            isSecret: true,
            hasDefault: true,
            defaultDisplay: "never-show-this",
            documentation: "Doc fallback text"
        )
        #expect(secretDesc.defaultDisplay == nil)
        #expect(secretDesc.documentation == "Doc fallback text")

        // RiggedSettings convenience extensions
        #expect(!ManualLoaderSettings.jsonSchema(title: "Manual", prettyPrinted: false).isEmpty)
        #expect(ManualLoaderSettings.dotEnvTemplate(includeDefaults: false).contains("MANUAL_"))
        #expect(ManualLoaderSettings.markdownDocs(title: "Manual Config").contains("Manual Config"))
    }

    @Test("LocalFileSystem and ProcessSubprocessRunner operate safely against temporary files and system binaries")
    func localFileSystemAndProcessSubprocessRunner() async throws {
        let fs = LocalFileSystem()
        let tempDir = "/tmp/rigging-fs-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tempDir) }

        let textFile = "\(tempDir)/hello.txt"
        try Data("hello rigging".utf8).write(to: URL(fileURLWithPath: textFile))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: textFile)

        let invalidUTF8File = "\(tempDir)/binary.bin"
        try Data([0xFF, 0xFE, 0x00, 0x81]).write(to: URL(fileURLWithPath: invalidUTF8File))

        #expect(fs.fileExists(atPath: textFile))
        #expect(!fs.fileExists(atPath: "\(tempDir)/does-not-exist"))
        #expect(fs.isDirectory(atPath: tempDir))
        #expect(!fs.isDirectory(atPath: textFile))
        #expect(!fs.isDirectory(atPath: "\(tempDir)/does-not-exist"))
        #expect(try fs.readString(atPath: textFile) == "hello rigging")
        #expect(throws: (any Error).self) {
            _ = try fs.readString(atPath: invalidUTF8File)
        }
        #expect(try fs.contentsOfDirectory(atPath: tempDir) == ["binary.bin", "hello.txt"])
        #expect(try fs.posixPermissions(atPath: textFile) == 0o600)
        #expect(!fs.isExecutableFile(atPath: textFile))
        #expect(fs.isExecutableFile(atPath: "/bin/echo"))

        // SubprocessSecurityError descriptions
        let secErrors: [SubprocessSecurityError] = [
            .relativeExecutablePath("./op"),
            .executableNotFound("/missing/op"),
            .notExecutable(textFile),
            .worldWritableExecutable(path: "/tmp/bad", permissions: 0o777),
            .timedOut(executablePath: "/bin/sleep", duration: .seconds(1)),
            .unsupportedPlatform("Unsupported"),
        ]
        for err in secErrors {
            #expect(!err.description.isEmpty)
        }

        // verifyExecutableTrust & resolveTrustedExecutable
        #expect(throws: SubprocessSecurityError.self) {
            try ProcessSubprocessRunner.verifyExecutableTrust(atPath: "/bin/\0echo", fileSystem: fs)
        }
        #expect(throws: SubprocessSecurityError.self) {
            try ProcessSubprocessRunner.verifyExecutableTrust(atPath: textFile, fileSystem: fs)
        }
        #expect(throws: SubprocessSecurityError.self) {
            try ProcessSubprocessRunner.verifyExecutableTrust(atPath: tempDir, fileSystem: fs)
        }
        let resolvedEcho = try ProcessSubprocessRunner.resolveTrustedExecutable(
            named: "echo",
            searchDirectories: [tempDir, "/bin"],
            fileSystem: fs
        )
        #expect(resolvedEcho == "/bin/echo")
        let explicitEcho = try ProcessSubprocessRunner.resolveTrustedExecutable(
            named: "echo",
            explicitPath: "/bin/echo",
            fileSystem: fs
        )
        #expect(explicitEcho == "/bin/echo")
        #expect(throws: SubprocessSecurityError.self) {
            _ = try ProcessSubprocessRunner.resolveTrustedExecutable(
                named: "definitely-not-a-binary-\(UUID().uuidString)",
                searchDirectories: [tempDir],
                fileSystem: fs
            )
        }

        #if os(macOS)
        let runner = ProcessSubprocessRunner()
        let echoRes = try await runner.run(executablePath: "/bin/echo", arguments: ["hello-subprocess"])
        #expect(echoRes.exitCode == 0)
        #expect(echoRes.stdoutString.trimmingCharacters(in: .whitespacesAndNewlines) == "hello-subprocess")
        #expect(echoRes.stderrString.isEmpty)

        let catRes = try await runner.run(
            executablePath: "/bin/cat",
            arguments: [],
            environment: ["TEST_ENV": "1"],
            stdin: Data("piped-input".utf8),
            timeout: nil
        )
        #expect(catRes.exitCode == 0)
        #expect(catRes.stdoutString == "piped-input")

        await #expect(throws: SubprocessSecurityError.self) {
            _ = try await runner.run(
                executablePath: "/bin/sleep",
                arguments: ["5"],
                environment: nil,
                stdin: nil,
                timeout: .milliseconds(40)
            )
        }
        #endif
    }
}

// MARK: - Suite 2: RawConfigTree & ValueDecoding Exhaustive Edge Cases

@Suite("RawConfigTree & ValueDecoding Exhaustive Edge Cases")
struct RawConfigTreeAndValueDecodingCoverageTests {
    @Test("RawConfigTree handles isNull, isEmpty, scalar-to-object overwrite, container prefixes, and identifier normalization")
    func rawConfigTreeEdgeCases() {
        #expect(RawValue.null.isNull == true)
        #expect(RawValue.string("x").isNull == false)

        var tree = RawConfigTree.empty
        #expect(tree.isEmpty)

        // Empty path is a no-op
        tree.set(path: ["", ""], value: .string("ignored"), origin: .defaultValue)
        #expect(tree.isEmpty)
        #expect(tree.lookup(path: []) == nil)

        // Scalar overwritten by deeper nested path preserves displaced scalar origin
        tree.set(path: ["server"], value: .string("legacy-scalar"), origin: .userConfig(path: "/u", keyPath: ["server"], profile: nil))
        #expect(tree.lookup(path: ["server", "host"]) == nil)
        tree.set(path: ["server", "host"], value: .string("prod.internal"), origin: .environment(variable: "SERVER__HOST"))
        #expect(!tree.isEmpty)
        #expect(tree.lookup(path: ["server", "host"])?.value == .string("prod.internal"))
        #expect(tree.lookup(path: ["server"])?.overriddenOrigins.count == 1)

        // Empty object container prefix is NOT flagged as unknown when child paths are declared
        var emptyContainerTree = RawConfigTree.empty
        emptyContainerTree.set(path: ["signing"], value: .object([:]), origin: .projectConfig(path: "/p", keyPath: ["signing"], profile: nil))
        let unknowns = emptyContainerTree.unknownKeyPaths(
            declaredPaths: [["signing", "teamId"]],
            arbitraryChildPrefixes: [["labels"]]
        )
        #expect(unknowns.isEmpty)

        // Direct environment entry overwrite & case-sensitive lookup
        tree.setEnvironmentEntry("API_TOKEN", value: .string("first"), origin: .dotEnv(path: ".env", line: 1, variable: "API_TOKEN"))
        tree.setEnvironmentEntry("API_TOKEN", value: .string("second"), origin: .environment(variable: "API_TOKEN"))
        let envEntry = tree.lookupEnvironmentEntry("API_TOKEN")
        #expect(envEntry?.value == .string("second"))
        #expect(envEntry?.overriddenOrigins == [.dotEnv(path: ".env", line: 1, variable: "API_TOKEN")])
        #expect(tree.lookupEnvironmentEntry("api_token", caseSensitive: true) == nil)
        #expect(tree.lookup(path: ["SERVER", "HOST"], caseSensitive: true) == nil)

        // keysMatch without identifier normalization & trailing underscore normalization
        #expect(RawConfigTree.keysMatch("api_key", "apiKey", caseSensitive: false, allowIdentifierNormalization: false) == false)
        #expect(RawConfigTree.normalizeIdentifier("trailing_underscores___") == "trailing_underscores")
        #expect(RawConfigTree.normalizeIdentifier("") == "")
    }

    @Test("ValueDecoding covers every scalar width, overflow, error path, and collection strategy")
    func valueDecodingExhaustiveTypesAndErrors() throws {
        // String coercions & errors
        #expect(try String.decodeSettingValue(from: .bool(true)) == "true")
        #expect(try String.decodeSettingValue(from: .bool(false)) == "false")
        #expect(try String.decodeSettingValue(from: .int(42)) == "42")
        #expect(try String.decodeSettingValue(from: .double(3.5)) == "3.5")
        #expect(try String.decodeSettingValue(from: .data(Data("ok".utf8))) == "ok")
        #expect(throws: ValueDecodingError.self) { _ = try String.decodeSettingValue(from: .data(Data([0xFF, 0xFE]))) }
        #expect(throws: ValueDecodingError.self) { _ = try String.decodeSettingValue(from: .null) }

        // Bool errors
        #expect(try Bool.decodeSettingValue(from: .bool(true)) == true)
        #expect(throws: ValueDecodingError.self) { _ = try Bool.decodeSettingValue(from: .double(1.0)) }

        // All FixedWidthInteger types + double coercion + overflow/non-integer errors
        #expect(try Int.decodeSettingValue(from: .double(12.0)) == 12)
        #expect(try Int8.decodeSettingValue(from: .int(-128)) == -128)
        #expect(try Int16.decodeSettingValue(from: .string("32_000")) == 32000)
        #expect(try Int32.decodeSettingValue(from: .int(100_000)) == 100_000)
        #expect(try Int64.decodeSettingValue(from: .int(9_000_000_000)) == 9_000_000_000)
        #expect(try UInt.decodeSettingValue(from: .int(42)) == 42)
        #expect(try UInt8.decodeSettingValue(from: .int(255)) == 255)
        #expect(try UInt16.decodeSettingValue(from: .int(65_535)) == 65_535)
        #expect(try UInt32.decodeSettingValue(from: .int(4_000_000_000)) == 4_000_000_000)
        #expect(try UInt64.decodeSettingValue(from: .string("18_446_744_073_709_551_615")) == UInt64.max)

        #expect(throws: ValueDecodingError.self) { _ = try Int8.decodeSettingValue(from: .int(200)) }
        #expect(throws: ValueDecodingError.self) { _ = try Int.decodeSettingValue(from: .double(12.5)) }
        #expect(throws: ValueDecodingError.self) { _ = try Int.decodeSettingValue(from: .string("not-an-int")) }
        #expect(throws: ValueDecodingError.self) { _ = try UInt8.decodeSettingValue(from: .bool(true)) }

        // Double, Float, Decimal edge cases & errors
        #expect(Float.settingTypeDisplayName == "Float")
        #expect(Decimal.settingTypeDisplayName == "Decimal")
        #expect(try Double.decodeSettingValue(from: .double(2.25)) == 2.25)
        #expect(throws: ValueDecodingError.self) { _ = try Double.decodeSettingValue(from: .double(.infinity)) }
        #expect(throws: ValueDecodingError.self) { _ = try Double.decodeSettingValue(from: .string("nan")) }
        #expect(throws: ValueDecodingError.self) { _ = try Double.decodeSettingValue(from: .bool(false)) }
        #expect(throws: ValueDecodingError.self) { _ = try Float.decodeSettingValue(from: .double(1e300)) }

        #expect(try Decimal.decodeSettingValue(from: .int(99)) == Decimal(99))
        #expect(try Decimal.decodeSettingValue(from: .double(19.95)) == Decimal(string: "19.95"))
        #expect(throws: ValueDecodingError.self) { _ = try Decimal.decodeSettingValue(from: .double(.infinity)) }
        #expect(throws: ValueDecodingError.self) { _ = try Decimal.decodeSettingValue(from: .string("bad-decimal")) }
        #expect(throws: ValueDecodingError.self) { _ = try Decimal.decodeSettingValue(from: .null) }

        // UUID, URL, Date, Data edge cases & errors
        #expect(throws: ValueDecodingError.self) { _ = try UUID.decodeSettingValue(from: .int(1)) }
        #expect(throws: ValueDecodingError.self) { _ = try UUID.decodeSettingValue(from: .string("not-a-uuid")) }
        #expect(throws: ValueDecodingError.self) { _ = try URL.decodeSettingValue(from: .int(1)) }
        #expect(throws: ValueDecodingError.self) { _ = try URL.decodeSettingValue(from: .string("   ")) }

        #expect(Date.settingTypeDisplayName == "Date")
        #expect(try Date.decodeSettingValue(from: .double(1_700_000_000.5)).timeIntervalSince1970 == 1_700_000_000.5)
        #expect(try Date.decodeSettingValue(from: .string("2026-11-15")).timeIntervalSince1970 > 0)
        #expect(throws: ValueDecodingError.self) { _ = try Date.decodeSettingValue(from: .double(.infinity)) }
        #expect(throws: ValueDecodingError.self) { _ = try Date.decodeSettingValue(from: .string("")) }
        #expect(throws: ValueDecodingError.self) { _ = try Date.decodeSettingValue(from: .string("not-a-date")) }
        #expect(throws: ValueDecodingError.self) { _ = try Date.decodeSettingValue(from: .bool(true)) }

        #expect(try Data.decodeSettingValue(from: .data(Data([1, 2, 3]))) == Data([1, 2, 3]))
        #expect(
            try Data.decodeSettingValue(
                from: .array([RawNode(value: .int(65), origin: .defaultValue), RawNode(value: .int(66), origin: .defaultValue)])
            ) == Data("AB".utf8)
        )
        #expect(throws: ValueDecodingError.self) { _ = try Data.decodeSettingValue(from: .string("base64:%%%invalid%%%")) }
        #expect(throws: ValueDecodingError.self) { _ = try Data.decodeSettingValue(from: .bool(false)) }

        // Duration all units & errors
        #expect(try Duration.decodeSettingValue(from: .string("500ns")) == .nanoseconds(500))
        #expect(try Duration.decodeSettingValue(from: .string("250us")) == .microseconds(250))
        #expect(try Duration.decodeSettingValue(from: .string("250µs")) == .microseconds(250))
        #expect(try Duration.decodeSettingValue(from: .string("1.5s 500ms")) == .seconds(2))
        #expect(try Duration.decodeSettingValue(from: .string("1d")) == .seconds(86_400))
        #expect(try Duration.decodeSettingValue(from: .string("2.5")) == .milliseconds(2500))
        #expect(try Duration.decodeSettingValue(from: .double(1.25)) == .milliseconds(1250))
        #expect(throws: ValueDecodingError.self) { _ = try Duration.decodeSettingValue(from: .int(-5)) }
        #expect(throws: ValueDecodingError.self) { _ = try Duration.decodeSettingValue(from: .double(-1.0)) }
        #expect(throws: ValueDecodingError.self) { _ = try Duration.decodeSettingValue(from: .string("")) }
        #expect(throws: ValueDecodingError.self) { _ = try Duration.decodeSettingValue(from: .string("-3")) }
        #expect(throws: ValueDecodingError.self) { _ = try Duration.decodeSettingValue(from: .string(".s")) }
        #expect(throws: ValueDecodingError.self) { _ = try Duration.decodeSettingValue(from: .string("10weeks")) }
        #expect(throws: ValueDecodingError.self) { _ = try Duration.decodeSettingValue(from: .bool(true)) }

        // ByteCount factories, Comparable, units & errors
        let kb = ByteCount.kilobytes(2)
        let mb = ByteCount.megabytes(1)
        let gb = ByteCount.gigabytes(1)
        let kib = ByteCount.kibibytes(2)
        let mib = ByteCount.mebibytes(1)
        let gib = ByteCount.gibibytes(1)
        let lit: ByteCount = 512
        #expect(lit < kb && kb < kib && kib < mb && mb < mib && mib < gb && gb < gib)
        #expect(lit.description == "512 B")
        #expect(ByteCount.settingTypeDisplayName == "ByteCount")
        #expect(try ByteCount.decodeSettingValue(from: .double(1024.0)) == ByteCount(bytes: 1024))
        #expect(try ByteCount.decodeSettingValue(from: .string("64B")) == ByteCount(bytes: 64))
        #expect(try ByteCount.decodeSettingValue(from: .string("1TB")) == ByteCount(bytes: 1_000_000_000_000))
        #expect(try ByteCount.decodeSettingValue(from: .string("1PB")) == ByteCount(bytes: 1_000_000_000_000_000))
        #expect(try ByteCount.decodeSettingValue(from: .string("1TiB")) == ByteCount(bytes: 1_099_511_627_776))
        #expect(try ByteCount.decodeSettingValue(from: .string("1PiB")) == ByteCount(bytes: 1_125_899_906_842_624))
        #expect(try ByteCount.decodeSettingValue(from: .string("1.5KB")) == ByteCount(bytes: 1_500))
        #expect(throws: ValueDecodingError.self) { _ = try ByteCount.decodeSettingValue(from: .int(-1)) }
        #expect(throws: ValueDecodingError.self) { _ = try ByteCount.decodeSettingValue(from: .double(-1.0)) }
        #expect(throws: ValueDecodingError.self) { _ = try ByteCount.decodeSettingValue(from: .string("")) }
        #expect(throws: ValueDecodingError.self) { _ = try ByteCount.decodeSettingValue(from: .string("-10")) }
        #expect(throws: ValueDecodingError.self) { _ = try ByteCount.decodeSettingValue(from: .string(".KB")) }
        #expect(throws: ValueDecodingError.self) { _ = try ByteCount.decodeSettingValue(from: .string("10ZB")) }
        #expect(throws: ValueDecodingError.self) { _ = try ByteCount.decodeSettingValue(from: .string("99999PiB")) }
        #expect(throws: ValueDecodingError.self) { _ = try ByteCount.decodeSettingValue(from: .bool(false)) }

        // RawRepresentable & Optional edge cases
        #expect(try SampleIntEnum.decodeSettingValue(from: .int(1)) == .one)
        #expect(throws: ValueDecodingError.self) { _ = try SampleIntEnum.decodeSettingValue(from: .int(99)) }
        #expect(try NonCaseIterableStringEnum.decodeSettingValue(from: .string("alpha")) == .alpha)
        #expect(throws: ValueDecodingError.self) { _ = try NonCaseIterableStringEnum.decodeSettingValue(from: .string("ALPHA")) }
        let csCtx = ValueDecodingContext(caseSensitive: true, envNullStrings: ["NULL"])
        #expect(throws: ValueDecodingError.self) {
            _ = try CaseIterableEnvMode.decodeSettingValue(from: .string("PRODUCTION"), context: csCtx)
        }
        #expect(Optional<Int>.settingTypeDisplayName == "Int?")
        #expect(try Optional<Int>.decodeSettingValue(from: .string("NULL"), context: csCtx) == nil)
        #expect(throws: ValueDecodingError.self) {
            _ = try Optional<Int>.decodeSettingValue(from: .string("null"), context: csCtx)
        }

        // Collection strategies ([T], Set<T>, [String: V]) & nested JSON object conversions
        #expect(Set<String>.settingTypeDisplayName == "Set<String>")
        #expect([String: Int].settingTypeDisplayName == "[String: Int]")

        let jsonOnlyCtx = ValueDecodingContext(envListStrategy: .jsonOnly)
        let sepCtx = ValueDecodingContext(envListStrategy: .separator(":"))
        let noDecodeCtx = ValueDecodingContext(envListStrategy: .noDecode)

        #expect(try [Int].decodeSettingValue(from: .string("[1, 2, 3]"), context: jsonOnlyCtx) == [1, 2, 3])
        #expect(try [[Int]].decodeSettingValue(from: .string("[[1, 2], [3]]"), context: jsonOnlyCtx) == [[1, 2], [3]])
        #expect(try [String?].decodeSettingValue(from: .string(#"["a", null]"#), context: jsonOnlyCtx) == ["a", nil])
        #expect(try [Bool].decodeSettingValue(from: .string("[true, false]"), context: jsonOnlyCtx) == [true, false])
        #expect(try [Double].decodeSettingValue(from: .string("[1.5, 2.5]"), context: jsonOnlyCtx) == [1.5, 2.5])
        #expect(try [[String: Int]].decodeSettingValue(from: .string(#"[{"a": 1}]"#), context: jsonOnlyCtx) == [["a": 1]])
        #expect(try [String].decodeSettingValue(from: .string(""), context: ValueDecodingContext()) == [])
        #expect(try [String].decodeSettingValue(from: .string(""), context: sepCtx) == [])
        #expect(try [String].decodeSettingValue(from: .string("a:b:c"), context: sepCtx) == ["a", "b", "c"])

        #expect(try [String: Int].decodeSettingValue(from: .string(""), context: ValueDecodingContext()) == [:])
        #expect(try [String: Int].decodeSettingValue(from: .string(""), context: sepCtx) == [:])
        #expect(try [String: Int].decodeSettingValue(from: .string("a=1:b=2"), context: sepCtx) == ["a": 1, "b": 2])
        #expect(try [String: Int].decodeSettingValue(from: .string(#"{"a": 1, "b": 2}"#), context: jsonOnlyCtx) == ["a": 1, "b": 2])

        #expect(throws: ValueDecodingError.self) { _ = try [String].decodeSettingValue(from: .int(1)) }
        #expect(throws: ValueDecodingError.self) { _ = try [String].decodeSettingValue(from: .string("a,b"), context: noDecodeCtx) }
        #expect(throws: ValueDecodingError.self) { _ = try [String].decodeSettingValue(from: .string("not-json"), context: jsonOnlyCtx) }
        #expect(throws: ValueDecodingError.self) { _ = try [String: String].decodeSettingValue(from: .int(1)) }
        #expect(throws: ValueDecodingError.self) { _ = try [String: String].decodeSettingValue(from: .string("a=1"), context: noDecodeCtx) }
        #expect(throws: ValueDecodingError.self) { _ = try [String: String].decodeSettingValue(from: .string("badpair"), context: sepCtx) }
        #expect(throws: ValueDecodingError.self) { _ = try [String: String].decodeSettingValue(from: .string("=nokey"), context: sepCtx) }
        #expect(throws: ValueDecodingError.self) { _ = try [String: String].decodeSettingValue(from: .string("[]"), context: jsonOnlyCtx) }
    }
}

// MARK: - Suite 3: SettingsLoader Exhaustive Two-Phase & Alias Branches

@Suite("SettingsLoader Exhaustive Two-Phase, Aliases & Validation Branches")
struct SettingsLoaderComprehensiveTests {
    @Test("SettingsLoader handles resolveSecrets on @Setting, optional/defaulted secrets, aliases, transforms, and nested validation")
    func settingsLoaderAllBranches() async throws {
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Vault/App/reqStr": "resolved-req-str",
            "op://Vault/App/defStr": "resolved-def-str",
            "op://Vault/App/optStr": "resolved-opt-str",
            "op://Vault/App/rawBytes": "binary-payload",
            "op://Vault/App/secretInt": "42",
        ])

        var tree = RawConfigTree.empty
        tree.set(path: ["reqResolved"], value: .string("op://Vault/App/reqStr"), origin: .environment(variable: "REQ_RESOLVED"))
        tree.set(path: ["defResolved"], value: .string("op://Vault/App/defStr"), origin: .environment(variable: "DEF_RESOLVED"))
        tree.set(path: ["optResolved"], value: .string("op://Vault/App/optStr"), origin: .environment(variable: "OPT_RESOLVED"))
        tree.set(path: ["bytesResolved"], value: .string("op://Vault/App/rawBytes"), origin: .environment(variable: "BYTES_RESOLVED"))
        tree.set(path: ["literalResolved"], value: .string("plain-literal-not-secret"), origin: .environment(variable: "LIT_RESOLVED"))
        tree.set(path: ["secInt"], value: .string("op://Vault/App/secretInt"), origin: .environment(variable: "SEC_INT"))
        tree.set(path: ["nullOptSecret"], value: .null, origin: .projectConfig(path: "/p", keyPath: ["nullOptSecret"], profile: nil))
        tree.set(path: ["nullOptField"], value: .null, origin: .projectConfig(path: "/p", keyPath: ["nullOptField"], profile: nil))

        let context = SettingsContext.inMemory(secretProviders: [mockOP])
        var loader = SettingsLoader(
            configuration: SettingsConfiguration(envPrefix: "APP_"),
            context: context,
            mergedTree: tree
        )

        loader.enqueuePotentialSecretReference(keyPath: ["reqResolved"])
        loader.enqueuePotentialSecretReference(keyPath: ["defResolved"], hasDefault: true)
        loader.enqueuePotentialSecretReference(keyPath: ["optResolved"], isOptional: true)
        loader.enqueuePotentialSecretReference(keyPath: ["bytesResolved"], expectedType: "Data")
        loader.enqueuePotentialSecretReference(keyPath: ["literalResolved"])
        loader.enqueuePotentialSecretReference(keyPath: ["missingPotential"], isOptional: true)
        loader.enqueueSecret(keyPath: ["secInt"], expectedType: "Secret<Int>")
        loader.enqueueSecret(keyPath: ["defSecret"], expectedType: "Secret<String>", hasDefault: true)
        loader.enqueueSecret(keyPath: ["optSecretWithDefault"], expectedType: "Secret<String>?", isOptional: true, hasDefault: true)
        loader.enqueueSecret(keyPath: ["nullOptSecret"], expectedType: "Secret<String>?", isOptional: true)

        await loader.resolveEnqueuedSecrets()
        #expect(loader.issues.isEmpty)

        let reqMeta = loader.decodeRequired(String.self, keyPath: ["reqResolved"], resolveSecrets: true)
        let defMeta = loader.decodeDefaulted(String.self, default: "fallback", keyPath: ["defResolved"], resolveSecrets: true)
        let optMeta = loader.decodeOptional(String.self, keyPath: ["optResolved"], resolveSecrets: true)
        let bytesMeta = loader.decodeRequired(Data.self, keyPath: ["bytesResolved"], resolveSecrets: true)
        let litMeta = loader.decodeRequired(String.self, keyPath: ["literalResolved"], resolveSecrets: true)
        let optWithDef = loader.decodeOptional(String.self, default: "opt-default", keyPath: ["unconfiguredOpt"])
        let optNilDef = loader.decodeOptional(String.self, keyPath: ["unconfiguredNilOpt"])
        let optNull = loader.decodeOptional(String.self, keyPath: ["nullOptField"])

        let secIntMeta = loader.decodeRequiredSecret(Int.self, keyPath: ["secInt"], validators: [.range(1...100)])
        let defSecMeta = loader.decodeDefaultedSecret(
            String.self,
            default: Secret("default-secret-val"),
            keyPath: ["defSecret"],
            validators: [.nonEmpty]
        )
        let optSecWithDefMeta = loader.decodeOptionalSecret(
            String.self,
            default: Secret("opt-secret-default"),
            keyPath: ["optSecretWithDefault"],
            validators: [.nonEmpty]
        )
        let nullOptSecMeta = loader.decodeOptionalSecret(String.self, keyPath: ["nullOptSecret"])
        let absentOptSec = loader.decodeOptionalNested(ValidatedNestedConfig.self, keyPath: ["absentPool"])

        #expect(reqMeta?.value == "resolved-req-str")
        #expect(defMeta?.value == "resolved-def-str")
        #expect(optMeta?.value == "resolved-opt-str")
        #expect(bytesMeta?.value == Data("binary-payload".utf8))
        #expect(litMeta?.value == "plain-literal-not-secret")
        #expect(optWithDef?.value == "opt-default")
        #expect(optNilDef?.value == nil)
        #expect(optNull?.value == nil)
        #expect(secIntMeta?.value.expose() == 42)
        #expect(defSecMeta?.value.expose() == "default-secret-val")
        #expect(optSecWithDefMeta?.value?.expose() == "opt-secret-default")
        #expect(nullOptSecMeta?.value == nil)
        #expect(absentOptSec == .some(nil))
        try loader.throwIfInvalid()
    }

    @Test("SettingsLoader accumulates missing/null/transform/malformed-URI/secret-decode errors and alias precedence")
    func settingsLoaderErrorPathsAndAliasPrecedence() async throws {
        var badTree = RawConfigTree.empty
        badTree.set(path: ["nullReq"], value: .null, origin: .projectConfig(path: "/p", keyPath: ["nullReq"], profile: nil))
        badTree.set(path: ["nullReqSec"], value: .null, origin: .projectConfig(path: "/p", keyPath: ["nullReqSec"], profile: nil))
        badTree.set(path: ["badPotential"], value: .string("op://-option-injection/item/field"), origin: .environment(variable: "BAD_POT"))
        badTree.set(path: ["badTransform"], value: .string("hello"), origin: .environment(variable: "BAD_TX"))
        badTree.set(path: ["badSecInt"], value: .string("not-an-int"), origin: .environment(variable: "BAD_SEC_INT"))

        let ctx = SettingsContext.inMemory()
        var loader = SettingsLoader(
            configuration: SettingsConfiguration(envPrefix: "ERR_"),
            context: ctx,
            mergedTree: badTree
        )

        loader.enqueueSecret(keyPath: ["missingReqSec"])
        loader.enqueueSecret(keyPath: ["nullReqSec"])
        loader.enqueueSecret(keyPath: ["badSecInt"], expectedType: "Secret<Int>")
        loader.enqueuePotentialSecretReference(keyPath: ["badPotential"])
        await loader.resolveEnqueuedSecrets()

        #expect(loader.decodeRequired(String.self, keyPath: ["missingReq"]) == nil)
        #expect(loader.decodeRequired(String.self, keyPath: ["nullReq"]) == nil)
        #expect(loader.decodeRequired(String.self, keyPath: ["badPotential"], resolveSecrets: true) == nil)
        #expect(loader.decodeDefaulted(String.self, default: "x", keyPath: ["badPotential"], resolveSecrets: true) == nil)
        #expect(loader.decodeOptional(String.self, keyPath: ["badPotential"], resolveSecrets: true) == nil)
        #expect(
            loader.decodeRequired(
                String.self,
                keyPath: ["badTransform"],
                transform: { _ in throw ValueDecodingError(expectedType: "String", reason: "boom") }
            ) == nil
        )
        #expect(loader.decodeRequiredSecret(Int.self, keyPath: ["badSecInt"]) == nil)
        loader.recordIssue(ValidationIssue(keyPath: ["custom"], kind: .invalidValue, message: "custom issue"))
        #expect(loader.issues.count >= 7)
        #expect(throws: SettingsValidationError.self) {
            try loader.throwIfInvalid()
        }

        // ManualLoaderSettings alias precedence, nested validation failure, and cross-field failure
        let aliasContext = SettingsContext.inMemory(
            cli: [
                .cli(flag: "--custom-host", keyPath: ["customHost"], value: .string("cli-alias.internal")),
            ],
            environment: [
                "legacy_manual_host": "env-alias.internal",
            ],
            files: [
                "/repo/.manual.json": """
                {
                    "$schema": "https://example.com/manual.json",
                    "legacy": { "host": "config-alias.internal" },
                    "altLabels": { "region": "ap-southeast-2" },
                    "extraUnknown": 1
                }
                """,
            ],
            directories: ["/repo/.git"]
        )
        let loaded = try await ManualLoaderSettings.load(context: aliasContext)
        #expect(loaded.host == "cli-alias.internal")
        #expect(loaded.labels == ["region": "ap-southeast-2"])
        #expect(loaded.provenanceReport().warnings.count == 1)

        // Nested validation failure (minThreads > maxThreads)
        let invalidNestedCtx = SettingsContext.inMemory(
            environment: ["MANUAL_POOL__MIN_THREADS": "10", "MANUAL_POOL__MAX_THREADS": "2"]
        )
        await #expect(throws: SettingsValidationError.self) {
            _ = try await ManualLoaderSettings.load(context: invalidNestedCtx)
        }

        // Cross-field validation failure
        let forbiddenHostCtx = SettingsContext.inMemory(
            environment: ["LEGACY_MANUAL_HOST": "forbidden.internal"]
        )
        await #expect(throws: SettingsValidationError.self) {
            _ = try await ManualLoaderSettings.load(context: forbiddenHostCtx)
        }
    }
}
