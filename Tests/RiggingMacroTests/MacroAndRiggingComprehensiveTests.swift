import Foundation
import Rigging
@testable import RiggingMacros
import RiggingTesting
import SwiftSyntax
import SwiftSyntaxMacroExpansion
import SwiftSyntaxMacros
import SwiftSyntaxMacrosGenericTestSupport
import SwiftSyntaxMacrosTestSupport
import Testing

// MARK: - Package & Internal Macro Models for Runtime + Fallback Provenance Coverage

public enum NonCaseIterablePort: Int, Sendable, Equatable {
    case http = 80
    case https = 443
    case alt = 8080
}

@Settings
package struct PackageEmptySettings: Equatable {}

@Settings
package struct PackageChildSettings: Equatable {
    @Setting(aliases: [.configPath(["legacyPort"]), .env("CHILD_LEGACY_PORT"), .cli("--child-port")])
    package var port: Int = 9000

    package static func validate(_ settings: Self) -> [ValidationIssue] {
        if settings.port < 1024 {
            return [ValidationIssue(keyPath: ["port"], kind: .crossField, message: "port must be >= 1024")]
        }
        return []
    }
}

@Rigged(
    envPrefix: "PKG_",
    extraKeys: .ignore,
    dotEnvFiles: []
)
package struct PackageRichSettings: Equatable {
    /**
     * Multi-line block doc comment
     * with leading asterisks and "quotes".
     */
    @Setting(transforms: [.trimWhitespace, .uppercased])
    package var code: String = "abc"

    @Setting
    package var fallbackLabel: String = "fallback"

    @SecretSetting(validate: .minLength(4), transforms: [.trimWhitespace])
    package var validatedSecret: Secret<String> = Secret("  secret123  ")

    @Setting
    package var rawBytes: [UInt8] = [1, 2]

    @Setting
    package var genericBytes: Array<UInt8> = [3]

    @Setting
    package var tags: Set<String> = ["a"]

    @Setting
    package var counts: Dictionary<String, Int> = [:]

    @Setting
    package var explicitOpt: Optional<String> = nil

    @Setting
    package var ratio: Float = 1.5

    @Setting
    package var budget: Decimal = 42.5

    @Setting
    package var maxBytes: ByteCount = .megabytes(5)

    @Setting
    package var fastTimeout: Duration = .milliseconds(250)

    @Setting
    package var nanoTimeout: Duration = .nanoseconds(1500)

    @SecretSetting
    package var byteSecret: Secret<[UInt8]> = Secret([0xAA, 0xBB])

    @SecretSetting
    package var defaultedSecret: Secret<String> = Secret("default-secret-val")

    @NestedSettings
    package var optChildWithDefault: PackageChildSettings? = .init(port: 9090)
}

@Settings
struct CustomInitSettings: RiggedSettings, RiggedNestedSettings, Sendable {
    @Setting var host: String
    var unannotatedOptional: Int?
    var computedLabel: String { host.uppercased() }

    init(host: String) {
        self.host = host
    }
}

private let comprehensiveMacroSpecs: [String: MacroSpec] = [
    "Settings": MacroSpec(type: SettingsMacro.self),
    "Rigged": MacroSpec(type: SettingsMacro.self),
    "Setting": MacroSpec(type: SettingMacro.self),
    "SecretSetting": MacroSpec(type: SecretSettingMacro.self),
    "NestedSettings": MacroSpec(type: NestedSettingsMacro.self),
]

private func collectExpansionFailures(_ source: String) -> [String] {
    var messages: [String] = []
    SwiftSyntaxMacrosGenericTestSupport.assertMacroExpansion(
        source,
        expandedSource: "",
        diagnostics: [],
        macroSpecs: comprehensiveMacroSpecs,
        indentationWidth: .spaces(4),
        failureHandler: { failure in
            if !failure.message.contains("expanded source") {
                messages.append(failure.message)
            }
        }
    )
    return messages
}

@Suite("Rigging Module, Macro Diagnostics & Support Comprehensive Coverage")
struct MacroAndRiggingComprehensiveTests {

    @Test("RiggingCompilerPlugin registers all 4 macro implementations and RiggingMacroDiagnostic covers all 10 cases")
    func pluginRegistrationAndDiagnosticsEnum() {
        let plugin = RiggingCompilerPlugin()
        #expect(plugin.providingMacros.count == 4)

        let allDiags: [RiggingMacroDiagnostic] = [
            .notAStruct(macroName: "Settings"),
            .notAStoredProperty(macroName: "Setting"),
            .staticPropertyNotAllowed(macroName: "Setting"),
            .multipleBindings(macroName: "Setting"),
            .missingTypeAnnotation(propertyName: "p", macroName: "Setting"),
            .immutablePropertyWithDefault(propertyName: "p", macroName: "Setting"),
            .unannotatedUninitializedProperty(propertyName: "p"),
            .invalidSecretSettingType(propertyName: "p", actualType: "Int"),
            .outsideSettingsStruct(macroName: "Setting"),
            .conflictingSettingAttributes(propertyName: "p"),
        ]
        for diag in allDiags {
            #expect(!diag.message.isEmpty)
            #expect(!String(describing: diag.diagnosticID).isEmpty)
            #expect(!String(describing: diag.severity).isEmpty)
        }
    }

    @Test("SettingTransform covers custom closures, String transforms, and URL expandTilde")
    func settingTransformCoverage() throws {
        let ctx = SettingsContext(homeDirectory: "/Users/jane")

        let indep = SettingTransform<Int> { $0 * 2 }
        #expect(try indep.apply(21) == 42)

        let customIndep = SettingTransform<Int>.custom { $0 + 1 }
        #expect(try customIndep.apply(9, context: ctx) == 10)

        let customCtx = SettingTransform<String>.custom { val, c in
            "\(c.homeDirectory)/\(val)"
        }
        #expect(try customCtx.apply("docs", context: ctx) == "/Users/jane/docs")

        #expect(try SettingTransform<String>.trimWhitespace.apply("  hi \n", context: ctx) == "hi")
        #expect(try SettingTransform<String>.lowercased.apply("HeLLo", context: ctx) == "hello")
        #expect(try SettingTransform<String>.uppercased.apply("HeLLo", context: ctx) == "HELLO")
        #expect(try SettingTransform<String>.expandTilde.apply("~/cache", context: ctx) == "/Users/jane/cache")

        let tildeURL = URL(string: "~/Library/Caches")!
        #expect(try SettingTransform<URL>.expandTilde.apply(tildeURL, context: ctx) == URL(fileURLWithPath: "/Users/jane/Library/Caches"))
        let httpsURL = URL(string: "https://example.com/path")!
        #expect(try SettingTransform<URL>.expandTilde.apply(httpsURL, context: ctx) == httpsURL)
    }

    @Test("SettingsLoader automatic CaseIterable String enum and RawRepresentable Int enum overloads")
    func automaticEnumLoaderOverloads() async throws {
        struct DummyEnumModel: RiggedSettings {
            static let configuration = SettingsConfiguration(envPrefix: "ENUM_")
            static let fieldDescriptors: [SettingFieldDescriptor] = []
            var provenance: ProvenanceReport
            static func load(context: SettingsContext, overrides: [SettingOverride]) async throws -> Self {
                Self(provenance: ProvenanceReport(entries: []))
            }
        }

        let validCtx = SettingsContext.inMemory(
            environment: [
                "ENUM_REQ_LEVEL": "WARN", // case-insensitive match on CaseIterable
                "ENUM_OPT_LEVEL": "debug",
                "ENUM_REQ_PORT": "443",
                "ENUM_OPT_PORT": "8080",
            ]
        )
        var loader = try await SettingsLoader.prepare(for: DummyEnumModel.self, context: validCtx)

        let reqLvl = loader.decodeRequired(
            RiggedLogLevel.self,
            keyPath: ["reqLevel"],
            transform: { $0 == .warn ? .error : $0 },
            validators: [.custom("not debug") { $0 != .debug }]
        )
        #expect(reqLvl?.value == .error)

        let defLvl = loader.decodeDefaulted(
            RiggedLogLevel.self,
            default: .info,
            keyPath: ["defLevel"],
            transform: { $0 },
            validators: [.custom("ok") { _ in true }]
        )
        #expect(defLvl?.value == .info)

        let optLvl = loader.decodeOptional(
            RiggedLogLevel.self,
            default: nil,
            keyPath: ["optLevel"],
            transform: { $0 },
            validators: [.custom("ok") { _ in true }]
        )
        #expect(optLvl?.value == .debug)

        // Non-CaseIterable Int RawRepresentable overloads
        let reqPort = loader.decodeRequired(
            NonCaseIterablePort.self,
            keyPath: ["reqPort"],
            transform: { $0 },
            validators: [.custom("https") { $0 == .https }]
        )
        #expect(reqPort?.value == .https)

        let defPort = loader.decodeDefaulted(
            NonCaseIterablePort.self,
            default: .http,
            keyPath: ["defPort"],
            transform: { $0 },
            validators: [.custom("ok") { _ in true }]
        )
        #expect(defPort?.value == .http)

        let optPort = loader.decodeOptional(
            NonCaseIterablePort.self,
            default: nil,
            keyPath: ["optPort"],
            transform: { $0 },
            validators: [.custom("ok") { _ in true }]
        )
        #expect(optPort?.value == .alt)
        #expect(loader.issues.isEmpty)

        // Error branches for invalid CaseIterable & invalid RawRepresentable values
        let badCtx = SettingsContext.inMemory(
            environment: [
                "ENUM_BAD_LEVEL": "trace_nonexistent",
                "ENUM_BAD_PORT": "9999",
            ]
        )
        var badLoader = try await SettingsLoader.prepare(for: DummyEnumModel.self, context: badCtx)
        #expect(badLoader.decodeRequired(RiggedLogLevel.self, keyPath: ["badLevel"]) == nil)
        #expect(badLoader.decodeDefaulted(RiggedLogLevel.self, default: .info, keyPath: ["badLevel"]) == nil)
        #expect(badLoader.decodeOptional(RiggedLogLevel.self, keyPath: ["badLevel"]) == nil)
        #expect(badLoader.decodeRequired(NonCaseIterablePort.self, keyPath: ["badPort"]) == nil)
        #expect(badLoader.decodeDefaulted(NonCaseIterablePort.self, default: .http, keyPath: ["badPort"]) == nil)
        #expect(badLoader.decodeOptional(NonCaseIterablePort.self, keyPath: ["badPort"]) == nil)
        #expect(badLoader.issues.count == 6)
    }

    @Test("_RiggingStorage, _RiggingMacroSupport helpers, defaultDisplay, and package/empty/custom-init models")
    func macroSupportAndPackageModelsCoverage() async throws {
        // _RiggingStorage Codable, Hashable, Equatable, FieldRecord
        let rec = _RiggingStorage.FieldRecord(keyPath: ["a"], origin: .defaultValue)
        var storage = _RiggingStorage(fields: ["a": rec])
        storage.recordField("b", metadata: SettingMetadata(keyPath: ["b"], value: 1, isSecret: false, origin: .defaultValue))
        #expect(storage.metadata(for: "b", defaultKeyPath: ["b"], value: 1, isSecret: false).keyPath == ["b"])
        #expect(storage.metadata(for: "missing", defaultKeyPath: ["m"], value: 2, isSecret: false).origin == .defaultValue)

        struct StorageBox: Codable, Equatable {
            var storage: _RiggingStorage
        }
        let encodedStorage = try JSONEncoder().encode(StorageBox(storage: storage))
        let decodedStorage = try JSONDecoder().decode(StorageBox.self, from: encodedStorage).storage
        #expect(decodedStorage == _RiggingStorage())
        var setStorage = Set<_RiggingStorage>()
        setStorage.insert(storage)
        setStorage.insert(storage)
        #expect(setStorage.count == 1)

        // _RiggingMacroSupport helpers
        let emptyTransforms = _RiggingMacroSupport.transforms(as: String.self, context: SettingsContext(), [SettingTransform<String>]())
        #expect(emptyTransforms == nil)
        let multiValidators = _RiggingMacroSupport.validators(as: String.self, [.nonEmpty, .minLength(2)])
        #expect(multiValidators.count == 2)

        let aliases: [SettingAlias] = [
            .configPath(["port"]),
            .configPath(["db", "port"]),
            .env("DB_PORT"),
            .cli("--db-port"),
        ]
        #expect(_RiggingMacroSupport.rebaseAliases(aliases, prefix: []) == aliases)
        let rebased = _RiggingMacroSupport.rebaseAliases(aliases, prefix: ["db"])
        #expect(rebased.contains(.configPath(["db", "port"])))

        let issues = [
            ValidationIssue(keyPath: ["port"], kind: .crossField, message: "bad"),
            ValidationIssue(keyPath: ["db", "host"], kind: .crossField, message: "bad host"),
        ]
        #expect(_RiggingMacroSupport.rebaseIssues(issues, prefix: []).count == 2)
        let rebasedIssues = _RiggingMacroSupport.rebaseIssues(issues, prefix: ["db"])
        #expect(rebasedIssues[0].keyPath == ["db", "port"])
        #expect(rebasedIssues[1].keyPath == ["db", "host"])

        // non-RiggedSettings nestedFallbackEntries overload
        #expect(_RiggingMacroSupport.nestedFallbackEntries(from: "not-settings", prefix: ["x"]).isEmpty)

        // All defaultDisplay overloads (including nil cases)
        struct CustomThing: CustomStringConvertible { var description: String { "custom-thing" } }
        #expect(_RiggingMacroSupport.defaultDisplay(as: String.self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: Bool.self, true) == "true")
        #expect(_RiggingMacroSupport.defaultDisplay(as: Bool.self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: Int.self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: Double.self, 2.5) == "2.5")
        #expect(_RiggingMacroSupport.defaultDisplay(as: Double.self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: Float.self, Float(1.5)) == "1.5")
        #expect(_RiggingMacroSupport.defaultDisplay(as: Float.self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: Decimal.self, Decimal(12)) == "12")
        #expect(_RiggingMacroSupport.defaultDisplay(as: Decimal.self, nil) == nil)
        let uid = UUID()
        #expect(_RiggingMacroSupport.defaultDisplay(as: UUID.self, uid) == uid.uuidString)
        #expect(_RiggingMacroSupport.defaultDisplay(as: UUID.self, nil) == nil)
        let url = URL(string: "https://example.com")!
        #expect(_RiggingMacroSupport.defaultDisplay(as: URL.self, url) == "https://example.com")
        #expect(_RiggingMacroSupport.defaultDisplay(as: URL.self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: ByteCount.self, .kilobytes(2)) == "2000")
        #expect(_RiggingMacroSupport.defaultDisplay(as: ByteCount.self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: Duration.self, .milliseconds(250)) == "250ms")
        #expect(_RiggingMacroSupport.defaultDisplay(as: Duration.self, .nanoseconds(1500))?.hasSuffix("s") == true)
        #expect(_RiggingMacroSupport.defaultDisplay(as: Duration.self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: RiggedLogLevel.self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: [String].self, ["x", "y"]) == "x,y")
        #expect(_RiggingMacroSupport.defaultDisplay(as: [String].self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: [String: Int].self, ["a": 1])?.contains("a") == true)
        #expect(_RiggingMacroSupport.defaultDisplay(as: [String: Int].self, nil) == nil)
        #expect(_RiggingMacroSupport.defaultDisplay(as: CustomThing.self, CustomThing()) == "custom-thing")
        #expect(_RiggingMacroSupport.defaultDisplay(as: CustomThing.self, nil) == nil)

        // PackageEmptySettings & PackageRichSettings load, direct init fallback provenance, schema & dotenv export
        let emptyLoaded = try await PackageEmptySettings.load(context: .inMemory())
        #expect(emptyLoaded == PackageEmptySettings())
        #expect(PackageEmptySettings().provenance.entries.isEmpty)
        #expect(PackageEmptySettings.fieldDescriptors.isEmpty)

        let directRich = PackageRichSettings()
        // Fallback provenance on direct memberwise init (exercises optional nil, optional non-nil nested, secrets, scalars)
        let fallbackEntries = directRich.provenance.entries
        #expect(!fallbackEntries.isEmpty)
        #expect(!directRich.redactor.scrub("default-secret-val").contains("default-secret-val"))

        let richLoaded = try await PackageRichSettings.load(
            context: .inMemory(environment: ["PKG_CODE": "  xyz  "])
        )
        #expect(richLoaded.code == "XYZ")
        #expect(richLoaded.optChildWithDefault?.port == 9090)
        #expect(PackageRichSettings.jsonSchema().contains("Multi-line block doc comment"))
        #expect(PackageRichSettings.dotEnvTemplate().contains("PKG_FAST_TIMEOUT=250ms"))

        // Also test loading PackageRichSettings when optChildWithDefault IS present in env with invalid port (< 1024)
        await #expect(throws: SettingsValidationError.self) {
            _ = try await PackageRichSettings.load(
                context: .inMemory(environment: ["PKG_OPT_CHILD_WITH_DEFAULT__PORT": "80"])
            )
        }

        // CustomInitSettings
        let customLoaded = try await CustomInitSettings.load(
            context: .inMemory(environment: ["HOST": "api.example.com"])
        )
        #expect(customLoaded.computedLabel == "API.EXAMPLE.COM")
    }

    @Test("All RiggingMacros compile-time error diagnostics and literal type inference")
    func allMacroDiagnosticsAndTypeInference() {
        // 1. @Settings on non-struct (enum / class)
        let enumFailures = collectExpansionFailures(
            """
            @Settings
            enum NotAStruct {
                case a
            }
            """
        )
        #expect(enumFailures.joined(separator: "\n").contains("@Settings can only be applied to a struct declaration."))

        // 2. @Setting / @SecretSetting / @NestedSettings outside @Settings struct
        let plainFailures = collectExpansionFailures(
            """
            struct PlainStruct {
                @Setting var a: Int = 1
                @SecretSetting var b: Secret<String>
                @NestedSettings var c: Child = .init()
            }
            """
        ).joined(separator: "\n")
        #expect(plainFailures.contains("@Setting can only be applied to properties inside a @Settings or @Rigged struct."))
        #expect(plainFailures.contains("@SecretSetting can only be applied to properties inside a @Settings or @Rigged struct."))
        #expect(plainFailures.contains("@NestedSettings can only be applied to properties inside a @Settings or @Rigged struct."))

        // 3. static property, multiple bindings, computed property, let with default, missing type annotation, invalid SecretSetting type, conflicting attributes, unannotated property
        let brokenFailures = collectExpansionFailures(
            """
            @Settings
            struct BrokenSettings {
                @Setting static var s: Int = 1
                @Setting var m1: Int = 1, m2: Int = 2
                @Setting var comp: Int { 42 }
                @Setting let immut: Int = 5
                @Setting var mystery = makeMystery()
                @SecretSetting var plain: String = "oops"
                @Setting @SecretSetting var both: Secret<String>
                var unannotatedRequired: String
            }
            """
        ).joined(separator: "\n")
        #expect(brokenFailures.contains("@Setting cannot be applied to a static or class property."))
        #expect(brokenFailures.contains("@Setting can only be applied to a stored property."))
        #expect(brokenFailures.contains("immut"))
        #expect(brokenFailures.contains("mystery"))
        #expect(brokenFailures.contains("Secret<Value>"))
        #expect(brokenFailures.contains("unannotatedRequired"))

        // 4. Literal type inference (`Bool`, `Int`, `Double`, `String`) + `let` without default + property observers (`willSet`/`didSet`) + `Rigging.Setting` member attribute syntax
        let validFailures = collectExpansionFailures(
            """
            @Settings
            struct InferredSettings {
                @Rigging.Setting var flag = true
                @Setting var count = 10
                @Setting var ratio = 2.5
                @Setting var title = "hi"
                @Setting let requiredId: String
                @Setting var observed: Int = 1 {
                    willSet {}
                    didSet {}
                }
            }
            """
        )
        #expect(validFailures.isEmpty)
    }
}
