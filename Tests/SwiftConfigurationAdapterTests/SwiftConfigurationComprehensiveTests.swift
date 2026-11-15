import Configuration
import Foundation
import Rigging
import RiggingCore
import RiggingSwiftConfiguration
import RiggingTesting
import Testing

// MARK: - Rich Settings Model Covering All SwiftConfiguration Coercions & Schema Specs

enum BridgeLogLevel: String, CaseIterable, Sendable, Equatable {
    case debug
    case info
    case warn
    case error
}

@Settings(
    envPrefix: "SWCFG_",
    caseSensitive: true
)
struct CaseSensitiveBridgeModel: Sendable {
    @Setting(aliases: [.configPath(["legacy", "hostName"])])
    var hostName: String = "localhost"

    @Setting
    var portNumber: Int = 8080

    @Setting
    var smallInt: Int16 = 16

    @Setting
    var unsignedPort: UInt16 = 443

    @Setting
    var floatRatio: Float = 0.5

    @Setting
    var doubleTimeout: Double = 12.5

    @Setting
    var budget: Decimal = 99.5

    @Setting
    var durationVal: Duration = .milliseconds(1500)

    @Setting
    var byteLimit: ByteCount = .kilobytes(4)

    @Setting
    var enabled: Bool = true

    @Setting
    var endpointURL: URL = URL(string: "https://example.com")!

    @Setting
    var requestID: UUID = UUID(uuidString: "00000000-0000-0000-0000-000000000042")!

    @Setting
    var createdAt: Date = Date(timeIntervalSince1970: 1_700_000_000)

    @Setting
    var rawData: Data = Data([0x01, 0x02, 0x03])

    @Setting
    var rawBytes: [UInt8] = [0x0A, 0x0B]

    @Setting
    var logLevel: BridgeLogLevel = .info

    @Setting
    var strList: [String] = ["a", "b"]

    @Setting
    var intList: [Int] = [10, 20]

    @Setting
    var dblList: [Double] = [1.25, 2.5]

    @Setting
    var boolList: [Bool] = [true, false]

    @Setting
    var labels: [String: Int] = ["alpha": 1, "beta": 2]

    @Setting
    var optionalUnset: String? = nil

    @SecretSetting
    var secretText: Secret<String> = Secret("42")

    @SecretSetting
    var secretBytes: Secret<[UInt8]> = Secret([0xDE, 0xAD])
}

/// Non-macro manual `RiggedSettings` implementation exercising fallback Mirror provenance lookup in `RiggingConfigProvider`.
struct ManualBridgeSettings: RiggedSettings {
    static let configuration = SettingsConfiguration(envPrefix: "MAN_", caseSensitive: false)
    static let fieldDescriptors: [SettingFieldDescriptor] = []

    var plainText: String = "123"
    var boolText: String = "yes"
    var chunks: [[UInt8]] = [[1, 2], [3]]
    var dataChunks: [Data] = [Data([4, 5])]
    var secretList: [Secret<String>] = [Secret("s1"), Secret("s2")]
    var nestedDict: [String: String] = ["region": "ap-southeast-2"]

    var provenance: ProvenanceReport {
        ProvenanceReport(entries: [
            ProvenanceEntry(
                keyPath: ["plainText"],
                typeName: "String",
                isSecret: false,
                displayValue: "123",
                origin: .defaultValue
            ),
            ProvenanceEntry(
                keyPath: ["secretList"],
                typeName: "[Secret<String>]",
                isSecret: true,
                displayValue: "**********",
                origin: .defaultValue
            ),
        ])
    }

    static func load(context: SettingsContext, overrides: [SettingOverride]) async throws -> Self {
        Self()
    }
}

/// Custom non-enumerable `ConfigProvider` (not `InMemoryProvider`) so `SwiftConfigurationSource`
/// exercises both synchronous `value(forKey:type:)` and async `fetchValue(forKey:type:)` probing across all 10 `ConfigType`s!
struct ProbingTestConfigProvider: ConfigProvider, Sendable {
    let providerName: String = "ProbingTestProvider"
    let store: [String: ConfigValue]

    func value(forKey key: AbsoluteConfigKey, type: ConfigType) throws -> LookupResult {
        let encoded = key.components.joined(separator: ".")
        guard let val = store[encoded], val.content.matches(type: type) else {
            return LookupResult(encodedKey: encoded, value: nil)
        }
        return LookupResult(encodedKey: encoded, value: val)
    }

    nonisolated(nonsending) func fetchValue(forKey key: AbsoluteConfigKey, type: ConfigType) async throws -> LookupResult {
        try value(forKey: key, type: type)
    }

    nonisolated(nonsending) func watchValue<Return: ~Copyable>(
        forKey key: AbsoluteConfigKey,
        type: ConfigType,
        updatesHandler: nonisolated(nonsending) (ConfigUpdatesAsyncSequence<Result<LookupResult, any Error>, Never>) async throws -> Return
    ) async throws -> Return {
        try await watchValueFromValue(forKey: key, type: type, updatesHandler: updatesHandler)
    }

    func snapshot() -> any ConfigSnapshot {
        InMemoryProvider(name: providerName, values: [:]).snapshot()
    }

    nonisolated(nonsending) func watchSnapshot<Return: ~Copyable>(
        updatesHandler: nonisolated(nonsending) (ConfigUpdatesAsyncSequence<any ConfigSnapshot, Never>) async throws -> Return
    ) async throws -> Return {
        try await watchSnapshotFromSnapshot(updatesHandler: updatesHandler)
    }
}

private extension ConfigContent {
    func matches(type: ConfigType) -> Bool {
        switch (self, type) {
        case (.string, .string),
             (.int, .int),
             (.double, .double),
             (.bool, .bool),
             (.bytes, .bytes),
             (.stringArray, .stringArray),
             (.intArray, .intArray),
             (.doubleArray, .doubleArray),
             (.boolArray, .boolArray),
             (.byteChunkArray, .byteChunkArray):
            return true
        default:
            return false
        }
    }
}

@Suite("SwiftConfigurationSource & RiggingConfigProvider Comprehensive Coverage")
struct SwiftConfigurationComprehensiveTests {

    @Test("SwiftConfigurationKeySpec and SwiftConfigurationSource cover all initializers and all 10 ConfigTypes (sync & async fetch)")
    func swiftConfigurationSourceAllTypesAndInitializers() async throws {
        // String literal ExpressibleByStringLiteral + specs(for:)
        let literalSpec: SwiftConfigurationKeySpec = "http.max_idle_conns"
        #expect(literalSpec.targetKeyPath == ["http", "max_idle_conns"])
        let derivedSpecs = SwiftConfigurationKeySpec.specs(for: CaseSensitiveBridgeModel.self)
        #expect(derivedSpecs.contains(where: { $0.targetKeyPath == ["hostName"] && $0.fallbackKeys.contains(ConfigKey(["legacy", "hostName"])) }))

        // 1. Static `values: [AbsoluteConfigKey: ConfigValue]` covering all 10 ConfigContent cases
        let staticValues: [AbsoluteConfigKey: ConfigValue] = [
            AbsoluteConfigKey(["s"]): ConfigValue(.string("hello"), isSecret: false),
            AbsoluteConfigKey(["i"]): ConfigValue(.int(42), isSecret: false),
            AbsoluteConfigKey(["d"]): ConfigValue(.double(3.5), isSecret: false),
            AbsoluteConfigKey(["b"]): ConfigValue(.bool(true), isSecret: false),
            AbsoluteConfigKey(["bytesUtf8"]): ConfigValue(.bytes(Array("utf8-str".utf8)), isSecret: false),
            AbsoluteConfigKey(["bytesBin"]): ConfigValue(.bytes([0xFF, 0xFE]), isSecret: false),
            AbsoluteConfigKey(["sa"]): ConfigValue(.stringArray(["x", "y"]), isSecret: false),
            AbsoluteConfigKey(["ia"]): ConfigValue(.intArray([1, 2]), isSecret: false),
            AbsoluteConfigKey(["da"]): ConfigValue(.doubleArray([0.5, 1.5]), isSecret: false),
            AbsoluteConfigKey(["ba"]): ConfigValue(.boolArray([true, false]), isSecret: false),
            AbsoluteConfigKey(["bca"]): ConfigValue(.byteChunkArray([Array("c1".utf8), [0xFF]]), isSecret: false),
        ]
        let staticSrc = SwiftConfigurationSource(values: staticValues, name: "StaticSource")
        #expect(staticSrc.sourceName == "StaticSource")
        let staticTree = try await staticSrc.load(configuration: SettingsConfiguration(), context: .inMemory())
        #expect(staticTree.lookup(path: ["s"])?.value == .string("hello"))
        #expect(staticTree.lookup(path: ["i"])?.value == .int(42))
        #expect(staticTree.lookup(path: ["d"])?.value == .double(3.5))
        #expect(staticTree.lookup(path: ["b"])?.value == .bool(true))
        #expect(staticTree.lookup(path: ["bytesUtf8"])?.value == .data(Data("utf8-str".utf8)))
        #expect(staticTree.lookup(path: ["bytesBin"])?.value == .data(Data([0xFF, 0xFE])))
        #expect(staticTree.lookup(path: ["ia"])?.value == .array([
            RawNode(value: .int(1), origin: .customSource(name: "StaticSource", detail: "ia")),
            RawNode(value: .int(2), origin: .customSource(name: "StaticSource", detail: "ia")),
        ]))

        // 2. `init(configValues:name:)`
        let relSrc = SwiftConfigurationSource(
            configValues: [ConfigKey(["nested", "flag"]): ConfigValue(.bool(false), isSecret: false)],
            name: "RelSource"
        )
        #expect(relSrc.sourceName == "RelSource")
        let relTree = try await relSrc.load(configuration: SettingsConfiguration(), context: .inMemory())
        #expect(relTree.lookup(path: ["nested", "flag"])?.value == .bool(false))

        // 3. Non-enumerable `ProbingTestConfigProvider` probed via `useFetch: false` and `useFetch: true`, plus `ConfigReader` `useFetch: false` & `true`!
        let probeStore: [String: ConfigValue] = [
            "legacy.hostName": ConfigValue(.string("alias-host"), isSecret: false),
            "port-number": ConfigValue(.int(9091), isSecret: false),
            "double_timeout": ConfigValue(.double(33.5), isSecret: false),
            "enabled": ConfigValue(.bool(false), isSecret: false),
            "raw-data": ConfigValue(.bytes([0xAA, 0xBB]), isSecret: false),
            "str-list": ConfigValue(.stringArray(["p", "q"]), isSecret: false),
            "int-list": ConfigValue(.intArray([7, 8]), isSecret: false),
            "dbl-list": ConfigValue(.doubleArray([2.0, 4.0]), isSecret: false),
            "bool-list": ConfigValue(.boolArray([false, true]), isSecret: false),
            "extra.chunks": ConfigValue(.byteChunkArray([Array("hi".utf8)]), isSecret: false),
        ]
        let probeProvider = ProbingTestConfigProvider(store: probeStore)
        let extraSpec = SwiftConfigurationKeySpec(
            configKey: ConfigKey(["extra", "chunks"]),
            candidateTypes: [.byteChunkArray]
        )

        let provSyncSrc = SwiftConfigurationSource(
            provider: probeProvider,
            for: CaseSensitiveBridgeModel.self,
            additionalKeys: [extraSpec],
            useFetch: false
        )
        #expect(provSyncSrc.sourceName == "ProbingTestProvider")
        let syncTree = try await provSyncSrc.load(configuration: CaseSensitiveBridgeModel.configuration, context: .inMemory())
        #expect(syncTree.lookup(path: ["hostName"])?.value == .string("alias-host"))
        #expect(syncTree.lookup(path: ["portNumber"])?.value == .int(9091))
        #expect(syncTree.lookup(path: ["doubleTimeout"])?.value == .double(33.5))
        #expect(syncTree.lookup(path: ["enabled"])?.value == .bool(false))
        #expect(syncTree.lookup(path: ["intList"]) != nil)
        #expect(syncTree.lookup(path: ["dblList"]) != nil)
        #expect(syncTree.lookup(path: ["boolList"]) != nil)
        #expect(syncTree.lookup(path: ["extra", "chunks"]) != nil)

        let provAsyncSrc = SwiftConfigurationSource(
            provider: probeProvider,
            for: CaseSensitiveBridgeModel.self,
            additionalKeys: [extraSpec],
            useFetch: true
        )
        let asyncTree = try await provAsyncSrc.load(configuration: CaseSensitiveBridgeModel.configuration, context: .inMemory())
        #expect(asyncTree.lookup(path: ["hostName"])?.value == .string("alias-host"))
        #expect(asyncTree.lookup(path: ["portNumber"])?.value == .int(9091))

        // Reader sync (`useFetch: false`) and async (`useFetch: true`) across all 10 ConfigTypes
        let reader = ConfigReader(provider: probeProvider)
        let readerSyncSrc = SwiftConfigurationSource(
            reader: reader,
            keys: SwiftConfigurationKeySpec.specs(for: CaseSensitiveBridgeModel.self) + [extraSpec],
            name: "ReaderSync",
            useFetch: false
        )
        #expect(readerSyncSrc.sourceName == "ReaderSync")
        let readerSyncTree = try await readerSyncSrc.load(configuration: CaseSensitiveBridgeModel.configuration, context: .inMemory())
        #expect(readerSyncTree.lookup(path: ["portNumber"])?.value == .int(9091))
        #expect(readerSyncTree.lookup(path: ["rawData"]) != nil)
        #expect(readerSyncTree.lookup(path: ["extra", "chunks"]) != nil)

        let readerAsyncSrc = SwiftConfigurationSource(
            reader: reader,
            for: CaseSensitiveBridgeModel.self,
            additionalKeys: [extraSpec],
            name: "ReaderAsync",
            useFetch: true
        )
        let readerAsyncTree = try await readerAsyncSrc.load(configuration: CaseSensitiveBridgeModel.configuration, context: .inMemory())
        #expect(readerAsyncTree.lookup(path: ["doubleTimeout"])?.value == .double(33.5))
        #expect(readerAsyncTree.lookup(path: ["extra", "chunks"]) != nil)
    }

    @Test("RiggingConfigProvider & RiggingConfigSnapshot cover all 10 ConfigType coercions, errors, case-sensitive paths, and manual models")
    func riggingConfigProviderAllCoercionsAndErrors() async throws {
        // Error descriptions
        let convErr = RiggingConfigProviderError.valueNotConvertible(key: "hostName", requestedType: .int)
        #expect(convErr.description.contains("hostName"))
        #expect(convErr.errorDescription == convErr.description)

        let model = try await CaseSensitiveBridgeModel.load(context: .inMemory())
        let provider = model.asConfigProvider(providerName: "CustomBridge")
        #expect(provider.providerName == "CustomBridge")
        #expect(provider.description.contains("CustomBridge["))
        #expect(provider.debugDescription.contains("secretText=**********"))
        #expect(!provider.debugDescription.contains("secretBytes=[222"))

        let snap = provider.snapshot()

        // Case-sensitive kebab-case -> camelCase normalization (`host-name` -> `hostName`, `PORT-NUMBER` -> `PORTNUMBER`)
        #expect(try snap.value(forKey: AbsoluteConfigKey(["host-name"]), type: .string).value?.content == .string("localhost"))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["nonexistent"]), type: .string).value == nil)

        // Coercions across scalar types
        #expect(try snap.value(forKey: AbsoluteConfigKey(["smallInt"]), type: .int).value?.content == .int(16))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["unsignedPort"]), type: .int).value?.content == .int(443))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["unsignedPort"]), type: .double).value?.content == .double(443.0))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["floatRatio"]), type: .double).value?.content == .double(0.5))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["budget"]), type: .double).value?.content == .double(99.5))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["budget"]), type: .string).value?.content == .string("99.5"))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["durationVal"]), type: .double).value?.content == .double(1.5))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["byteLimit"]), type: .int).value?.content == .int(4000))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["byteLimit"]), type: .string).value?.content == .string("4000"))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["enabled"]), type: .bool).value?.content == .bool(true))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["endpointURL"]), type: .string).value?.content == .string("https://example.com"))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["requestID"]), type: .string).value?.content == .string("00000000-0000-0000-0000-000000000042"))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["createdAt"]), type: .string).value != nil)
        #expect(try snap.value(forKey: AbsoluteConfigKey(["rawData"]), type: .bytes).value?.content == .bytes([1, 2, 3]))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["rawBytes"]), type: .bytes).value?.content == .bytes([0x0A, 0x0B]))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["logLevel"]), type: .string).value?.content == .string("info"))

        // Array & dictionary flattening coercions
        #expect(try snap.value(forKey: AbsoluteConfigKey(["intList"]), type: .intArray).value?.content == .intArray([10, 20]))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["intList"]), type: .doubleArray).value?.content == .doubleArray([10.0, 20.0]))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["strList"]), type: .stringArray).value?.content == .stringArray(["a", "b"]))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["dblList"]), type: .doubleArray).value?.content == .doubleArray([1.25, 2.5]))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["boolList"]), type: .boolArray).value?.content == .boolArray([true, false]))
        #expect(try snap.value(forKey: AbsoluteConfigKey(["labels", "alpha"]), type: .int).value?.content == .int(1))

        // Secret coercions preserve `isSecret == true`
        let secInt = try snap.value(forKey: AbsoluteConfigKey(["secretText"]), type: .int)
        #expect(secInt.value?.content == .int(42))
        #expect(secInt.value?.isSecret == true)
        let secBytes = try snap.value(forKey: AbsoluteConfigKey(["secretBytes"]), type: .bytes)
        #expect(secBytes.value?.content == .bytes([0xDE, 0xAD]))
        #expect(secBytes.value?.isSecret == true)

        // Unconvertible type throws RiggingConfigProviderError
        #expect(throws: RiggingConfigProviderError.self) {
            _ = try snap.value(forKey: AbsoluteConfigKey(["hostName"]), type: .int)
        }
        #expect(throws: RiggingConfigProviderError.self) {
            _ = try snap.value(forKey: AbsoluteConfigKey(["hostName"]), type: .boolArray)
        }

        // Watch snapshot emits initial snapshot
        let watchedCount = try await provider.watchSnapshot { updates in
            var iter = updates.makeAsyncIterator()
            let first = try await iter.next()
            return first != nil ? 1 : 0
        }
        #expect(watchedCount == 1)

        // Manual RiggedSettings fallback reflection + string->int/bool/double coercions + byteChunkArray + [Secret<String>]
        let manualProv = ManualBridgeSettings().asConfigProvider()
        #expect(try manualProv.value(forKey: AbsoluteConfigKey(["plainText"]), type: .int).value?.content == .int(123))
        #expect(try manualProv.value(forKey: AbsoluteConfigKey(["plainText"]), type: .double).value?.content == .double(123.0))
        #expect(try manualProv.value(forKey: AbsoluteConfigKey(["boolText"]), type: .bool).value?.content == .bool(true))
        #expect(try manualProv.value(forKey: AbsoluteConfigKey(["chunks"]), type: .byteChunkArray).value?.content == .byteChunkArray([[1, 2], [3]]))
        #expect(try manualProv.value(forKey: AbsoluteConfigKey(["dataChunks"]), type: .byteChunkArray).value?.content == .byteChunkArray([[4, 5]]))
        let manualSecList = try manualProv.value(forKey: AbsoluteConfigKey(["secretList"]), type: .stringArray)
        #expect(manualSecList.value?.content == .stringArray(["s1", "s2"]))
        #expect(manualSecList.value?.isSecret == true)
        #expect(try manualProv.value(forKey: AbsoluteConfigKey(["nestedDict", "region"]), type: .string).value?.content == .string("ap-southeast-2"))
    }
}
