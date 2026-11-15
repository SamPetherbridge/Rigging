import Configuration
import Foundation
import RiggingCore

// MARK: - Key Specification for `SwiftConfigurationSource`

/// Describes a lookup key path, fallback aliases, and candidate value types when bridging an
/// `apple/swift-configuration` `ConfigProvider` or `ConfigReader` into Rigging.
///
/// Use ``specs(for:)`` to derive specifications automatically for every leaf property in a
/// `RiggedSettings` model, or construct custom specifications with string literals:
///
/// ```swift
/// let spec: SwiftConfigurationKeySpec = "http.max-connections"
/// ```
public struct SwiftConfigurationKeySpec: Sendable, Equatable, Hashable, ExpressibleByStringLiteral {
    /// Primary `swift-configuration` key queried first.
    public let configKey: ConfigKey

    /// Fallback `swift-configuration` keys (such as `kebab-case`, `snake_case`, or `.configPath` aliases)
    /// queried in order when ``configKey`` returns `nil`.
    public let fallbackKeys: [ConfigKey]

    /// Destination key path written into Rigging's `RawConfigTree`.
    public let targetKeyPath: [String]

    /// Ordered `Configuration.ConfigType` candidates probed when reading from a `ConfigProvider` or `ConfigReader`.
    public let candidateTypes: [ConfigType]

    /// Creates a key specification mapping a `swift-configuration` key to a Rigging key path.
    ///
    /// - Parameters:
    ///   - configKey: Primary `ConfigKey` to query.
    ///   - fallbackKeys: Alternate keys probed when `configKey` yields `nil`.
    ///   - targetKeyPath: Destination Rigging key path; defaults to `configKey.components`.
    ///   - candidateTypes: Ordered `ConfigType`s to probe; defaults to ``allProbeTypes``.
    public init(
        configKey: ConfigKey,
        fallbackKeys: [ConfigKey] = [],
        targetKeyPath: [String]? = nil,
        candidateTypes: [ConfigType] = Self.allProbeTypes
    ) {
        self.configKey = configKey
        self.fallbackKeys = fallbackKeys
        self.targetKeyPath = targetKeyPath ?? configKey.components
        self.candidateTypes = candidateTypes
    }

    /// Creates a key specification from a dot-separated string literal (for example, `"http.port"`).
    ///
    /// - Parameter value: Dot-separated key path passed to `ConfigKey.init(_:)`.
    public init(stringLiteral value: String) {
        let key = ConfigKey(value)
        self.init(configKey: key, targetKeyPath: key.components)
    }

    /// Exhaustive list of `Configuration.ConfigType` cases probed when no schema-specific order is supplied.
    public static let allProbeTypes: [ConfigType] = [
        .string,
        .int,
        .double,
        .bool,
        .stringArray,
        .intArray,
        .doubleArray,
        .boolArray,
        .bytes,
        .byteChunkArray,
    ]

    /// Derives ``SwiftConfigurationKeySpec`` entries for every leaf field (including `.configPath` aliases,
    /// `kebab-case` variants, and `snake_case` variants) declared on `settingsType`.
    ///
    /// - Parameter settingsType: The `RiggedSettings` type whose `fieldDescriptors` will be inspected.
    /// - Returns: Schema-ordered key specifications covering all leaf settings.
    public static func specs<Settings: RiggedSettings>(
        for settingsType: Settings.Type
    ) -> [SwiftConfigurationKeySpec] {
        collectSpecs(from: Settings.fieldDescriptors, parentPath: [])
    }

    private static func collectSpecs(
        from descriptors: [SettingFieldDescriptor],
        parentPath: [String]
    ) -> [SwiftConfigurationKeySpec] {
        var specs: [SwiftConfigurationKeySpec] = []

        for field in descriptors {
            let canonicalPath: [String]
            if !parentPath.isEmpty && !field.keyPath.starts(with: parentPath) {
                canonicalPath = parentPath + [field.name]
            } else {
                canonicalPath = field.keyPath
            }

            if case .object(let children) = field.schemaType {
                specs.append(contentsOf: collectSpecs(from: children, parentPath: canonicalPath))
                continue
            }

            let primaryKey = ConfigKey(canonicalPath)
            var fallbacks: [ConfigKey] = []

            for alias in field.aliases {
                if case .configPath(let altPath) = alias, altPath != canonicalPath {
                    fallbacks.append(ConfigKey(altPath))
                }
            }

            let kebabPath = canonicalPath.map(camelToKebab)
            if kebabPath != canonicalPath {
                let key = ConfigKey(kebabPath)
                if !fallbacks.contains(key) {
                    fallbacks.append(key)
                }
            }

            let snakePath = canonicalPath.map { camelToKebab($0).replacingOccurrences(of: "-", with: "_") }
            if snakePath != canonicalPath {
                let key = ConfigKey(snakePath)
                if !fallbacks.contains(key) {
                    fallbacks.append(key)
                }
            }

            specs.append(
                SwiftConfigurationKeySpec(
                    configKey: primaryKey,
                    fallbackKeys: fallbacks,
                    targetKeyPath: canonicalPath,
                    candidateTypes: preferredProbeTypes(for: field)
                )
            )
        }

        return specs
    }

    private static func preferredProbeTypes(for field: SettingFieldDescriptor) -> [ConfigType] {
        let baseTypes: [ConfigType]
        switch field.schemaType {
        case .string, .enumValues:
            baseTypes = [.string, .int, .double, .bool, .bytes]
        case .integer:
            baseTypes = [.int, .string, .double]
        case .number:
            baseTypes = [.double, .int, .string]
        case .boolean:
            baseTypes = [.bool, .string, .int]
        case .array(let itemType):
            switch itemType {
            case .integer:
                baseTypes = [.intArray, .stringArray, .string]
            case .number:
                baseTypes = [.doubleArray, .stringArray, .string]
            case .boolean:
                baseTypes = [.boolArray, .stringArray, .string]
            default:
                baseTypes = [.stringArray, .byteChunkArray, .string]
            }
        case .dictionary, .object:
            baseTypes = [.string, .bytes]
        }

        guard field.isSecret else {
            return baseTypes
        }

        // Probe `.string` first on `@SecretSetting` fields so `op://` / `keychain://` / `bws://`
        // URI references resolve before typed coercions, then fall back to typed ConfigTypes & `.bytes`.
        var ordered: [ConfigType] = [.string]
        for candidate in baseTypes where !ordered.contains(candidate) {
            ordered.append(candidate)
        }
        if !ordered.contains(.bytes) {
            ordered.append(.bytes)
        }
        return ordered
    }

    static func camelToKebab(_ input: String) -> String {
        let scalars = Array(input.unicodeScalars)
        guard !scalars.isEmpty else { return input }
        var out = ""
        for idx in scalars.indices {
            let current = scalars[idx]
            if CharacterSet.uppercaseLetters.contains(current) {
                if idx > 0 {
                    let prev = scalars[idx - 1]
                    let prevUpper = CharacterSet.uppercaseLetters.contains(prev)
                    let nextLower = (idx + 1 < scalars.count)
                        && CharacterSet.lowercaseLetters.contains(scalars[idx + 1])
                    if prev != "_" && prev != "-" && (!prevUpper || nextLower) {
                        out.append("-")
                    }
                }
                out.append(String(current).lowercased())
            } else if current == "_" {
                if !out.hasSuffix("-") && !out.isEmpty {
                    out.append("-")
                }
            } else {
                out.append(Character(current))
            }
        }
        return out
    }
}

// MARK: - Direction A: `SwiftConfigurationSource`

/// A `SettingsSource` adapter that bridges a `Configuration.ConfigProvider`, `Configuration.ConfigReader`,
/// or `[AbsoluteConfigKey: ConfigValue]` dictionary into Rigging's configuration pipeline.
///
/// Values read from `swift-configuration` participate in Rigging's full source precedence cascade,
/// two-phase batched secret resolution (for example, `"op://..."` strings supplied via a
/// `ConfigProvider`), aggregated schema validation, and `$field` provenance tracking.
///
/// ```swift
/// let provider = InMemoryProvider(values: [
///     "http.host": "0.0.0.0",
///     "http.port": 8080,
/// ])
/// let source = SwiftConfigurationSource(provider: provider, for: AppSettings.self)
/// ```
public struct SwiftConfigurationSource: SettingsSource, Sendable {
    private enum Backing: Sendable {
        case staticValues(name: String, values: [AbsoluteConfigKey: ConfigValue])
        case provider(
            provider: any ConfigProvider,
            keys: [SwiftConfigurationKeySpec],
            useFetch: Bool
        )
        case reader(
            reader: ConfigReader,
            name: String,
            keys: [SwiftConfigurationKeySpec],
            useFetch: Bool
        )
    }

    private let backing: Backing

    /// Human-readable name identifying the underlying `ConfigProvider` or `ConfigReader` in provenance reports.
    public var sourceName: String {
        switch backing {
        case .staticValues(let name, _):
            return name
        case .provider(let provider, _, _):
            return provider.providerName
        case .reader(_, let name, _, _):
            return name
        }
    }

    /// Creates a `SettingsSource` from an explicit dictionary of `AbsoluteConfigKey` values.
    ///
    /// - Parameters:
    ///   - values: Static `ConfigValue` entries keyed by `AbsoluteConfigKey`.
    ///   - name: Provenance source name recorded in `SettingOrigin.customSource`.
    public init(
        values: [AbsoluteConfigKey: ConfigValue],
        name: String = "SwiftConfigurationSource"
    ) {
        self.backing = .staticValues(name: name, values: values)
    }

    /// Creates a `SettingsSource` from a dictionary of relative `ConfigKey` values.
    ///
    /// - Parameters:
    ///   - configValues: Static `ConfigValue` entries keyed by `ConfigKey`.
    ///   - name: Provenance source name recorded in `SettingOrigin.customSource`.
    public init(
        configValues: [ConfigKey: ConfigValue],
        name: String = "SwiftConfigurationSource"
    ) {
        var converted: [AbsoluteConfigKey: ConfigValue] = [:]
        for (key, value) in configValues {
            converted[AbsoluteConfigKey(key.components, context: key.context)] = value
        }
        self.backing = .staticValues(name: name, values: converted)
    }

    /// Wraps any `Configuration.ConfigProvider` as a Rigging `SettingsSource`.
    ///
    /// - Parameters:
    ///   - provider: The upstream `swift-configuration` provider.
    ///   - keys: Optional explicit key specifications to query. Enumerable snapshot entries (such as
    ///     `InMemoryProvider`) are extracted automatically; for non-enumerable providers like
    ///     `EnvironmentVariablesProvider`, prefer ``init(provider:for:additionalKeys:useFetch:)`` or pass `keys`.
    ///   - useFetch: When `true`, calls `provider.fetchValue(forKey:type:)` instead of `provider.value(forKey:type:)`.
    public init(
        provider: any ConfigProvider,
        keys: [SwiftConfigurationKeySpec] = [],
        useFetch: Bool = false
    ) {
        self.backing = .provider(provider: provider, keys: keys, useFetch: useFetch)
    }

    /// Wraps any `Configuration.ConfigProvider` using schema key specifications derived from `settingsType`.
    ///
    /// - Parameters:
    ///   - provider: The upstream `swift-configuration` provider.
    ///   - settingsType: The `RiggedSettings` model whose leaf key paths, `kebab-case`, and `snake_case` variants are probed.
    ///   - additionalKeys: Extra key specifications probed alongside schema-derived keys.
    ///   - useFetch: When `true`, calls `provider.fetchValue(forKey:type:)` instead of `provider.value(forKey:type:)`.
    public init<Settings: RiggedSettings>(
        provider: any ConfigProvider,
        for settingsType: Settings.Type,
        additionalKeys: [SwiftConfigurationKeySpec] = [],
        useFetch: Bool = false
    ) {
        let derived = SwiftConfigurationKeySpec.specs(for: settingsType) + additionalKeys
        self.backing = .provider(provider: provider, keys: derived, useFetch: useFetch)
    }

    /// Wraps a `Configuration.ConfigReader` as a Rigging `SettingsSource`.
    ///
    /// - Parameters:
    ///   - reader: Upstream `ConfigReader` (including scoped readers created with `reader.scoped(to:)`).
    ///   - keys: Optional explicit key specifications to probe through `reader`.
    ///   - name: Provenance source name recorded in `SettingOrigin.customSource`.
    ///   - useFetch: When `true`, invokes `fetch*` methods on `ConfigReader` instead of synchronous accessors.
    public init(
        reader: ConfigReader,
        keys: [SwiftConfigurationKeySpec] = [],
        name: String = "ConfigReader",
        useFetch: Bool = false
    ) {
        self.backing = .reader(reader: reader, name: name, keys: keys, useFetch: useFetch)
    }

    /// Wraps a `Configuration.ConfigReader` using schema key specifications derived from `settingsType`.
    ///
    /// - Parameters:
    ///   - reader: Upstream `ConfigReader` (including scoped readers).
    ///   - settingsType: The `RiggedSettings` model whose leaf key paths, `kebab-case`, and `snake_case` variants are probed.
    ///   - additionalKeys: Extra key specifications probed alongside schema-derived keys.
    ///   - name: Provenance source name recorded in `SettingOrigin.customSource`.
    ///   - useFetch: When `true`, invokes `fetch*` methods on `ConfigReader` instead of synchronous accessors.
    public init<Settings: RiggedSettings>(
        reader: ConfigReader,
        for settingsType: Settings.Type,
        additionalKeys: [SwiftConfigurationKeySpec] = [],
        name: String = "ConfigReader",
        useFetch: Bool = false
    ) {
        let derived = SwiftConfigurationKeySpec.specs(for: settingsType) + additionalKeys
        self.backing = .reader(reader: reader, name: name, keys: derived, useFetch: useFetch)
    }

    /// Reads values from the underlying `ConfigProvider`, `ConfigReader`, or dictionary into a `RawConfigTree`.
    ///
    /// - Parameters:
    ///   - configuration: Settings configuration controlling key case sensitivity.
    ///   - context: Execution context for the load pass.
    /// - Returns: A `RawConfigTree` tagged with `SettingOrigin.customSource` provenance.
    /// - Throws: Rethrows unexpected transport errors thrown by asynchronous `fetchValue` providers.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        var tree = RawConfigTree()

        switch backing {
        case .staticValues(let name, let values):
            insertSnapshotDictionary(
                values,
                into: &tree,
                providerName: name,
                caseSensitive: configuration.caseSensitive
            )

        case .provider(let provider, let specs, let useFetch):
            // 1. Extract any enumerable snapshot values first (covers InMemoryProvider & extraKeys)
            let snapshotValues = SnapshotMirrorIntrospector.extractValues(fromSnapshot: provider.snapshot())
            if !snapshotValues.isEmpty {
                insertSnapshotDictionary(
                    snapshotValues,
                    into: &tree,
                    providerName: provider.providerName,
                    caseSensitive: configuration.caseSensitive
                )
            }

            // 2. Probe explicit / schema-derived key specs via ConfigProvider protocol
            for spec in specs {
                if let (encodedKey, configVal) = try await probeProvider(
                    provider,
                    spec: spec,
                    useFetch: useFetch
                ) {
                    let origin = SettingOrigin.customSource(
                        name: provider.providerName,
                        detail: encodedKey
                    )
                    let rawVal = Self.convertContent(configVal.content, origin: origin)
                    tree.set(
                        path: spec.targetKeyPath,
                        value: rawVal,
                        origin: origin,
                        caseSensitive: configuration.caseSensitive
                    )
                }
            }

        case .reader(let reader, let name, let specs, let useFetch):
            // 1. Extract enumerable snapshot values from underlying providers (respecting reader keyPrefix & provider order)
            let extracted = SnapshotMirrorIntrospector.extractValues(fromReader: reader)
            for layer in extracted.reversed() {
                insertSnapshotDictionary(
                    layer.values,
                    into: &tree,
                    providerName: layer.providerName,
                    caseSensitive: configuration.caseSensitive
                )
            }

            // 2. Probe explicit / schema-derived key specs through ConfigReader public accessors
            for spec in specs {
                if let (matchedKey, rawVal) = try await probeReader(
                    reader,
                    spec: spec,
                    sourceName: name,
                    useFetch: useFetch
                ) {
                    let origin = SettingOrigin.customSource(
                        name: name,
                        detail: matchedKey.description
                    )
                    tree.set(
                        path: spec.targetKeyPath,
                        value: rawVal,
                        origin: origin,
                        caseSensitive: configuration.caseSensitive
                    )
                }
            }
        }

        return tree
    }

    // MARK: - Probing & Conversion Helpers

    private func insertSnapshotDictionary(
        _ values: [AbsoluteConfigKey: ConfigValue],
        into tree: inout RawConfigTree,
        providerName: String,
        caseSensitive: Bool
    ) {
        let sortedKeys = values.keys.sorted {
            $0.components.joined(separator: ".") < $1.components.joined(separator: ".")
        }
        for key in sortedKeys {
            guard let configValue = values[key], !key.components.isEmpty else { continue }
            let detail = key.components.joined(separator: ".")
            let origin = SettingOrigin.customSource(name: providerName, detail: detail)
            let rawValue = Self.convertContent(configValue.content, origin: origin)
            tree.set(
                path: key.components,
                value: rawValue,
                origin: origin,
                caseSensitive: caseSensitive
            )
        }
    }

    private func probeProvider(
        _ provider: any ConfigProvider,
        spec: SwiftConfigurationKeySpec,
        useFetch: Bool
    ) async throws -> (String, ConfigValue)? {
        let candidateKeys = [spec.configKey] + spec.fallbackKeys
        for key in candidateKeys {
            let absKey = AbsoluteConfigKey(key.components, context: key.context)
            for candidateType in spec.candidateTypes {
                do {
                    let result: LookupResult
                    if useFetch {
                        result = try await provider.fetchValue(forKey: absKey, type: candidateType)
                    } else {
                        result = try provider.value(forKey: absKey, type: candidateType)
                    }
                    if let found = result.value {
                        let detail = result.encodedKey.isEmpty
                            ? absKey.components.joined(separator: ".")
                            : result.encodedKey
                        return (detail, found)
                    }
                } catch {
                    // Type mismatch on a typed provider (e.g. InMemoryProvider) -> try next ConfigType
                    continue
                }
            }
        }
        return nil
    }

    private func probeReader(
        _ reader: ConfigReader,
        spec: SwiftConfigurationKeySpec,
        sourceName: String,
        useFetch: Bool
    ) async throws -> (ConfigKey, RawValue)? {
        let candidateKeys = [spec.configKey] + spec.fallbackKeys
        for key in candidateKeys {
            let origin = SettingOrigin.customSource(name: sourceName, detail: key.description)
            for candidateType in spec.candidateTypes {
                if let value = try await readSingleType(
                    from: reader,
                    key: key,
                    type: candidateType,
                    origin: origin,
                    useFetch: useFetch
                ) {
                    return (key, value)
                }
            }
        }
        return nil
    }

    private func readSingleType(
        from reader: ConfigReader,
        key: ConfigKey,
        type: ConfigType,
        origin: SettingOrigin,
        useFetch: Bool
    ) async throws -> RawValue? {
        switch type {
        case .string:
            let val = useFetch ? try await reader.fetchString(forKey: key) : reader.string(forKey: key)
            return val.map(RawValue.string)
        case .int:
            let val = useFetch ? try await reader.fetchInt(forKey: key) : reader.int(forKey: key)
            return val.map { .int(Int64($0)) }
        case .double:
            let val = useFetch ? try await reader.fetchDouble(forKey: key) : reader.double(forKey: key)
            return val.map(RawValue.double)
        case .bool:
            let val = useFetch ? try await reader.fetchBool(forKey: key) : reader.bool(forKey: key)
            return val.map(RawValue.bool)
        case .bytes:
            let val = useFetch ? try await reader.fetchBytes(forKey: key) : reader.bytes(forKey: key)
            return val.map { .data(Data($0)) }
        case .stringArray:
            let val = useFetch ? try await reader.fetchStringArray(forKey: key) : reader.stringArray(forKey: key)
            return val.map { arr in .array(arr.map { RawNode(value: .string($0), origin: origin) }) }
        case .intArray:
            let val = useFetch ? try await reader.fetchIntArray(forKey: key) : reader.intArray(forKey: key)
            return val.map { arr in .array(arr.map { RawNode(value: .int(Int64($0)), origin: origin) }) }
        case .doubleArray:
            let val = useFetch ? try await reader.fetchDoubleArray(forKey: key) : reader.doubleArray(forKey: key)
            return val.map { arr in .array(arr.map { RawNode(value: .double($0), origin: origin) }) }
        case .boolArray:
            let val = useFetch ? try await reader.fetchBoolArray(forKey: key) : reader.boolArray(forKey: key)
            return val.map { arr in .array(arr.map { RawNode(value: .bool($0), origin: origin) }) }
        case .byteChunkArray:
            let val = useFetch ? try await reader.fetchByteChunkArray(forKey: key) : reader.byteChunkArray(forKey: key)
            return val.map { arr in .array(arr.map { RawNode(value: .data(Data($0)), origin: origin) }) }
        }
    }

    static func convertContent(_ content: ConfigContent, origin: SettingOrigin) -> RawValue {
        switch content {
        case .string(let value):
            return .string(value)
        case .int(let value):
            return .int(Int64(value))
        case .double(let value):
            return .double(value)
        case .bool(let value):
            return .bool(value)
        case .bytes(let bytes):
            return .data(Data(bytes))
        case .stringArray(let values):
            return .array(values.map { RawNode(value: .string($0), origin: origin) })
        case .intArray(let values):
            return .array(values.map { RawNode(value: .int(Int64($0)), origin: origin) })
        case .doubleArray(let values):
            return .array(values.map { RawNode(value: .double($0), origin: origin) })
        case .boolArray(let values):
            return .array(values.map { RawNode(value: .bool($0), origin: origin) })
        case .byteChunkArray(let chunks):
            return .array(chunks.map { RawNode(value: .data(Data($0)), origin: origin) })
        }
    }
}

// MARK: - Snapshot Introspection Helper

enum SnapshotMirrorIntrospector {
    struct ExtractedLayer {
        let providerName: String
        let values: [AbsoluteConfigKey: ConfigValue]
    }

    static func extractValues(fromSnapshot snapshot: any ConfigSnapshot) -> [AbsoluteConfigKey: ConfigValue] {
        let mirror = Mirror(reflecting: snapshot)
        for child in mirror.children {
            if let dict = child.value as? [AbsoluteConfigKey: ConfigValue] {
                return dict
            }
        }
        return [:]
    }

    static func extractValues(fromReader reader: ConfigReader) -> [ExtractedLayer] {
        let readerMirror = Mirror(reflecting: reader)
        let keyPrefix = readerMirror.children
            .first(where: { $0.label == "keyPrefix" })
            .flatMap { $0.value as? AbsoluteConfigKey }

        guard let storageChild = readerMirror.children.first(where: { $0.label == "storage" }) else {
            return []
        }

        let storageMirror = Mirror(reflecting: storageChild.value)
        guard let multiProviderChild = storageMirror.children.first(where: { $0.label == "provider" }) else {
            return []
        }

        let providers = extractProvidersFromMultiProvider(multiProviderChild.value)
        var layers: [ExtractedLayer] = []

        for provider in providers {
            let rawDict = extractValues(fromSnapshot: provider.snapshot())
            guard !rawDict.isEmpty else { continue }

            let scopedDict: [AbsoluteConfigKey: ConfigValue]
            if let prefix = keyPrefix?.components, !prefix.isEmpty {
                var filtered: [AbsoluteConfigKey: ConfigValue] = [:]
                for (absKey, val) in rawDict where absKey.components.starts(with: prefix) {
                    let remainder = Array(absKey.components.dropFirst(prefix.count))
                    guard !remainder.isEmpty else { continue }
                    filtered[AbsoluteConfigKey(remainder, context: absKey.context)] = val
                }
                scopedDict = filtered
            } else {
                scopedDict = rawDict
            }

            if !scopedDict.isEmpty {
                layers.append(ExtractedLayer(providerName: provider.providerName, values: scopedDict))
            }
        }

        return layers
    }

    private static func extractProvidersFromMultiProvider(_ multiProvider: Any) -> [any ConfigProvider] {
        let mpMirror = Mirror(reflecting: multiProvider)
        for child in mpMirror.children {
            if let list = child.value as? [any ConfigProvider] {
                return list
            }
            let innerMirror = Mirror(reflecting: child.value)
            for innerChild in innerMirror.children {
                if let list = innerChild.value as? [any ConfigProvider] {
                    return list
                }
            }
        }
        return []
    }
}
