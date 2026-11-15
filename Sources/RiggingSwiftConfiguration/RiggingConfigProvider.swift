import Configuration
import Foundation
import RiggingCore

// MARK: - Conversion Errors

/// Errors thrown when `RiggingConfigProvider` cannot coerce a stored setting value to a requested `ConfigType`.
public enum RiggingConfigProviderError: Error, Sendable, Equatable, CustomStringConvertible {
    case valueNotConvertible(key: String, requestedType: ConfigType)

    public var description: String {
        switch self {
        case .valueNotConvertible(let key, let requestedType):
            return "Configuration value for key '\(key)' cannot be converted to '\(requestedType.rawValue)'."
        }
    }
}

// MARK: - Direction B: `RiggingConfigProvider` & `RiggingConfigSnapshot`

/// Immutable `Configuration.ConfigSnapshot` backed by a validated, secret-resolved `Rigging` settings value.
public struct RiggingConfigSnapshot: ConfigSnapshot, Sendable {
    public let providerName: String
    fileprivate let entriesByExactPath: [[String]: StoredSettingEntry]
    fileprivate let canonicalPathByNormalized: [[String]: [String]]
    fileprivate let caseSensitive: Bool

    public func value(
        forKey key: AbsoluteConfigKey,
        type: ConfigType
    ) throws -> LookupResult {
        let encodedKey = key.components.joined(separator: ".")
        guard let entry = lookupEntry(for: key.components) else {
            return LookupResult(encodedKey: encodedKey, value: nil)
        }
        let content = try entry.coerce(to: type, encodedKey: encodedKey)
        return LookupResult(
            encodedKey: encodedKey,
            value: ConfigValue(content, isSecret: entry.isSecret)
        )
    }

    fileprivate func lookupEntry(for components: [String]) -> StoredSettingEntry? {
        if let exact = entriesByExactPath[components] {
            return exact
        }
        let normalized = Self.normalizePath(components, caseSensitive: caseSensitive)
        if let canonical = canonicalPathByNormalized[normalized],
           let found = entriesByExactPath[canonical] {
            return found
        }
        return nil
    }

    static func normalizePath(_ path: [String], caseSensitive: Bool) -> [String] {
        path.map { segment in
            let condensed = segment
                .replacingOccurrences(of: "-", with: "")
                .replacingOccurrences(of: "_", with: "")
            return caseSensitive ? condensed : condensed.lowercased()
        }
    }
}

extension RiggingConfigSnapshot: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "\(providerName)[\(entriesByExactPath.count) keys]"
    }

    public var debugDescription: String {
        let sorted = entriesByExactPath.keys.sorted {
            $0.joined(separator: ".") < $1.joined(separator: ".")
        }
        let summary = sorted.compactMap { path -> String? in
            guard let entry = entriesByExactPath[path] else { return nil }
            let rendered = entry.isSecret ? "**********" : entry.safeSummary
            return "\(path.joined(separator: "."))=\(rendered)"
        }.joined(separator: ", ")
        return "\(providerName)[\(summary)]"
    }
}

/// `Configuration.ConfigProvider` exposing a validated, secret-dereferenced `Rigging` settings
/// model to the `apple/swift-configuration` ecosystem (`ConfigReader`, Hummingbird, gRPC, etc.).
///
/// Every `@SecretSetting` field (and any entry marked `isSecret` in `ProvenanceReport`) is
/// surfaced with `ConfigValue(..., isSecret: true)` so `swift-configuration`'s `AccessReporter` /
/// `AccessLogger` automatically redacts sensitive values in logs and traces.
public struct RiggingConfigProvider: ConfigProvider, Sendable {
    private let _snapshot: RiggingConfigSnapshot

    public var providerName: String {
        _snapshot.providerName
    }

    /// Creates a `ConfigProvider` backed by a resolved `RiggedSettings` instance.
    public init<Settings: RiggedSettings>(
        settings: Settings,
        providerName: String? = nil
    ) {
        let resolvedName = providerName ?? "Rigging[\(String(describing: Settings.self))]"
        self._snapshot = SettingsSnapshotBuilder.buildSnapshot(
            from: settings,
            providerName: resolvedName
        )
    }

    public func value(
        forKey key: AbsoluteConfigKey,
        type: ConfigType
    ) throws -> LookupResult {
        try _snapshot.value(forKey: key, type: type)
    }

    nonisolated(nonsending) public func fetchValue(
        forKey key: AbsoluteConfigKey,
        type: ConfigType
    ) async throws -> LookupResult {
        try _snapshot.value(forKey: key, type: type)
    }

    nonisolated(nonsending) public func watchValue<Return: ~Copyable>(
        forKey key: AbsoluteConfigKey,
        type: ConfigType,
        updatesHandler: nonisolated(nonsending) (
            _ updates: ConfigUpdatesAsyncSequence<Result<LookupResult, any Error>, Never>
        ) async throws -> Return
    ) async throws -> Return {
        try await watchValueFromValue(
            forKey: key,
            type: type,
            updatesHandler: updatesHandler
        )
    }

    public func snapshot() -> any ConfigSnapshot {
        _snapshot
    }

    nonisolated(nonsending) public func watchSnapshot<Return: ~Copyable>(
        updatesHandler: nonisolated(nonsending) (_ updates: ConfigUpdatesAsyncSequence<any ConfigSnapshot, Never>) async throws -> Return
    ) async throws -> Return {
        try await watchSnapshotFromSnapshot(updatesHandler: updatesHandler)
    }
}

extension RiggingConfigProvider: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { _snapshot.description }
    public var debugDescription: String { _snapshot.debugDescription }
}

// MARK: - `RiggedSettings` Convenience Extensions

extension RiggedSettings {
    /// Exposes this validated, secret-resolved `Rigging` settings instance as an
    /// `apple/swift-configuration` `ConfigProvider`, preserving `isSecret: true` on all
    /// `@SecretSetting` fields.
    public func asConfigProvider(providerName: String? = nil) -> RiggingConfigProvider {
        RiggingConfigProvider(settings: self, providerName: providerName)
    }

    /// Exposes this validated, secret-resolved `Rigging` settings instance as a standard
    /// `Configuration.ConfigReader` ready for downstream Swift Server components.
    public func asConfigReader(
        providerName: String? = nil,
        accessReporter: (any AccessReporter)? = nil
    ) -> ConfigReader {
        ConfigReader(
            provider: asConfigProvider(providerName: providerName),
            accessReporter: accessReporter
        )
    }
}

// MARK: - Internal Extraction & Type Coercion

private protocol ExposedSecretBox {
    var exposedSecretValue: Any { get }
}

extension Secret: ExposedSecretBox {
    var exposedSecretValue: Any {
        expose()
    }
}

private protocol OptionalBox {
    var unwrappedAny: Any? { get }
}

extension Optional: OptionalBox {
    var unwrappedAny: Any? {
        switch self {
        case .some(let wrapped):
            if let nested = wrapped as? any OptionalBox {
                return nested.unwrappedAny
            }
            return wrapped
        case .none:
            return nil
        }
    }
}

private protocol RawRepresentableStringBox {
    var rawStringRepresentation: String? { get }
    var rawIntRepresentation: Int? { get }
}

extension RawRepresentable {
    var _bridgedRawString: String? {
        if let s = rawValue as? String {
            return s
        }
        return nil
    }

    var _bridgedRawInt: Int? {
        if let i = rawValue as? Int {
            return i
        }
        if let i64 = rawValue as? Int64 {
            return Int(exactly: i64)
        }
        return nil
    }
}

struct StoredSettingEntry: @unchecked Sendable {
    let rawValue: Any
    let isSecret: Bool
    let safeSummary: String

    func coerce(to requestedType: ConfigType, encodedKey: String) throws -> ConfigContent {
        switch requestedType {
        case .string:
            if let str = coerceString(from: rawValue) {
                return .string(str)
            }
        case .int:
            if let intVal = coerceInt(from: rawValue) {
                return .int(intVal)
            }
        case .double:
            if let dblVal = coerceDouble(from: rawValue) {
                return .double(dblVal)
            }
        case .bool:
            if let boolVal = coerceBool(from: rawValue) {
                return .bool(boolVal)
            }
        case .bytes:
            if let bytes = coerceBytes(from: rawValue) {
                return .bytes(bytes)
            }
        case .stringArray:
            if let arr = coerceArray(from: rawValue, elementTransform: coerceString(from:)) {
                return .stringArray(arr)
            }
        case .intArray:
            if let arr = coerceArray(from: rawValue, elementTransform: coerceInt(from:)) {
                return .intArray(arr)
            }
        case .doubleArray:
            if let arr = coerceArray(from: rawValue, elementTransform: coerceDouble(from:)) {
                return .doubleArray(arr)
            }
        case .boolArray:
            if let arr = coerceArray(from: rawValue, elementTransform: coerceBool(from:)) {
                return .boolArray(arr)
            }
        case .byteChunkArray:
            if let arr = coerceArray(from: rawValue, elementTransform: coerceBytes(from:)) {
                return .byteChunkArray(arr)
            }
        }

        throw RiggingConfigProviderError.valueNotConvertible(
            key: encodedKey,
            requestedType: requestedType
        )
    }

    private func coerceString(from value: Any) -> String? {
        if let str = value as? String {
            return str
        }
        if let sub = value as? Substring {
            return String(sub)
        }
        if let url = value as? URL {
            return url.absoluteString
        }
        if let uuid = value as? UUID {
            return uuid.uuidString
        }
        if let date = value as? Date {
            return date.ISO8601Format()
        }
        if let byteCount = value as? ByteCount {
            return String(byteCount.bytes)
        }
        if let data = value as? Data {
            return String(data: data, encoding: .utf8) ?? data.base64EncodedString()
        }
        if let bytes = value as? [UInt8] {
            return String(bytes: bytes, encoding: .utf8) ?? Data(bytes).base64EncodedString()
        }
        if let decimal = value as? Decimal {
            return NSDecimalNumber(decimal: decimal).stringValue
        }
        let mirror = Mirror(reflecting: value)
        if mirror.displayStyle == .enum {
            return extractEnumString(value)
        }
        return nil
    }

    private func coerceInt(from value: Any) -> Int? {
        if let i = value as? Int { return i }
        if let i8 = value as? Int8 { return Int(i8) }
        if let i16 = value as? Int16 { return Int(i16) }
        if let i32 = value as? Int32 { return Int(i32) }
        if let i64 = value as? Int64 { return Int(exactly: i64) }
        if let u = value as? UInt { return Int(exactly: u) }
        if let u8 = value as? UInt8 { return Int(u8) }
        if let u16 = value as? UInt16 { return Int(u16) }
        if let u32 = value as? UInt32 { return Int(u32) }
        if let u64 = value as? UInt64 { return Int(exactly: u64) }
        if let byteCount = value as? ByteCount { return Int(exactly: byteCount.bytes) }
        if let duration = value as? Duration {
            let (seconds, attoseconds) = duration.components
            if attoseconds == 0 {
                return Int(exactly: seconds)
            }
        }
        if let str = value as? String, let parsed = Int(str.trimmingCharacters(in: .whitespaces)) {
            return parsed
        }
        return nil
    }

    private func coerceDouble(from value: Any) -> Double? {
        if let d = value as? Double { return d }
        if let f = value as? Float { return Double(f) }
        if let dec = value as? Decimal { return NSDecimalNumber(decimal: dec).doubleValue }
        if let duration = value as? Duration {
            let (seconds, attoseconds) = duration.components
            return Double(seconds) + (Double(attoseconds) / 1e18)
        }
        if let i = coerceInt(from: value) {
            return Double(i)
        }
        if let str = value as? String, let parsed = Double(str.trimmingCharacters(in: .whitespaces)) {
            return parsed
        }
        return nil
    }

    private func coerceBool(from value: Any) -> Bool? {
        if let b = value as? Bool { return b }
        if let str = value as? String {
            switch str.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "true", "1", "yes", "on": return true
            case "false", "0", "no", "off": return false
            default: return nil
            }
        }
        return nil
    }

    private func coerceBytes(from value: Any) -> [UInt8]? {
        if let bytes = value as? [UInt8] { return bytes }
        if let data = value as? Data { return Array(data) }
        if let str = value as? String { return Array(str.utf8) }
        return nil
    }

    private func coerceArray<Element>(
        from value: Any,
        elementTransform: (Any) -> Element?
    ) -> [Element]? {
        let mirror = Mirror(reflecting: value)
        guard mirror.displayStyle == .collection || mirror.displayStyle == .set else {
            return nil
        }
        var output: [Element] = []
        output.reserveCapacity(mirror.children.count)
        for child in mirror.children {
            let item: Any
            if let secret = child.value as? any ExposedSecretBox {
                item = secret.exposedSecretValue
            } else {
                item = child.value
            }
            guard let converted = elementTransform(item) else {
                return nil
            }
            output.append(converted)
        }
        return output
    }

    private func extractEnumString(_ value: Any) -> String {
        if let custom = value as? any CustomStringConvertible {
            let desc = custom.description
            if !desc.isEmpty {
                return desc
            }
        }
        return String(describing: value)
    }
}

enum SettingsSnapshotBuilder {
    private struct SchemaFieldMeta {
        let isSecret: Bool
        let aliasPaths: [[String]]
    }

    static func buildSnapshot<Settings: RiggedSettings>(
        from settings: Settings,
        providerName: String
    ) -> RiggingConfigSnapshot {
        let config = Settings.configuration
        let report = settings.provenanceReport()

        var schemaMetaByPath: [[String]: SchemaFieldMeta] = [:]
        collectSchemaMetadata(
            descriptors: Settings.fieldDescriptors,
            parentPath: [],
            into: &schemaMetaByPath
        )

        var secretPaths = Set<[String]>()
        for (path, meta) in schemaMetaByPath where meta.isSecret {
            secretPaths.insert(path)
        }
        for entry in report.entries where entry.isSecret {
            secretPaths.insert(entry.keyPath)
        }

        var entriesByExactPath: [[String]: StoredSettingEntry] = [:]
        var canonicalPathByNormalized: [[String]: [String]] = [:]

        func register(path: [String], entry: StoredSettingEntry) {
            guard !path.isEmpty else { return }
            entriesByExactPath[path] = entry
            let normalized = RiggingConfigSnapshot.normalizePath(path, caseSensitive: config.caseSensitive)
            if canonicalPathByNormalized[normalized] == nil {
                canonicalPathByNormalized[normalized] = path
            }
            if let meta = schemaMetaByPath[path] {
                for aliasPath in meta.aliasPaths where !aliasPath.isEmpty {
                    entriesByExactPath[aliasPath] = entry
                    let normAlias = RiggingConfigSnapshot.normalizePath(aliasPath, caseSensitive: config.caseSensitive)
                    if canonicalPathByNormalized[normAlias] == nil {
                        canonicalPathByNormalized[normAlias] = path
                    }
                }
            }
        }

        walkValue(
            settings,
            prefix: [],
            secretPaths: secretPaths,
            register: register
        )

        // Fallback for manual `RiggedSettings` implementations that expose non-secret entries via `provenanceReport()`
        for provEntry in report.entries where entriesByExactPath[provEntry.keyPath] == nil && !provEntry.isSecret {
            let fallbackEntry = StoredSettingEntry(
                rawValue: provEntry.displayValue,
                isSecret: false,
                safeSummary: provEntry.displayValue
            )
            register(path: provEntry.keyPath, entry: fallbackEntry)
        }

        return RiggingConfigSnapshot(
            providerName: providerName,
            entriesByExactPath: entriesByExactPath,
            canonicalPathByNormalized: canonicalPathByNormalized,
            caseSensitive: config.caseSensitive
        )
    }

    private static func collectSchemaMetadata(
        descriptors: [SettingFieldDescriptor],
        parentPath: [String],
        into map: inout [[String]: SchemaFieldMeta]
    ) {
        for field in descriptors {
            let fullPath: [String]
            if !parentPath.isEmpty && !field.keyPath.starts(with: parentPath) {
                fullPath = parentPath + [field.name]
            } else {
                fullPath = field.keyPath
            }

            var aliasPaths: [[String]] = []
            for alias in field.aliases {
                if case .configPath(let alt) = alias {
                    aliasPaths.append(alt)
                }
            }

            map[fullPath] = SchemaFieldMeta(isSecret: field.isSecret, aliasPaths: aliasPaths)

            if case .object(let children) = field.schemaType {
                collectSchemaMetadata(descriptors: children, parentPath: fullPath, into: &map)
            }
        }
    }

    private static func walkValue(
        _ instance: Any,
        prefix: [String],
        secretPaths: Set<[String]>,
        register: ([String], StoredSettingEntry) -> Void
    ) {
        let mirror = Mirror(reflecting: instance)
        for child in mirror.children {
            guard let label = child.label, !label.isEmpty, !label.hasPrefix("_") else {
                continue
            }

            let path = prefix + [label]

            // Unwrap Optional<T>: omit nil optionals so ConfigReader falls back to defaults cleanly
            let unwrapped: Any
            if let opt = child.value as? any OptionalBox {
                guard let inner = opt.unwrappedAny else {
                    continue
                }
                unwrapped = inner
            } else {
                unwrapped = child.value
            }

            // Unwrap Secret<T> via ExposedSecretBox (never via Mirror, since Secret.customMirror is empty)
            if let secretBox = unwrapped as? any ExposedSecretBox {
                let innerSecret = secretBox.exposedSecretValue
                register(
                    path,
                    StoredSettingEntry(
                        rawValue: innerSecret,
                        isSecret: true,
                        safeSummary: "**********"
                    )
                )
                continue
            }

            // Recurse into nested `@NestedSettings` structs
            if unwrapped is any RiggedNestedSettings {
                walkValue(
                    unwrapped,
                    prefix: path,
                    secretPaths: secretPaths,
                    register: register
                )
                continue
            }

            // Flatten `[String: V]` dictionaries under `path + [key]` as well
            let valueMirror = Mirror(reflecting: unwrapped)
            if valueMirror.displayStyle == .dictionary {
                let inheritedSecret = secretPaths.contains(path)
                for pair in valueMirror.children {
                    let pairMirror = Mirror(reflecting: pair.value)
                    let tupleItems = Array(pairMirror.children)
                    guard tupleItems.count == 2,
                          let dictKey = tupleItems[0].value as? String else {
                        continue
                    }
                    let rawDictVal = tupleItems[1].value
                    let subPath = path + [dictKey]
                    if let secretBox = rawDictVal as? any ExposedSecretBox {
                        register(
                            subPath,
                            StoredSettingEntry(
                                rawValue: secretBox.exposedSecretValue,
                                isSecret: true,
                                safeSummary: "**********"
                            )
                        )
                    } else {
                        let isSec = inheritedSecret || secretPaths.contains(subPath)
                        register(
                            subPath,
                            StoredSettingEntry(
                                rawValue: rawDictVal,
                                isSecret: isSec,
                                safeSummary: isSec ? "**********" : String(describing: rawDictVal)
                            )
                        )
                    }
                }
                continue
            }

            let isMarkedSecret = secretPaths.contains(path)
            register(
                path,
                StoredSettingEntry(
                    rawValue: unwrapped,
                    isSecret: isMarkedSecret,
                    safeSummary: isMarkedSecret ? "**********" : String(describing: unwrapped)
                )
            )
        }
    }
}
