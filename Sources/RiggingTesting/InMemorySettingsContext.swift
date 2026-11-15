import Foundation
import RiggingCore

extension SettingsContext {
    /// Creates a 100% hermetic, zero-I/O `SettingsContext` backed by `InMemoryFileSystem`
    /// and `MockSubprocessRunner`.
    ///
    /// Built-in `FileSecretProvider` and `IndirectEnvProvider` are included before any custom
    /// `secretProviders` by default (custom providers listed in `secretProviders` take precedence
    /// when handling the same scheme).
    public static func inMemory(
        cli: [SettingOverride] = [],
        environment: [String: String] = [:],
        files: [String: String] = [:],
        binaryFiles: [String: Data] = [:],
        directories: Set<String> = [],
        filePermissions: [String: UInt16] = [:],
        executables: Set<String> = [],
        workingDirectory: String = "/repo",
        homeDirectory: String = "/Users/test",
        fileSystem: (any FileSystem)? = nil,
        subprocessRunner: (any SubprocessRunner)? = nil,
        secretProviders: [any SecretProvider] = [],
        includeBuiltInSecretProviders: Bool = true,
        redactor: DiagnosticRedactor = DiagnosticRedactor(),
        secretCache: SecretResolutionCache? = nil
    ) -> SettingsContext {
        let resolvedFS: any FileSystem = fileSystem ?? InMemoryFileSystem(
            files: files,
            binaryFiles: binaryFiles,
            directories: directories,
            permissions: filePermissions,
            executables: executables
        )

        let resolvedRunner: any SubprocessRunner = subprocessRunner ?? MockSubprocessRunner()

        let effectiveProviders: [any SecretProvider]
        if includeBuiltInSecretProviders {
            effectiveProviders = [FileSecretProvider(), IndirectEnvProvider()] + secretProviders
        } else {
            effectiveProviders = secretProviders
        }

        return SettingsContext(
            environment: environment,
            workingDirectory: workingDirectory,
            homeDirectory: homeDirectory,
            cliOverrides: cli,
            fileSystem: resolvedFS,
            subprocessRunner: resolvedRunner,
            secretProviders: effectiveProviders,
            redactor: redactor,
            secretCache: secretCache
        )
    }

    /// Creates a 100% hermetic, zero-I/O `SettingsContext` converting dictionary CLI entries
    /// (such as `cli: ["readOnly": true]` or `cli: ["signing.enabled": true]`) into explicit
    /// `SettingOverride` items with kebab-case CLI flag origins (e.g. `.cliArgument(flag: "--read-only")`).
    public static func inMemory(
        cli: [String: Any],
        environment: [String: String] = [:],
        files: [String: String] = [:],
        binaryFiles: [String: Data] = [:],
        directories: Set<String> = [],
        filePermissions: [String: UInt16] = [:],
        executables: Set<String> = [],
        workingDirectory: String = "/repo",
        homeDirectory: String = "/Users/test",
        fileSystem: (any FileSystem)? = nil,
        subprocessRunner: (any SubprocessRunner)? = nil,
        secretProviders: [any SecretProvider] = [],
        includeBuiltInSecretProviders: Bool = true,
        redactor: DiagnosticRedactor = DiagnosticRedactor(),
        secretCache: SecretResolutionCache? = nil
    ) -> SettingsContext {
        inMemory(
            cli: cliOverrides(from: cli),
            environment: environment,
            files: files,
            binaryFiles: binaryFiles,
            directories: directories,
            filePermissions: filePermissions,
            executables: executables,
            workingDirectory: workingDirectory,
            homeDirectory: homeDirectory,
            fileSystem: fileSystem,
            subprocessRunner: subprocessRunner,
            secretProviders: secretProviders,
            includeBuiltInSecretProviders: includeBuiltInSecretProviders,
            redactor: redactor,
            secretCache: secretCache
        )
    }

    /// Converts a `[String: Any]` CLI override dictionary (e.g. `["readOnly": true]`) into
    /// deterministic `SettingOverride` items with `.cliArgument(flag: "--read-only")` provenance.
    ///
    /// Any `nil` optional values inside `dictionary` are omitted so unset flags never clobber lower layers.
    public static func cliOverrides(from dictionary: [String: Any]) -> [SettingOverride] {
        var overrides: [SettingOverride] = []
        for rawKey in dictionary.keys.sorted() {
            guard let anyValue = dictionary[rawKey],
                  let rawValue = convertToRawValue(anyValue) else {
                continue
            }

            let (keyPath, flag) = parseCLIKey(rawKey)
            guard !keyPath.isEmpty else { continue }
            overrides.append(.cli(flag: flag, keyPath: keyPath, value: rawValue))
        }
        return overrides
    }

    // MARK: - CLI Key & Value Conversion Helpers

    private static func parseCLIKey(_ rawKey: String) -> (keyPath: [String], flag: String) {
        let trimmed = rawKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return ([], "--") }

        let hasLeadingDashes = trimmed.hasPrefix("-")
        let stripped = trimmed.drop(while: { $0 == "-" })
        guard !stripped.isEmpty else { return ([], trimmed) }

        let segments: [String]
        if stripped.contains(".") {
            segments = stripped.split(separator: ".", omittingEmptySubsequences: true).map(String.init)
        } else if stripped.contains("__") {
            segments = stripped.components(separatedBy: "__").filter { !$0.isEmpty }
        } else {
            segments = [String(stripped)]
        }

        let normalizedKeyPath: [String]
        if hasLeadingDashes {
            normalizedKeyPath = segments.map(kebabToCamelCase)
        } else {
            normalizedKeyPath = segments
        }

        let flag: String
        if trimmed.hasPrefix("--") {
            flag = trimmed
        } else if trimmed.hasPrefix("-") {
            flag = trimmed
        } else {
            let kebabSegments = segments.map { segment in
                RawConfigTree.normalizeIdentifier(segment).replacingOccurrences(of: "_", with: "-")
            }
            flag = "--" + kebabSegments.joined(separator: "-")
        }

        return (normalizedKeyPath, flag)
    }

    private static func kebabToCamelCase(_ segment: String) -> String {
        guard segment.contains("-") || segment.contains("_") else {
            return segment
        }
        let parts = segment.split(whereSeparator: { $0 == "-" || $0 == "_" })
        guard let first = parts.first else { return segment }
        var result = first.lowercased()
        for part in parts.dropFirst() {
            guard let head = part.first else { continue }
            result += head.uppercased() + part.dropFirst().lowercased()
        }
        return result
    }

    private static func convertToRawValue(_ value: Any) -> RawValue? {
        if let optionalCheck = unwrapOptional(value) {
            return convertNonNilToRawValue(optionalCheck)
        }
        return nil
    }

    private static func unwrapOptional(_ any: Any) -> Any? {
        let mirror = Mirror(reflecting: any)
        guard mirror.displayStyle == .optional else {
            return any
        }
        guard let firstChild = mirror.children.first else {
            return nil
        }
        return unwrapOptional(firstChild.value)
    }

    private static func convertNonNilToRawValue(_ value: Any) -> RawValue {
        if let raw = value as? RawValue {
            return raw
        }
        if let b = value as? Bool {
            return .bool(b)
        }
        if let i = value as? Int {
            return .int(Int64(i))
        }
        if let i64 = value as? Int64 {
            return .int(i64)
        }
        if let i32 = value as? Int32 {
            return .int(Int64(i32))
        }
        if let i16 = value as? Int16 {
            return .int(Int64(i16))
        }
        if let i8 = value as? Int8 {
            return .int(Int64(i8))
        }
        if let u = value as? UInt {
            return u <= UInt(Int64.max) ? .int(Int64(u)) : .string(String(u))
        }
        if let u64 = value as? UInt64 {
            return u64 <= UInt64(Int64.max) ? .int(Int64(u64)) : .string(String(u64))
        }
        if let u32 = value as? UInt32 {
            return .int(Int64(u32))
        }
        if let u16 = value as? UInt16 {
            return .int(Int64(u16))
        }
        if let u8 = value as? UInt8 {
            return .int(Int64(u8))
        }
        if let d = value as? Double {
            return .double(d)
        }
        if let f = value as? Float {
            return .double(Double(f))
        }
        if let s = value as? String {
            return .string(s)
        }
        if let sub = value as? Substring {
            return .string(String(sub))
        }
        if let data = value as? Data {
            return .data(data)
        }
        if let uuid = value as? UUID {
            return .string(uuid.uuidString)
        }
        if let url = value as? URL {
            return .string(url.absoluteString)
        }
        if let array = value as? [Any] {
            let nodes = array.compactMap { elem -> RawNode? in
                guard let rv = convertToRawValue(elem) else { return nil }
                return RawNode(value: rv, origin: .defaultValue)
            }
            return .array(nodes)
        }
        if let dict = value as? [String: Any] {
            var map: [String: RawNode] = [:]
            for (k, v) in dict {
                if let rv = convertToRawValue(v) {
                    map[k] = RawNode(value: rv, origin: .defaultValue)
                }
            }
            return .object(map)
        }
        return .string(String(describing: value))
    }
}
