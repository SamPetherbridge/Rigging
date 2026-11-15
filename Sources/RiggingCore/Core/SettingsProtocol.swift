import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Provenance & Origin

/// Exact source provenance for a resolved configuration value.
public indirect enum SettingOrigin: Sendable, Equatable, Hashable, Codable, CustomStringConvertible {
    case initOverride(keyPath: [String])
    case cliArgument(flag: String)
    case environment(variable: String)
    case dotEnv(path: String, line: Int, variable: String)
    case secretsDirectory(path: String)
    case projectConfig(path: String, keyPath: [String], profile: String?)
    case userConfig(path: String, keyPath: [String], profile: String?)
    case managedPolicy(domain: String, key: String)
    case customSource(name: String, detail: String)
    case secretProvider(scheme: String, referenceRedacted: String, via: SettingOrigin)
    case defaultValue

    public var description: String {
        switch self {
        case .initOverride(let keyPath):
            return "init override (\(keyPath.joined(separator: ".")))"
        case .cliArgument(let flag):
            return "CLI flag \(flag)"
        case .environment(let variable):
            return "environment \(variable)"
        case .dotEnv(let path, let line, let variable):
            return "\(path):\(line) (\(variable))"
        case .secretsDirectory(let path):
            return "secrets file \(path)"
        case .projectConfig(let path, let keyPath, let profile):
            if let profile {
                return "project config \(path) [profile: \(profile)] → \(keyPath.joined(separator: "."))"
            }
            return "project config \(path) → \(keyPath.joined(separator: "."))"
        case .userConfig(let path, let keyPath, let profile):
            if let profile {
                return "user config \(path) [profile: \(profile)] → \(keyPath.joined(separator: "."))"
            }
            return "user config \(path) → \(keyPath.joined(separator: "."))"
        case .managedPolicy(let domain, let key):
            return "managed policy \(domain) (\(key))"
        case .customSource(let name, let detail):
            return detail.isEmpty ? name : "\(name) (\(detail))"
        case .secretProvider(_, let referenceRedacted, let via):
            return "\(referenceRedacted) via \(via.description)"
        case .defaultValue:
            return "default value"
        }
    }
}

// MARK: - Aliases & Policies

/// Alternate lookup aliases for a setting field.
public enum SettingAlias: Sendable, Equatable, Hashable, Codable {
    case env(String)
    case configPath([String])
    case cli(String)
}

/// Behavior when a configuration source contains keys not declared in the schema.
public enum ExtraKeysPolicy: String, Sendable, Equatable, Hashable, Codable {
    case ignore
    case allow
    case warn
    case forbid
}

/// Strategy for decoding collection settings (`[T]`, `Set<T>`, `[String: V]`) from string sources
/// such as environment variables or `.env` files.
public enum EnvCollectionStrategy: Sendable, Equatable, Hashable, Codable {
    case jsonOrCommaSeparated
    case jsonOnly
    case separator(Character)
    case noDecode

    private enum CodingKeys: String, CodingKey {
        case kind
        case separator
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(String.self, forKey: .kind)
        switch kind {
        case "jsonOrCommaSeparated":
            self = .jsonOrCommaSeparated
        case "jsonOnly":
            self = .jsonOnly
        case "separator":
            let sep = try container.decode(String.self, forKey: .separator)
            guard let first = sep.first else {
                throw DecodingError.dataCorruptedError(
                    forKey: .separator,
                    in: container,
                    debugDescription: "Expected non-empty separator character."
                )
            }
            self = .separator(first)
        case "noDecode":
            self = .noDecode
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .kind,
                in: container,
                debugDescription: "Unknown EnvCollectionStrategy '\(kind)'."
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .jsonOrCommaSeparated:
            try container.encode("jsonOrCommaSeparated", forKey: .kind)
        case .jsonOnly:
            try container.encode("jsonOnly", forKey: .kind)
        case .separator(let ch):
            try container.encode("separator", forKey: .kind)
            try container.encode(String(ch), forKey: .separator)
        case .noDecode:
            try container.encode("noDecode", forKey: .kind)
        }
    }
}

/// An explicit programmatic or CLI argument override passed into `InitSource` / `SettingsContext`.
public struct SettingOverride: Sendable, Equatable, Hashable, Codable {
    public var keyPath: [String]
    public var value: RawValue
    public var flag: String?

    public init(keyPath: [String], value: RawValue, flag: String? = nil) {
        self.keyPath = keyPath
        self.value = value
        self.flag = flag
    }

    public static func cli(flag: String, keyPath: [String], value: RawValue) -> SettingOverride {
        SettingOverride(keyPath: keyPath, value: value, flag: flag)
    }

    public static func initValue(keyPath: [String], value: RawValue) -> SettingOverride {
        SettingOverride(keyPath: keyPath, value: value, flag: nil)
    }

    public var origin: SettingOrigin {
        if let flag {
            return .cliArgument(flag: flag)
        }
        return .initOverride(keyPath: keyPath)
    }
}

// MARK: - FileSystem Abstraction

/// Injectable filesystem interface enabling deterministic unit tests without touching host disk.
public protocol FileSystem: Sendable {
    func fileExists(atPath path: String) -> Bool
    func isDirectory(atPath path: String) -> Bool
    func readFile(atPath path: String) throws -> Data
    func contentsOfDirectory(atPath path: String) throws -> [String]
    func posixPermissions(atPath path: String) throws -> UInt16
    func isExecutableFile(atPath path: String) -> Bool
}

extension FileSystem {
    public func readString(atPath path: String, encoding: String.Encoding = .utf8) throws -> String {
        let data = try readFile(atPath: path)
        guard let string = String(data: data, encoding: encoding) else {
            throw CocoaError(.fileReadInapplicableStringEncoding, userInfo: [NSFilePathErrorKey: path])
        }
        return string
    }
}

/// Production `FileSystem` backed by `Foundation.FileManager` and POSIX `stat`.
public struct LocalFileSystem: FileSystem, Sendable {
    public init() {}

    public func fileExists(atPath path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    public func isDirectory(atPath path: String) -> Bool {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else {
            return false
        }
        return isDir.boolValue
    }

    public func readFile(atPath path: String) throws -> Data {
        try Data(contentsOf: URL(fileURLWithPath: path))
    }

    public func contentsOfDirectory(atPath path: String) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: path).sorted()
    }

    public func posixPermissions(atPath path: String) throws -> UInt16 {
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        if let number = attrs[.posixPermissions] as? NSNumber {
            return number.uint16Value & 0o7777
        }
        var st = stat()
        guard stat(path, &st) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ENOENT)
        }
        return UInt16(st.st_mode) & 0o7777
    }

    public func isExecutableFile(atPath path: String) -> Bool {
        FileManager.default.isExecutableFile(atPath: path)
    }
}

// MARK: - Subprocess Abstraction & Executable Trust

/// Captured output and exit status from an external CLI invocation.
public struct SubprocessResult: Sendable, Equatable {
    public let exitCode: Int32
    public let stdout: Data
    public let stderr: Data

    public init(exitCode: Int32, stdout: Data, stderr: Data = Data()) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }

    public var stdoutString: String {
        String(decoding: stdout, as: UTF8.self)
    }

    public var stderrString: String {
        String(decoding: stderr, as: UTF8.self)
    }
}

/// Errors thrown when an external CLI binary fails security trust checks or execution fails.
public enum SubprocessSecurityError: Error, Sendable, Equatable, CustomStringConvertible {
    case relativeExecutablePath(String)
    case executableNotFound(String)
    case notExecutable(String)
    case worldWritableExecutable(path: String, permissions: UInt16)
    case timedOut(executablePath: String, duration: Duration)
    case unsupportedPlatform(String)

    public var description: String {
        switch self {
        case .relativeExecutablePath(let path):
            return "Refusing relative executable path '\(path)'; provide an absolute path."
        case .executableNotFound(let path):
            return "Executable not found at '\(path)'."
        case .notExecutable(let path):
            return "File at '\(path)' is not an executable binary."
        case .worldWritableExecutable(let path, let perms):
            let octal = String(perms, radix: 8)
            return "Refusing world-writable executable '\(path)' (mode 0\(octal))."
        case .timedOut(let path, let duration):
            return "Subprocess '\(path)' timed out after \(duration)."
        case .unsupportedPlatform(let message):
            return message
        }
    }
}

/// Injectable subprocess runner used by external CLI secret providers (`op`, `bws`, `bw`, `pass`).
/// Implementations MUST pass `arguments` directly without invoking `/bin/sh -c`.
public protocol SubprocessRunner: Sendable {
    func run(
        executablePath: String,
        arguments: [String],
        environment: [String: String]?,
        stdin: Data?,
        timeout: Duration?
    ) async throws -> SubprocessResult
}

extension SubprocessRunner {
    public func run(
        executablePath: String,
        arguments: [String],
        environment: [String: String]? = nil,
        stdin: Data? = nil,
        timeout: Duration? = .seconds(30)
    ) async throws -> SubprocessResult {
        try await run(
            executablePath: executablePath,
            arguments: arguments,
            environment: environment,
            stdin: stdin,
            timeout: timeout
        )
    }
}

/// Production `SubprocessRunner` backed by `Foundation.Process` without shell interpolation.
public struct ProcessSubprocessRunner: SubprocessRunner, Sendable {
    public init() {}

    /// Verifies that `executablePath` is an absolute, existing, non-directory, executable file
    /// and is NOT world-writable (`mode & 0o002 == 0`).
    public static func verifyExecutableTrust(
        atPath executablePath: String,
        fileSystem: any FileSystem = LocalFileSystem()
    ) throws {
        guard executablePath.hasPrefix("/") else {
            throw SubprocessSecurityError.relativeExecutablePath(executablePath)
        }
        guard !executablePath.contains("\0") else {
            throw SubprocessSecurityError.executableNotFound(executablePath)
        }
        guard fileSystem.fileExists(atPath: executablePath) else {
            throw SubprocessSecurityError.executableNotFound(executablePath)
        }
        guard !fileSystem.isDirectory(atPath: executablePath),
              fileSystem.isExecutableFile(atPath: executablePath) else {
            throw SubprocessSecurityError.notExecutable(executablePath)
        }
        let perms = try fileSystem.posixPermissions(atPath: executablePath)
        if (perms & 0o002) != 0 {
            throw SubprocessSecurityError.worldWritableExecutable(
                path: executablePath,
                permissions: perms
            )
        }
    }

    /// Resolves a trusted binary name against well-known system directories when an explicit path
    /// is not configured (never searching relative PATH entries).
    public static func resolveTrustedExecutable(
        named binaryName: String,
        explicitPath: String? = nil,
        searchDirectories: [String] = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ],
        fileSystem: any FileSystem = LocalFileSystem()
    ) throws -> String {
        if let explicitPath {
            try verifyExecutableTrust(atPath: explicitPath, fileSystem: fileSystem)
            return explicitPath
        }

        for dir in searchDirectories where dir.hasPrefix("/") {
            let candidate = dir.hasSuffix("/") ? "\(dir)\(binaryName)" : "\(dir)/\(binaryName)"
            if fileSystem.fileExists(atPath: candidate) {
                try verifyExecutableTrust(atPath: candidate, fileSystem: fileSystem)
                return candidate
            }
        }

        throw SubprocessSecurityError.executableNotFound(binaryName)
    }

    public func run(
        executablePath: String,
        arguments: [String],
        environment: [String: String]?,
        stdin: Data?,
        timeout: Duration?
    ) async throws -> SubprocessResult {
        try Self.verifyExecutableTrust(atPath: executablePath)

        #if os(macOS)
        return try await runMacOSProcess(
            executablePath: executablePath,
            arguments: arguments,
            environment: environment,
            stdin: stdin,
            timeout: timeout
        )
        #else
        throw SubprocessSecurityError.unsupportedPlatform(
            "External subprocess execution is only available on macOS."
        )
        #endif
    }

    #if os(macOS)
    private func runMacOSProcess(
        executablePath: String,
        arguments: [String],
        environment: [String: String]?,
        stdin: Data?,
        timeout: Duration?
    ) async throws -> SubprocessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments
        if let environment {
            process.environment = environment
        }

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let stdinPipe: Pipe?
        if stdin != nil {
            let pipe = Pipe()
            process.standardInput = pipe
            stdinPipe = pipe
        } else {
            process.standardInput = FileHandle.nullDevice
            stdinPipe = nil
        }

        try process.run()

        if let stdin, let stdinPipe {
            try? stdinPipe.fileHandleForWriting.write(contentsOf: stdin)
            try? stdinPipe.fileHandleForWriting.close()
        }

        let stdoutTask = Task.detached {
            stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        }
        let stderrTask = Task.detached {
            stderrPipe.fileHandleForReading.readDataToEndOfFile()
        }

        let timedOutFlag = LockedFlag()
        let timeoutTask: Task<Void, Never>?
        if let timeout {
            timeoutTask = Task {
                try? await Task.sleep(for: timeout)
                if !Task.isCancelled && process.isRunning {
                    timedOutFlag.setTrue()
                    process.terminate()
                }
            }
        } else {
            timeoutTask = nil
        }

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            if !process.isRunning {
                continuation.resume()
            } else {
                process.terminationHandler = { _ in
                    continuation.resume()
                }
            }
        }

        timeoutTask?.cancel()
        let stdoutData = await stdoutTask.value
        let stderrData = await stderrTask.value

        if let timeout, timedOutFlag.value {
            throw SubprocessSecurityError.timedOut(executablePath: executablePath, duration: timeout)
        }

        return SubprocessResult(
            exitCode: process.terminationStatus,
            stdout: stdoutData,
            stderr: stderrData
        )
    }
    #endif
}

private final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false

    var value: Bool {
        lock.lock()
        defer { lock.unlock() }
        return flag
    }

    func setTrue() {
        lock.lock()
        flag = true
        lock.unlock()
    }
}

// MARK: - SettingsConfiguration & SettingsContext

/// Declarative configuration options governing source discovery, environment parsing,
/// secret directory semantics, and unknown-key enforcement.
public struct SettingsConfiguration: Sendable, Equatable {
    public var envPrefix: String
    public var envNestedDelimiter: String
    public var envNestedMaxSplit: Int?
    public var caseSensitive: Bool
    public var envIgnoreEmpty: Bool
    public var envNullStrings: Set<String>
    public var extraKeys: ExtraKeysPolicy
    public var dotEnvFiles: [String]
    public var projectConfigFiles: [String]
    public var xdgAppName: String?
    public var profile: String?
    public var secretsDirectory: String?
    public var secretsNestedSubdir: Bool
    public var trimSecretTrailingNewline: Bool
    public var envListStrategy: EnvCollectionStrategy
    public var managedPreferencesDomain: String?

    public init(
        envPrefix: String = "",
        envNestedDelimiter: String = "__",
        envNestedMaxSplit: Int? = nil,
        caseSensitive: Bool = false,
        envIgnoreEmpty: Bool = true,
        envNullStrings: Set<String> = ["null", "none", "~"],
        extraKeys: ExtraKeysPolicy = .ignore,
        dotEnvFiles: [String] = [".env"],
        projectConfigFiles: [String] = [],
        xdgAppName: String? = nil,
        profile: String? = nil,
        secretsDirectory: String? = nil,
        secretsNestedSubdir: Bool = false,
        trimSecretTrailingNewline: Bool = true,
        envListStrategy: EnvCollectionStrategy = .jsonOrCommaSeparated,
        managedPreferencesDomain: String? = nil
    ) {
        self.envPrefix = envPrefix
        self.envNestedDelimiter = envNestedDelimiter
        self.envNestedMaxSplit = envNestedMaxSplit
        self.caseSensitive = caseSensitive
        self.envIgnoreEmpty = envIgnoreEmpty
        self.envNullStrings = envNullStrings
        self.extraKeys = extraKeys
        self.dotEnvFiles = dotEnvFiles
        self.projectConfigFiles = projectConfigFiles
        self.xdgAppName = xdgAppName
        self.profile = profile
        self.secretsDirectory = secretsDirectory
        self.secretsNestedSubdir = secretsNestedSubdir
        self.trimSecretTrailingNewline = trimSecretTrailingNewline
        self.envListStrategy = envListStrategy
        self.managedPreferencesDomain = managedPreferencesDomain
    }
}

/// Execution environment and injectable runtime dependencies used when loading settings.
public struct SettingsContext: Sendable {
    public var environment: [String: String]
    public var workingDirectory: String
    public var homeDirectory: String
    public var cliOverrides: [SettingOverride]
    public var fileSystem: any FileSystem
    public var subprocessRunner: any SubprocessRunner
    public var secretProviders: [any SecretProvider]
    public var redactor: DiagnosticRedactor
    public var secretCache: SecretResolutionCache?

    public init(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        workingDirectory: String = FileManager.default.currentDirectoryPath,
        homeDirectory: String = NSHomeDirectory(),
        cliOverrides: [SettingOverride] = [],
        fileSystem: any FileSystem = LocalFileSystem(),
        subprocessRunner: any SubprocessRunner = ProcessSubprocessRunner(),
        secretProviders: [any SecretProvider] = [
            FileSecretProvider(),
            IndirectEnvProvider(),
        ],
        redactor: DiagnosticRedactor = DiagnosticRedactor(),
        secretCache: SecretResolutionCache? = nil
    ) {
        self.environment = environment
        self.workingDirectory = workingDirectory
        self.homeDirectory = homeDirectory
        self.cliOverrides = cliOverrides
        self.fileSystem = fileSystem
        self.subprocessRunner = subprocessRunner
        self.secretProviders = secretProviders
        self.redactor = redactor
        self.secretCache = secretCache
    }
}

// MARK: - SettingsSource & DefaultSources

/// A pluggable configuration layer capable of loading a `RawConfigTree` with provenance.
public protocol SettingsSource: Sendable {
    var sourceName: String { get }
    func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree
}

extension SettingsSource {
    public var sourceName: String {
        String(describing: Self.self)
    }
}

/// Standard ordered source slots exposed to `RiggedSettings.customizeSources(_:)`.
public struct DefaultSources: Sendable {
    public var initOverrides: any SettingsSource
    public var environment: any SettingsSource
    public var dotEnv: any SettingsSource
    public var secretsDirectory: any SettingsSource
    public var projectConfig: any SettingsSource
    public var userConfig: any SettingsSource
    public var managedPreferences: any SettingsSource

    public init(
        initOverrides: any SettingsSource = InitSource(),
        environment: any SettingsSource = EnvironmentSource(),
        dotEnv: any SettingsSource = DotEnvSource(),
        secretsDirectory: any SettingsSource = SecretsDirSource(),
        projectConfig: any SettingsSource = ProjectConfigSource(),
        userConfig: any SettingsSource = UserConfigSource(),
        managedPreferences: any SettingsSource = ManagedPreferencesSource()
    ) {
        self.initOverrides = initOverrides
        self.environment = environment
        self.dotEnv = dotEnv
        self.secretsDirectory = secretsDirectory
        self.projectConfig = projectConfig
        self.userConfig = userConfig
        self.managedPreferences = managedPreferences
    }

    /// Default precedence order from highest priority (`initOverrides`) to lowest (`managedPreferences`).
    public var ordered: [any SettingsSource] {
        [
            initOverrides,
            environment,
            dotEnv,
            secretsDirectory,
            projectConfig,
            userConfig,
            managedPreferences,
        ]
    }
}

// MARK: - Provenance Metadata & Schema Descriptors

/// Typed per-field metadata capturing resolved value, winning `SettingOrigin`, and shadowed origins.
public struct SettingMetadata<Value: Sendable>: Sendable, Encodable {
    public let keyPath: [String]
    public let value: Value
    public let isSecret: Bool
    public let origin: SettingOrigin
    public let overriddenOrigins: [SettingOrigin]

    public init(
        keyPath: [String],
        value: Value,
        isSecret: Bool = false,
        origin: SettingOrigin,
        overriddenOrigins: [SettingOrigin] = []
    ) {
        self.keyPath = keyPath
        self.value = value
        self.isSecret = isSecret
        self.origin = origin
        self.overriddenOrigins = overriddenOrigins
    }

    public var source: SettingOrigin { origin }
    public var overriddenSources: [SettingOrigin] { overriddenOrigins }

    public var displayValue: String {
        isSecret ? "**********" : String(describing: value)
    }

    public var valueSummary: String {
        displayValue
    }

    private enum CodingKeys: String, CodingKey {
        case keyPath
        case valueSummary
        case isSecret
        case source
        case overriddenSources
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(keyPath, forKey: .keyPath)
        try container.encode(valueSummary, forKey: .valueSummary)
        try container.encode(isSecret, forKey: .isSecret)
        try container.encode(source, forKey: .source)
        try container.encode(overriddenSources, forKey: .overriddenSources)
    }
}

extension SettingMetadata: Equatable where Value: Equatable {}
extension SettingMetadata: Hashable where Value: Hashable {}

/// Type-erased provenance entry suitable for CLI inspection (`config show --provenance`).
public struct ProvenanceEntry: Sendable, Equatable, Hashable, Codable {
    public let keyPath: [String]
    public let typeName: String
    public let isSecret: Bool
    public let displayValue: String
    public let origin: SettingOrigin
    public let overriddenOrigins: [SettingOrigin]

    public var source: SettingOrigin { origin }
    public var overriddenSources: [SettingOrigin] { overriddenOrigins }
    public var valueSummary: String { displayValue }

    public init(
        keyPath: [String],
        typeName: String,
        isSecret: Bool,
        displayValue: String,
        origin: SettingOrigin,
        overriddenOrigins: [SettingOrigin] = []
    ) {
        self.keyPath = keyPath
        self.typeName = typeName
        self.isSecret = isSecret
        self.displayValue = isSecret ? "**********" : displayValue
        self.origin = origin
        self.overriddenOrigins = overriddenOrigins
    }
}

/// Complete provenance report for a loaded `RiggedSettings` value.
public struct ProvenanceReport: Sendable, Equatable, Codable, CustomStringConvertible {
    public let entries: [ProvenanceEntry]
    public let warnings: [ValidationIssue]

    public init(entries: [ProvenanceEntry] = [], warnings: [ValidationIssue] = []) {
        self.entries = entries
        self.warnings = warnings
    }

    public func entry(forKeyPath keyPath: [String]) -> ProvenanceEntry? {
        entries.first { $0.keyPath == keyPath }
    }

    public subscript(keyPath: String...) -> ProvenanceEntry? {
        entry(forKeyPath: keyPath)
    }

    public var description: String {
        formattedTable()
    }

    public func formattedTable() -> String {
        guard !entries.isEmpty else { return "(no settings)" }
        var lines: [String] = []
        for entry in entries {
            let key = entry.keyPath.joined(separator: ".")
            var line = "\(key) = \(entry.displayValue)  [\(entry.origin.description)]"
            if !entry.overriddenOrigins.isEmpty {
                let shadowed = entry.overriddenOrigins.map(\.description).joined(separator: ", ")
                line += " (overrides: \(shadowed))"
            }
            lines.append(line)
        }
        return lines.joined(separator: "\n")
    }

    public func jsonPayload(prettyPrinted: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        var formatting: JSONEncoder.OutputFormatting = [.sortedKeys]
        if prettyPrinted {
            formatting.insert(.prettyPrinted)
        }
        encoder.outputFormatting = formatting
        return try encoder.encode(self)
    }
}

/// JSON Schema structural type representation for `SettingFieldDescriptor`.
public indirect enum JSONSchemaFieldType: Sendable, Equatable, Hashable {
    case string(format: String? = nil)
    case integer
    case number
    case boolean
    case array(items: JSONSchemaFieldType)
    case dictionary(values: JSONSchemaFieldType)
    case enumValues([String])
    case object(fields: [SettingFieldDescriptor])
}

/// Static schema metadata describing a single field or nested group on a `RiggedSettings` type.
public struct SettingFieldDescriptor: Sendable, Equatable, Hashable {
    public let name: String
    public let keyPath: [String]
    public let envVariable: String?
    public let aliases: [SettingAlias]
    public let typeName: String
    public let schemaType: JSONSchemaFieldType
    public let isOptional: Bool
    public let isSecret: Bool
    public let hasDefault: Bool
    public let defaultDisplay: String?
    public let help: String?
    public let deprecated: String?
    public let examples: [String]
    public let allowsArbitraryChildKeys: Bool

    public var documentation: String? { help }

    public init(
        name: String,
        keyPath: [String],
        envVariable: String? = nil,
        aliases: [SettingAlias] = [],
        typeName: String,
        schemaType: JSONSchemaFieldType = .string(),
        isOptional: Bool = false,
        isSecret: Bool = false,
        hasDefault: Bool = false,
        defaultDisplay: String? = nil,
        help: String? = nil,
        documentation: String? = nil,
        deprecated: String? = nil,
        examples: [String] = [],
        allowsArbitraryChildKeys: Bool = false
    ) {
        self.name = name
        self.keyPath = keyPath
        self.envVariable = envVariable
        self.aliases = aliases
        self.typeName = typeName
        self.schemaType = schemaType
        self.isOptional = isOptional
        self.isSecret = isSecret
        self.hasDefault = hasDefault
        self.defaultDisplay = isSecret ? nil : defaultDisplay
        self.help = help ?? documentation
        self.deprecated = deprecated
        self.examples = examples
        self.allowsArbitraryChildKeys = allowsArbitraryChildKeys
    }
}

// MARK: - RiggedSettings Protocol

/// Protocol conformed to by `@Settings` models.
public protocol RiggedSettings: Sendable {
    static var configuration: SettingsConfiguration { get }
    static var fieldDescriptors: [SettingFieldDescriptor] { get }

    var provenance: ProvenanceReport { get }

    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource]
    static func validate(_ settings: Self) -> [ValidationIssue]

    static func load(
        context: SettingsContext,
        overrides: [SettingOverride]
    ) async throws -> Self
}

extension RiggedSettings {
    public func provenanceReport() -> ProvenanceReport {
        provenance
    }

    public static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        defaults.ordered
    }

    public static func validate(_ settings: Self) -> [ValidationIssue] {
        []
    }

    public static func load(
        context: SettingsContext = SettingsContext()
    ) async throws -> Self {
        try await load(context: context, overrides: [])
    }

    public static func jsonSchema(
        title: String? = nil,
        prettyPrinted: Bool = true
    ) -> String {
        JSONSchemaExporter.export(
            for: Self.self,
            title: title ?? String(describing: Self.self),
            prettyPrinted: prettyPrinted
        )
    }

    public static func dotEnvTemplate(includeDefaults: Bool = true) -> String {
        DotEnvExporter.exportDotEnvTemplate(
            for: Self.self,
            includeDefaults: includeDefaults
        )
    }

    public static func markdownDocs(title: String? = nil) -> String {
        DotEnvExporter.exportMarkdownDocs(
            for: Self.self,
            title: title ?? String(describing: Self.self)
        )
    }
}
