import Foundation
import Synchronization
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif canImport(WASILibc)
import WASILibc
#elseif canImport(WinSDK)
import WinSDK
#endif

// MARK: - Provenance & Origin

/// Exact source provenance describing where a resolved configuration value originated.
///
/// Every value loaded through ``SettingsLoader`` carries a `SettingOrigin` alongside any
/// lower-precedence origins that it shadowed. Inspect ``RiggedSettings/provenance`` at runtime
/// to audit configuration layering without exposing secret payloads.
public indirect enum SettingOrigin: Sendable, Equatable, Hashable, Codable, CustomStringConvertible {
    /// An explicit programmatic override supplied via ``SettingOverride/initValue(keyPath:value:)``.
    case initOverride(keyPath: [String])

    /// A command-line flag override supplied via ``SettingOverride/cli(flag:keyPath:value:)``.
    case cliArgument(flag: String)

    /// A process environment variable read by ``EnvironmentSource``.
    case environment(variable: String)

    /// A key-value entry parsed from a `.env` file by ``DotEnvSource``, including its 1-based line number.
    case dotEnv(path: String, line: Int, variable: String)

    /// A mounted secret file read from a directory such as `/run/secrets` by ``SecretsDirSource``.
    case secretsDirectory(path: String)

    /// A key path read from a repository- or working-directory-scoped configuration file.
    case projectConfig(path: String, keyPath: [String], profile: String?)

    /// A key path read from a user-level XDG or `~/Library/Application Support` configuration file.
    case userConfig(path: String, keyPath: [String], profile: String?)

    /// A managed MDM or system policy key read by ``ManagedPreferencesSource``.
    case managedPolicy(domain: String, key: String)

    /// A custom ``SettingsSource`` implementation identified by name and source-specific detail.
    case customSource(name: String, detail: String)

    /// A secret resolved through a ``SecretProvider`` from a redacted URI reference that was supplied by `via`.
    case secretProvider(scheme: String, referenceRedacted: String, via: SettingOrigin)

    /// The compile-time default value declared on the settings property.
    case defaultValue

    /// A human-readable summary of the configuration origin suitable for diagnostics and provenance tables.
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

/// An alternate lookup alias for a setting field across environment variables, structured config paths, or CLI flags.
public enum SettingAlias: Sendable, Equatable, Hashable, Codable {
    /// Looks up an alternate environment variable name (for example, `"LEGACY_API_KEY"`).
    case env(String)

    /// Looks up an alternate nested path in structured configuration files (for example, `["legacy", "host"]`).
    case configPath([String])

    /// Looks up an alternate CLI flag name (for example, `"--api-endpoint"`).
    case cli(String)
}

/// The policy governing how ``SettingsLoader`` handles undeclared keys in configuration sources.
public enum ExtraKeysPolicy: String, Sendable, Equatable, Hashable, Codable {
    /// Silently ignores undeclared configuration keys.
    case ignore

    /// Explicitly permits arbitrary extra keys without emitting diagnostics.
    case allow

    /// Records non-fatal ``ValidationIssue`` entries in ``ProvenanceReport/warnings`` when unknown keys are present.
    case warn

    /// Fails configuration loading with ``ValidationIssueKind/unknownKey`` when undeclared keys are present.
    case forbid
}

/// The strategy for decoding collection settings (`[T]`, `Set<T>`, `[String: V]`) from string-based sources
/// such as environment variables or `.env` files.
public enum EnvCollectionStrategy: Sendable, Equatable, Hashable, Codable {
    /// Parses JSON arrays (`["a","b"]`) when valid, falling back to comma-separated tokens (`a,b`).
    case jsonOrCommaSeparated

    /// Requires valid JSON array or object syntax (`["a","b"]` or `{"k":"v"}`).
    case jsonOnly

    /// Splits string inputs on a custom delimiter character and trims surrounding whitespace from each element.
    case separator(Character)

    /// Disables string-splitting collection decoding, requiring structured array or dictionary nodes.
    case noDecode

    private enum CodingKeys: String, CodingKey {
        case kind
        case separator
    }

    /// Creates an environment collection decoding strategy by decoding from the given decoder.
    ///
    /// - Parameter decoder: The decoder to read data from.
    /// - Throws: `DecodingError.dataCorrupted` if the encoded strategy kind or separator is invalid.
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

    /// Encodes this environment collection decoding strategy into the given encoder.
    ///
    /// - Parameter encoder: The encoder to write data to.
    /// - Throws: An error if any value throws an error during encoding.
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

/// An explicit programmatic or CLI argument override passed into ``InitSource`` and ``SettingsContext``.
///
/// Overrides take highest precedence in ``DefaultSources`` ahead of environment variables and config files.
public struct SettingOverride: Sendable, Equatable, Hashable, Codable {
    /// The canonical nested setting key path targeted by this override.
    public var keyPath: [String]

    /// The raw override value to inject at ``keyPath``.
    public var value: RawValue

    /// The CLI flag name (such as `"--port"`) when the override originated from command-line parsing, or `nil` for programmatic overrides.
    public var flag: String?

    /// Creates a setting override for a canonical key path.
    ///
    /// - Parameters:
    ///   - keyPath: The canonical nested setting key path.
    ///   - value: The raw value to assign.
    ///   - flag: Optional CLI flag name for provenance reporting.
    public init(keyPath: [String], value: RawValue, flag: String? = nil) {
        self.keyPath = keyPath
        self.value = value
        self.flag = flag
    }

    /// Creates a CLI flag override with ``SettingOrigin/cliArgument(flag:)`` provenance.
    ///
    /// - Parameters:
    ///   - flag: The CLI flag name (for example, `"--issuer-id"`).
    ///   - keyPath: The canonical nested setting key path.
    ///   - value: The raw value parsed from the command line.
    /// - Returns: A configured ``SettingOverride``.
    public static func cli(flag: String, keyPath: [String], value: RawValue) -> SettingOverride {
        SettingOverride(keyPath: keyPath, value: value, flag: flag)
    }

    /// Creates a programmatic initializer override with ``SettingOrigin/initOverride(keyPath:)`` provenance.
    ///
    /// - Parameters:
    ///   - keyPath: The canonical nested setting key path.
    ///   - value: The raw value to inject.
    /// - Returns: A configured ``SettingOverride``.
    public static func initValue(keyPath: [String], value: RawValue) -> SettingOverride {
        SettingOverride(keyPath: keyPath, value: value, flag: nil)
    }

    /// The ``SettingOrigin`` attributed to this override when merged into a ``RawConfigTree``.
    public var origin: SettingOrigin {
        if let flag {
            return .cliArgument(flag: flag)
        }
        return .initOverride(keyPath: keyPath)
    }
}

// MARK: - FileSystem Abstraction

/// An injectable filesystem interface enabling deterministic configuration and secret loading without touching host disk.
public protocol FileSystem: Sendable {
    /// Returns whether a file or directory exists at the specified path.
    ///
    /// - Parameter path: The path to check.
    /// - Returns: `true` if an item exists at `path`; otherwise, `false`.
    func fileExists(atPath path: String) -> Bool

    /// Returns whether the item at the specified path is an existing directory.
    ///
    /// - Parameter path: The path to check.
    /// - Returns: `true` if `path` exists and is a directory; otherwise, `false`.
    func isDirectory(atPath path: String) -> Bool

    /// Reads the raw bytes of the file at the specified path.
    ///
    /// - Parameter path: The file path to read.
    /// - Returns: The file contents as `Data`.
    /// - Throws: An I/O error if the file cannot be opened or read.
    func readFile(atPath path: String) throws -> Data

    /// Returns the sorted entry names contained directly within a directory.
    ///
    /// - Parameter path: The directory path to enumerate.
    /// - Returns: An array of entry names (excluding `"."` and `".."`).
    /// - Throws: An I/O error if the directory cannot be listed.
    func contentsOfDirectory(atPath path: String) throws -> [String]

    /// Returns the 12-bit POSIX permission mask (for example, `0o600` or `0o755`) for the item at the specified path.
    ///
    /// - Parameter path: The file or directory path to inspect.
    /// - Returns: The lower 12 permission bits of the item's mode.
    /// - Throws: An error if the item's attributes cannot be read.
    func posixPermissions(atPath path: String) throws -> UInt16

    /// Returns whether the item at the specified path is marked executable for the current process.
    ///
    /// - Parameter path: The file path to check.
    /// - Returns: `true` if the file is executable; otherwise, `false`.
    func isExecutableFile(atPath path: String) -> Bool
}

extension FileSystem {
    /// Reads and decodes a text file at the specified path using the given string encoding.
    ///
    /// - Parameters:
    ///   - path: The file path to read.
    ///   - encoding: The text encoding to apply. Defaults to `.utf8`.
    /// - Returns: The decoded string contents of the file.
    /// - Throws: An I/O error or `CocoaError(.fileReadInapplicableStringEncoding)` if decoding fails.
    public func readString(atPath path: String, encoding: String.Encoding = .utf8) throws -> String {
        let data = try readFile(atPath: path)
        guard let string = String(data: data, encoding: encoding) else {
            throw CocoaError(.fileReadInapplicableStringEncoding, userInfo: [NSFilePathErrorKey: path])
        }
        return string
    }
}

/// The production ``FileSystem`` implementation backed by `Foundation.FileManager` and POSIX `stat`.
public struct LocalFileSystem: FileSystem, Sendable {
    /// Creates a local host filesystem accessor.
    public init() {}

    /// Returns whether a file or directory exists on the local filesystem at `path`.
    public func fileExists(atPath path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    /// Returns whether `path` refers to an existing directory on the local filesystem.
    public func isDirectory(atPath path: String) -> Bool {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else {
            return false
        }
        return isDir.boolValue
    }

    /// Reads the raw bytes of the local file at `path`.
    public func readFile(atPath path: String) throws -> Data {
        try Data(contentsOf: URL(fileURLWithPath: path))
    }

    /// Returns the sorted directory entry names at `path`.
    public func contentsOfDirectory(atPath path: String) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: path).sorted()
    }

    /// Returns the 12-bit POSIX permission mask (`mode & 0o7777`) for the local item at `path`.
    ///
    /// On platforms that do not expose POSIX mode bits via `FileManager` or `stat` (such as Windows
    /// and WASI), existing files default to owner-only semantics (`0o600` for files, `0o700` for directories).
    public func posixPermissions(atPath path: String) throws -> UInt16 {
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        if let number = attrs[.posixPermissions] as? NSNumber {
            return number.uint16Value & 0o7777
        }
        #if canImport(Darwin) || canImport(Glibc) || canImport(Musl) || canImport(Android)
        var st = stat()
        guard stat(path, &st) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ENOENT)
        }
        return UInt16(truncatingIfNeeded: st.st_mode) & 0o7777
        #else
        return isDirectory(atPath: path) ? 0o700 : 0o600
        #endif
    }

    /// Returns whether the local file at `path` has execute permissions for the current user.
    public func isExecutableFile(atPath path: String) -> Bool {
        FileManager.default.isExecutableFile(atPath: path)
    }
}

// MARK: - Subprocess Abstraction & Executable Trust

/// Captured standard output, standard error, and exit code from an external CLI invocation.
public struct SubprocessResult: Sendable, Equatable, Hashable {
    /// The process termination status (`0` typically indicates success).
    public let exitCode: Int32

    /// Raw bytes captured from the child process's standard output pipe.
    public let stdout: Data

    /// Raw bytes captured from the child process's standard error pipe.
    public let stderr: Data

    /// Creates a subprocess execution result.
    ///
    /// - Parameters:
    ///   - exitCode: The process termination status code.
    ///   - stdout: Captured standard output bytes.
    ///   - stderr: Captured standard error bytes. Defaults to empty `Data`.
    public init(exitCode: Int32, stdout: Data, stderr: Data = Data()) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }

    /// The captured ``stdout`` bytes decoded as UTF-8 (replacing ill-formed sequences).
    public var stdoutString: String {
        String(decoding: stdout, as: UTF8.self)
    }

    /// The captured ``stderr`` bytes decoded as UTF-8 (replacing ill-formed sequences).
    public var stderrString: String {
        String(decoding: stderr, as: UTF8.self)
    }
}

/// Errors thrown when an external CLI binary fails pre-execution security trust checks or execution fails.
public enum SubprocessSecurityError: Error, Sendable, Equatable, Hashable, CustomStringConvertible, LocalizedError {
    /// The executable path is relative rather than an explicit absolute path starting with `"/"`.
    case relativeExecutablePath(String)

    /// No file exists at the requested executable path or in trusted system search directories.
    case executableNotFound(String)

    /// The target path is a directory or lacks executable permissions.
    case notExecutable(String)

    /// The binary is world-writable (`mode & 0o002 != 0`) and could be tampered with by untrusted local users.
    case worldWritableExecutable(path: String, permissions: UInt16)

    /// The child process exceeded its configured execution timeout and was terminated.
    case timedOut(executablePath: String, duration: Duration)

    /// The current target platform does not support spawning external child processes.
    case unsupportedPlatform(String)

    /// A human-readable diagnostic describing the executable security or runtime failure.
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

    /// A localized message describing what error occurred, matching ``description`` for CLI output.
    public var errorDescription: String? {
        description
    }
}

/// An injectable subprocess runner used by external CLI secret providers (`op`, `bws`, `bw`, `pass`).
///
/// Implementations must execute `executablePath` directly with `arguments` as an argument vector
/// and must never interpolate arguments through `/bin/sh -c`.
public protocol SubprocessRunner: Sendable {
    /// Executes an external binary directly without shell interpolation.
    ///
    /// - Parameters:
    ///   - executablePath: The absolute path to the binary to execute.
    ///   - arguments: Command-line arguments passed directly in `argv`.
    ///   - environment: Explicit environment dictionary for the child process, or `nil` to inherit.
    ///   - stdin: Optional bytes written to the child process's standard input before closing it.
    ///   - timeout: Maximum execution duration before terminating the child process, or `nil` for no timeout.
    /// - Returns: The captured ``SubprocessResult``.
    /// - Throws: ``SubprocessSecurityError`` or an OS process launch error.
    func run(
        executablePath: String,
        arguments: [String],
        environment: [String: String]?,
        stdin: Data?,
        timeout: Duration?
    ) async throws -> SubprocessResult
}

extension SubprocessRunner {
    /// Executes an external binary with default optional environment, standard input, and a 30-second timeout.
    ///
    /// - Parameters:
    ///   - executablePath: The absolute path to the binary to execute.
    ///   - arguments: Command-line arguments passed directly in `argv`.
    ///   - environment: Explicit environment dictionary, or `nil` to inherit.
    ///   - stdin: Optional standard input payload.
    ///   - timeout: Maximum execution duration. Defaults to `.seconds(30)`.
    /// - Returns: The captured ``SubprocessResult``.
    /// - Throws: ``SubprocessSecurityError`` or an OS process launch error.
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

/// The production ``SubprocessRunner`` backed by `Foundation.Process` on macOS and Linux without shell interpolation.
///
/// Before launching any binary, `ProcessSubprocessRunner` enforces ``verifyExecutableTrust(atPath:fileSystem:)``
/// to reject relative paths, directories, non-executables, and world-writable binaries (`mode & 0o002 != 0`).
public struct ProcessSubprocessRunner: SubprocessRunner, Sendable {
    /// Creates a production subprocess runner.
    public init() {}

    private static func isAbsoluteExecutablePath(_ path: String) -> Bool {
        if path.hasPrefix("/") {
            return true
        }
        #if os(Windows)
        if path.hasPrefix("\\\\") {
            return true
        }
        let chars = Array(path)
        if chars.count >= 3,
           chars[0].isASCII && chars[0].isLetter,
           chars[1] == ":",
           chars[2] == "\\" || chars[2] == "/" {
            return true
        }
        #endif
        return false
    }

    /// Verifies that `executablePath` is an absolute, existing, non-directory, executable file
    /// that is not world-writable (`mode & 0o002 == 0`).
    ///
    /// - Parameters:
    ///   - executablePath: Candidate path to verify.
    ///   - fileSystem: Filesystem abstraction used to inspect file existence and permissions.
    /// - Throws: ``SubprocessSecurityError`` if any trust check fails.
    public static func verifyExecutableTrust(
        atPath executablePath: String,
        fileSystem: any FileSystem = LocalFileSystem()
    ) throws {
        guard isAbsoluteExecutablePath(executablePath) else {
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

    /// Resolves a trusted binary name against well-known absolute system directories when an explicit path
    /// is not configured, never searching relative `PATH` entries.
    ///
    /// - Parameters:
    ///   - binaryName: Binary filename to locate (for example, `"op"` or `"bws"`).
    ///   - explicitPath: Optional caller-supplied absolute override path.
    ///   - searchDirectories: Ordered list of trusted absolute directories to probe.
    ///   - fileSystem: Filesystem abstraction used for probing and permission verification.
    /// - Returns: The verified absolute path to the executable.
    /// - Throws: ``SubprocessSecurityError`` if the binary cannot be found or fails trust checks.
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

        for dir in searchDirectories where isAbsoluteExecutablePath(dir) {
            let candidate = (dir.hasSuffix("/") || dir.hasSuffix("\\")) ? "\(dir)\(binaryName)" : "\(dir)/\(binaryName)"
            if fileSystem.fileExists(atPath: candidate) {
                try verifyExecutableTrust(atPath: candidate, fileSystem: fileSystem)
                return candidate
            }
            #if os(Windows)
            if !binaryName.lowercased().hasSuffix(".exe") {
                let exeCandidate = "\(candidate).exe"
                if fileSystem.fileExists(atPath: exeCandidate) {
                    try verifyExecutableTrust(atPath: exeCandidate, fileSystem: fileSystem)
                    return exeCandidate
                }
            }
            #endif
        }

        throw SubprocessSecurityError.executableNotFound(binaryName)
    }

    /// Verifies binary trust and executes `executablePath` directly via `Foundation.Process`.
    ///
    /// - Parameters:
    ///   - executablePath: The absolute path to the executable binary.
    ///   - arguments: Command-line arguments passed directly in `argv`.
    ///   - environment: Optional explicit environment variables for the child process.
    ///   - stdin: Optional bytes written to standard input before closing the pipe.
    ///   - timeout: Optional timeout duration after which the child process is terminated.
    /// - Returns: The captured ``SubprocessResult``.
    /// - Throws: ``SubprocessSecurityError`` if trust verification fails, the platform is unsupported, or execution times out.
    public func run(
        executablePath: String,
        arguments: [String],
        environment: [String: String]?,
        stdin: Data?,
        timeout: Duration?
    ) async throws -> SubprocessResult {
        try Self.verifyExecutableTrust(atPath: executablePath)

        #if os(macOS) || os(Linux) || os(Windows)
        return try await runPlatformProcess(
            executablePath: executablePath,
            arguments: arguments,
            environment: environment,
            stdin: stdin,
            timeout: timeout
        )
        #else
        throw SubprocessSecurityError.unsupportedPlatform(
            "External subprocess execution is only available on macOS, Linux, and Windows."
        )
        #endif
    }

    #if os(macOS) || os(Linux) || os(Windows)
    private func runPlatformProcess(
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

        let stdinTask: Task<Void, Never>?
        if let stdin, let stdinPipe {
            stdinTask = Task.detached {
                try? stdinPipe.fileHandleForWriting.write(contentsOf: stdin)
                try? stdinPipe.fileHandleForWriting.close()
            }
        } else {
            stdinTask = nil
        }

        let stdoutTask = Task.detached {
            stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        }
        let stderrTask = Task.detached {
            stderrPipe.fileHandleForReading.readDataToEndOfFile()
        }

        let timedOutFlag = Mutex(false)
        let timeoutTask: Task<Void, Never>?
        if let timeout {
            timeoutTask = Task {
                try? await Task.sleep(for: timeout)
                if !Task.isCancelled && process.isRunning {
                    timedOutFlag.withLock { $0 = true }
                    process.terminate()
                }
            }
        } else {
            timeoutTask = nil
        }

        let waitTask = Task.detached {
            process.waitUntilExit()
        }

        await waitTask.value
        timeoutTask?.cancel()
        await stdinTask?.value
        let stdoutData = await stdoutTask.value
        let stderrData = await stderrTask.value

        if let timeout, timedOutFlag.withLock({ $0 }) {
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

// MARK: - SettingsConfiguration & SettingsContext

/// Declarative configuration options governing source discovery, environment variable mapping,
/// secret directory semantics, and unknown-key enforcement.
///
/// Configure these options through arguments to the `@Settings` macro or by providing a custom
/// ``RiggedSettings/configuration`` property on a manual conformance.
public struct SettingsConfiguration: Sendable, Equatable, Hashable, Codable {
    /// Prefix stripped from environment variable and `.env` names (for example, `"ASC_"`).
    public var envPrefix: String

    /// Delimiter splitting flat environment variable names into nested key paths (defaults to `"__"`).
    public var envNestedDelimiter: String

    /// Optional cap on how many times ``envNestedDelimiter`` splits a variable name, preserving underscores in leaf keys.
    public var envNestedMaxSplit: Int?

    /// Whether key matching across environment variables and configuration trees is case-sensitive.
    public var caseSensitive: Bool

    /// Whether empty-string (`""`) environment variables are ignored so lower-precedence defaults apply.
    public var envIgnoreEmpty: Bool

    /// Case-insensitive string literals treated as `null` when decoding optional settings (defaults to `["null", "none", "~"]`).
    public var envNullStrings: Set<String>

    /// Policy applied when structured configuration files or prefixed environment variables contain undeclared keys.
    public var extraKeys: ExtraKeysPolicy

    /// Ordered list of `.env` file paths loaded by ``DotEnvSource`` (later files override earlier files when keys collide).
    public var dotEnvFiles: [String]

    /// Ordered list of project-level configuration file paths probed by ``ProjectConfigSource``.
    public var projectConfigFiles: [String]

    /// Application directory name under `$XDG_CONFIG_HOME/<xdgAppName>/` and `~/Library/Application Support/<xdgAppName>/` for ``UserConfigSource``.
    public var xdgAppName: String?

    /// Optional active profile name (`profiles.<name>`) overlaid on top of base configuration files, overridable via `<ENV_PREFIX>PROFILE`.
    public var profile: String?

    /// Optional directory path (such as `"/run/secrets"`) from which ``SecretsDirSource`` reads secret files.
    public var secretsDirectory: String?

    /// Whether ``SecretsDirSource`` traverses nested subdirectories as nested configuration key paths.
    public var secretsNestedSubdir: Bool

    /// Whether single trailing `\n` or `\r\n` sequences are stripped from file-mounted secrets.
    public var trimSecretTrailingNewline: Bool

    /// Default strategy used when decoding collection fields from string sources such as environment variables.
    public var envListStrategy: EnvCollectionStrategy

    /// Reverse-DNS preferences domain (for example, `"com.example.asc"`) queried on Apple platforms by ``ManagedPreferencesSource``.
    public var managedPreferencesDomain: String?

    /// Creates a declarative settings configuration.
    ///
    /// - Parameters:
    ///   - envPrefix: Environment variable prefix (for example, `"ASC_"`). Defaults to `""`.
    ///   - envNestedDelimiter: Nested path delimiter for environment variables. Defaults to `"__"`.
    ///   - envNestedMaxSplit: Optional maximum number of delimiter splits. Defaults to `nil`.
    ///   - caseSensitive: Whether key matching is case-sensitive. Defaults to `false`.
    ///   - envIgnoreEmpty: Whether empty environment variables (`""`) are ignored. Defaults to `true`.
    ///   - envNullStrings: Strings interpreted as explicit `null`. Defaults to `["null", "none", "~"]`.
    ///   - extraKeys: Policy for undeclared configuration keys. Defaults to ``ExtraKeysPolicy/ignore``.
    ///   - dotEnvFiles: `.env` file paths probed relative to the working directory. Defaults to `[".env"]`.
    ///   - projectConfigFiles: Project config file paths probed by ``ProjectConfigSource``. Defaults to `[]`.
    ///   - xdgAppName: Application name for user config discovery. Defaults to `nil`.
    ///   - profile: Active configuration profile name. Defaults to `nil`.
    ///   - secretsDirectory: Mounted secrets directory path. Defaults to `nil`.
    ///   - secretsNestedSubdir: Whether subdirectories in ``secretsDirectory`` map to nested keys. Defaults to `false`.
    ///   - trimSecretTrailingNewline: Whether trailing newlines are trimmed from file secrets. Defaults to `true`.
    ///   - envListStrategy: Collection decoding strategy for string sources. Defaults to ``EnvCollectionStrategy/jsonOrCommaSeparated``.
    ///   - managedPreferencesDomain: Apple MDM/preferences bundle identifier. Defaults to `nil`.
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

/// The execution environment and injectable runtime dependencies used when loading a ``RiggedSettings`` model.
///
/// Pass a customized `SettingsContext` to ``RiggedSettings/load(context:overrides:)`` in tests or
/// multi-provider applications to supply in-memory environment dictionaries, virtual filesystems,
/// secret vaults (`op://`, `keychain://`, `bws://`, `pass://`), and shared secret caches without
/// mutating global process state.
///
/// ```swift
/// let context = SettingsContext(
///     environment: ["APP_HOST": "api.example.com"],
///     workingDirectory: "/Users/jane/project"
/// )
/// let settings = try await AppSettings.load(context: context)
/// ```
public struct SettingsContext: Sendable {
    /// Process environment key-value dictionary consulted by ``EnvironmentSource`` and ``IndirectEnvProvider``.
    public var environment: [String: String]

    /// Base directory used to resolve relative `.env`, project configuration, and `file://` paths.
    public var workingDirectory: String

    /// User home directory used to expand `~` prefixes and locate XDG or `~/Library/Application Support` configs.
    public var homeDirectory: String

    /// Explicit CLI flag and programmatic overrides read at top precedence by ``InitSource``.
    public var cliOverrides: [SettingOverride]

    /// Filesystem implementation used by all file-backed configuration sources and secret providers.
    public var fileSystem: any FileSystem

    /// Subprocess runner used by CLI-backed secret providers (`op`, `bws`, `bw`, `pass`).
    public var subprocessRunner: any SubprocessRunner

    /// Registered ``SecretProvider`` instances dispatched by URI scheme during batched secret resolution.
    public var secretProviders: [any SecretProvider]

    /// Thread-safe redactor that tracks resolved secret values and scrubs diagnostic strings.
    public var redactor: DiagnosticRedactor

    /// Optional TTL cache shared across ``RiggedSettings/load(context:overrides:)`` or ``SettingsWatcher`` reloads.
    public var secretCache: SecretResolutionCache?

    /// Resolves the current platform's default user home directory cleanly across Apple platforms,
    /// Linux, Windows, Android, and WebAssembly (WASI).
    public static var defaultHomeDirectory: String {
        #if os(WASI)
        return ProcessInfo.processInfo.environment["HOME"] ?? "/"
        #elseif os(Windows)
        if let userProfile = ProcessInfo.processInfo.environment["USERPROFILE"], !userProfile.isEmpty {
            return userProfile
        }
        return NSHomeDirectory()
        #else
        return NSHomeDirectory()
        #endif
    }

    /// Creates an execution context for loading settings.
    ///
    /// - Parameters:
    ///   - environment: Environment variable dictionary. Defaults to `ProcessInfo.processInfo.environment`.
    ///   - workingDirectory: Base path for relative files. Defaults to `FileManager.default.currentDirectoryPath`.
    ///   - homeDirectory: User home directory path. Defaults to ``defaultHomeDirectory``.
    ///   - cliOverrides: Initial CLI or programmatic overrides. Defaults to `[]`.
    ///   - fileSystem: Filesystem implementation. Defaults to ``LocalFileSystem``.
    ///   - subprocessRunner: Subprocess runner implementation. Defaults to ``ProcessSubprocessRunner``.
    ///   - secretProviders: Active secret providers. Defaults to `[FileSecretProvider(), IndirectEnvProvider()]`.
    ///   - redactor: Secret diagnostic redactor. Defaults to a fresh ``DiagnosticRedactor``.
    ///   - secretCache: Optional secret resolution cache. Defaults to `nil`.
    public init(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        workingDirectory: String = FileManager.default.currentDirectoryPath,
        homeDirectory: String = SettingsContext.defaultHomeDirectory,
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

/// A pluggable configuration layer capable of loading a ``RawConfigTree`` annotated with ``SettingOrigin`` provenance.
public protocol SettingsSource: Sendable {
    /// Human-readable identifier for this configuration source.
    var sourceName: String { get }

    /// Loads raw configuration values from this source.
    ///
    /// - Parameters:
    ///   - configuration: Schema-level configuration options for the target settings type.
    ///   - context: Runtime environment, filesystem, and overrides.
    /// - Returns: A ``RawConfigTree`` containing all values discovered by this source, or ``RawConfigTree/empty`` when absent.
    /// - Throws: ``ValidationIssue``, ``SettingsValidationError``, or a source-specific error if a present source is malformed.
    func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree
}

extension SettingsSource {
    /// Default source name derived from the conforming Swift type name.
    public var sourceName: String {
        String(describing: Self.self)
    }
}

/// The standard ordered configuration source slots passed to ``RiggedSettings/customizeSources(_:)``.
///
/// By default, ``ordered`` evaluates sources from highest precedence to lowest precedence:
/// 1. ``initOverrides`` (CLI flags & programmatic overrides)
/// 2. ``environment`` (process environment variables)
/// 3. ``dotEnv`` (`.env` files)
/// 4. ``secretsDirectory`` (`/run/secrets` mounted files)
/// 5. ``projectConfig`` (workspace JSON/plist/TOML/YAML config files)
/// 6. ``userConfig`` (`~/.config/<app>/` or `~/Library/Application Support/<app>/`)
/// 7. ``managedPreferences`` (Apple `CFPreferences` / MDM policies)
public struct DefaultSources: Sendable {
    /// Top-precedence programmatic and CLI flag override source (defaults to ``InitSource``).
    public var initOverrides: any SettingsSource

    /// Process environment variable source (defaults to ``EnvironmentSource``).
    public var environment: any SettingsSource

    /// `.env` file source (defaults to ``DotEnvSource``).
    public var dotEnv: any SettingsSource

    /// Mounted secrets directory source (defaults to ``SecretsDirSource``).
    public var secretsDirectory: any SettingsSource

    /// Project-scoped configuration file source (defaults to ``ProjectConfigSource``).
    public var projectConfig: any SettingsSource

    /// User-scoped configuration file source (defaults to ``UserConfigSource``).
    public var userConfig: any SettingsSource

    /// Managed preferences / MDM policy source (defaults to ``ManagedPreferencesSource``).
    public var managedPreferences: any SettingsSource

    /// Creates a collection of standard configuration source slots.
    ///
    /// - Parameters:
    ///   - initOverrides: Override source. Defaults to ``InitSource``.
    ///   - environment: Environment source. Defaults to ``EnvironmentSource``.
    ///   - dotEnv: DotEnv source. Defaults to ``DotEnvSource``.
    ///   - secretsDirectory: Secrets directory source. Defaults to ``SecretsDirSource``.
    ///   - projectConfig: Project config source. Defaults to ``ProjectConfigSource``.
    ///   - userConfig: User config source. Defaults to ``UserConfigSource``.
    ///   - managedPreferences: Managed preferences source. Defaults to ``ManagedPreferencesSource``.
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

    /// The standard precedence cascade ordered from highest priority (``initOverrides``) to lowest (``managedPreferences``).
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

/// Typed per-field provenance metadata capturing the resolved value, winning ``SettingOrigin``, and shadowed origins.
///
/// Projected `$field` properties synthesized by `@Settings` expose `SettingMetadata<Value>` so callers can
/// inspect where an individual field came from without parsing string tables. Secret fields always mask
/// ``displayValue`` and serialized ``valueSummary`` as `"**********"`.
public struct SettingMetadata<Value: Sendable>: Sendable, Encodable {
    /// The canonical nested key path of the setting field.
    public let keyPath: [String]

    /// The resolved, validated field value.
    public let value: Value

    /// Whether this field holds sensitive secret material whose display representation must be redacted.
    public let isSecret: Bool

    /// The winning ``SettingOrigin`` that supplied ``value``.
    public let origin: SettingOrigin

    /// Lower-precedence ``SettingOrigin`` entries that also provided values for ``keyPath`` but were shadowed by ``origin``.
    public let overriddenOrigins: [SettingOrigin]

    /// Creates typed provenance metadata for a resolved setting field.
    ///
    /// - Parameters:
    ///   - keyPath: The canonical nested key path.
    ///   - value: The resolved value.
    ///   - isSecret: Whether ``displayValue`` should mask the value. Defaults to `false`.
    ///   - origin: Winning ``SettingOrigin``.
    ///   - overriddenOrigins: Shadowed lower-precedence origins. Defaults to `[]`.
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

    /// Alias for ``origin`` matching CLI provenance JSON output keys.
    public var source: SettingOrigin { origin }

    /// Alias for ``overriddenOrigins`` matching CLI provenance JSON output keys.
    public var overriddenSources: [SettingOrigin] { overriddenOrigins }

    /// Redacted-safe string representation of ``value`` (`"**********"` when ``isSecret`` is `true`).
    public var displayValue: String {
        isSecret ? "**********" : String(describing: value)
    }

    /// Summary string written when encoding provenance metadata to JSON, identical to ``displayValue``.
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

    /// Encodes redacted-safe provenance metadata into the given encoder.
    ///
    /// - Parameter encoder: The encoder to write data to.
    /// - Throws: An error if encoding fails.
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

/// A type-erased provenance entry for a single field, suitable for CLI inspection (`config show --provenance`).
public struct ProvenanceEntry: Sendable, Equatable, Hashable, Codable {
    /// The canonical nested key path of the setting field.
    public let keyPath: [String]

    /// Human-readable Swift type name of the field (for example, `"Int"` or `"Secret<String>"`).
    public let typeName: String

    /// Whether the field is a secret whose value is masked as `"**********"`.
    public let isSecret: Bool

    /// Redacted-safe display representation of the resolved value.
    public let displayValue: String

    /// The winning ``SettingOrigin`` that supplied the field's value.
    public let origin: SettingOrigin

    /// Lower-precedence ``SettingOrigin`` entries shadowed by ``origin``.
    public let overriddenOrigins: [SettingOrigin]

    /// Alias for ``origin``.
    public var source: SettingOrigin { origin }

    /// Alias for ``overriddenOrigins``.
    public var overriddenSources: [SettingOrigin] { overriddenOrigins }

    /// Alias for ``displayValue``.
    public var valueSummary: String { displayValue }

    /// Creates a type-erased provenance entry, automatically masking `displayValue` when `isSecret` is `true`.
    ///
    /// - Parameters:
    ///   - keyPath: Canonical nested key path.
    ///   - typeName: Human-readable Swift type name.
    ///   - isSecret: Whether the field holds secret material.
    ///   - displayValue: Unmasked or formatted value summary (forced to `"**********"` if `isSecret` is `true`).
    ///   - origin: Winning ``SettingOrigin``.
    ///   - overriddenOrigins: Shadowed lower-precedence origins. Defaults to `[]`.
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

/// Complete, redacted-safe provenance report for a loaded ``RiggedSettings`` instance.
///
/// Use ``formattedTable()`` for human-readable terminal inspection or ``jsonPayload(prettyPrinted:)``
/// for machine-readable `--provenance --json` CLI output.
public struct ProvenanceReport: Sendable, Equatable, Hashable, Codable, CustomStringConvertible {
    /// Ordered provenance entries for every decoded leaf field on the settings model.
    public let entries: [ProvenanceEntry]

    /// Non-fatal warnings collected while loading settings (for example, when ``ExtraKeysPolicy/warn`` is active).
    public let warnings: [ValidationIssue]

    /// Creates a provenance report from decoded entries and non-fatal warnings.
    ///
    /// - Parameters:
    ///   - entries: Ordered per-field provenance entries. Defaults to `[]`.
    ///   - warnings: Non-fatal warnings recorded during loading. Defaults to `[]`.
    public init(entries: [ProvenanceEntry] = [], warnings: [ValidationIssue] = []) {
        self.entries = entries
        self.warnings = warnings
    }

    /// Looks up the provenance entry matching an exact nested `keyPath`.
    ///
    /// - Parameter keyPath: Path segments such as `["database", "port"]`.
    /// - Returns: The matching ``ProvenanceEntry``, or `nil` if not found.
    public func entry(forKeyPath keyPath: [String]) -> ProvenanceEntry? {
        entries.first { $0.keyPath == keyPath }
    }

    /// Looks up a provenance entry using variadic path segments (for example, `report["database", "port"]`).
    ///
    /// - Parameter keyPath: Variadic path components.
    /// - Returns: The matching ``ProvenanceEntry``, or `nil` if not found.
    public subscript(keyPath: String...) -> ProvenanceEntry? {
        entry(forKeyPath: keyPath)
    }

    /// Human-readable multi-line provenance summary produced by ``formattedTable()``.
    public var description: String {
        formattedTable()
    }

    /// Formats all provenance entries as a redacted-safe multi-line text report showing winning and overridden origins.
    ///
    /// - Returns: Formatted provenance lines, or `"(no settings)"` when ``entries`` is empty.
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

    /// Encodes the provenance report as deterministic, sorted-key UTF-8 JSON `Data`.
    ///
    /// - Parameter prettyPrinted: Whether to indent the JSON output. Defaults to `true`.
    /// - Returns: UTF-8 JSON bytes representing this report.
    /// - Throws: An encoding error if JSON serialization fails.
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

/// Structural JSON Schema type representation attached to a ``SettingFieldDescriptor``.
public indirect enum JSONSchemaFieldType: Sendable, Equatable, Hashable {
    /// A JSON `"string"` property with an optional semantic format such as `"uri"`, `"uuid"`, or `"duration"`.
    case string(format: String? = nil)

    /// A JSON `"integer"` property.
    case integer

    /// A JSON `"number"` floating-point property.
    case number

    /// A JSON `"boolean"` property.
    case boolean

    /// A JSON `"array"` property whose elements conform to `items`.
    case array(items: JSONSchemaFieldType)

    /// A JSON `"object"` map with arbitrary string keys whose values conform to `values`.
    case dictionary(values: JSONSchemaFieldType)

    /// A JSON `"string"` enumeration restricted to a fixed list of allowed `rawValue` strings.
    case enumValues([String])

    /// A nested JSON `"object"` group containing strongly typed child field descriptors.
    case object(fields: [SettingFieldDescriptor])
}

/// Static schema metadata describing a single field or nested group on a ``RiggedSettings`` model.
///
/// ``JSONSchemaExporter`` and ``DotEnvExporter`` consume `SettingFieldDescriptor` trees to generate
/// JSON Schema Draft 2020-12 documents, `.env.example` templates, and Markdown configuration tables
/// without instantiating or loading runtime settings.
public struct SettingFieldDescriptor: Sendable, Equatable, Hashable {
    /// Swift property identifier of the field.
    public let name: String

    /// Canonical nested configuration key path for the field.
    public let keyPath: [String]

    /// Explicit environment variable name override, or `nil` when derived from ``SettingsConfiguration/envPrefix`` and ``keyPath``.
    public let envVariable: String?

    /// Additional lookup aliases (`.env`, `.configPath`, `.cli`) accepted for this field.
    public let aliases: [SettingAlias]

    /// Human-readable Swift type name (for example, `"URL"`, `"Duration"`, or `"Secret<String>"`).
    public let typeName: String

    /// Structural JSON Schema representation of the field's value type.
    public let schemaType: JSONSchemaFieldType

    /// Whether the Swift property has an `Optional` type (`T?`).
    public let isOptional: Bool

    /// Whether the property stores secret material (`Secret<T>`), suppressing default values in generated schemas and templates.
    public let isSecret: Bool

    /// Whether the property declares a compile-time default value.
    public let hasDefault: Bool

    /// Redacted-safe string representation of the default value (`nil` when ``isSecret`` is `true` or no default exists).
    public let defaultDisplay: String?

    /// Human-readable documentation summary extracted from `///` doc comments or `help:` macro arguments.
    public let help: String?

    /// Optional deprecation message emitted in JSON Schema `deprecated` annotations and Markdown tables.
    public let deprecated: String?

    /// Example literal or URI values rendered in JSON Schema `examples` arrays and documentation.
    public let examples: [String]

    /// Whether dynamic child keys under ``keyPath`` are permitted (for example, `[String: V]` dictionary settings).
    public let allowsArbitraryChildKeys: Bool

    /// Alias for ``help`` providing the field's documentation string.
    public var documentation: String? { help }

    /// Creates a static schema descriptor for a setting field or nested settings group.
    ///
    /// - Parameters:
    ///   - name: Swift property name.
    ///   - keyPath: Canonical nested key path.
    ///   - envVariable: Optional explicit environment variable name.
    ///   - aliases: Alternate lookup aliases. Defaults to `[]`.
    ///   - typeName: Human-readable Swift type name.
    ///   - schemaType: JSON Schema structural type. Defaults to `.string()`.
    ///   - isOptional: Whether the field is optional. Defaults to `false`.
    ///   - isSecret: Whether the field is secret (`defaultDisplay` is automatically cleared when `true`). Defaults to `false`.
    ///   - hasDefault: Whether the field has a compile-time default. Defaults to `false`.
    ///   - defaultDisplay: String representation of the default value. Defaults to `nil`.
    ///   - help: Documentation summary string. Defaults to `nil`.
    ///   - documentation: Alternate parameter for `help` when `help` is `nil`. Defaults to `nil`.
    ///   - deprecated: Optional deprecation warning message. Defaults to `nil`.
    ///   - examples: Optional example strings. Defaults to `[]`.
    ///   - allowsArbitraryChildKeys: Whether arbitrary nested keys under `keyPath` are valid. Defaults to `false`.
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

/// The primary protocol implemented by typed configuration models (typically synthesized via `@Settings`).
///
/// Conforming types declare their source discovery rules via ``configuration``, expose compile-time
/// ``fieldDescriptors`` for zero-reflection schema export, and load validated, immutable snapshots
/// asynchronously via ``load(context:overrides:)``.
public protocol RiggedSettings: Sendable {
    /// Declarative configuration governing environment prefixes, file discovery, and unknown-key handling.
    static var configuration: SettingsConfiguration { get }

    /// Static descriptors for every declared field and nested group on this settings model.
    static var fieldDescriptors: [SettingFieldDescriptor] { get }

    /// Complete per-field provenance report recorded when this settings instance was loaded.
    var provenance: ProvenanceReport { get }

    /// Customizes the ordered cascade of ``SettingsSource`` layers evaluated from highest to lowest precedence.
    ///
    /// - Parameter defaults: Standard source slots (`initOverrides`, `environment`, `dotEnv`, `secretsDirectory`, `projectConfig`, `userConfig`, `managedPreferences`).
    /// - Returns: The ordered array of ``SettingsSource`` instances to query.
    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource]

    /// Performs cross-field model validation after all individual fields have been decoded and validated.
    ///
    /// - Parameter settings: The decoded settings candidate.
    /// - Returns: Any cross-field ``ValidationIssue`` violations, or an empty array when valid.
    static func validate(_ settings: Self) -> [ValidationIssue]

    /// Default secret providers used when loading this settings model without an explicit
    /// ``SettingsContext``, including turnkey CLI subcommands such as `ConfigSubcommand`.
    ///
    /// Override this property on a `@Settings` or `@Rigged` model to register external secret
    /// managers once for both `load()` and `config show` / `config doctor`:
    ///
    /// ```swift
    /// extension AppSettings {
    ///     public static var defaultSecretProviders: [any SecretProvider] {
    ///         [.file(), .env(), .onePassword(), .keychain()]
    ///     }
    /// }
    /// ```
    static var defaultSecretProviders: [any SecretProvider] { get }

    /// Loads, resolves batched secrets, decodes, and exhaustively validates an immutable settings snapshot.
    ///
    /// - Parameters:
    ///   - context: Execution environment, filesystem, and secret providers.
    ///   - overrides: Explicit CLI or programmatic overrides prepended ahead of `context.cliOverrides`.
    /// - Returns: A fully validated instance of `Self`.
    /// - Throws: ``SettingsValidationError`` aggregating every missing, invalid, unknown, or secret error.
    static func load(
        context: SettingsContext,
        overrides: [SettingOverride]
    ) async throws -> Self
}

extension RiggedSettings {
    /// Returns the ``ProvenanceReport`` captured when this settings model was loaded.
    ///
    /// - Returns: The model's ``provenance`` report.
    public func provenanceReport() -> ProvenanceReport {
        provenance
    }

    /// Returns ``DefaultSources/ordered`` when the conforming type does not customize source ordering.
    public static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        defaults.ordered
    }

    /// Returns no cross-field validation issues by default.
    public static func validate(_ settings: Self) -> [ValidationIssue] {
        []
    }

    /// Returns the built-in ``FileSecretProvider`` and ``IndirectEnvProvider`` backends.
    public static var defaultSecretProviders: [any SecretProvider] {
        [
            FileSecretProvider(),
            IndirectEnvProvider(),
        ]
    }

    /// Creates a live ``SettingsContext`` pre-populated with ``defaultSecretProviders``.
    ///
    /// - Returns: A default ``SettingsContext`` configured with this model's ``defaultSecretProviders``.
    public static func makeDefaultContext() -> SettingsContext {
        SettingsContext(secretProviders: defaultSecretProviders)
    }

    /// Loads and validates an immutable settings snapshot using the given ``SettingsContext`` and no extra overrides.
    ///
    /// - Parameter context: Execution context. Defaults to ``makeDefaultContext()``.
    /// - Returns: A fully validated instance of `Self`.
    /// - Throws: ``SettingsValidationError`` if one or more fields or secrets fail validation.
    public static func load(
        context: SettingsContext = Self.makeDefaultContext()
    ) async throws -> Self {
        try await load(context: context, overrides: [])
    }

    /// Exports a JSON Schema (Draft 2020-12) document describing this settings model.
    ///
    /// - Parameters:
    ///   - title: Optional schema `title` override. Defaults to the Swift type name.
    ///   - prettyPrinted: Whether to format the JSON output with indentation. Defaults to `true`.
    /// - Returns: A UTF-8 JSON Schema string.
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

    /// Exports a documented `.env.example` template listing environment variable names, types, and safe defaults.
    ///
    /// - Parameter includeDefaults: Whether non-secret default values are emitted. Defaults to `true`.
    /// - Returns: A `.env.example` document string.
    public static func dotEnvTemplate(includeDefaults: Bool = true) -> String {
        DotEnvExporter.exportDotEnvTemplate(
            for: Self.self,
            includeDefaults: includeDefaults
        )
    }

    /// Exports a Markdown reference table documenting every setting's key path, environment variable, type, and help text.
    ///
    /// - Parameter title: Optional Markdown heading override. Defaults to the Swift type name.
    /// - Returns: A Markdown documentation string.
    public static func markdownDocs(title: String? = nil) -> String {
        DotEnvExporter.exportMarkdownDocs(
            for: Self.self,
            title: title ?? String(describing: Self.self)
        )
    }
}
