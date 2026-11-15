import ArgumentParser
import Foundation
import RiggingCore

// MARK: - Execution Result

/// Captured output and exit status from executing a `ConfigSubcommand` operation.
public struct ConfigCommandExecutionResult: Sendable, Equatable {
    public let stdout: String
    public let stderr: String
    public let exitCode: Int32

    public init(stdout: String = "", stderr: String = "", exitCode: Int32 = 0) {
        self.stdout = stdout
        self.stderr = stderr
        self.exitCode = exitCode
    }
}

/// Protocol implemented by operational `ConfigSubcommand` leaves supporting hermetic execution
/// against an explicit `SettingsContext`.
public protocol ConfigSubcommandExecutable: AsyncParsableCommand {
    func execute(
        context: SettingsContext,
        overrides: [SettingOverride]
    ) async throws -> ConfigCommandExecutionResult
}

// MARK: - Turnkey Operational `config` Subcommand Group

/// Turnkey operational `config` subcommand group (`show`, `doctor`, `schema`, `init`) for any
/// `RiggedSettings` model.
///
/// Mount directly in a root `ParsableCommand` / `AsyncParsableCommand`:
/// ```swift
/// static let configuration = CommandConfiguration(
///     commandName: "my-cli",
///     subcommands: [
///         RunCommand.self,
///         ConfigSubcommand<AppSettings>.self,
///     ]
/// )
/// ```
public struct ConfigSubcommand<Settings: RiggedSettings>: AsyncParsableCommand {
    public static var configuration: CommandConfiguration {
        CommandConfiguration(
            commandName: "config",
            abstract: "Inspect, validate, and scaffold configuration.",
            subcommands: [
                Show.self,
                Doctor.self,
                Schema.self,
                Init.self,
            ]
        )
    }

    public init() {}

    /// Parses and executes a `config` subcommand invocation (`["show", "--json"]`, `["doctor"]`,
    /// `["schema"]`, `["init", "--dotenv"]`) hermetically against `context`.
    public static func execute(
        arguments: [String],
        context: SettingsContext = SettingsContext(),
        overrides: [SettingOverride] = []
    ) async throws -> ConfigCommandExecutionResult {
        let command = try parseAsRoot(arguments)
        if let executable = command as? any ConfigSubcommandExecutable {
            return try await executable.execute(context: context, overrides: overrides)
        }
        var mutableCommand = command
        if var asyncCmd = mutableCommand as? any AsyncParsableCommand {
            try await asyncCmd.run()
        } else {
            try mutableCommand.run()
        }
        return ConfigCommandExecutionResult()
    }

    // MARK: - `config show`

    public struct Show: ConfigSubcommandExecutable {
        public static var configuration: CommandConfiguration {
            CommandConfiguration(
                commandName: "show",
                abstract: "Display effective resolved settings and provenance with secrets redacted."
            )
        }

        @Flag(name: .long, help: "Output resolved settings and provenance as deterministic JSON.")
        public var json: Bool = false

        @Option(name: .long, help: "Active configuration profile override.")
        public var profile: String?

        public init() {}

        public mutating func run() async throws {
            let result = try await execute(context: SettingsContext(), overrides: [])
            try ConfigSubcommandIO.emitAndExitIfNeeded(result)
        }

        public func execute(
            context: SettingsContext = SettingsContext(),
            overrides: [SettingOverride] = []
        ) async throws -> ConfigCommandExecutionResult {
            var allOverrides = overrides
            if let profile, !profile.isEmpty {
                allOverrides.insert(
                    .cli(flag: "--profile", keyPath: ["profile"], value: .string(profile)),
                    at: 0
                )
            }

            do {
                let settings = try await Settings.load(context: context, overrides: allOverrides)
                let report = settings.provenanceReport()

                if json {
                    let payload = ShowJSONEnvelope(from: report, redactor: context.redactor)
                    let text = try Self.encodeSortedJSON(payload, prettyPrinted: true)
                    return ConfigCommandExecutionResult(
                        stdout: context.redactor.scrub(text),
                        exitCode: 0
                    )
                } else {
                    var output = context.redactor.scrub(report.formattedTable())
                    if !report.warnings.isEmpty {
                        var warningLines: [String] = ["", "Warnings (\(report.warnings.count)):"]
                        for warning in report.warnings {
                            warningLines.append(contentsOf: warning.formattedLines(redactor: context.redactor))
                        }
                        output += warningLines.joined(separator: "\n")
                    }
                    return ConfigCommandExecutionResult(stdout: output, exitCode: 0)
                }
            } catch let validationError as SettingsValidationError {
                if json {
                    let data = validationError.jsonPayload(prettyPrinted: true, redactor: context.redactor)
                    let text = context.redactor.scrub(String(decoding: data, as: UTF8.self))
                    return ConfigCommandExecutionResult(
                        stdout: text,
                        exitCode: validationError.exitCode
                    )
                } else {
                    let errText = validationError.formattedDescription(redactor: context.redactor)
                    return ConfigCommandExecutionResult(
                        stderr: errText,
                        exitCode: validationError.exitCode
                    )
                }
            }
        }

        private static func encodeSortedJSON<T: Encodable>(_ value: T, prettyPrinted: Bool) throws -> String {
            let encoder = JSONEncoder()
            var formatting: JSONEncoder.OutputFormatting = [.sortedKeys]
            if prettyPrinted {
                formatting.insert(.prettyPrinted)
            }
            encoder.outputFormatting = formatting
            let data = try encoder.encode(value)
            return String(decoding: data, as: UTF8.self)
        }
    }

    // MARK: - `config doctor`

    public struct Doctor: ConfigSubcommandExecutable {
        public static var configuration: CommandConfiguration {
            CommandConfiguration(
                commandName: "doctor",
                abstract: "Validate configuration files, file permissions, and secret providers without exposing plaintext."
            )
        }

        @Flag(name: .long, help: "Output health report and structured issues as deterministic JSON.")
        public var json: Bool = false

        @Option(name: .long, help: "Active configuration profile override.")
        public var profile: String?

        public init() {}

        public mutating func run() async throws {
            let result = try await execute(context: SettingsContext(), overrides: [])
            try ConfigSubcommandIO.emitAndExitIfNeeded(result)
        }

        public func execute(
            context: SettingsContext = SettingsContext(),
            overrides: [SettingOverride] = []
        ) async throws -> ConfigCommandExecutionResult {
            var allOverrides = overrides
            if let profile, !profile.isEmpty {
                allOverrides.insert(
                    .cli(flag: "--profile", keyPath: ["profile"], value: .string(profile)),
                    at: 0
                )
            }

            let config = Settings.configuration
            let preflightWarnings = ConfigDoctorInspector.inspectSourceFilePermissions(
                configuration: config,
                context: context
            )

            do {
                let settings = try await Settings.load(context: context, overrides: allOverrides)
                let report = settings.provenanceReport()
                let deprecationWarnings = ConfigDoctorInspector.inspectDeprecatedUsage(
                    descriptors: Settings.fieldDescriptors,
                    report: report
                )
                let combinedWarnings = Self.deduplicateIssues(
                    report.warnings + preflightWarnings + deprecationWarnings
                )
                let secretCount = report.entries.filter(\.isSecret).count

                if json {
                    let envelope = DoctorJSONEnvelope(
                        healthy: true,
                        status: combinedWarnings.isEmpty ? "ok" : "warning",
                        exitCode: 0,
                        entryCount: report.entries.count,
                        secretCount: secretCount,
                        issues: [],
                        warnings: combinedWarnings,
                        redactor: context.redactor
                    )
                    let text = try Self.encodeSortedJSON(envelope)
                    return ConfigCommandExecutionResult(
                        stdout: context.redactor.scrub(text),
                        exitCode: 0
                    )
                } else {
                    var lines: [String] = [
                        "✓ Configuration healthy (\(report.entries.count) settings verified, \(secretCount) secrets resolved)"
                    ]
                    if !combinedWarnings.isEmpty {
                        lines.append("Warnings (\(combinedWarnings.count)):")
                        for warning in combinedWarnings {
                            lines.append(contentsOf: warning.formattedLines(redactor: context.redactor))
                        }
                    }
                    return ConfigCommandExecutionResult(
                        stdout: context.redactor.scrub(lines.joined(separator: "\n")),
                        exitCode: 0
                    )
                }
            } catch let validationError as SettingsValidationError {
                let combinedWarnings = Self.deduplicateIssues(
                    validationError.warnings + preflightWarnings
                )
                let exitCode = validationError.exitCode

                if json {
                    let envelope = DoctorJSONEnvelope(
                        healthy: false,
                        status: "failed",
                        exitCode: exitCode,
                        entryCount: 0,
                        secretCount: 0,
                        issues: validationError.issues,
                        warnings: combinedWarnings,
                        redactor: context.redactor
                    )
                    let text = try Self.encodeSortedJSON(envelope)
                    return ConfigCommandExecutionResult(
                        stdout: context.redactor.scrub(text),
                        exitCode: exitCode
                    )
                } else {
                    let enrichedError = SettingsValidationError(
                        issues: validationError.issues,
                        warnings: combinedWarnings,
                        redactor: context.redactor
                    )
                    return ConfigCommandExecutionResult(
                        stderr: enrichedError.formattedDescription(redactor: context.redactor),
                        exitCode: exitCode
                    )
                }
            }
        }

        private static func deduplicateIssues(_ issues: [ValidationIssue]) -> [ValidationIssue] {
            var seen = Set<ValidationIssue>()
            var ordered: [ValidationIssue] = []
            for issue in issues where seen.insert(issue).inserted {
                ordered.append(issue)
            }
            return ordered
        }

        private static func encodeSortedJSON<T: Encodable>(_ value: T) throws -> String {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(value)
            return String(decoding: data, as: UTF8.self)
        }
    }

    // MARK: - `config schema`

    public struct Schema: ConfigSubcommandExecutable {
        public static var configuration: CommandConfiguration {
            CommandConfiguration(
                commandName: "schema",
                abstract: "Export JSON Schema (Draft 2020-12) for editor autocomplete and validation."
            )
        }

        @Flag(name: .long, help: "Output compact single-line JSON Schema.")
        public var compact: Bool = false

        @Option(name: .long, help: "Override the root JSON Schema title.")
        public var title: String?

        public init() {}

        public mutating func run() async throws {
            let result = try await execute(context: SettingsContext(), overrides: [])
            try ConfigSubcommandIO.emitAndExitIfNeeded(result)
        }

        public func execute(
            context: SettingsContext = SettingsContext(),
            overrides: [SettingOverride] = []
        ) async throws -> ConfigCommandExecutionResult {
            let schemaString = Settings.jsonSchema(
                title: title,
                prettyPrinted: !compact
            )
            return ConfigCommandExecutionResult(stdout: schemaString, exitCode: 0)
        }
    }

    // MARK: - `config init`

    public struct Init: ConfigSubcommandExecutable {
        public static var configuration: CommandConfiguration {
            CommandConfiguration(
                commandName: "init",
                abstract: "Generate a starter .env template or JSON configuration file."
            )
        }

        @Flag(name: .long, help: "Generate a commented .env template.")
        public var dotenv: Bool = false

        @Flag(name: .long, help: "Generate a starter JSON configuration file.")
        public var json: Bool = false

        public init() {}

        public mutating func validate() throws {
            if dotenv && json {
                throw ValidationError("Specify either --dotenv or --json, not both.")
            }
        }

        public mutating func run() async throws {
            let result = try await execute(context: SettingsContext(), overrides: [])
            try ConfigSubcommandIO.emitAndExitIfNeeded(result)
        }

        public func execute(
            context: SettingsContext = SettingsContext(),
            overrides: [SettingOverride] = []
        ) async throws -> ConfigCommandExecutionResult {
            if dotenv && json {
                throw ValidationError("Specify either --dotenv or --json, not both.")
            }

            if json {
                let starter = StarterJSONGenerator.generate(
                    descriptors: Settings.fieldDescriptors,
                    configuration: Settings.configuration
                )
                return ConfigCommandExecutionResult(stdout: starter, exitCode: 0)
            }

            // Default (or explicit --dotenv) emits commented .env template
            let template = Settings.dotEnvTemplate(includeDefaults: true)
            return ConfigCommandExecutionResult(stdout: template, exitCode: 0)
        }
    }
}

/// Alias matching Section 6.6 naming (`SettingsCommandGroup<MySettings>`).
public typealias SettingsCommandGroup<Settings: RiggedSettings> = ConfigSubcommand<Settings>

// MARK: - JSON Envelopes & Helpers

private struct ShowJSONEnvelope: Encodable {
    struct EntryPayload: Encodable {
        let displayValue: String
        let isSecret: Bool
        let keyPath: [String]
        let origin: SettingOrigin
        let originDescription: String
        let overriddenOrigins: [SettingOrigin]
        let overriddenDescriptions: [String]
        let typeName: String
    }

    struct WarningPayload: Encodable {
        let keyPath: String
        let kind: String
        let message: String
        let origin: String?
    }

    let entries: [EntryPayload]
    let values: [String: String]
    let warnings: [WarningPayload]

    init(from report: ProvenanceReport, redactor: DiagnosticRedactor) {
        var flatValues: [String: String] = [:]
        var payloads: [EntryPayload] = []

        for entry in report.entries {
            let safeValue = entry.isSecret ? "**********" : redactor.scrub(entry.displayValue)
            let joinedKey = entry.keyPath.joined(separator: ".")
            flatValues[joinedKey] = safeValue
            payloads.append(
                EntryPayload(
                    displayValue: safeValue,
                    isSecret: entry.isSecret,
                    keyPath: entry.keyPath,
                    origin: entry.origin,
                    originDescription: redactor.scrub(entry.origin.description),
                    overriddenOrigins: entry.overriddenOrigins,
                    overriddenDescriptions: entry.overriddenOrigins.map { redactor.scrub($0.description) },
                    typeName: entry.typeName
                )
            )
        }

        self.entries = payloads
        self.values = flatValues
        self.warnings = report.warnings.map { warning in
            WarningPayload(
                keyPath: warning.keyPathString,
                kind: warning.kind.rawValue,
                message: redactor.scrub(warning.message),
                origin: warning.origin.map { redactor.scrub($0.description) }
            )
        }
    }
}

private struct DoctorJSONEnvelope: Encodable {
    struct IssuePayload: Encodable {
        let envVariableHint: String?
        let exitCode: Int32
        let expectedType: String?
        let keyPath: String
        let kind: String
        let message: String
        let origin: String?
        let remediation: String?
    }

    let entryCount: Int
    let errorCount: Int
    let exitCode: Int32
    let healthy: Bool
    let issues: [IssuePayload]
    let secretCount: Int
    let status: String
    let warningCount: Int
    let warnings: [IssuePayload]

    init(
        healthy: Bool,
        status: String,
        exitCode: Int32,
        entryCount: Int,
        secretCount: Int,
        issues: [ValidationIssue],
        warnings: [ValidationIssue],
        redactor: DiagnosticRedactor
    ) {
        let mapIssue: (ValidationIssue) -> IssuePayload = { issue in
            IssuePayload(
                envVariableHint: issue.envVariableHint,
                exitCode: issue.exitCode,
                expectedType: issue.expectedType,
                keyPath: issue.keyPathString,
                kind: issue.kind.rawValue,
                message: redactor.scrub(issue.message),
                origin: issue.origin.map { redactor.scrub($0.description) },
                remediation: issue.remediation.map { redactor.scrub($0) }
            )
        }

        self.healthy = healthy
        self.status = status
        self.exitCode = exitCode
        self.entryCount = entryCount
        self.secretCount = secretCount
        self.errorCount = issues.count
        self.issues = issues.map(mapIssue)
        self.warningCount = warnings.count
        self.warnings = warnings.map(mapIssue)
    }
}

// MARK: - Doctor Inspection Helpers

enum ConfigDoctorInspector {
    static func inspectSourceFilePermissions(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) -> [ValidationIssue] {
        var warnings: [ValidationIssue] = []

        // Check .env files for overly permissive group/world access
        for dotEnvFile in configuration.dotEnvFiles {
            let resolvedPath: String
            if dotEnvFile.hasPrefix("/") {
                resolvedPath = dotEnvFile
            } else {
                resolvedPath = context.workingDirectory.hasSuffix("/")
                    ? "\(context.workingDirectory)\(dotEnvFile)"
                    : "\(context.workingDirectory)/\(dotEnvFile)"
            }
            guard context.fileSystem.fileExists(atPath: resolvedPath),
                  !context.fileSystem.isDirectory(atPath: resolvedPath),
                  let perms = try? context.fileSystem.posixPermissions(atPath: resolvedPath) else {
                continue
            }
            if (perms & 0o002) != 0 {
                let octal = String(perms & 0o777, radix: 8)
                warnings.append(
                    ValidationIssue(
                        keyPath: [dotEnvFile],
                        kind: .unsafeSecret,
                        message: "Environment file '\(resolvedPath)' is world-writable (mode 0\(octal)).",
                        remediation: "chmod 600 \(resolvedPath)"
                    )
                )
            }
        }

        // Check XDG user config files if configured
        if let appName = configuration.xdgAppName, !appName.isEmpty {
            let xdgRoot: String
            if let xdgEnv = context.environment["XDG_CONFIG_HOME"], !xdgEnv.isEmpty {
                xdgRoot = xdgEnv
            } else {
                xdgRoot = context.homeDirectory.hasSuffix("/")
                    ? "\(context.homeDirectory).config"
                    : "\(context.homeDirectory)/.config"
            }
            for ext in ["json", "toml", "yaml", "yml"] {
                let candidate = "\(xdgRoot)/\(appName)/config.\(ext)"
                guard context.fileSystem.fileExists(atPath: candidate),
                      !context.fileSystem.isDirectory(atPath: candidate),
                      let perms = try? context.fileSystem.posixPermissions(atPath: candidate) else {
                    continue
                }
                if (perms & 0o002) != 0 {
                    let octal = String(perms & 0o777, radix: 8)
                    warnings.append(
                        ValidationIssue(
                            keyPath: ["config.\(ext)"],
                            kind: .unsafeSecret,
                            message: "User configuration file '\(candidate)' is world-writable (mode 0\(octal)).",
                            remediation: "chmod 600 \(candidate)"
                        )
                    )
                }
            }
        }

        return warnings
    }

    static func inspectDeprecatedUsage(
        descriptors: [SettingFieldDescriptor],
        report: ProvenanceReport,
        parentPath: [String] = []
    ) -> [ValidationIssue] {
        var warnings: [ValidationIssue] = []

        for field in descriptors {
            let fullPath: [String]
            if !parentPath.isEmpty && !field.keyPath.starts(with: parentPath) {
                fullPath = parentPath + [field.name]
            } else {
                fullPath = field.keyPath
            }

            if case .object(let children) = field.schemaType {
                warnings.append(
                    contentsOf: inspectDeprecatedUsage(
                        descriptors: children,
                        report: report,
                        parentPath: fullPath
                    )
                )
                continue
            }

            guard let deprecationMessage = field.deprecated,
                  let entry = report.entry(forKeyPath: fullPath),
                  entry.origin != .defaultValue else {
                continue
            }

            warnings.append(
                ValidationIssue(
                    keyPath: fullPath,
                    kind: .invalidValue,
                    message: "Deprecated setting '\(fullPath.joined(separator: "."))' is in use: \(deprecationMessage)",
                    origin: entry.origin
                )
            )
        }

        return warnings
    }
}

// MARK: - Starter JSON Generator (`config init --json`)

enum StarterJSONGenerator {
    static func generate(
        descriptors: [SettingFieldDescriptor],
        configuration: SettingsConfiguration
    ) -> String {
        let rootObject = buildObject(descriptors: descriptors, configuration: configuration)
        guard JSONSerialization.isValidJSONObject(rootObject),
              let data = try? JSONSerialization.data(
                  withJSONObject: rootObject,
                  options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
              ) else {
            return "{\n}"
        }
        return String(decoding: data, as: UTF8.self)
    }

    private static func buildObject(
        descriptors: [SettingFieldDescriptor],
        configuration: SettingsConfiguration
    ) -> [String: Any] {
        var dict: [String: Any] = [:]
        let appSlug = configuration.xdgAppName
            ?? (configuration.envPrefix.isEmpty
                ? "app"
                : configuration.envPrefix
                    .trimmingCharacters(in: CharacterSet(charactersIn: "_"))
                    .lowercased())

        for field in descriptors {
            dict[field.name] = starterValue(for: field, appSlug: appSlug, configuration: configuration)
        }

        return dict
    }

    private static func starterValue(
        for field: SettingFieldDescriptor,
        appSlug: String,
        configuration: SettingsConfiguration
    ) -> Any {
        if field.isSecret {
            if let example = field.examples.first,
               example.contains("://") || example.hasPrefix("@") {
                return example
            }
            return "op://Personal/\(appSlug)/\(field.name)"
        }

        if case .object(let children) = field.schemaType {
            return buildObject(descriptors: children, configuration: configuration)
        }

        if let defaultDisplay = field.defaultDisplay {
            let trimmed = defaultDisplay.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed == "nil" || trimmed == "null" {
                if field.isOptional {
                    return NSNull()
                }
            } else if let parsed = parseDefaultDisplay(trimmed, schemaType: field.schemaType) {
                return parsed
            }
        }

        if let firstExample = field.examples.first,
           let parsedExample = parseDefaultDisplay(firstExample, schemaType: field.schemaType) {
            return parsedExample
        }

        switch field.schemaType {
        case .string:
            return field.isOptional ? NSNull() : ""
        case .integer:
            return field.isOptional ? NSNull() : 0
        case .number:
            return field.isOptional ? NSNull() : 0.0
        case .boolean:
            return field.isOptional ? NSNull() : false
        case .enumValues(let values):
            return values.first ?? ""
        case .array:
            return [Any]()
        case .dictionary:
            return [String: Any]()
        case .object(let children):
            return buildObject(descriptors: children, configuration: configuration)
        }
    }

    private static func parseDefaultDisplay(_ raw: String, schemaType: JSONSchemaFieldType) -> Any? {
        switch schemaType {
        case .boolean:
            switch raw.lowercased() {
            case "true": return true
            case "false": return false
            default: return nil
            }
        case .integer:
            let cleaned = raw.replacingOccurrences(of: "_", with: "")
            return Int64(cleaned).map { NSNumber(value: $0) }
        case .number:
            let cleaned = raw.replacingOccurrences(of: "_", with: "")
            return Double(cleaned).map { NSNumber(value: $0) }
        case .string, .enumValues:
            return unquoteSwiftLiteral(raw)
        case .array:
            if let data = raw.data(using: .utf8),
               let arr = try? JSONSerialization.jsonObject(with: data) as? [Any] {
                return arr
            }
            if raw == "[]" {
                return [Any]()
            }
            return nil
        case .dictionary:
            if let data = raw.data(using: .utf8),
               let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return dict
            }
            if raw == "[:]" || raw == "{}" {
                return [String: Any]()
            }
            return nil
        case .object:
            return nil
        }
    }

    private static func unquoteSwiftLiteral(_ raw: String) -> String {
        if raw.count >= 2 && raw.hasPrefix("\"") && raw.hasSuffix("\"") {
            let inner = String(raw.dropFirst().dropLast())
            return inner
                .replacingOccurrences(of: "\\\"", with: "\"")
                .replacingOccurrences(of: "\\\\", with: "\\")
        }
        if raw.hasPrefix(".") && raw.count > 1 {
            // Swift enum shorthand literal `.info` -> `"info"`
            return String(raw.dropFirst())
        }
        return raw
    }
}

// MARK: - Terminal I/O Helper

enum ConfigSubcommandIO {
    static func emitAndExitIfNeeded(_ result: ConfigCommandExecutionResult) throws {
        if !result.stdout.isEmpty {
            print(result.stdout)
        }
        if !result.stderr.isEmpty {
            let message = result.stderr.hasSuffix("\n") ? result.stderr : "\(result.stderr)\n"
            FileHandle.standardError.write(Data(message.utf8))
        }
        if result.exitCode != 0 {
            throw ExitCode(result.exitCode)
        }
    }
}
