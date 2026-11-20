import Foundation

/// Classifies configuration and secret validation failures into deterministic CLI exit-code buckets.
///
/// `RiggingCore` maps each issue category to a standard process exit status so command-line tools
/// and container orchestrators can distinguish schema mistakes from secret-safety violations and
/// transient secret-backend outages:
///
/// - Exit code `2`: ``missingRequired``, ``invalidValue``, ``unknownKey``, and ``crossField``.
/// - Exit code `4`: ``unsafeSecret`` (for example, a plaintext secret committed in project config or an over-permissive key file).
/// - Exit code `6`: ``providerFailure`` (for example, an unauthenticated CLI vault session or unreachable secret item).
public enum ValidationIssueKind: String, Sendable, Equatable, Hashable, Codable {
    /// A required setting was absent or resolved to a null sentinel.
    case missingRequired

    /// A raw configuration value failed type coercion, format parsing, or field-level validation.
    case invalidValue

    /// An undeclared configuration key was encountered when ``ExtraKeysPolicy/forbid`` or ``ExtraKeysPolicy/warn`` is active.
    case unknownKey

    /// A model-level cross-field invariant failed in ``RiggedSettings/validate(_:)``.
    case crossField

    /// A secret violated storage or executable trust safety checks (exit code `4`).
    case unsafeSecret

    /// A secret provider failed to authenticate, locate, or read a referenced secret (exit code `6`).
    case providerFailure

    /// Process exit code associated with this issue category (`2`, `4`, or `6`).
    public var exitCode: Int32 {
        switch self {
        case .missingRequired, .invalidValue, .unknownKey, .crossField:
            return 2
        case .unsafeSecret:
            return 4
        case .providerFailure:
            return 6
        }
    }
}

/// A structured diagnostic describing a single configuration, validation, or secret-resolution issue.
///
/// Instances of `ValidationIssue` are accumulated exhaustively by ``SettingsLoader`` and ``SecretResolver``
/// rather than failing on the first invalid field, then surfaced together inside ``SettingsValidationError``.
///
/// ```swift
/// let issue = ValidationIssue(
///     path: ["tlsCertPath"],
///     kind: .crossField,
///     message: "TLS certificate path is required when TLS is enabled.",
///     remediation: "Set APP_TLS_CERT_PATH or disable APP_TLS_ENABLED."
/// )
/// ```
public struct ValidationIssue: Error, Sendable, Equatable, Hashable, Codable, CustomStringConvertible, LocalizedError {
    /// Hierarchical setting key path where the issue occurred, or an empty array for model-root issues.
    public let keyPath: [String]

    /// Classification determining diagnostic grouping and CLI exit code.
    public let kind: ValidationIssueKind

    /// Human-readable explanation of why validation or resolution failed.
    public let message: String

    /// Provenance of the offending value when known.
    public let origin: SettingOrigin?

    /// Display name of the expected Swift type when applicable.
    public let expectedType: String?

    /// Canonical environment variable name that can supply or fix this setting.
    public let envVariableHint: String?

    /// Actionable remediation guidance (such as a `chmod 600` command or CLI login hint).
    public let remediation: String?

    /// Whether the underlying secret provider failure was caused by rate limiting.
    public let isRateLimited: Bool

    /// Provider-supplied retry delay when ``isRateLimited`` is `true` and a valid interval was reported.
    public let retryAfter: Duration?

    /// Alias for ``keyPath`` matching model-level validation conventions.
    public var path: [String] { keyPath }

    /// Creates a structured validation issue keyed by `keyPath`.
    ///
    /// - Parameters:
    ///   - keyPath: Hierarchical setting path segments.
    ///   - kind: Issue category determining exit code.
    ///   - message: Human-readable explanation of the failure.
    ///   - origin: Source provenance of the invalid value, if available.
    ///   - expectedType: Expected Swift type name, if applicable.
    ///   - envVariableHint: Suggested environment variable name for remediation.
    ///   - remediation: Optional actionable fix instruction.
    ///   - isRateLimited: Whether this issue originated from a secret provider rate limit.
    ///   - retryAfter: Optional provider-supplied retry interval.
    public init(
        keyPath: [String],
        kind: ValidationIssueKind,
        message: String,
        origin: SettingOrigin? = nil,
        expectedType: String? = nil,
        envVariableHint: String? = nil,
        remediation: String? = nil,
        isRateLimited: Bool = false,
        retryAfter: Duration? = nil
    ) {
        self.keyPath = keyPath
        self.kind = kind
        self.message = message
        self.origin = origin
        self.expectedType = expectedType
        self.envVariableHint = envVariableHint
        self.remediation = remediation
        self.isRateLimited = isRateLimited
        self.retryAfter = retryAfter
    }

    /// Creates a structured validation issue keyed by `path`, defaulting `kind` to ``ValidationIssueKind/crossField``.
    ///
    /// - Parameters:
    ///   - path: Hierarchical setting path segments.
    ///   - kind: Issue category determining exit code (defaults to ``ValidationIssueKind/crossField``).
    ///   - message: Human-readable explanation of the failure.
    ///   - origin: Source provenance of the invalid value, if available.
    ///   - expectedType: Expected Swift type name, if applicable.
    ///   - envVariableHint: Suggested environment variable name for remediation.
    ///   - remediation: Optional actionable fix instruction.
    ///   - isRateLimited: Whether this issue originated from a secret provider rate limit.
    ///   - retryAfter: Optional provider-supplied retry interval.
    public init(
        path: [String],
        kind: ValidationIssueKind = .crossField,
        message: String,
        origin: SettingOrigin? = nil,
        expectedType: String? = nil,
        envVariableHint: String? = nil,
        remediation: String? = nil,
        isRateLimited: Bool = false,
        retryAfter: Duration? = nil
    ) {
        self.init(
            keyPath: path,
            kind: kind,
            message: message,
            origin: origin,
            expectedType: expectedType,
            envVariableHint: envVariableHint,
            remediation: remediation,
            isRateLimited: isRateLimited,
            retryAfter: retryAfter
        )
    }

    private enum CodingKeys: String, CodingKey {
        case keyPath
        case kind
        case message
        case origin
        case expectedType
        case envVariableHint
        case remediation
        case isRateLimited
        case retryAfter
    }

    /// Decodes a validation issue, defaulting ``isRateLimited`` to `false` when absent.
    ///
    /// - Parameter decoder: Decoder reading serialized validation data.
    /// - Throws: A decoding error if required fields are missing or malformed.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.keyPath = try container.decode([String].self, forKey: .keyPath)
        self.kind = try container.decode(ValidationIssueKind.self, forKey: .kind)
        self.message = try container.decode(String.self, forKey: .message)
        self.origin = try container.decodeIfPresent(SettingOrigin.self, forKey: .origin)
        self.expectedType = try container.decodeIfPresent(String.self, forKey: .expectedType)
        self.envVariableHint = try container.decodeIfPresent(String.self, forKey: .envVariableHint)
        self.remediation = try container.decodeIfPresent(String.self, forKey: .remediation)
        self.isRateLimited = try container.decodeIfPresent(Bool.self, forKey: .isRateLimited) ?? false
        self.retryAfter = try container.decodeIfPresent(Duration.self, forKey: .retryAfter)
    }

    /// Encodes this validation issue into `encoder`.
    ///
    /// - Parameter encoder: Encoder receiving serialized validation data.
    /// - Throws: An encoding error if encoding any field fails.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(keyPath, forKey: .keyPath)
        try container.encode(kind, forKey: .kind)
        try container.encode(message, forKey: .message)
        try container.encodeIfPresent(origin, forKey: .origin)
        try container.encodeIfPresent(expectedType, forKey: .expectedType)
        try container.encodeIfPresent(envVariableHint, forKey: .envVariableHint)
        try container.encodeIfPresent(remediation, forKey: .remediation)
        if isRateLimited {
            try container.encode(isRateLimited, forKey: .isRateLimited)
        }
        try container.encodeIfPresent(retryAfter, forKey: .retryAfter)
    }

    /// Process exit code associated with this issue (`2`, `4`, or `6`).
    public var exitCode: Int32 {
        kind.exitCode
    }

    /// Dot-delimited representation of ``keyPath``, or `"<root>"` when ``keyPath`` is empty.
    public var keyPathString: String {
        keyPath.isEmpty ? "<root>" : keyPath.joined(separator: ".")
    }

    /// Multi-line human-readable rendering of this issue.
    public var description: String {
        formattedLines(redactor: nil).joined(separator: "\n")
    }

    /// Localized error description matching ``description`` for CLI error reporters.
    public var errorDescription: String? {
        description
    }

    /// Formats this issue as indented diagnostic lines, optionally scrubbing registered secrets.
    ///
    /// - Parameter redactor: Optional ``DiagnosticRedactor`` used to scrub accidental secret substrings.
    /// - Returns: Indented lines suitable for terminal error output.
    public func formattedLines(redactor: DiagnosticRedactor?) -> [String] {
        let scrub: (String) -> String = { text in
            redactor?.scrub(text) ?? text
        }

        var header = "  ✗ \(keyPathString)"
        if let origin {
            header += " (from \(scrub(origin.description)))"
        } else if let envVariableHint {
            header += " (env: \(envVariableHint))"
        }

        var lines = [header, "    \(scrub(message))"]
        if let remediation {
            let prefix = remediation.hasPrefix("Fix:") ? "" : "Fix: "
            lines.append("    \(prefix)\(scrub(remediation))")
        }
        return lines
    }
}

/// Aggregated validation error containing every configuration, secret-safety, and provider failure
/// encountered during a ``RiggedSettings/load(context:overrides:)`` pass.
///
/// `SettingsValidationError` scrubs both its human-readable ``description`` and machine-readable
/// ``jsonPayload(prettyPrinted:redactor:)`` through ``DiagnosticRedactor`` at initialization time
/// so resolved secrets never leak to `stderr` or structured logs.
///
/// ```swift
/// do {
///     let settings = try await AppSettings.load()
/// } catch let error as SettingsValidationError {
///     FileHandle.standardError.write(Data((error.description + "\n").utf8))
///     exit(error.exitCode)
/// }
/// ```
public struct SettingsValidationError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    /// Blocking validation, secret-safety, and provider issues that prevented loading.
    public let issues: [ValidationIssue]

    /// Non-fatal warnings collected during loading (such as unknown keys under ``ExtraKeysPolicy/warn``).
    public let warnings: [ValidationIssue]

    private let scrubbedHumanDescription: String
    private let scrubbedJSONPayloadData: Data

    /// Creates an aggregated validation error and pre-scrubs its diagnostic output.
    ///
    /// - Parameters:
    ///   - issues: Blocking validation issues.
    ///   - warnings: Non-blocking validation warnings.
    ///   - redactor: Optional ``DiagnosticRedactor`` used to scrub secret plaintext from rendered messages.
    public init(
        issues: [ValidationIssue],
        warnings: [ValidationIssue] = [],
        redactor: DiagnosticRedactor? = nil
    ) {
        self.issues = issues
        self.warnings = warnings
        self.scrubbedHumanDescription = Self.buildHumanDescription(
            issues: issues,
            warnings: warnings,
            redactor: redactor
        )
        self.scrubbedJSONPayloadData = Self.buildJSONPayload(
            issues: issues,
            warnings: warnings,
            prettyPrinted: false,
            redactor: redactor
        )
    }

    /// Returns `true` when two validation errors carry identical ``issues`` and ``warnings``.
    public static func == (lhs: SettingsValidationError, rhs: SettingsValidationError) -> Bool {
        lhs.issues == rhs.issues && lhs.warnings == rhs.warnings
    }

    /// Highest-severity CLI exit code across ``issues`` (`6` for provider failures, `4` for unsafe secrets, otherwise `2`).
    public var exitCode: Int32 {
        issues.map(\.exitCode).max() ?? 2
    }

    /// Scrubbed human-readable multi-issue diagnostic report.
    public var description: String {
        scrubbedHumanDescription
    }

    /// Localized error description matching ``description`` for `ArgumentParser` and `Foundation` error reporting.
    public var errorDescription: String? {
        scrubbedHumanDescription
    }

    /// Renders the human-readable diagnostic report, applying an additional `redactor` when supplied.
    ///
    /// - Parameter redactor: Optional additional ``DiagnosticRedactor`` to scrub the output.
    /// - Returns: Multi-line human-readable error report.
    public func formattedDescription(redactor: DiagnosticRedactor? = nil) -> String {
        if let redactor {
            return Self.buildHumanDescription(issues: issues, warnings: warnings, redactor: redactor)
        }
        return scrubbedHumanDescription
    }

    /// Serializes all issues, warnings, and the aggregated exit code as deterministic sorted-key JSON.
    ///
    /// - Parameters:
    ///   - prettyPrinted: Whether to indent the JSON output with whitespace and newlines.
    ///   - redactor: Optional additional ``DiagnosticRedactor`` to scrub string fields.
    /// - Returns: UTF-8 JSON `Data` suitable for `--format json` CLI diagnostics.
    public func jsonPayload(prettyPrinted: Bool = false, redactor: DiagnosticRedactor? = nil) -> Data {
        if !prettyPrinted && redactor == nil {
            return scrubbedJSONPayloadData
        }
        return Self.buildJSONPayload(
            issues: issues,
            warnings: warnings,
            prettyPrinted: prettyPrinted,
            redactor: redactor
        )
    }

    // MARK: - Formatting

    private struct JSONErrorEnvelope: Encodable {
        let errorCount: Int
        let exitCode: Int32
        let issues: [JSONIssueEntry]
        let warnings: [JSONIssueEntry]
    }

    private struct JSONIssueEntry: Encodable {
        let envVariableHint: String?
        let exitCode: Int32
        let expectedType: String?
        let isRateLimited: Bool?
        let keyPath: String
        let kind: String
        let message: String
        let origin: String?
        let remediation: String?
        let retryAfterSeconds: Double?
    }

    private static func buildHumanDescription(
        issues: [ValidationIssue],
        warnings: [ValidationIssue],
        redactor: DiagnosticRedactor?
    ) -> String {
        let count = issues.count
        let noun = count == 1 ? "error" : "errors"
        var lines: [String] = ["Configuration validation failed with \(count) \(noun):"]
        for issue in issues {
            lines.append(contentsOf: issue.formattedLines(redactor: redactor))
        }
        if !warnings.isEmpty {
            lines.append("Warnings (\(warnings.count)):")
            for warning in warnings {
                lines.append(contentsOf: warning.formattedLines(redactor: redactor))
            }
        }
        return lines.joined(separator: "\n")
    }

    private static func buildJSONPayload(
        issues: [ValidationIssue],
        warnings: [ValidationIssue],
        prettyPrinted: Bool,
        redactor: DiagnosticRedactor?
    ) -> Data {
        let scrub: (String?) -> String? = { value in
            guard let value else { return nil }
            return redactor?.scrub(value) ?? value
        }

        let mapIssue: (ValidationIssue) -> JSONIssueEntry = { issue in
            let retrySeconds = issue.retryAfter.map { duration in
                Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1_000_000_000_000_000_000.0
            }
            return JSONIssueEntry(
                envVariableHint: issue.envVariableHint,
                exitCode: issue.exitCode,
                expectedType: issue.expectedType,
                isRateLimited: issue.isRateLimited ? true : nil,
                keyPath: issue.keyPathString,
                kind: issue.kind.rawValue,
                message: scrub(issue.message) ?? issue.message,
                origin: scrub(issue.origin?.description),
                remediation: scrub(issue.remediation),
                retryAfterSeconds: retrySeconds
            )
        }

        let envelope = JSONErrorEnvelope(
            errorCount: issues.count,
            exitCode: issues.map(\.exitCode).max() ?? 2,
            issues: issues.map(mapIssue),
            warnings: warnings.map(mapIssue)
        )

        let encoder = JSONEncoder()
        var formatting: JSONEncoder.OutputFormatting = [.sortedKeys]
        if prettyPrinted {
            formatting.insert(.prettyPrinted)
        }
        encoder.outputFormatting = formatting
        return (try? encoder.encode(envelope)) ?? Data("{}".utf8)
    }
}
