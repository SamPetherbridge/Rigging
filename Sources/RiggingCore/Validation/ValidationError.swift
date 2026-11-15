import Foundation

/// Exit-code-mapped validation issue classification.
///
/// - `missingRequired`, `invalidValue`, `unknownKey`, `crossField` -> exit code `2`
/// - `unsafeSecret` -> exit code `4`
/// - `providerFailure` -> exit code `6`
public enum ValidationIssueKind: String, Sendable, Equatable, Hashable, Codable {
    case missingRequired
    case invalidValue
    case unknownKey
    case crossField
    case unsafeSecret
    case providerFailure

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

/// A single structured configuration or secret resolution error (or warning).
public struct ValidationIssue: Error, Sendable, Equatable, Hashable, Codable, CustomStringConvertible {
    public let keyPath: [String]
    public let kind: ValidationIssueKind
    public let message: String
    public let origin: SettingOrigin?
    public let expectedType: String?
    public let envVariableHint: String?
    public let remediation: String?

    public var path: [String] { keyPath }

    public init(
        keyPath: [String],
        kind: ValidationIssueKind,
        message: String,
        origin: SettingOrigin? = nil,
        expectedType: String? = nil,
        envVariableHint: String? = nil,
        remediation: String? = nil
    ) {
        self.keyPath = keyPath
        self.kind = kind
        self.message = message
        self.origin = origin
        self.expectedType = expectedType
        self.envVariableHint = envVariableHint
        self.remediation = remediation
    }

    public init(
        path: [String],
        kind: ValidationIssueKind = .crossField,
        message: String,
        origin: SettingOrigin? = nil,
        expectedType: String? = nil,
        envVariableHint: String? = nil,
        remediation: String? = nil
    ) {
        self.init(
            keyPath: path,
            kind: kind,
            message: message,
            origin: origin,
            expectedType: expectedType,
            envVariableHint: envVariableHint,
            remediation: remediation
        )
    }

    public var exitCode: Int32 {
        kind.exitCode
    }

    public var keyPathString: String {
        keyPath.isEmpty ? "<root>" : keyPath.joined(separator: ".")
    }

    public var description: String {
        formattedLines(redactor: nil).joined(separator: "\n")
    }

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

/// Multi-issue validation error aggregating all configuration, secret safety, and provider failures
/// encountered during a single `RiggedSettings.load` invocation.
public struct SettingsValidationError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    public let issues: [ValidationIssue]
    public let warnings: [ValidationIssue]
    private let scrubbedHumanDescription: String
    private let scrubbedJSONPayloadData: Data

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

    public static func == (lhs: SettingsValidationError, rhs: SettingsValidationError) -> Bool {
        lhs.issues == rhs.issues && lhs.warnings == rhs.warnings
    }

    /// Deterministic CLI exit code (`6` if any provider failure, `4` if any unsafe secret, else `2`).
    public var exitCode: Int32 {
        issues.map(\.exitCode).max() ?? 2
    }

    public var description: String {
        scrubbedHumanDescription
    }

    public var errorDescription: String? {
        scrubbedHumanDescription
    }

    public func formattedDescription(redactor: DiagnosticRedactor? = nil) -> String {
        if let redactor {
            return Self.buildHumanDescription(issues: issues, warnings: warnings, redactor: redactor)
        }
        return scrubbedHumanDescription
    }

    /// Deterministic, sorted-key JSON payload representing all issues and the aggregated exit code.
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
        let keyPath: String
        let kind: String
        let message: String
        let origin: String?
        let remediation: String?
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
            JSONIssueEntry(
                envVariableHint: issue.envVariableHint,
                exitCode: issue.exitCode,
                expectedType: issue.expectedType,
                keyPath: issue.keyPathString,
                kind: issue.kind.rawValue,
                message: scrub(issue.message) ?? issue.message,
                origin: scrub(issue.origin?.description),
                remediation: scrub(issue.remediation)
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
