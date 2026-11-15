import Foundation

/// A composable, thread-safe field validator evaluated after typed setting decoding.
///
/// Built-in factory methods cover common constraints such as numeric ranges, non-empty strings,
/// regular expressions, allowed URL schemes, and filesystem existence checks against
/// ``SettingsContext/fileSystem``. Custom domain rules can be expressed with ``custom(_:)-((Value)->String?)``
/// or ``custom(_:predicate:)``.
///
/// ```swift
/// let portValidator: SettingValidator<Int> = .range(1...65_535)
/// let endpointValidator: SettingValidator<URL> = .url(allowedSchemes: ["https"])
/// ```
public struct SettingValidator<Value: Sendable>: Sendable {
    private let evaluator: @Sendable (Value, SettingsContext) -> String?

    /// Creates a validator from a context-aware evaluation closure.
    ///
    /// - Parameter evaluator: Closure returning `nil` when the value is valid, or a human-readable
    ///   failure message when validation fails.
    public init(_ evaluator: @escaping @Sendable (Value, SettingsContext) -> String?) {
        self.evaluator = evaluator
    }

    /// Evaluates `value` against this rule.
    ///
    /// - Parameters:
    ///   - value: Decoded setting value to validate.
    ///   - context: Execution context providing filesystem and redactor access.
    /// - Returns: `nil` when `value` satisfies the rule, or a human-readable failure reason otherwise.
    public func validate(
        _ value: Value,
        context: SettingsContext = SettingsContext()
    ) -> String? {
        evaluator(value, context)
    }

    /// Evaluates `value` and packages any failure into a structured ``ValidationIssue``.
    ///
    /// - Parameters:
    ///   - value: Decoded setting value to validate.
    ///   - keyPath: Hierarchical key path of the field being validated.
    ///   - origin: Provenance of the decoded value.
    ///   - envVariableHint: Canonical environment variable hint for diagnostics.
    ///   - context: Execution context providing filesystem and redactor access.
    /// - Returns: A ``ValidationIssue`` with ``ValidationIssueKind/invalidValue`` on failure, or `nil` on success.
    public func validate(
        _ value: Value,
        keyPath: [String],
        origin: SettingOrigin?,
        envVariableHint: String? = nil,
        context: SettingsContext
    ) -> ValidationIssue? {
        guard let failureReason = evaluator(value, context) else {
            return nil
        }
        return ValidationIssue(
            keyPath: keyPath,
            kind: .invalidValue,
            message: context.redactor.scrub(failureReason),
            origin: origin,
            expectedType: String(describing: Value.self),
            envVariableHint: envVariableHint
        )
    }

    /// Lifts this validator to an optional value, succeeding automatically when the value is `nil`.
    ///
    /// - Returns: A validator for `Value?` that runs `self` only when a non-`nil` value is present.
    public func optional() -> SettingValidator<Value?> {
        SettingValidator<Value?> { maybeValue, context in
            guard let unwrapped = maybeValue else { return nil }
            return self.evaluator(unwrapped, context)
        }
    }

    /// Lifts this validator to ``Secret``, scrubbing any failure message through ``DiagnosticRedactor``.
    ///
    /// - Returns: A validator for `Secret<Value>` that validates the underlying secret without leaking plaintext.
    public func forSecret() -> SettingValidator<Secret<Value>> {
        SettingValidator<Secret<Value>> { secret, context in
            guard let reason = self.evaluator(secret.expose(), context) else {
                return nil
            }
            return context.redactor.scrub(reason)
        }
    }

    // MARK: - Custom Validators

    /// Creates a validator from a closure returning `nil` on success or an error message on failure.
    ///
    /// - Parameter check: Closure inspecting the decoded value.
    /// - Returns: A custom ``SettingValidator``.
    public static func custom(
        _ check: @escaping @Sendable (Value) -> String?
    ) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            check(value)
        }
    }

    /// Creates a validator from a context-aware closure returning `nil` on success or an error message on failure.
    ///
    /// - Parameter check: Closure inspecting the decoded value and ``SettingsContext``.
    /// - Returns: A custom ``SettingValidator``.
    public static func custom(
        _ check: @escaping @Sendable (Value, SettingsContext) -> String?
    ) -> SettingValidator<Value> {
        SettingValidator(check)
    }

    /// Creates a validator from a boolean predicate and a fixed failure message.
    ///
    /// - Parameters:
    ///   - message: Diagnostic message emitted when `predicate` returns `false`.
    ///   - predicate: Closure returning `true` when the value is valid.
    /// - Returns: A custom ``SettingValidator``.
    public static func custom(
        _ message: String,
        predicate: @escaping @Sendable (Value) -> Bool
    ) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            predicate(value) ? nil : message
        }
    }
}

// MARK: - Collection & String Length Validators

extension SettingValidator where Value: Collection {
    /// Requires a collection to contain at least one element, or a `String` to contain non-whitespace characters.
    public static var nonEmpty: SettingValidator<Value> {
        SettingValidator { value, _ in
            if let str = value as? String {
                return str.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? "Value must not be empty."
                    : nil
            }
            return value.isEmpty ? "Value must not be empty." : nil
        }
    }

    /// Requires `value.count` to be greater than or equal to `minimum`.
    ///
    /// - Parameter minimum: Minimum allowed element or character count.
    /// - Returns: A length-checking ``SettingValidator``.
    public static func minLength(_ minimum: Int) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            value.count >= minimum
                ? nil
                : "Length must be at least \(minimum) (got \(value.count))."
        }
    }

    /// Requires `value.count` to be less than or equal to `maximum`.
    ///
    /// - Parameter maximum: Maximum allowed element or character count.
    /// - Returns: A length-checking ``SettingValidator``.
    public static func maxLength(_ maximum: Int) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            value.count <= maximum
                ? nil
                : "Length must be at most \(maximum) (got \(value.count))."
        }
    }
}

// MARK: - Comparable Range Validators

extension SettingValidator where Value: Comparable {
    /// Requires `value` to fall within the inclusive `bounds` range.
    ///
    /// - Parameter bounds: Inclusive lower and upper bounds.
    /// - Returns: A range-checking ``SettingValidator``.
    public static func range(_ bounds: ClosedRange<Value>) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            bounds.contains(value)
                ? nil
                : "Value must be in range \(bounds.lowerBound)...\(bounds.upperBound)."
        }
    }

    /// Requires `value` to fall within the half-open `bounds` range.
    ///
    /// - Parameter bounds: Half-open lower and upper bounds.
    /// - Returns: A range-checking ``SettingValidator``.
    public static func range(_ bounds: Range<Value>) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            bounds.contains(value)
                ? nil
                : "Value must be in range \(bounds.lowerBound)..<\(bounds.upperBound)."
        }
    }
}

// MARK: - Membership Validators

extension SettingValidator where Value: Equatable {
    /// Requires `value` to equal one of the `allowed` candidates.
    ///
    /// - Parameter allowed: Permitted values.
    /// - Returns: A membership-checking ``SettingValidator``.
    public static func oneOf(_ allowed: [Value]) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            guard !allowed.contains(value) else { return nil }
            let rendered = allowed.map { String(describing: $0) }.joined(separator: ", ")
            return "Value must be one of [\(rendered)]."
        }
    }
}

// MARK: - String Validators (Regex, URL, File Exists)

extension SettingValidator where Value == String {
    /// Requires the string to match the regular expression `pattern`.
    ///
    /// - Parameters:
    ///   - pattern: ICU regular expression pattern evaluated via `NSRegularExpression`.
    ///   - message: Optional custom failure message overriding the default pattern diagnostic.
    /// - Returns: A regular-expression ``SettingValidator``.
    public static func regex(_ pattern: String, message: String? = nil) -> SettingValidator<String> {
        SettingValidator { value, _ in
            guard let regex = try? NSRegularExpression(pattern: pattern) else {
                return "Invalid regular expression pattern '\(pattern)'."
            }
            let nsRange = NSRange(value.startIndex..<value.endIndex, in: value)
            let matched = regex.firstMatch(in: value, options: [], range: nsRange) != nil
            if matched { return nil }
            return message ?? "Value does not match required pattern '\(pattern)'."
        }
    }

    /// Requires the string to parse as a valid URL with an allowed scheme and optional non-empty host.
    ///
    /// - Parameters:
    ///   - allowedSchemes: Permitted lowercase URL schemes (defaults to `["http", "https"]`), or `nil` to allow any scheme.
    ///   - requireHost: Whether non-`file` URLs must include a non-empty host component.
    /// - Returns: A URL-validating ``SettingValidator``.
    public static func url(
        allowedSchemes: Set<String>? = ["http", "https"],
        requireHost: Bool = true
    ) -> SettingValidator<String> {
        SettingValidator { value, _ in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  let components = URLComponents(string: trimmed),
                  let scheme = components.scheme?.lowercased() else {
                return "Value must be a valid URL."
            }
            if let allowedSchemes {
                let normalizedAllowed = Set(allowedSchemes.map { $0.lowercased() })
                if !normalizedAllowed.contains(scheme) {
                    let list = normalizedAllowed.sorted().joined(separator: ", ")
                    return "URL scheme '\(scheme)' is not allowed (expected one of: \(list))."
                }
            }
            if requireHost && scheme != "file" {
                guard let host = components.host, !host.isEmpty else {
                    return "URL must include a non-empty host."
                }
            }
            return nil
        }
    }

    /// Requires the path to exist in ``SettingsContext/fileSystem``, expanding leading `~` against ``SettingsContext/homeDirectory``.
    ///
    /// - Parameter mustBeDirectory: Pass `true` to require a directory, `false` to require a regular file,
    ///   or `nil` to accept either.
    /// - Returns: A filesystem-checking ``SettingValidator``.
    public static func fileExists(mustBeDirectory: Bool? = nil) -> SettingValidator<String> {
        SettingValidator { rawPath, context in
            let resolved = resolveFilesystemPath(rawPath, context: context)
            guard context.fileSystem.fileExists(atPath: resolved) else {
                return "Path does not exist at '\(resolved)'."
            }
            if let mustBeDirectory {
                let isDir = context.fileSystem.isDirectory(atPath: resolved)
                if mustBeDirectory && !isDir {
                    return "Expected a directory at '\(resolved)', found a file."
                }
                if !mustBeDirectory && isDir {
                    return "Expected a regular file at '\(resolved)', found a directory."
                }
            }
            return nil
        }
    }
}

// MARK: - URL Validators

extension SettingValidator where Value == URL {
    /// Requires the `URL` to specify an allowed scheme and optional non-empty host.
    ///
    /// - Parameters:
    ///   - allowedSchemes: Permitted lowercase URL schemes (defaults to `["http", "https"]`), or `nil` to allow any scheme.
    ///   - requireHost: Whether non-`file` URLs must include a non-empty host component.
    /// - Returns: A URL-validating ``SettingValidator``.
    public static func url(
        allowedSchemes: Set<String>? = ["http", "https"],
        requireHost: Bool = true
    ) -> SettingValidator<URL> {
        SettingValidator { urlValue, _ in
            guard let scheme = urlValue.scheme?.lowercased() else {
                return "URL must specify a scheme."
            }
            if let allowedSchemes {
                let normalizedAllowed = Set(allowedSchemes.map { $0.lowercased() })
                if !normalizedAllowed.contains(scheme) {
                    let list = normalizedAllowed.sorted().joined(separator: ", ")
                    return "URL scheme '\(scheme)' is not allowed (expected one of: \(list))."
                }
            }
            if requireHost && scheme != "file" {
                guard let host = urlValue.host(percentEncoded: false), !host.isEmpty else {
                    return "URL must include a non-empty host."
                }
            }
            return nil
        }
    }

    /// Requires the file URL path to exist in ``SettingsContext/fileSystem``.
    ///
    /// - Parameter mustBeDirectory: Pass `true` to require a directory, `false` to require a regular file,
    ///   or `nil` to accept either.
    /// - Returns: A filesystem-checking ``SettingValidator``.
    public static func fileExists(mustBeDirectory: Bool? = nil) -> SettingValidator<URL> {
        SettingValidator { urlValue, context in
            let path = urlValue.isFileURL ? urlValue.path(percentEncoded: false) : urlValue.path
            let resolved = resolveFilesystemPath(path, context: context)
            guard context.fileSystem.fileExists(atPath: resolved) else {
                return "Path does not exist at '\(resolved)'."
            }
            if let mustBeDirectory {
                let isDir = context.fileSystem.isDirectory(atPath: resolved)
                if mustBeDirectory && !isDir {
                    return "Expected a directory at '\(resolved)', found a file."
                }
                if !mustBeDirectory && isDir {
                    return "Expected a regular file at '\(resolved)', found a directory."
                }
            }
            return nil
        }
    }
}

private func resolveFilesystemPath(_ rawPath: String, context: SettingsContext) -> String {
    let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed == "~" {
        return context.homeDirectory
    }
    if trimmed.hasPrefix("~/") {
        let suffix = String(trimmed.dropFirst(2))
        return context.homeDirectory.hasSuffix("/")
            ? "\(context.homeDirectory)\(suffix)"
            : "\(context.homeDirectory)/\(suffix)"
    }
    if trimmed.hasPrefix("/") {
        return trimmed
    }
    return context.workingDirectory.hasSuffix("/")
        ? "\(context.workingDirectory)\(trimmed)"
        : "\(context.workingDirectory)/\(trimmed)"
}
