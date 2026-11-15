import Foundation

/// Composable, `Sendable` field-level validator evaluated after typed decoding.
public struct SettingValidator<Value: Sendable>: Sendable {
    private let evaluator: @Sendable (Value, SettingsContext) -> String?

    public init(_ evaluator: @escaping @Sendable (Value, SettingsContext) -> String?) {
        self.evaluator = evaluator
    }

    /// Evaluates `value`, returning `nil` if valid or a human-readable failure reason if invalid.
    public func validate(
        _ value: Value,
        context: SettingsContext = SettingsContext()
    ) -> String? {
        evaluator(value, context)
    }

    /// Evaluates `value` and wraps any failure in a structured `ValidationIssue`.
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
            message: failureReason,
            origin: origin,
            expectedType: String(describing: Value.self),
            envVariableHint: envVariableHint
        )
    }

    /// Lifts a `SettingValidator<Value>` to `Optional<Value>`, succeeding when the value is `nil`.
    public func optional() -> SettingValidator<Value?> {
        SettingValidator<Value?> { maybeValue, context in
            guard let unwrapped = maybeValue else { return nil }
            return self.evaluator(unwrapped, context)
        }
    }

    /// Lifts a `SettingValidator<Value>` to `Secret<Value>`, validating the underlying secret
    /// without including plaintext in failure messages.
    public func forSecret() -> SettingValidator<Secret<Value>> {
        SettingValidator<Secret<Value>> { secret, context in
            guard let reason = self.evaluator(secret.expose(), context) else {
                return nil
            }
            return context.redactor.scrub(reason)
        }
    }

    // MARK: - Custom Validators

    /// Validates using a closure returning `nil` on success or an error description on failure.
    public static func custom(
        _ check: @escaping @Sendable (Value) -> String?
    ) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            check(value)
        }
    }

    /// Validates using a context-aware closure returning `nil` on success or an error description on failure.
    public static func custom(
        _ check: @escaping @Sendable (Value, SettingsContext) -> String?
    ) -> SettingValidator<Value> {
        SettingValidator(check)
    }

    /// Validates using a boolean predicate and fixed error message.
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
    /// Requires the collection or string to contain at least one element/character.
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

    /// Requires `value.count >= minimum`.
    public static func minLength(_ minimum: Int) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            value.count >= minimum
                ? nil
                : "Length must be at least \(minimum) (got \(value.count))."
        }
    }

    /// Requires `value.count <= maximum`.
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
    /// Requires `bounds.contains(value)`.
    public static func range(_ bounds: ClosedRange<Value>) -> SettingValidator<Value> {
        SettingValidator { value, _ in
            bounds.contains(value)
                ? nil
                : "Value must be in range \(bounds.lowerBound)...\(bounds.upperBound)."
        }
    }

    /// Requires `bounds.contains(value)`.
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
    /// Requires `value` to equal one of `allowed`.
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
    /// Requires the entire string (or match) to satisfy regular expression `pattern`.
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

    /// Requires `value` to parse as a URL with an allowed scheme (default `["http", "https"]`).
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

    /// Requires the path to exist in `context.fileSystem`.
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
    /// Requires `url` to have an allowed scheme and optional host.
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

    /// Requires the file URL path to exist in `context.fileSystem`.
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
