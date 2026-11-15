import Foundation

/// Built-in ``SecretProvider`` resolving indirect `env://<VAR_NAME>` references from ``SettingsContext/environment``.
///
/// Use `env://` references inside JSON or `.env` configuration files (for example,
/// `"apiKey": "env://PROD_API_KEY"`) to delegate secret lookup to a process environment variable
/// without committing literal secret material to version control.
///
/// ```swift
/// let provider = IndirectEnvProvider()
/// ```
public struct IndirectEnvProvider: SecretProvider, Sendable {
    /// Supported URI schemes (`["env"]`).
    public let supportedSchemes: Set<String> = ["env"]

    /// Whether an empty string (`""`) is accepted instead of throwing ``SecretResolutionError/environmentVariableNotSet(variableName:)``.
    public let allowEmptyValue: Bool

    /// Creates an indirect environment-variable secret provider.
    ///
    /// - Parameter allowEmptyValue: Pass `true` to accept empty environment variable values; defaults to `false`.
    public init(allowEmptyValue: Bool = false) {
        self.allowEmptyValue = allowEmptyValue
    }

    /// Resolves a batch of `env://` secret references against ``SettingsContext/environment``.
    ///
    /// - Parameters:
    ///   - references: Deduplicated ``SecretReference`` items to look up.
    ///   - context: Execution context providing the environment dictionary and ``DiagnosticRedactor``.
    /// - Returns: Dictionary mapping each resolved ``SecretReference`` to UTF-8 `Data`.
    /// - Throws: ``SecretResolutionError/environmentVariableNotSet(variableName:)`` or ``SecretBatchPartialFailureError``.
    public func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        var resolved: [SecretReference: Data] = [:]
        var failures: [SecretReference: any Error] = [:]
        resolved.reserveCapacity(references.count)

        for reference in references {
            guard case .env(let envRef) = reference else {
                continue
            }
            guard let rawValue = context.environment[envRef.variableName] else {
                let error = SecretResolutionError.environmentVariableNotSet(
                    variableName: envRef.variableName
                )
                if references.count == 1 { throw error }
                failures[reference] = error
                continue
            }
            if !allowEmptyValue && rawValue.isEmpty {
                let error = SecretResolutionError.environmentVariableNotSet(
                    variableName: envRef.variableName
                )
                if references.count == 1 { throw error }
                failures[reference] = error
                continue
            }
            let bytes = Data(rawValue.utf8)
            context.redactor.register(rawValue)
            resolved[reference] = bytes
        }

        if !failures.isEmpty {
            if resolved.isEmpty, failures.count == 1, let singleError = failures.values.first {
                throw singleError
            }
            throw SecretBatchPartialFailureError(resolved: resolved, failures: failures)
        }

        return resolved
    }
}

extension SecretProvider where Self == IndirectEnvProvider {
    /// Creates an indirect environment-variable ``IndirectEnvProvider``.
    ///
    /// - Parameter allowEmptyValue: Whether empty environment variable strings are accepted.
    /// - Returns: Configured ``IndirectEnvProvider``.
    public static func env(allowEmptyValue: Bool = false) -> IndirectEnvProvider {
        IndirectEnvProvider(allowEmptyValue: allowEmptyValue)
    }
}
