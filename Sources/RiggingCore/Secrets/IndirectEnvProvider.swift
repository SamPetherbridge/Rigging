import Foundation

/// Built-in `SecretProvider` resolving indirect `env://<VAR_NAME>` references against `SettingsContext.environment`.
///
/// Useful when a configuration file (such as `.asc.json` or `~/.config/app/config.json`) delegates secret lookup
/// to a named environment variable (`"apiKey": "env://PROD_API_KEY"`).
public struct IndirectEnvProvider: SecretProvider, Sendable {
    public let supportedSchemes: Set<String> = ["env"]
    public let allowEmptyValue: Bool

    public init(allowEmptyValue: Bool = false) {
        self.allowEmptyValue = allowEmptyValue
    }

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
    public static func env(allowEmptyValue: Bool = false) -> IndirectEnvProvider {
        IndirectEnvProvider(allowEmptyValue: allowEmptyValue)
    }
}
