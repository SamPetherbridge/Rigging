import Foundation
import RiggingCore

/// Actor-isolated in-memory `SecretProvider` for `"op"` (`1Password`) references that records
/// batch invocation counts so tests can assert single-batch resolution (`invocationCount == 1`).
public actor MockOnePasswordProvider: SecretProvider {
    public nonisolated let supportedSchemes: Set<String> = ["op"]

    /// Number of `resolveBatch(_:context:)` calls executed against this mock provider.
    public private(set) var invocationCount: Int = 0

    /// Exact batches of `SecretReference` items passed to each `resolveBatch(_:context:)` invocation.
    public private(set) var batchHistory: [[SecretReference]] = []

    private var secretsByParsedRef: [SecretReference: Data] = [:]
    private var secretsByRawKey: [String: Data] = [:]
    private var forcedFailure: (any Error)?

    /// Creates a mock 1Password provider seeded with UTF-8 string secrets keyed by `op://...` URI.
    public init(secrets: [String: String] = [:]) {
        for (uri, value) in secrets {
            Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a mock 1Password provider seeded with raw binary `Data` secrets keyed by `op://...` URI.
    public init(binarySecrets: [String: Data]) {
        for (uri, data) in binarySecrets {
            Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a mock 1Password provider that throws `error` on every batch invocation.
    public init(failingWith error: any Error) {
        self.forcedFailure = error
    }

    /// Inserts or updates a UTF-8 secret value for `uri`.
    public func setSecret(_ value: String, for uri: String) {
        Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Inserts or updates a binary secret value for `uri`.
    public func setBinarySecret(_ data: Data, for uri: String) {
        Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Configures an error to throw on subsequent `resolveBatch` calls (or `nil` to clear).
    public func setFailure(_ error: (any Error)?) {
        self.forcedFailure = error
    }

    /// Resets `invocationCount` and `batchHistory` back to empty without clearing stored secrets.
    public func resetHistory() {
        invocationCount = 0
        batchHistory.removeAll()
    }

    public func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        invocationCount += 1
        batchHistory.append(references)

        if let forcedFailure {
            throw forcedFailure
        }

        var resolved: [SecretReference: Data] = [:]
        var failures: [SecretReference: any Error] = [:]

        for reference in references {
            if let data = lookup(reference) {
                resolved[reference] = data
            } else {
                let err = SecretResolutionError.itemNotFound(
                    scheme: "op",
                    referenceRedacted: reference.redactedDescription,
                    message: "Mock secret not registered in MockOnePasswordProvider."
                )
                if references.count == 1 {
                    throw err
                }
                failures[reference] = err
            }
        }

        if !failures.isEmpty {
            if resolved.isEmpty, failures.count == 1, let single = failures.values.first {
                throw single
            }
            throw SecretBatchPartialFailureError(resolved: resolved, failures: failures)
        }

        return resolved
    }

    private func lookup(_ reference: SecretReference) -> Data? {
        if let exact = secretsByParsedRef[reference] {
            return exact
        }
        if let byRedacted = secretsByRawKey[reference.redactedDescription] {
            return byRedacted
        }
        if case .onePassword(let opRef) = reference {
            if let byReadURI = secretsByRawKey[opRef.opReadURI] {
                return byReadURI
            }
            // Fallback when secret was registered without ?account=... query items
            let baseRef = SecretReference.onePassword(
                OnePasswordSecretReference(
                    vault: opRef.vault,
                    item: opRef.item,
                    section: opRef.section,
                    field: opRef.field
                )
            )
            if let baseMatch = secretsByParsedRef[baseRef] {
                return baseMatch
            }
        }
        return nil
    }

    private static func storeEntry(
        _ data: Data,
        for uri: String,
        into parsedMap: inout [SecretReference: Data],
        rawMap: inout [String: Data]
    ) {
        let normalizedKey = uri.hasPrefix("op://") ? uri : "op://\(uri)"
        rawMap[uri] = data
        rawMap[normalizedKey] = data
        if let parsed = try? SecretReference.parse(normalizedKey) {
            parsedMap[parsed] = data
            rawMap[parsed.redactedDescription] = data
            if case .onePassword(let opRef) = parsed {
                rawMap[opRef.opReadURI] = data
            }
        }
    }
}

/// Actor-isolated in-memory `SecretProvider` for `"keychain"` references that records
/// batch invocation counts without touching the host's login Keychain.
public actor MockKeychainProvider: SecretProvider {
    public nonisolated let supportedSchemes: Set<String> = ["keychain"]

    /// Number of `resolveBatch(_:context:)` calls executed against this mock provider.
    public private(set) var invocationCount: Int = 0

    /// Exact batches of `SecretReference` items passed to each `resolveBatch(_:context:)` invocation.
    public private(set) var batchHistory: [[SecretReference]] = []

    private var secretsByParsedRef: [SecretReference: Data] = [:]
    private var secretsByRawKey: [String: Data] = [:]
    private var forcedFailure: (any Error)?

    /// Creates a mock Keychain provider seeded with UTF-8 string secrets keyed by `keychain://<service>/<account>` (or `<service>/<account>`).
    public init(secrets: [String: String] = [:]) {
        for (uri, value) in secrets {
            Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a mock Keychain provider seeded with raw binary `Data` secrets keyed by `keychain://<service>/<account>` (or `<service>/<account>`).
    public init(binarySecrets: [String: Data]) {
        for (uri, data) in binarySecrets {
            Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a mock Keychain provider that throws `error` on every batch invocation.
    public init(failingWith error: any Error) {
        self.forcedFailure = error
    }

    /// Inserts or updates a UTF-8 secret value for `uri`.
    public func setSecret(_ value: String, for uri: String) {
        Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Inserts or updates a binary secret value for `uri`.
    public func setBinarySecret(_ data: Data, for uri: String) {
        Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Configures an error to throw on subsequent `resolveBatch` calls (or `nil` to clear).
    public func setFailure(_ error: (any Error)?) {
        self.forcedFailure = error
    }

    /// Resets `invocationCount` and `batchHistory` back to empty without clearing stored secrets.
    public func resetHistory() {
        invocationCount = 0
        batchHistory.removeAll()
    }

    public func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        invocationCount += 1
        batchHistory.append(references)

        if let forcedFailure {
            throw forcedFailure
        }

        var resolved: [SecretReference: Data] = [:]
        var failures: [SecretReference: any Error] = [:]

        for reference in references {
            if let data = lookup(reference) {
                resolved[reference] = data
            } else {
                let err = SecretResolutionError.itemNotFound(
                    scheme: "keychain",
                    referenceRedacted: reference.redactedDescription,
                    message: "Mock secret not registered in MockKeychainProvider."
                )
                if references.count == 1 {
                    throw err
                }
                failures[reference] = err
            }
        }

        if !failures.isEmpty {
            if resolved.isEmpty, failures.count == 1, let single = failures.values.first {
                throw single
            }
            throw SecretBatchPartialFailureError(resolved: resolved, failures: failures)
        }

        return resolved
    }

    private func lookup(_ reference: SecretReference) -> Data? {
        if let exact = secretsByParsedRef[reference] {
            return exact
        }
        if let byRedacted = secretsByRawKey[reference.redactedDescription] {
            return byRedacted
        }
        if case .keychain(let kcRef) = reference {
            let baseRef = SecretReference.keychain(
                KeychainSecretReference(service: kcRef.service, account: kcRef.account)
            )
            if let baseMatch = secretsByParsedRef[baseRef] {
                return baseMatch
            }
            if let slashKey = secretsByRawKey["\(kcRef.service)/\(kcRef.account)"] {
                return slashKey
            }
        }
        return nil
    }

    private static func storeEntry(
        _ data: Data,
        for uri: String,
        into parsedMap: inout [SecretReference: Data],
        rawMap: inout [String: Data]
    ) {
        let normalizedKey = uri.hasPrefix("keychain://") ? uri : "keychain://\(uri)"
        rawMap[uri] = data
        rawMap[normalizedKey] = data
        if let parsed = try? SecretReference.parse(normalizedKey) {
            parsedMap[parsed] = data
            rawMap[parsed.redactedDescription] = data
        }
    }
}
