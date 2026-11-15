import Foundation
import RiggingCore

/// Actor-isolated in-memory `SecretProvider` for `"op"` (`1Password`) references that records
/// batch invocation counts so tests can assert single-batch resolution (`invocationCount == 1`).
///
/// ```swift
/// let mockOP = MockOnePasswordProvider(secrets: [
///     "op://Eng/API/token": "test-token-value",
/// ])
/// let context = SettingsContext.inMemory(secretProviders: [mockOP])
/// ```
public actor MockOnePasswordProvider: SecretProvider {
    /// URI schemes handled by this mock provider (`["op"]`).
    public nonisolated let supportedSchemes: Set<String> = ["op"]

    /// Number of ``resolveBatch(_:context:)`` calls executed against this mock provider.
    public private(set) var invocationCount: Int = 0

    /// Exact batches of `SecretReference` items passed to each ``resolveBatch(_:context:)`` invocation.
    public private(set) var batchHistory: [[SecretReference]] = []

    private var secretsByParsedRef: [SecretReference: Data] = [:]
    private var secretsByRawKey: [String: Data] = [:]
    private var forcedFailure: (any Error)?

    /// Creates a mock 1Password provider seeded with UTF-8 string secrets keyed by `op://...` URI.
    ///
    /// - Parameter secrets: Dictionary mapping `op://Vault/Item/[Section/]field` URIs to plaintext values.
    public init(secrets: [String: String] = [:]) {
        for (uri, value) in secrets {
            Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a mock 1Password provider seeded with raw binary `Data` secrets keyed by `op://...` URI.
    ///
    /// - Parameter binarySecrets: Dictionary mapping `op://...` URIs to raw `Data` payloads.
    public init(binarySecrets: [String: Data]) {
        for (uri, data) in binarySecrets {
            Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a mock 1Password provider that throws `error` on every batch invocation.
    ///
    /// - Parameter error: Error thrown whenever ``resolveBatch(_:context:)`` is called.
    public init(failingWith error: any Error) {
        self.forcedFailure = error
    }

    /// Inserts or updates a UTF-8 secret value for `uri`.
    ///
    /// - Parameters:
    ///   - value: Plaintext secret string to return.
    ///   - uri: Target `op://...` URI.
    public func setSecret(_ value: String, for uri: String) {
        Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Inserts or updates a binary secret value for `uri`.
    ///
    /// - Parameters:
    ///   - data: Raw secret bytes to return.
    ///   - uri: Target `op://...` URI.
    public func setBinarySecret(_ data: Data, for uri: String) {
        Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Configures an error to throw on subsequent ``resolveBatch(_:context:)`` calls, or passes `nil` to clear.
    ///
    /// - Parameter error: Forced error to throw, or `nil` to resume normal secret lookup.
    public func setFailure(_ error: (any Error)?) {
        self.forcedFailure = error
    }

    /// Resets ``invocationCount`` and ``batchHistory`` back to empty without clearing stored secrets.
    public func resetHistory() {
        invocationCount = 0
        batchHistory.removeAll()
    }

    /// Resolves a batch of `op://` secret references in memory and records the batch in ``batchHistory``.
    ///
    /// - Parameters:
    ///   - references: Deduplicated `SecretReference` items routed to `"op"`.
    ///   - context: Active `SettingsContext`.
    /// - Returns: Resolved secret `Data` payloads keyed by `SecretReference`.
    /// - Throws: `SecretResolutionError.itemNotFound`, `SecretBatchPartialFailureError`, or the configured forced failure.
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
/// batch invocation counts without touching the host login Keychain.
///
/// ```swift
/// let mockKeychain = MockKeychainProvider(secrets: [
///     "keychain://com.example.app/api-token": "local-dev-token",
/// ])
/// ```
public actor MockKeychainProvider: SecretProvider {
    /// URI schemes handled by this mock provider (`["keychain"]`).
    public nonisolated let supportedSchemes: Set<String> = ["keychain"]

    /// Number of ``resolveBatch(_:context:)`` calls executed against this mock provider.
    public private(set) var invocationCount: Int = 0

    /// Exact batches of `SecretReference` items passed to each ``resolveBatch(_:context:)`` invocation.
    public private(set) var batchHistory: [[SecretReference]] = []

    private var secretsByParsedRef: [SecretReference: Data] = [:]
    private var secretsByRawKey: [String: Data] = [:]
    private var forcedFailure: (any Error)?

    /// Creates a mock Keychain provider seeded with UTF-8 string secrets keyed by `keychain://<service>/<account>` (or `<service>/<account>`).
    ///
    /// - Parameter secrets: Dictionary mapping `keychain://...` URIs to plaintext secret strings.
    public init(secrets: [String: String] = [:]) {
        for (uri, value) in secrets {
            Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a mock Keychain provider seeded with raw binary `Data` secrets keyed by `keychain://<service>/<account>` (or `<service>/<account>`).
    ///
    /// - Parameter binarySecrets: Dictionary mapping `keychain://...` URIs to raw `Data` payloads.
    public init(binarySecrets: [String: Data]) {
        for (uri, data) in binarySecrets {
            Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a mock Keychain provider that throws `error` on every batch invocation.
    ///
    /// - Parameter error: Error thrown whenever ``resolveBatch(_:context:)`` is called.
    public init(failingWith error: any Error) {
        self.forcedFailure = error
    }

    /// Inserts or updates a UTF-8 secret value for `uri`.
    ///
    /// - Parameters:
    ///   - value: Plaintext secret string to return.
    ///   - uri: Target `keychain://...` URI.
    public func setSecret(_ value: String, for uri: String) {
        Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Inserts or updates a binary secret value for `uri`.
    ///
    /// - Parameters:
    ///   - data: Raw secret bytes to return.
    ///   - uri: Target `keychain://...` URI.
    public func setBinarySecret(_ data: Data, for uri: String) {
        Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Configures an error to throw on subsequent ``resolveBatch(_:context:)`` calls, or passes `nil` to clear.
    ///
    /// - Parameter error: Forced error to throw, or `nil` to resume normal secret lookup.
    public func setFailure(_ error: (any Error)?) {
        self.forcedFailure = error
    }

    /// Resets ``invocationCount`` and ``batchHistory`` back to empty without clearing stored secrets.
    public func resetHistory() {
        invocationCount = 0
        batchHistory.removeAll()
    }

    /// Resolves a batch of `keychain://` secret references in memory and records the batch in ``batchHistory``.
    ///
    /// - Parameters:
    ///   - references: Deduplicated `SecretReference` items routed to `"keychain"`.
    ///   - context: Active `SettingsContext`.
    /// - Returns: Resolved secret `Data` payloads keyed by `SecretReference`.
    /// - Throws: `SecretResolutionError.itemNotFound`, `SecretBatchPartialFailureError`, or the configured forced failure.
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

/// Actor-isolated in-memory `SecretProvider` configurable for any custom or built-in URI schemes
/// (such as `["bws", "bw"]`, `["pass"]`, or `["vault"]`).
///
/// ```swift
/// let mockPass = MockSecretProvider(
///     schemes: ["pass"],
///     secrets: ["pass://infra/prod/db-password": "super-secret-password"]
/// )
/// ```
public actor MockSecretProvider: SecretProvider {
    /// Lowercased URI schemes handled by this mock provider.
    public nonisolated let supportedSchemes: Set<String>

    /// Number of ``resolveBatch(_:context:)`` calls executed against this mock provider.
    public private(set) var invocationCount: Int = 0

    /// Exact batches of `SecretReference` items passed to each ``resolveBatch(_:context:)`` invocation.
    public private(set) var batchHistory: [[SecretReference]] = []

    private var secretsByParsedRef: [SecretReference: Data] = [:]
    private var secretsByRawKey: [String: Data] = [:]
    private var forcedFailure: (any Error)?

    /// Creates a scheme-configurable mock secret provider seeded with UTF-8 string secrets.
    ///
    /// - Parameters:
    ///   - schemes: URI schemes handled by this provider (for example, `["bws", "bw"]` or `["pass"]`).
    ///   - secrets: Dictionary mapping full `<scheme>://...` URIs to plaintext secret strings.
    public init(schemes: Set<String>, secrets: [String: String] = [:]) {
        self.supportedSchemes = Set(schemes.map { $0.lowercased() })
        for (uri, value) in secrets {
            Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a scheme-configurable mock secret provider seeded with raw binary `Data` secrets.
    ///
    /// - Parameters:
    ///   - schemes: URI schemes handled by this provider.
    ///   - binarySecrets: Dictionary mapping full `<scheme>://...` URIs to raw `Data` payloads.
    public init(schemes: Set<String>, binarySecrets: [String: Data]) {
        self.supportedSchemes = Set(schemes.map { $0.lowercased() })
        for (uri, data) in binarySecrets {
            Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
        }
    }

    /// Creates a scheme-configurable mock secret provider that throws `error` on every batch invocation.
    ///
    /// - Parameters:
    ///   - schemes: URI schemes handled by this provider.
    ///   - error: Error thrown whenever ``resolveBatch(_:context:)`` is called.
    public init(schemes: Set<String>, failingWith error: any Error) {
        self.supportedSchemes = Set(schemes.map { $0.lowercased() })
        self.forcedFailure = error
    }

    /// Inserts or updates a UTF-8 secret value for `uri`.
    ///
    /// - Parameters:
    ///   - value: Plaintext secret string to return.
    ///   - uri: Full `<scheme>://...` URI.
    public func setSecret(_ value: String, for uri: String) {
        Self.storeEntry(Data(value.utf8), for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Inserts or updates a binary secret value for `uri`.
    ///
    /// - Parameters:
    ///   - data: Raw secret bytes to return.
    ///   - uri: Full `<scheme>://...` URI.
    public func setBinarySecret(_ data: Data, for uri: String) {
        Self.storeEntry(data, for: uri, into: &secretsByParsedRef, rawMap: &secretsByRawKey)
    }

    /// Configures an error to throw on subsequent ``resolveBatch(_:context:)`` calls, or passes `nil` to clear.
    ///
    /// - Parameter error: Forced error to throw, or `nil` to resume normal secret lookup.
    public func setFailure(_ error: (any Error)?) {
        self.forcedFailure = error
    }

    /// Resets ``invocationCount`` and ``batchHistory`` back to empty without clearing stored secrets.
    public func resetHistory() {
        invocationCount = 0
        batchHistory.removeAll()
    }

    /// Resolves a batch of secret references matching ``supportedSchemes`` in memory.
    ///
    /// - Parameters:
    ///   - references: Deduplicated `SecretReference` items routed to this provider.
    ///   - context: Active `SettingsContext`.
    /// - Returns: Resolved secret `Data` payloads keyed by `SecretReference`.
    /// - Throws: `SecretResolutionError.itemNotFound`, `SecretBatchPartialFailureError`, or the configured forced failure.
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
            if let exact = secretsByParsedRef[reference] ?? secretsByRawKey[reference.redactedDescription] {
                resolved[reference] = exact
            } else {
                let err = SecretResolutionError.itemNotFound(
                    scheme: reference.scheme,
                    referenceRedacted: reference.redactedDescription,
                    message: "Mock secret not registered in MockSecretProvider."
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

    private static func storeEntry(
        _ data: Data,
        for uri: String,
        into parsedMap: inout [SecretReference: Data],
        rawMap: inout [String: Data]
    ) {
        rawMap[uri] = data
        if let parsed = try? SecretReference.parse(uri) {
            parsedMap[parsed] = data
            rawMap[parsed.redactedDescription] = data
        }
    }
}
