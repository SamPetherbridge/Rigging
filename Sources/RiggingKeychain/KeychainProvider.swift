import Foundation
import RiggingCore
#if canImport(Security)
import Security
#endif

/// Password item class supported by `KeychainProvider`.
public enum KeychainPasswordKind: String, Sendable, Equatable, Hashable {
    case generic
    case internet
}

#if canImport(Security)
/// Result returned by a `KeychainProvider` lookup backend.
public struct KeychainBackendResponse: Sendable, Equatable {
    public let status: OSStatus
    public let data: Data?

    public init(status: OSStatus, data: Data? = nil) {
        self.status = status
        self.data = data
    }
}
#endif

/// Native Apple `Security.framework` Keychain secret provider (`keychain://<service>/<account>`).
///
/// On Apple platforms (`canImport(Security)`), lookups invoke `SecItemCopyMatching` directly in-process
/// with zero subprocess execution. On non-Apple platforms (e.g. Linux), this module compiles cleanly and
/// emits a structured `SecretResolutionError.providerFailed` (`exitCode = 6`).
public struct KeychainProvider: SecretProvider, Sendable {
    public let supportedSchemes: Set<String> = ["keychain"]

    /// Optional default Keychain access group (`kSecAttrAccessGroup`) used when the URI omits `?accessGroup=...`.
    public let defaultAccessGroup: String?

    /// Optional default iCloud Keychain synchronizable filter (`kSecAttrSynchronizable`) used when the URI omits `?synchronizable=...`.
    public let defaultSynchronizable: Bool?

    #if canImport(Security)
    /// Injectable synchronous lookup closure enabling deterministic, hermetic unit tests without touching the login Keychain.
    public typealias Backend = @Sendable ([String: Any]) -> KeychainBackendResponse

    private let backend: Backend

    /// Production backend invoking `Security.SecItemCopyMatching` directly.
    public static let systemBackend: Backend = { query in
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return KeychainBackendResponse(status: status, data: item as? Data)
    }

    public init(
        accessGroup: String? = nil,
        synchronizable: Bool? = nil,
        backend: @escaping Backend = KeychainProvider.systemBackend
    ) {
        self.defaultAccessGroup = accessGroup
        self.defaultSynchronizable = synchronizable
        self.backend = backend
    }
    #else
    public init(
        accessGroup: String? = nil,
        synchronizable: Bool? = nil
    ) {
        self.defaultAccessGroup = accessGroup
        self.defaultSynchronizable = synchronizable
    }
    #endif

    public func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        guard !references.isEmpty else { return [:] }

        #if canImport(Security)
        var resolved: [SecretReference: Data] = [:]
        var failures: [SecretReference: any Error] = [:]
        resolved.reserveCapacity(references.count)

        for reference in references {
            guard case .keychain(let keychainRef) = reference else {
                continue
            }
            if resolved[reference] != nil {
                continue
            }

            do {
                let query = try Self.buildSecItemQuery(
                    for: keychainRef,
                    defaultAccessGroup: defaultAccessGroup,
                    defaultSynchronizable: defaultSynchronizable
                )
                let response = backend(query)
                let secretBytes = try Self.unwrapResponse(response, for: reference)
                context.redactor.register(secretBytes)
                resolved[reference] = secretBytes
            } catch {
                if references.count == 1 {
                    throw error
                }
                failures[reference] = error
            }
        }

        if !failures.isEmpty {
            if resolved.isEmpty, failures.count == 1, let singleError = failures.values.first {
                throw singleError
            }
            throw SecretBatchPartialFailureError(resolved: resolved, failures: failures)
        }

        return resolved
        #else
        throw SecretResolutionError.providerFailed(
            scheme: "keychain",
            message: "Security.framework Keychain is only available on Apple platforms.",
            remediation: "Use 'op://', 'bws://', 'pass://', 'sops://', 'env://', or 'file://' on Linux."
        )
        #endif
    }

    #if canImport(Security)
    /// Builds the `SecItemCopyMatching` query dictionary for a `KeychainSecretReference`.
    public static func buildSecItemQuery(
        for reference: KeychainSecretReference,
        defaultAccessGroup: String? = nil,
        defaultSynchronizable: Bool? = nil
    ) throws -> [String: Any] {
        try validateSegment(reference.service, name: "service")
        try validateSegment(reference.account, name: "account")

        let kind = try parseKind(from: reference)

        var query: [String: Any] = [
            kSecAttrAccount as String: reference.account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne as String,
        ]

        switch kind {
        case .generic:
            query[kSecClass as String] = kSecClassGenericPassword as String
            query[kSecAttrService as String] = reference.service
        case .internet:
            query[kSecClass as String] = kSecClassInternetPassword as String
            query[kSecAttrServer as String] = reference.service
        }

        if let effectiveAccessGroup = reference.accessGroup ?? defaultAccessGroup,
           !effectiveAccessGroup.isEmpty {
            try validateSegment(effectiveAccessGroup, name: "accessGroup")
            query[kSecAttrAccessGroup as String] = effectiveAccessGroup
        }

        if let effectiveSynchronizable = reference.synchronizable ?? defaultSynchronizable {
            query[kSecAttrSynchronizable as String] = effectiveSynchronizable
        }

        return query
    }

    private static func parseKind(from reference: KeychainSecretReference) throws -> KeychainPasswordKind {
        guard let rawKind = reference.queryItems.last(where: { $0.name == "kind" })?.value else {
            if reference.queryItems.contains(where: { $0.name == "kind" }) {
                throw SecretResolutionError.invalidReference(
                    .invalidQueryParameter(scheme: "keychain", name: "kind", value: "")
                )
            }
            return .generic
        }

        switch rawKind.lowercased() {
        case "generic":
            return .generic
        case "internet":
            return .internet
        default:
            throw SecretResolutionError.invalidReference(
                .invalidQueryParameter(scheme: "keychain", name: "kind", value: rawKind)
            )
        }
    }

    private static func validateSegment(_ value: String, name: String) throws {
        if value.utf8.contains(0) {
            throw SecretResolutionError.invalidReference(.containsNullByte)
        }
        guard !value.isEmpty else {
            throw SecretResolutionError.invalidReference(
                .invalidFormat(scheme: "keychain", message: "Keychain '\(name)' must not be empty.")
            )
        }
        if value.hasPrefix("-") {
            throw SecretResolutionError.invalidReference(
                .optionInjection(scheme: "keychain", segment: value)
            )
        }
        for scalar in value.unicodeScalars where scalar.value < 0x20 || scalar.value == 0x7F {
            throw SecretResolutionError.invalidReference(.containsControlCharacter(scheme: "keychain"))
        }
    }

    private static func unwrapResponse(
        _ response: KeychainBackendResponse,
        for reference: SecretReference
    ) throws -> Data {
        switch response.status {
        case errSecSuccess:
            guard let data = response.data else {
                throw SecretResolutionError.providerFailed(
                    scheme: "keychain",
                    message: "Keychain item '\(reference.redactedDescription)' did not return raw secret bytes."
                )
            }
            return data

        case errSecItemNotFound:
            throw SecretResolutionError.itemNotFound(
                scheme: "keychain",
                referenceRedacted: reference.redactedDescription,
                message: "Item not found in Apple Keychain (OSStatus \(response.status))."
            )

        case errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed:
            throw SecretResolutionError.authenticationFailed(
                scheme: "keychain",
                message: "Keychain access denied or interaction disallowed for '\(reference.redactedDescription)' (OSStatus \(response.status)).",
                remediation: "Unlock the Keychain or allow access to this item in Keychain Access."
            )

        default:
            throw SecretResolutionError.providerFailed(
                scheme: "keychain",
                message: "SecItemCopyMatching failed for '\(reference.redactedDescription)' with OSStatus \(response.status).",
                remediation: "Verify the Keychain service, account, and accessGroup attributes."
            )
        }
    }
    #endif
}

extension SecretProvider where Self == KeychainProvider {
    /// Native Apple `Security.framework` Keychain secret provider (`keychain://<service>/<account>`).
    public static func keychain(
        accessGroup: String? = nil,
        synchronizable: Bool? = nil
    ) -> KeychainProvider {
        KeychainProvider(accessGroup: accessGroup, synchronizable: synchronizable)
    }
}
