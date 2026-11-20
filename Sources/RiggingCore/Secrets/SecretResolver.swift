import Foundation

// MARK: - SecretProvider Protocol

/// A pluggable secret-manager backend capable of resolving deduplicated batches of ``SecretReference`` values.
///
/// ``SecretResolver`` partitions all secret references across a configuration load by `(scheme, accountHint)`
/// and invokes ``resolveBatch(_:context:)`` at most once per partition so external CLIs (`op`, `bws`, `bw`, `pass`)
/// authenticate and execute in a single round-trip.
///
/// ```swift
/// struct VaultSecretProvider: SecretProvider {
///     let supportedSchemes: Set<String> = ["vault"]
///
///     func resolveBatch(
///         _ references: [SecretReference],
///         context: SettingsContext
///     ) async throws -> [SecretReference: Data] {
///         // Fetch all requested references in one call...
///         [:]
///     }
/// }
/// ```
public protocol SecretProvider: Sendable {
    /// Lowercase URI schemes handled by this provider (for example, `["op"]`, `["keychain"]`, or `["bws", "bw"]`).
    var supportedSchemes: Set<String> { get }

    /// Resolves a deduplicated batch of ``SecretReference`` items sharing a scheme and ``SecretReference/accountHint``.
    ///
    /// - Parameters:
    ///   - references: Unique secret references to fetch.
    ///   - context: Execution context providing filesystem, subprocess runner, environment, and ``DiagnosticRedactor``.
    /// - Returns: Dictionary mapping each resolved ``SecretReference`` to its raw secret `Data`.
    /// - Throws: ``SecretResolutionError`` when the entire batch fails, or ``SecretBatchPartialFailureError``
    ///   when a subset of references succeeded while others failed.
    func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data]
}

/// Thrown by a ``SecretProvider`` when a subset of items in a multi-reference batch resolved while others failed.
///
///Throwing `SecretBatchPartialFailureError` allows ``SecretResolver`` to preserve resolved sibling secrets
/// and attribute exact per-field errors without failing the entire batch identically.
public struct SecretBatchPartialFailureError: Error, Sendable, CustomStringConvertible, LocalizedError {
    /// Successfully resolved references and their secret byte payloads.
    public let resolved: [SecretReference: Data]

    /// Per-reference errors for items in the batch that failed to resolve.
    public let failures: [SecretReference: any Error]

    /// Creates a partial batch failure report.
    ///
    /// - Parameters:
    ///   - resolved: References that resolved successfully.
    ///   - failures: References that failed, mapped to their individual errors.
    public init(resolved: [SecretReference: Data], failures: [SecretReference: any Error]) {
        self.resolved = resolved
        self.failures = failures
    }

    /// Redacted summary of resolved vs. failed secret references in the batch.
    public var description: String {
        let details = failures
            .map { "\($0.key.redactedDescription): \($0.value.localizedDescription)" }
            .sorted()
            .joined(separator: "; ")
        return "Partial secret batch failure (\(resolved.count) resolved, \(failures.count) failed: \(details))"
    }

    /// Localized error description matching ``description`` for CLI error reporters.
    public var errorDescription: String? {
        description
    }
}

// MARK: - SecretResolutionError

/// Structured errors surfaced during secret URI parsing, storage-safety verification, provider execution, or byte transforms.
public enum SecretResolutionError: Error, Sendable, Equatable, Hashable, CustomStringConvertible, LocalizedError {
    /// Exit code `4`: Plaintext literal secret was found in a repo-committed project configuration file.
    case unsafePlaintextInProjectConfig(keyPath: [String], origin: SettingOrigin)

    /// Exit code `4`: Secret file has group or world POSIX permissions (for example, `0644` instead of `0600`).
    case insecureFilePermissions(path: String, actualPermissions: UInt16, requiredPermissions: UInt16)

    /// Exit code `4`: Secret provider CLI binary failed executable trust verification.
    case unsafeExecutable(scheme: String, path: String, reason: String, remediation: String? = nil)

    /// Exit code `6`: Referenced local secret file does not exist or is a directory.
    case secretFileNotFound(path: String)

    /// Exit code `6`: Failed to read bytes from a local secret file.
    case secretFileReadFailed(path: String, reason: String)

    /// Exit code `6`: Indirect `env://<VAR>` environment variable is unset or empty.
    case environmentVariableNotSet(variableName: String)

    /// Exit code `6`: No ``SecretProvider`` in ``SettingsContext/secretProviders`` supports the URI scheme.
    case unregisteredScheme(scheme: String, referenceRedacted: String)

    /// Exit code `6`: Provider returned a batch dictionary omitting a requested ``SecretReference``.
    case unresolvedReference(referenceRedacted: String)

    /// Exit code `6`: Secret provider authentication or session unlock failure.
    case authenticationFailed(scheme: String, message: String, remediation: String? = nil)

    /// Exit code `6`: Secret item or field was not found in the secret provider vault.
    case itemNotFound(scheme: String, referenceRedacted: String, message: String? = nil)

    /// Exit code `6`: Secret provider rejected the request due to rate limiting.
    case rateLimited(
        scheme: String,
        message: String,
        retryAfter: Duration?,
        remediation: String? = nil
    )

    /// Exit code `6`: General secret provider invocation failure.
    case providerFailed(scheme: String, message: String, remediation: String? = nil)

    /// Exit code `2`: Malformed or option-injection-unsafe ``SecretReference``.
    case invalidReference(SecretReferenceError)

    /// Exit code `2`: Post-resolution ``SecretTransform`` step failed.
    case transformFailed(transform: String, reason: String)

    /// Maps this error to its corresponding ``ValidationIssueKind`` bucket.
    public var issueKind: ValidationIssueKind {
        switch self {
        case .unsafePlaintextInProjectConfig, .insecureFilePermissions, .unsafeExecutable:
            return .unsafeSecret
        case .secretFileNotFound,
             .secretFileReadFailed,
             .environmentVariableNotSet,
             .unregisteredScheme,
             .unresolvedReference,
             .authenticationFailed,
             .itemNotFound,
             .rateLimited,
             .providerFailed:
            return .providerFailure
        case .invalidReference, .transformFailed:
            return .invalidValue
        }
    }

    /// Deterministic CLI exit code (`4` for unsafe secret storage, `6` for provider failures, `2` for invalid syntax/transforms).
    public var exitCode: Int32 {
        issueKind.exitCode
    }

    /// Optional actionable remediation guidance (such as `chmod 600 <path>` or `op signin`).
    public var remediation: String? {
        switch self {
        case .unsafePlaintextInProjectConfig:
            return "Replace with a secret reference ('op://...', 'keychain://...', 'bws://...', 'pass://...', '@~/path'), move to a gitignored '.env' file, or place in user config ('~/.config/.../config.json' with chmod 600)."
        case .insecureFilePermissions(let path, _, let required):
            let reqOctal = Self.formatChmodOctal(required)
            return "Fix: chmod \(reqOctal) \(path)"
        case .unsafeExecutable(_, let path, _, let hint):
            return hint ?? "Provide an absolute path to a trusted root/user-owned binary and remove group/world write permissions (`chmod 755 \(path)`)."
        case .secretFileNotFound(let path):
            return "Create the secret file at '\(path)' with mode 0600 (`chmod 600 \(path)`)."
        case .secretFileReadFailed(let path, _):
            return "Verify read permissions and ownership for '\(path)'."
        case .environmentVariableNotSet(let variableName):
            return "Export '\(variableName)' in the process environment before launching."
        case .unregisteredScheme(let scheme, _):
            return "Register a SecretProvider supporting '\(scheme)://' in SettingsContext.secretProviders."
        case .unresolvedReference(let ref):
            return "Verify that '\(ref)' exists and that the provider returns an entry for it."
        case .authenticationFailed(_, _, let hint):
            return hint
        case .itemNotFound(_, let ref, _):
            return "Verify the vault, item, and field path in '\(ref)'."
        case .rateLimited(_, _, _, let hint):
            return hint
        case .providerFailed(_, _, let hint):
            return hint
        case .invalidReference:
            return nil
        case .transformFailed:
            return nil
        }
    }

    /// Human-readable error message safe for terminal diagnostics.
    public var description: String {
        switch self {
        case .unsafePlaintextInProjectConfig:
            return "UnsafeSecretStorage: Plaintext literal secret is forbidden in repo-committed project configuration."
        case .insecureFilePermissions(let path, let actual, let required):
            let actualOctal = Self.formatFourDigitOctal(actual)
            let requiredOctal = Self.formatFourDigitOctal(required)
            return "UnsafeSecretStorage: Secret file '\(path)' has insecure permissions \(actualOctal) (expected \(requiredOctal) or stricter with no group/world access)."
        case .unsafeExecutable(let scheme, let path, let reason, _):
            return "UnsafeExecutable (\(scheme)): Refusing untrusted executable '\(path)': \(reason)"
        case .secretFileNotFound(let path):
            return "Secret file not found at '\(path)'."
        case .secretFileReadFailed(let path, let reason):
            return "Failed to read secret file '\(path)': \(reason)"
        case .environmentVariableNotSet(let variableName):
            return "Referenced secret environment variable '\(variableName)' is not set."
        case .unregisteredScheme(let scheme, let ref):
            return "No registered SecretProvider supports scheme '\(scheme)://' for '\(ref)'."
        case .unresolvedReference(let ref):
            return "Secret provider did not return a value for '\(ref)'."
        case .authenticationFailed(let scheme, let message, _):
            return "Secret provider '\(scheme)' authentication failed: \(message)"
        case .itemNotFound(let scheme, let ref, let detail):
            if let detail, !detail.isEmpty {
                return "Secret '\(ref)' not found in '\(scheme)' provider: \(detail)"
            }
            return "Secret '\(ref)' not found in '\(scheme)' provider."
        case .rateLimited(let scheme, let message, _, _):
            return "Secret provider '\(scheme)' rate-limited: \(message)"
        case .providerFailed(let scheme, let message, _):
            return "Secret provider '\(scheme)' failed: \(message)"
        case .invalidReference(let error):
            return error.description
        case .transformFailed(let transform, let reason):
            return "Secret transform '\(transform)' failed: \(reason)"
        }
    }

    /// Localized error description matching ``description`` for CLI error reporters.
    public var errorDescription: String? {
        description
    }

    /// Formats a POSIX permission bitmask as a zero-padded four-digit octal string (for example, `"0644"`).
    ///
    /// - Parameter permissions: POSIX mode bits.
    /// - Returns: Four-digit octal string.
    public static func formatFourDigitOctal(_ permissions: UInt16) -> String {
        let masked = permissions & 0o777
        let digits = String(masked, radix: 8)
        if digits.count >= 4 {
            return digits
        }
        return String(repeating: "0", count: 4 - digits.count) + digits
    }

    /// Formats a POSIX permission bitmask as a three-digit `chmod` octal argument (for example, `"600"`).
    ///
    /// - Parameter permissions: POSIX mode bits.
    /// - Returns: Three-digit octal string suitable for `chmod`.
    public static func formatChmodOctal(_ permissions: UInt16) -> String {
        let masked = permissions & 0o777
        let digits = String(masked, radix: 8)
        if digits.count >= 3 {
            return digits
        }
        return String(repeating: "0", count: 3 - digits.count) + digits
    }
}

// MARK: - Actor-Isolated SecretResolutionCache

/// Actor-isolated time-to-live (TTL) cache for resolved secret bytes in long-running services and daemons.
///
/// Short-lived CLIs leave ``SettingsContext/secretCache`` set to `nil` by default so resolved secrets
/// are never retained beyond the load pass. Long-running servers or ``SettingsWatcher`` instances can
/// attach a `SecretResolutionCache` to avoid redundant external vault round-trips during live reloads.
///
/// ```swift
/// let cache = SecretResolutionCache(ttl: .seconds(300))
/// let context = SettingsContext(secretCache: cache)
/// ```
public actor SecretResolutionCache {
    /// Time-to-live duration applied to stored entries.
    public let ttl: Duration

    private struct Entry: Sendable {
        let data: Data
        let expiresAt: ContinuousClock.Instant
    }

    private let nowProvider: @Sendable () -> ContinuousClock.Instant
    private var storage: [SecretReference: Entry] = [:]

    /// Creates an actor-isolated secret resolution cache.
    ///
    /// - Parameters:
    ///   - ttl: Expiration duration for cached entries (defaults to `300` seconds).
    ///   - now: Monotonic clock closure used for expiration checks (injectable for deterministic unit tests).
    public init(
        ttl: Duration = .seconds(300),
        now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now }
    ) {
        self.ttl = ttl
        self.nowProvider = now
    }

    /// Looks up a cached, non-expired secret byte payload for `reference`.
    ///
    /// - Parameter reference: Secret reference to query.
    /// - Returns: Cached `Data` if present and unexpired, or `nil` otherwise.
    public func value(for reference: SecretReference) -> Data? {
        let current = nowProvider()
        guard let entry = storage[reference] else { return nil }
        guard current < entry.expiresAt else {
            storage.removeValue(forKey: reference)
            return nil
        }
        return entry.data
    }

    /// Partitions `references` into unexpired cache hits and missing/expired references in one actor call.
    ///
    /// - Parameter references: Candidate secret references to inspect.
    /// - Returns: Tuple of cached `Data` hits and uncached `missing` references.
    public func values(
        for references: [SecretReference]
    ) -> (cached: [SecretReference: Data], missing: [SecretReference]) {
        let current = nowProvider()
        var cached: [SecretReference: Data] = [:]
        var missing: [SecretReference] = []

        for reference in references {
            if let entry = storage[reference] {
                if current < entry.expiresAt {
                    cached[reference] = entry.data
                } else {
                    storage.removeValue(forKey: reference)
                    missing.append(reference)
                }
            } else {
                missing.append(reference)
            }
        }

        return (cached, missing)
    }

    /// Stores a single resolved secret value with the configured ``ttl``.
    ///
    /// - Parameters:
    ///   - data: Resolved secret bytes.
    ///   - reference: Associated ``SecretReference`` key.
    public func store(_ data: Data, for reference: SecretReference) {
        guard ttl > .zero else { return }
        let expiresAt = nowProvider().advanced(by: ttl)
        storage[reference] = Entry(data: data, expiresAt: expiresAt)
    }

    /// Stores a dictionary of resolved secret values with the configured ``ttl``.
    ///
    /// - Parameter values: Resolved secret byte payloads keyed by ``SecretReference``.
    public func store(_ values: [SecretReference: Data]) {
        guard ttl > .zero, !values.isEmpty else { return }
        let expiresAt = nowProvider().advanced(by: ttl)
        for (reference, data) in values {
            storage[reference] = Entry(data: data, expiresAt: expiresAt)
        }
    }

    /// Evicts a single cached secret reference immediately.
    ///
    /// - Parameter reference: Secret reference to remove.
    public func invalidate(_ reference: SecretReference) {
        storage.removeValue(forKey: reference)
    }

    /// Evicts all cached secret entries immediately.
    public func invalidateAll() {
        storage.removeAll()
    }

    /// Number of unexpired secret entries currently held in the cache.
    public var count: Int {
        let current = nowProvider()
        storage = storage.filter { $0.value.expiresAt > current }
        return storage.count
    }
}

// MARK: - SecretTransform Pipeline

/// Post-resolution byte transformations applied to a secret's raw payload before typed decoding.
public enum SecretTransform: Sendable, Equatable, Hashable {
    /// Trims leading and trailing whitespace and newline characters.
    case trimWhitespace

    /// Expands a leading `~` or `~/` prefix against ``SettingsContext/homeDirectory``.
    case expandTilde

    /// Expands `@path` file references (such as `@keys/AuthKey.p8` or `@~/key.pem`) via ``SettingsContext/fileSystem``,
    /// enforcing `requirePermissions` (`0o600` by default) when non-`nil`.
    case expandFileReference(requirePermissions: UInt16? = 0o600)

    /// Decodes standard or URL-safe Base64 text into raw binary bytes.
    case decodeBase64

    /// Decodes Base64 text only when prefixed with `"base64:"`, leaving unprefixed payloads unchanged.
    case decodeBase64IfPrefixed

    /// Unescapes literal `\n` sequences and normalizes PEM armor headers, 64-column body lines, and footers.
    case normalizePEM

    /// Verifies that the secret bytes form valid UTF-8 text.
    case utf8Data

    /// Applies this transformation step to `data`.
    ///
    /// - Parameters:
    ///   - data: Input secret byte buffer.
    ///   - context: Execution context providing filesystem, home directory, and ``DiagnosticRedactor``.
    /// - Returns: Tuple containing transformed `data` and any `@file` reference path that was expanded.
    /// - Throws: ``SecretResolutionError`` if transformation or file permission verification fails.
    public func apply(
        to data: Data,
        context: SettingsContext
    ) throws -> (data: Data, expandedFileReference: String?) {
        switch self {
        case .trimWhitespace:
            if let text = String(data: data, encoding: .utf8) {
                return (Data(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8), nil)
            }
            return (Self.trimASCIIWhitespace(data), nil)

        case .expandTilde:
            guard let text = String(data: data, encoding: .utf8) else {
                throw SecretResolutionError.transformFailed(
                    transform: "expandTilde",
                    reason: "Secret bytes are not valid UTF-8 text."
                )
            }
            let expanded = FileSecretProvider.expandHome(text, homeDirectory: context.homeDirectory)
            return (Data(expanded.utf8), nil)

        case .expandFileReference(let requirePermissions):
            guard let text = String(data: data, encoding: .utf8) else {
                return (data, nil)
            }
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.hasPrefix("@") else {
                return (data, nil)
            }
            let rawPath = String(trimmed.dropFirst())
            guard !rawPath.isEmpty, !rawPath.utf8.contains(0) else {
                throw SecretResolutionError.transformFailed(
                    transform: "expandFileReference",
                    reason: "Invalid '@file' secret path."
                )
            }
            let loaded = try FileSecretProvider.loadSecretFile(
                rawPath: rawPath,
                requiredPermissions: requirePermissions,
                context: context
            )
            context.redactor.register(loaded.data)
            return (loaded.data, "@\(rawPath)")

        case .decodeBase64:
            guard let text = String(data: data, encoding: .utf8) else {
                throw SecretResolutionError.transformFailed(
                    transform: "decodeBase64",
                    reason: "Input is not valid UTF-8 Base64 text."
                )
            }
            guard let decoded = Self.decodeBase64Flexible(text) else {
                throw SecretResolutionError.transformFailed(
                    transform: "decodeBase64",
                    reason: "Input is not valid Base64."
                )
            }
            context.redactor.register(decoded)
            return (decoded, nil)

        case .decodeBase64IfPrefixed:
            guard let text = String(data: data, encoding: .utf8) else {
                return (data, nil)
            }
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            let prefix = "base64:"
            guard trimmed.count >= prefix.count,
                  trimmed.prefix(prefix.count).lowercased() == prefix else {
                return (data, nil)
            }
            let payload = String(trimmed.dropFirst(prefix.count))
            guard let decoded = Self.decodeBase64Flexible(payload) else {
                throw SecretResolutionError.transformFailed(
                    transform: "decodeBase64IfPrefixed",
                    reason: "Payload following 'base64:' prefix is not valid Base64."
                )
            }
            context.redactor.register(decoded)
            return (decoded, nil)

        case .normalizePEM:
            guard let text = String(data: data, encoding: .utf8) else {
                throw SecretResolutionError.transformFailed(
                    transform: "normalizePEM",
                    reason: "Input is not valid UTF-8 PEM text."
                )
            }
            let normalized = Self.normalizePEMString(text)
            let normalizedData = Data(normalized.utf8)
            context.redactor.register(normalized)
            return (normalizedData, nil)

        case .utf8Data:
            guard String(data: data, encoding: .utf8) != nil else {
                throw SecretResolutionError.transformFailed(
                    transform: "utf8Data",
                    reason: "Secret bytes are not valid UTF-8."
                )
            }
            return (data, nil)
        }
    }

    /// Applies an ordered pipeline of ``SecretTransform`` steps to `initialData`.
    ///
    /// - Parameters:
    ///   - transforms: Ordered transformation steps to execute.
    ///   - initialData: Raw bytes returned by a ``SecretProvider`` or inline literal.
    ///   - context: Execution context passed to each step.
    /// - Returns: Tuple containing final transformed bytes and any expanded `@file` reference label.
    /// - Throws: ``SecretResolutionError`` if any step in the pipeline fails.
    public static func applyAll(
        _ transforms: [SecretTransform],
        to initialData: Data,
        context: SettingsContext
    ) throws -> (data: Data, expandedFileReference: String?) {
        var current = initialData
        var expandedRef: String?
        for transform in transforms {
            let step = try transform.apply(to: current, context: context)
            current = step.data
            if let ref = step.expandedFileReference {
                expandedRef = ref
            }
        }
        return (current, expandedRef)
    }

    // MARK: - Transform Helpers

    private static func trimASCIIWhitespace(_ data: Data) -> Data {
        let isSpace: (UInt8) -> Bool = { $0 == 0x20 || $0 == 0x09 || $0 == 0x0A || $0 == 0x0D }
        var start = data.startIndex
        var end = data.endIndex
        while start < end && isSpace(data[start]) {
            start = data.index(after: start)
        }
        while end > start && isSpace(data[data.index(before: end)]) {
            end = data.index(before: end)
        }
        return Data(data[start..<end])
    }

    private static func decodeBase64Flexible(_ raw: String) -> Data? {
        let stripped = String(raw.unicodeScalars.filter { !CharacterSet.whitespacesAndNewlines.contains($0) })
        if stripped.isEmpty {
            return Data()
        }
        if let standard = Data(base64Encoded: stripped) {
            return standard
        }
        var urlNormalized = stripped
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = urlNormalized.count % 4
        if remainder == 2 {
            urlNormalized += "=="
        } else if remainder == 3 {
            urlNormalized += "="
        } else if remainder == 1 {
            return nil
        }
        return Data(base64Encoded: urlNormalized)
    }

    private static func normalizePEMString(_ raw: String) -> String {
        var working = raw
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .replacingOccurrences(of: "\\r\\n", with: "\n")
            .replacingOccurrences(of: "\\n", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard !working.isEmpty else { return working }

        working = separatePEMMarkersOntoOwnLines(working)

        let rawLines = working.split(separator: "\n", omittingEmptySubsequences: false)
        var normalizedLines: [String] = []
        var insideArmorBody = false

        for rawLine in rawLines {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            if trimmed.hasPrefix("-----BEGIN ") && trimmed.hasSuffix("-----") {
                insideArmorBody = true
                normalizedLines.append(trimmed)
            } else if trimmed.hasPrefix("-----END ") && trimmed.hasSuffix("-----") {
                insideArmorBody = false
                normalizedLines.append(trimmed)
            } else if insideArmorBody && !trimmed.contains(":") {
                let compact = String(trimmed.filter { !$0.isWhitespace })
                if compact.count > 64 {
                    var idx = compact.startIndex
                    while idx < compact.endIndex {
                        let end = compact.index(idx, offsetBy: 64, limitedBy: compact.endIndex) ?? compact.endIndex
                        normalizedLines.append(String(compact[idx..<end]))
                        idx = end
                    }
                } else if !compact.isEmpty {
                    normalizedLines.append(compact)
                }
            } else {
                normalizedLines.append(trimmed)
            }
        }

        return normalizedLines.joined(separator: "\n")
    }

    private static func separatePEMMarkersOntoOwnLines(_ text: String) -> String {
        var result = text
        var searchStart = result.startIndex

        while let beginRange = result.range(of: "-----BEGIN ", range: searchStart..<result.endIndex),
              let closeRange = result.range(of: "-----", range: beginRange.upperBound..<result.endIndex) {
            let afterHeader = closeRange.upperBound
            if afterHeader < result.endIndex && result[afterHeader] != "\n" {
                result.insert("\n", at: afterHeader)
                searchStart = result.index(after: afterHeader)
            } else {
                searchStart = afterHeader
            }
        }

        searchStart = result.startIndex
        while let endRange = result.range(of: "-----END ", range: searchStart..<result.endIndex),
              let closeRange = result.range(of: "-----", range: endRange.upperBound..<result.endIndex) {
            var nextSearch = closeRange.upperBound
            if endRange.lowerBound > result.startIndex {
                let beforeFooter = result.index(before: endRange.lowerBound)
                if result[beforeFooter] != "\n" {
                    result.insert("\n", at: endRange.lowerBound)
                    nextSearch = result.index(after: closeRange.upperBound)
                }
            }
            if nextSearch < result.endIndex && result[nextSearch] != "\n" {
                result.insert("\n", at: nextSearch)
                nextSearch = result.index(after: nextSearch)
            }
            searchStart = nextSearch
        }

        return result
    }
}

// MARK: - Two-Phase Batched SecretResolver

/// Describes a single secret field queued for batched resolution by ``SecretResolver``.
public struct SecretResolutionRequest: Sendable, Equatable {
    /// Hierarchical key path of the secret setting.
    public let keyPath: [String]

    /// Winning configuration node containing the raw URI or literal value and its ``SettingOrigin``.
    public let node: RawNode

    /// Ordered post-resolution ``SecretTransform`` steps applied to the resolved bytes.
    public let transforms: [SecretTransform]

    /// Whether inline literal secrets originating from `.projectConfig` are explicitly allowed.
    public let allowLiteralInProjectConfig: Bool

    /// Optional display name of the expected Swift type for diagnostics.
    public let expectedType: String?

    /// Optional canonical environment variable name hint for diagnostics.
    public let envVariableHint: String?

    /// Creates a secret resolution request from a ``RawNode``.
    ///
    /// - Parameters:
    ///   - keyPath: Hierarchical setting key path.
    ///   - node: Winning configuration node.
    ///   - transforms: Post-resolution byte transforms.
    ///   - allowLiteralInProjectConfig: Whether literal values from `.projectConfig` are permitted.
    ///   - expectedType: Optional expected Swift type display name.
    ///   - envVariableHint: Optional environment variable remediation hint.
    public init(
        keyPath: [String],
        node: RawNode,
        transforms: [SecretTransform] = [],
        allowLiteralInProjectConfig: Bool = false,
        expectedType: String? = nil,
        envVariableHint: String? = nil
    ) {
        self.keyPath = keyPath
        self.node = node
        self.transforms = transforms
        self.allowLiteralInProjectConfig = allowLiteralInProjectConfig
        self.expectedType = expectedType
        self.envVariableHint = envVariableHint
    }

    /// Creates a secret resolution request from a raw string and provenance metadata.
    ///
    /// - Parameters:
    ///   - keyPath: Hierarchical setting key path.
    ///   - rawString: Raw configuration string (secret URI or inline literal).
    ///   - origin: Winning ``SettingOrigin`` of `rawString`.
    ///   - overriddenOrigins: Lower-priority origins shadowed by `origin`.
    ///   - transforms: Post-resolution byte transforms.
    ///   - allowLiteralInProjectConfig: Whether literal values from `.projectConfig` are permitted.
    ///   - expectedType: Optional expected Swift type display name.
    ///   - envVariableHint: Optional environment variable remediation hint.
    public init(
        keyPath: [String],
        rawString: String,
        origin: SettingOrigin,
        overriddenOrigins: [SettingOrigin] = [],
        transforms: [SecretTransform] = [],
        allowLiteralInProjectConfig: Bool = false,
        expectedType: String? = nil,
        envVariableHint: String? = nil
    ) {
        self.init(
            keyPath: keyPath,
            node: RawNode(value: .string(rawString), origin: origin, overriddenOrigins: overriddenOrigins),
            transforms: transforms,
            allowLiteralInProjectConfig: allowLiteralInProjectConfig,
            expectedType: expectedType,
            envVariableHint: envVariableHint
        )
    }
}

/// Output of resolving and transforming a single ``SecretResolutionRequest``.
public struct ResolvedSecret: Sendable, Equatable {
    /// Hierarchical key path of the resolved secret setting.
    public let keyPath: [String]

    /// Final transformed secret byte payload.
    public let data: Data

    /// Parsed ``SecretReference`` that produced ``data``.
    public let reference: SecretReference

    /// Effective ``SettingOrigin`` (wrapped in `.secretProvider(...)` when resolved via a provider or `@file`).
    public let origin: SettingOrigin

    /// Lower-priority origins shadowed by this setting.
    public let overriddenOrigins: [SettingOrigin]

    /// Creates a resolved secret record.
    ///
    /// - Parameters:
    ///   - keyPath: Hierarchical setting key path.
    ///   - data: Resolved and transformed secret bytes.
    ///   - reference: Parsed ``SecretReference``.
    ///   - origin: Effective provenance origin.
    ///   - overriddenOrigins: Shadowed lower-priority origins.
    public init(
        keyPath: [String],
        data: Data,
        reference: SecretReference,
        origin: SettingOrigin,
        overriddenOrigins: [SettingOrigin] = []
    ) {
        self.keyPath = keyPath
        self.data = data
        self.reference = reference
        self.origin = origin
        self.overriddenOrigins = overriddenOrigins
    }

    /// Decodes ``data`` as a UTF-8 ``Secret`` string.
    ///
    /// - Returns: A `Secret<String>` wrapping the UTF-8 decoded text.
    /// - Throws: ``ValueDecodingError`` if ``data`` is not valid UTF-8.
    public func utf8Secret() throws -> Secret<String> {
        guard let string = String(data: data, encoding: .utf8) else {
            throw ValueDecodingError(
                expectedType: "Secret<String>",
                reason: "Resolved secret bytes are not valid UTF-8."
            )
        }
        return Secret(string)
    }

    /// Wraps ``data`` in `Secret<Data>`.
    public var dataSecret: Secret<Data> {
        Secret(data)
    }

    /// Wraps ``data`` as a `Secret<[UInt8]>` byte array.
    public var bytesSecret: Secret<[UInt8]> {
        Secret(Array(data))
    }

    /// Decodes ``data`` into any ``SettingValueDecodable`` payload wrapped in ``Secret``.
    ///
    /// - Parameters:
    ///   - type: Target decoded payload type.
    ///   - context: Value decoding context.
    /// - Returns: `Secret<Value>` wrapping the decoded value.
    /// - Throws: ``ValueDecodingError`` if ``data`` is not valid UTF-8 or fails `Value` coercion.
    public func decode<Value: SettingValueDecodable>(
        as type: Value.Type = Value.self,
        context: ValueDecodingContext = ValueDecodingContext()
    ) throws -> Secret<Value> {
        if Value.self == Data.self {
            return Secret(data as! Value)
        }
        if Value.self == [UInt8].self {
            return Secret(Array(data) as! Value)
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw ValueDecodingError(
                expectedType: "Secret<\(Value.settingTypeDisplayName)>",
                reason: "Resolved secret bytes are not valid UTF-8."
            )
        }
        return Secret(try Value.decodeSettingValue(from: .string(text), context: context))
    }
}

/// Aggregated result of a two-phase batched secret resolution pass across a settings model.
public struct SecretBatchResolutionResult: Sendable, Equatable {
    /// Successfully resolved secrets in request order.
    public let resolved: [ResolvedSecret]

    /// Lookup table indexing ``resolved`` by ``ResolvedSecret/keyPath``.
    public let resolvedByKeyPath: [[String]: ResolvedSecret]

    /// Validation, unsafe-secret (`exitCode == 4`), and provider (`exitCode == 6`) issues accumulated during the batch.
    public let issues: [ValidationIssue]

    /// Creates a batch resolution result.
    ///
    /// - Parameters:
    ///   - resolved: Resolved secret entries.
    ///   - issues: Accumulated validation and resolution issues.
    public init(resolved: [ResolvedSecret], issues: [ValidationIssue]) {
        self.resolved = resolved
        var map: [[String]: ResolvedSecret] = [:]
        map.reserveCapacity(resolved.count)
        for item in resolved {
            map[item.keyPath] = item
        }
        self.resolvedByKeyPath = map
        self.issues = issues
    }
}

/// Two-phase batched secret resolver that deduplicates secret URIs across the configuration tree,
/// partitions provider calls by `(scheme, accountHint)`, enforces repo-committed plaintext guards,
/// registers resolved secrets in ``DiagnosticRedactor``, and runs ``SecretTransform`` pipelines.
///
/// ```swift
/// let resolver = SecretResolver()
/// let result = await resolver.resolveAll(requests, context: context)
/// ```
public struct SecretResolver: Sendable {
    /// Creates a batched secret resolver.
    public init() {}

    private struct BatchKey: Hashable, Sendable {
        let scheme: String
        let accountHint: String?
    }

    private enum PreparedItem {
        case directBytes(request: SecretResolutionRequest, rawData: Data, reference: SecretReference)
        case providerBacked(request: SecretResolutionRequest, reference: SecretReference)
        case customPermFile(
            request: SecretResolutionRequest,
            reference: SecretReference,
            fileRef: FileSecretReference,
            requiredPermissions: UInt16?
        )
    }

    /// Resolves all `requests` in deduplicated provider batches without short-circuiting on errors.
    ///
    /// - Parameters:
    ///   - requests: Secret resolution requests collected from top-level and nested settings fields.
    ///   - context: Execution context providing registered ``SecretProvider`` backends, optional cache, and ``DiagnosticRedactor``.
    /// - Returns: A ``SecretBatchResolutionResult`` containing all resolved secrets and accumulated ``ValidationIssue`` items.
    public func resolveAll(
        _ requests: [SecretResolutionRequest],
        context: SettingsContext
    ) async -> SecretBatchResolutionResult {
        guard !requests.isEmpty else {
            return SecretBatchResolutionResult(resolved: [], issues: [])
        }

        let customSchemes = Set(context.secretProviders.flatMap(\.supportedSchemes))

        var prepared: [PreparedItem] = []
        prepared.reserveCapacity(requests.count)

        var uniqueProviderRefs: [SecretReference] = []
        var seenProviderRefs: Set<SecretReference> = []
        var issues: [ValidationIssue] = []

        // MARK: Phase 1 — Parse references, enforce repo-committed guard, & collect deduplicated batches

        for request in requests {
            switch request.node.value {
            case .data(let rawData):
                context.redactor.register(rawData)
                if Self.isProjectConfigOrigin(request.node.origin) && !request.allowLiteralInProjectConfig {
                    let error = SecretResolutionError.unsafePlaintextInProjectConfig(
                        keyPath: request.keyPath,
                        origin: request.node.origin
                    )
                    issues.append(Self.makeIssue(from: error, for: request, redactor: context.redactor))
                    continue
                }
                prepared.append(
                    .directBytes(
                        request: request,
                        rawData: rawData,
                        reference: .literal("<binary>")
                    )
                )

            case .string(let rawString):
                let parsedRef: SecretReference
                do {
                    parsedRef = try SecretReference.parse(rawString, additionalSchemes: customSchemes)
                } catch let refError as SecretReferenceError {
                    issues.append(
                        Self.makeIssue(
                            from: .invalidReference(refError),
                            for: request,
                            redactor: context.redactor
                        )
                    )
                    continue
                } catch {
                    issues.append(
                        Self.makeGenericIssue(
                            from: error,
                            for: request,
                            defaultKind: .invalidValue,
                            redactor: context.redactor
                        )
                    )
                    continue
                }

                switch parsedRef {
                case .literal(let literalValue):
                    // Register immediately so even rejected project-config literals are scrubbed from diagnostics.
                    context.redactor.register(literalValue)

                    let expandsAtFile = literalValue.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("@")
                        && request.transforms.contains {
                            if case .expandFileReference = $0 { return true }
                            return false
                        }

                    if Self.isProjectConfigOrigin(request.node.origin)
                        && !request.allowLiteralInProjectConfig
                        && !expandsAtFile
                    {
                        let error = SecretResolutionError.unsafePlaintextInProjectConfig(
                            keyPath: request.keyPath,
                            origin: request.node.origin
                        )
                        issues.append(Self.makeIssue(from: error, for: request, redactor: context.redactor))
                        continue
                    }

                    prepared.append(
                        .directBytes(
                            request: request,
                            rawData: Data(literalValue.utf8),
                            reference: parsedRef
                        )
                    )

                case .file(let fileRef):
                    if let customPermOverride = Self.customFilePermissionOverride(in: request.transforms) {
                        prepared.append(
                            .customPermFile(
                                request: request,
                                reference: parsedRef,
                                fileRef: fileRef,
                                requiredPermissions: customPermOverride.permissions
                            )
                        )
                    } else {
                        if seenProviderRefs.insert(parsedRef).inserted {
                            uniqueProviderRefs.append(parsedRef)
                        }
                        prepared.append(.providerBacked(request: request, reference: parsedRef))
                    }

                default:
                    if seenProviderRefs.insert(parsedRef).inserted {
                        uniqueProviderRefs.append(parsedRef)
                    }
                    prepared.append(.providerBacked(request: request, reference: parsedRef))
                }

            default:
                let scalarString: String?
                switch request.node.value {
                case .int(let v): scalarString = String(v)
                case .double(let v): scalarString = String(v)
                case .bool(let v): scalarString = v ? "true" : "false"
                default: scalarString = nil
                }

                guard let coerced = scalarString else {
                    issues.append(
                        ValidationIssue(
                            keyPath: request.keyPath,
                            kind: .invalidValue,
                            message: "Expected string or secret URI reference for secret setting.",
                            origin: request.node.origin,
                            expectedType: request.expectedType,
                            envVariableHint: request.envVariableHint
                        )
                    )
                    continue
                }

                context.redactor.register(coerced)
                if Self.isProjectConfigOrigin(request.node.origin) && !request.allowLiteralInProjectConfig {
                    let error = SecretResolutionError.unsafePlaintextInProjectConfig(
                        keyPath: request.keyPath,
                        origin: request.node.origin
                    )
                    issues.append(Self.makeIssue(from: error, for: request, redactor: context.redactor))
                    continue
                }

                prepared.append(
                    .directBytes(
                        request: request,
                        rawData: Data(coerced.utf8),
                        reference: .literal(coerced)
                    )
                )
            }
        }

        // MARK: Phase 2 — Cache lookup & single batched call per `(scheme, accountHint)`

        var resolvedDataByRef: [SecretReference: Data] = [:]
        var errorByRef: [SecretReference: any Error] = [:]

        let refsToFetch: [SecretReference]
        if let cache = context.secretCache, !uniqueProviderRefs.isEmpty {
            let (cachedHits, missingRefs) = await cache.values(for: uniqueProviderRefs)
            for (ref, bytes) in cachedHits {
                context.redactor.register(bytes)
                resolvedDataByRef[ref] = bytes
            }
            refsToFetch = missingRefs
        } else {
            refsToFetch = uniqueProviderRefs
        }

        if !refsToFetch.isEmpty {
            var orderedBatchKeys: [BatchKey] = []
            var batches: [BatchKey: [SecretReference]] = [:]

            for ref in refsToFetch {
                let key = BatchKey(scheme: ref.scheme, accountHint: ref.accountHint)
                if batches[key] == nil {
                    orderedBatchKeys.append(key)
                    batches[key] = [ref]
                } else {
                    batches[key]?.append(ref)
                }
            }

            for batchKey in orderedBatchKeys {
                guard let batchRefs = batches[batchKey] else { continue }

                guard let provider = context.secretProviders.last(where: {
                    $0.supportedSchemes.contains(batchKey.scheme)
                }) else {
                    for ref in batchRefs {
                        errorByRef[ref] = SecretResolutionError.unregisteredScheme(
                            scheme: batchKey.scheme,
                            referenceRedacted: ref.redactedDescription
                        )
                    }
                    continue
                }

                do {
                    let batchResult = try await provider.resolveBatch(batchRefs, context: context)
                    for (_, bytes) in batchResult {
                        context.redactor.register(bytes)
                    }
                    if let cache = context.secretCache, !batchResult.isEmpty {
                        await cache.store(batchResult)
                    }
                    for ref in batchRefs {
                        if let bytes = batchResult[ref] {
                            resolvedDataByRef[ref] = bytes
                        } else {
                            errorByRef[ref] = SecretResolutionError.unresolvedReference(
                                referenceRedacted: ref.redactedDescription
                            )
                        }
                    }
                } catch let partial as SecretBatchPartialFailureError {
                    for (_, bytes) in partial.resolved {
                        context.redactor.register(bytes)
                    }
                    if let cache = context.secretCache, !partial.resolved.isEmpty {
                        await cache.store(partial.resolved)
                    }
                    for ref in batchRefs {
                        if let bytes = partial.resolved[ref] {
                            resolvedDataByRef[ref] = bytes
                        } else if let refError = partial.failures[ref] {
                            errorByRef[ref] = refError
                        } else {
                            errorByRef[ref] = SecretResolutionError.unresolvedReference(
                                referenceRedacted: ref.redactedDescription
                            )
                        }
                    }
                } catch {
                    for ref in batchRefs {
                        errorByRef[ref] = error
                    }
                }
            }
        }

        // MARK: Phase 3 — Apply per-field SecretTransforms & wrap provenance origins

        var resolvedOutputs: [ResolvedSecret] = []
        resolvedOutputs.reserveCapacity(prepared.count)

        for item in prepared {
            switch item {
            case .directBytes(let request, let rawData, let ref):
                do {
                    let (transformed, expandedAtRef) = try SecretTransform.applyAll(
                        request.transforms,
                        to: rawData,
                        context: context
                    )
                    context.redactor.register(transformed)

                    let finalOrigin: SettingOrigin
                    if let expandedAtRef {
                        finalOrigin = .secretProvider(
                            scheme: "file",
                            referenceRedacted: expandedAtRef,
                            via: request.node.origin
                        )
                    } else {
                        finalOrigin = request.node.origin
                    }

                    resolvedOutputs.append(
                        ResolvedSecret(
                            keyPath: request.keyPath,
                            data: transformed,
                            reference: ref,
                            origin: finalOrigin,
                            overriddenOrigins: request.node.overriddenOrigins
                        )
                    )
                } catch {
                    issues.append(
                        Self.makeGenericIssue(
                            from: error,
                            for: request,
                            defaultKind: .invalidValue,
                            redactor: context.redactor
                        )
                    )
                }

            case .customPermFile(let request, let ref, let fileRef, let requiredPermissions):
                do {
                    let loaded = try FileSecretProvider.loadSecretFile(
                        rawPath: fileRef.path,
                        requiredPermissions: requiredPermissions,
                        context: context
                    )
                    context.redactor.register(loaded.data)

                    let transformsWithoutFileExpand = request.transforms.filter {
                        if case .expandFileReference = $0 { return false }
                        return true
                    }
                    let (transformed, _) = try SecretTransform.applyAll(
                        transformsWithoutFileExpand,
                        to: loaded.data,
                        context: context
                    )
                    context.redactor.register(transformed)

                    let wrappedOrigin = SettingOrigin.secretProvider(
                        scheme: ref.scheme,
                        referenceRedacted: ref.redactedDescription,
                        via: request.node.origin
                    )
                    resolvedOutputs.append(
                        ResolvedSecret(
                            keyPath: request.keyPath,
                            data: transformed,
                            reference: ref,
                            origin: wrappedOrigin,
                            overriddenOrigins: request.node.overriddenOrigins
                        )
                    )
                } catch {
                    issues.append(
                        Self.makeGenericIssue(
                            from: error,
                            for: request,
                            defaultKind: .providerFailure,
                            redactor: context.redactor
                        )
                    )
                }

            case .providerBacked(let request, let ref):
                if let error = errorByRef[ref] {
                    issues.append(
                        Self.makeGenericIssue(
                            from: error,
                            for: request,
                            defaultKind: .providerFailure,
                            redactor: context.redactor
                        )
                    )
                    continue
                }

                guard let rawBytes = resolvedDataByRef[ref] else {
                    let error = SecretResolutionError.unresolvedReference(
                        referenceRedacted: ref.redactedDescription
                    )
                    issues.append(Self.makeIssue(from: error, for: request, redactor: context.redactor))
                    continue
                }

                do {
                    let effectiveTransforms: [SecretTransform]
                    if case .file = ref {
                        effectiveTransforms = request.transforms.filter {
                            if case .expandFileReference = $0 { return false }
                            return true
                        }
                    } else {
                        effectiveTransforms = request.transforms
                    }
                    let (transformed, _) = try SecretTransform.applyAll(
                        effectiveTransforms,
                        to: rawBytes,
                        context: context
                    )
                    context.redactor.register(transformed)

                    let wrappedOrigin = SettingOrigin.secretProvider(
                        scheme: ref.scheme,
                        referenceRedacted: ref.redactedDescription,
                        via: request.node.origin
                    )
                    resolvedOutputs.append(
                        ResolvedSecret(
                            keyPath: request.keyPath,
                            data: transformed,
                            reference: ref,
                            origin: wrappedOrigin,
                            overriddenOrigins: request.node.overriddenOrigins
                        )
                    )
                } catch {
                    issues.append(
                        Self.makeGenericIssue(
                            from: error,
                            for: request,
                            defaultKind: .invalidValue,
                            redactor: context.redactor
                        )
                    )
                }
            }
        }

        return SecretBatchResolutionResult(resolved: resolvedOutputs, issues: issues)
    }

    /// Resolves a single ``SecretResolutionRequest``, throwing ``SettingsValidationError`` on failure.
    ///
    /// - Parameters:
    ///   - request: Secret resolution request to resolve.
    ///   - context: Execution context providing providers, optional cache, and ``DiagnosticRedactor``.
    /// - Returns: Resolved ``ResolvedSecret`` payload.
    /// - Throws: ``SettingsValidationError`` if resolution, safety checks, or transforms fail.
    public func resolve(
        _ request: SecretResolutionRequest,
        context: SettingsContext
    ) async throws -> ResolvedSecret {
        let batch = await resolveAll([request], context: context)
        if !batch.issues.isEmpty {
            throw SettingsValidationError(issues: batch.issues, redactor: context.redactor)
        }
        guard let first = batch.resolved.first else {
            throw SettingsValidationError(
                issues: [
                    ValidationIssue(
                        keyPath: request.keyPath,
                        kind: .providerFailure,
                        message: "Failed to resolve secret.",
                        origin: request.node.origin
                    )
                ],
                redactor: context.redactor
            )
        }
        return first
    }

    // MARK: - Internal Classification Helpers

    private static func isProjectConfigOrigin(_ origin: SettingOrigin) -> Bool {
        if case .projectConfig = origin {
            return true
        }
        return false
    }

    private struct CustomFilePermOverride {
        let permissions: UInt16?
    }

    private static func customFilePermissionOverride(
        in transforms: [SecretTransform]
    ) -> CustomFilePermOverride? {
        for transform in transforms {
            if case .expandFileReference(let perms) = transform, perms != 0o600 {
                return CustomFilePermOverride(permissions: perms)
            }
        }
        return nil
    }

    private static func makeIssue(
        from error: SecretResolutionError,
        for request: SecretResolutionRequest,
        redactor: DiagnosticRedactor
    ) -> ValidationIssue {
        let isRateLimited: Bool
        let retryAfter: Duration?
        if case .rateLimited(_, _, let interval, _) = error {
            isRateLimited = true
            retryAfter = interval
        } else {
            isRateLimited = false
            retryAfter = nil
        }
        return ValidationIssue(
            keyPath: request.keyPath,
            kind: error.issueKind,
            message: redactor.scrub(error.description),
            origin: request.node.origin,
            expectedType: request.expectedType,
            envVariableHint: request.envVariableHint,
            remediation: error.remediation.map { redactor.scrub($0) },
            isRateLimited: isRateLimited,
            retryAfter: retryAfter
        )
    }

    private static func makeGenericIssue(
        from error: any Error,
        for request: SecretResolutionRequest,
        defaultKind: ValidationIssueKind,
        redactor: DiagnosticRedactor
    ) -> ValidationIssue {
        if let secretError = error as? SecretResolutionError {
            return makeIssue(from: secretError, for: request, redactor: redactor)
        }
        if let refError = error as? SecretReferenceError {
            return makeIssue(from: .invalidReference(refError), for: request, redactor: redactor)
        }
        if let subprocessError = error as? SubprocessSecurityError {
            let kind: ValidationIssueKind
            let remediation: String?
            switch subprocessError {
            case .relativeExecutablePath:
                kind = .unsafeSecret
                remediation = "Configure an absolute path to a trusted binary (e.g. '/opt/homebrew/bin/...' or '/usr/local/bin/...')."
            case .worldWritableExecutable(let path, _):
                kind = .unsafeSecret
                remediation = "Fix: chmod 755 \(path)"
            case .executableNotFound, .notExecutable, .timedOut, .unsupportedPlatform:
                kind = .providerFailure
                remediation = nil
            }
            return ValidationIssue(
                keyPath: request.keyPath,
                kind: kind,
                message: redactor.scrub(subprocessError.description),
                origin: request.node.origin,
                expectedType: request.expectedType,
                envVariableHint: request.envVariableHint,
                remediation: remediation.map { redactor.scrub($0) }
            )
        }
        if let issue = error as? ValidationIssue {
            return issue
        }
        return ValidationIssue(
            keyPath: request.keyPath,
            kind: defaultKind,
            message: redactor.scrub(String(describing: error)),
            origin: request.node.origin,
            expectedType: request.expectedType,
            envVariableHint: request.envVariableHint
        )
    }
}
