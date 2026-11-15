import Foundation

// MARK: - SecretProvider Protocol

/// Pluggable secret manager backend capable of resolving batches of `SecretReference` items.
public protocol SecretProvider: Sendable {
    /// URI schemes handled by this provider (e.g. `["op"]`, `["keychain"]`, `["bws", "bw"]`, `["file"]`, `["env"]`).
    var supportedSchemes: Set<String> { get }

    /// Resolves a deduplicated batch of `SecretReference` items sharing a scheme and `accountHint`.
    func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data]
}

/// Thrown by a `SecretProvider` when some references in a multi-item batch succeeded while others failed,
/// allowing `SecretResolver` to attribute per-reference errors accurately without failing sibling secrets.
public struct SecretBatchPartialFailureError: Error, Sendable {
    public let resolved: [SecretReference: Data]
    public let failures: [SecretReference: any Error]

    public init(resolved: [SecretReference: Data], failures: [SecretReference: any Error]) {
        self.resolved = resolved
        self.failures = failures
    }
}

// MARK: - SecretResolutionError

/// Structured errors surfaced during secret URI parsing, safety checks, provider execution, or transforms.
public enum SecretResolutionError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    /// Exit code `4`: Plaintext literal secret committed in a project configuration file.
    case unsafePlaintextInProjectConfig(keyPath: [String], origin: SettingOrigin)

    /// Exit code `4`: Secret file has overly permissive group/world POSIX mode bits (e.g. `0644` instead of `0600`).
    case insecureFilePermissions(path: String, actualPermissions: UInt16, requiredPermissions: UInt16)

    /// Exit code `4`: Secret provider CLI binary failed executable trust verification (e.g. relative path or world-writable mode).
    case unsafeExecutable(scheme: String, path: String, reason: String, remediation: String? = nil)

    /// Exit code `6`: Referenced local secret file does not exist or is a directory.
    case secretFileNotFound(path: String)

    /// Exit code `6`: Failed to read bytes from local secret file.
    case secretFileReadFailed(path: String, reason: String)

    /// Exit code `6`: Indirect `env://<VAR>` environment variable is unset or empty.
    case environmentVariableNotSet(variableName: String)

    /// Exit code `6`: No `SecretProvider` in `SettingsContext.secretProviders` supports the URI scheme.
    case unregisteredScheme(scheme: String, referenceRedacted: String)

    /// Exit code `6`: Provider returned a batch dictionary omitting a requested `SecretReference`.
    case unresolvedReference(referenceRedacted: String)

    /// Exit code `6`: Secret provider authentication or session unlock failure.
    case authenticationFailed(scheme: String, message: String, remediation: String? = nil)

    /// Exit code `6`: Secret item or field was not found in the secret provider vault.
    case itemNotFound(scheme: String, referenceRedacted: String, message: String? = nil)

    /// Exit code `6`: General secret provider invocation failure.
    case providerFailed(scheme: String, message: String, remediation: String? = nil)

    /// Exit code `2`: Malformed or option-injection-unsafe `SecretReference`.
    case invalidReference(SecretReferenceError)

    /// Exit code `2`: Post-resolution `SecretTransform` failed (e.g. invalid Base64 or non-UTF8 bytes).
    case transformFailed(transform: String, reason: String)

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
             .providerFailed:
            return .providerFailure
        case .invalidReference, .transformFailed:
            return .invalidValue
        }
    }

    public var exitCode: Int32 {
        issueKind.exitCode
    }

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
        case .providerFailed(_, _, let hint):
            return hint
        case .invalidReference:
            return nil
        case .transformFailed:
            return nil
        }
    }

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
        case .providerFailed(let scheme, let message, _):
            return "Secret provider '\(scheme)' failed: \(message)"
        case .invalidReference(let error):
            return error.description
        case .transformFailed(let transform, let reason):
            return "Secret transform '\(transform)' failed: \(reason)"
        }
    }

    public var errorDescription: String? {
        description
    }

    public static func formatFourDigitOctal(_ permissions: UInt16) -> String {
        let masked = permissions & 0o777
        let digits = String(masked, radix: 8)
        if digits.count >= 4 {
            return digits
        }
        return String(repeating: "0", count: 4 - digits.count) + digits
    }

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

/// Actor-isolated TTL cache for resolved secret bytes, intended for long-running daemons or servers.
public actor SecretResolutionCache {
    public let ttl: Duration

    private struct Entry: Sendable {
        let data: Data
        let expiresAt: ContinuousClock.Instant
    }

    private let nowProvider: @Sendable () -> ContinuousClock.Instant
    private var storage: [SecretReference: Entry] = [:]

    /// Creates a secret resolution cache with a configurable TTL (default `300` seconds).
    public init(
        ttl: Duration = .seconds(300),
        now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now }
    ) {
        self.ttl = ttl
        self.nowProvider = now
    }

    /// Looks up a single non-expired cached secret value.
    public func value(for reference: SecretReference) -> Data? {
        let current = nowProvider()
        guard let entry = storage[reference] else { return nil }
        guard current < entry.expiresAt else {
            storage.removeValue(forKey: reference)
            return nil
        }
        return entry.data
    }

    /// Partitions `references` into cached hits and uncached/expired misses in a single actor hop.
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

    /// Stores a single resolved secret value with the cache's configured TTL.
    public func store(_ data: Data, for reference: SecretReference) {
        guard ttl > .zero else { return }
        let expiresAt = nowProvider().advanced(by: ttl)
        storage[reference] = Entry(data: data, expiresAt: expiresAt)
    }

    /// Stores a batch of resolved secret values with the cache's configured TTL.
    public func store(_ values: [SecretReference: Data]) {
        guard ttl > .zero, !values.isEmpty else { return }
        let expiresAt = nowProvider().advanced(by: ttl)
        for (reference, data) in values {
            storage[reference] = Entry(data: data, expiresAt: expiresAt)
        }
    }

    /// Removes a specific cached secret reference.
    public func invalidate(_ reference: SecretReference) {
        storage.removeValue(forKey: reference)
    }

    /// Clears all cached secret entries immediately.
    public func invalidateAll() {
        storage.removeAll()
    }

    /// Number of non-expired entries currently held in the cache.
    public var count: Int {
        let current = nowProvider()
        storage = storage.filter { $0.value.expiresAt > current }
        return storage.count
    }
}

// MARK: - SecretTransform Pipeline

/// Post-resolution value transformation steps applied to a secret's raw bytes.
public enum SecretTransform: Sendable, Equatable, Hashable {
    /// Trims leading and trailing whitespace and newlines.
    case trimWhitespace
    /// Expands leading `~` or `~/` against `context.homeDirectory`.
    case expandTilde
    /// Expands `@path` file references (e.g. `@keys/AuthKey.p8` or `@~/key.pem`) using `context.fileSystem`,
    /// enforcing `requirePermissions` (default `0600`) when non-nil.
    case expandFileReference(requirePermissions: UInt16? = 0o600)
    /// Decodes standard or URL-safe Base64 text into raw bytes.
    case decodeBase64
    /// Decodes Base64 only when the string starts with `"base64:"`; otherwise passes bytes through unchanged.
    case decodeBase64IfPrefixed
    /// Unescapes literal `\n` sequences into real newlines and normalizes PEM armor header/body/footer whitespace.
    case normalizePEM
    /// Validates that the secret bytes form valid UTF-8 text and returns the UTF-8 `Data`.
    case utf8Data

    /// Applies this transform to `data`, returning transformed bytes and whether an `@file` reference was expanded.
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

    /// Runs a sequence of `SecretTransform`s in order.
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
        // Fallback to URL-safe Base64 (`-` -> `+`, `_` -> `/`, optional `=` padding)
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

        // Ensure PEM `-----BEGIN ...-----` and `-----END ...-----` markers sit on dedicated lines
        // even if the input was supplied as a single space-separated line.
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

/// Describes a single `@SecretSetting` field queued for batched secret resolution.
public struct SecretResolutionRequest: Sendable, Equatable {
    public let keyPath: [String]
    public let node: RawNode
    public let transforms: [SecretTransform]
    public let allowLiteralInProjectConfig: Bool
    public let expectedType: String?
    public let envVariableHint: String?

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

/// Output of resolving and transforming a single `@SecretSetting` field.
public struct ResolvedSecret: Sendable, Equatable {
    public let keyPath: [String]
    public let data: Data
    public let reference: SecretReference
    public let origin: SettingOrigin
    public let overriddenOrigins: [SettingOrigin]

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

    /// Decodes the resolved bytes as a UTF-8 `Secret<String>`.
    public func utf8Secret() throws -> Secret<String> {
        guard let string = String(data: data, encoding: .utf8) else {
            throw ValueDecodingError(
                expectedType: "Secret<String>",
                reason: "Resolved secret bytes are not valid UTF-8."
            )
        }
        return Secret(string)
    }

    /// Wraps the resolved bytes as `Secret<Data>`.
    public var dataSecret: Secret<Data> {
        Secret(data)
    }

    /// Wraps the resolved bytes as `Secret<[UInt8]>`.
    public var bytesSecret: Secret<[UInt8]> {
        Secret(Array(data))
    }

    /// Decodes the resolved secret bytes into any `SettingValueDecodable` payload wrapped in `Secret`.
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

/// Aggregated result of a two-phase batched secret resolution pass across an entire settings graph.
public struct SecretBatchResolutionResult: Sendable, Equatable {
    public let resolved: [ResolvedSecret]
    public let resolvedByKeyPath: [[String]: ResolvedSecret]
    public let issues: [ValidationIssue]

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
/// groups provider lookups by `(scheme, accountHint)`, enforces repo-committed plaintext guards,
/// registers resolved plaintext in `DiagnosticRedactor`, and applies `SecretTransform` pipelines.
public struct SecretResolver: Sendable {
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

    /// Executes two-phase batched resolution across all `requests`, accumulating any validation,
    /// unsafe-secret (`exitCode = 4`), or provider (`exitCode = 6`) issues without short-circuiting.
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
                    issues.append(Self.makeIssue(from: error, for: request))
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
                            for: request
                        )
                    )
                    continue
                } catch {
                    issues.append(Self.makeGenericIssue(from: error, for: request, defaultKind: .invalidValue))
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
                        issues.append(Self.makeIssue(from: error, for: request))
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
                    issues.append(Self.makeIssue(from: error, for: request))
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
                    issues.append(Self.makeGenericIssue(from: error, for: request, defaultKind: .invalidValue))
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
                    issues.append(Self.makeGenericIssue(from: error, for: request, defaultKind: .providerFailure))
                }

            case .providerBacked(let request, let ref):
                if let error = errorByRef[ref] {
                    issues.append(Self.makeGenericIssue(from: error, for: request, defaultKind: .providerFailure))
                    continue
                }

                guard let rawBytes = resolvedDataByRef[ref] else {
                    let error = SecretResolutionError.unresolvedReference(
                        referenceRedacted: ref.redactedDescription
                    )
                    issues.append(Self.makeIssue(from: error, for: request))
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
                    issues.append(Self.makeGenericIssue(from: error, for: request, defaultKind: .invalidValue))
                }
            }
        }

        return SecretBatchResolutionResult(resolved: resolvedOutputs, issues: issues)
    }

    /// Convenience helper for resolving a single `SecretResolutionRequest`, throwing `SettingsValidationError` on failure.
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
        for request: SecretResolutionRequest
    ) -> ValidationIssue {
        ValidationIssue(
            keyPath: request.keyPath,
            kind: error.issueKind,
            message: contextScrubSafeMessage(error.description),
            origin: request.node.origin,
            expectedType: request.expectedType,
            envVariableHint: request.envVariableHint,
            remediation: error.remediation
        )
    }

    private static func makeGenericIssue(
        from error: any Error,
        for request: SecretResolutionRequest,
        defaultKind: ValidationIssueKind
    ) -> ValidationIssue {
        if let secretError = error as? SecretResolutionError {
            return makeIssue(from: secretError, for: request)
        }
        if let refError = error as? SecretReferenceError {
            return makeIssue(from: .invalidReference(refError), for: request)
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
                message: subprocessError.description,
                origin: request.node.origin,
                expectedType: request.expectedType,
                envVariableHint: request.envVariableHint,
                remediation: remediation
            )
        }
        if let issue = error as? ValidationIssue {
            return issue
        }
        return ValidationIssue(
            keyPath: request.keyPath,
            kind: defaultKind,
            message: String(describing: error),
            origin: request.node.origin,
            expectedType: request.expectedType,
            envVariableHint: request.envVariableHint
        )
    }

    private static func contextScrubSafeMessage(_ message: String) -> String {
        message
    }
}
