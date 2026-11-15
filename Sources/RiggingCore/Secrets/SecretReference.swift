import Foundation

/// Validation errors thrown when parsing a malformed or security-sensitive secret URI reference.
public enum SecretReferenceError: Error, Sendable, Equatable, Hashable, CustomStringConvertible, LocalizedError {
    /// Input contained an embedded NUL (`\0` or `%00`) byte.
    case containsNullByte

    /// Non-literal secret URI contained illegal ASCII control characters such as `\r` or `\n`.
    case containsControlCharacter(scheme: String)

    /// Percent-encoding inside a secret URI component was malformed.
    case invalidPercentEncoding(scheme: String, component: String)

    /// URI segment or query value started with `-`, which is rejected to prevent CLI option injection.
    case optionInjection(scheme: String, segment: String)

    /// URI path attempted relative directory traversal (`.` or `..`) where disallowed.
    case pathTraversal(scheme: String, segment: String)

    /// URI structure did not match the expected syntax for its scheme.
    case invalidFormat(scheme: String, message: String)

    /// Query parameter carried an unrecognized or malformed value.
    case invalidQueryParameter(scheme: String, name: String, value: String)

    /// Human-readable description of the URI syntax or security violation.
    public var description: String {
        switch self {
        case .containsNullByte:
            return "Secret reference must not contain embedded NUL bytes."
        case .containsControlCharacter(let scheme):
            return "Secret reference with scheme '\(scheme)' must not contain control characters or newlines."
        case .invalidPercentEncoding(let scheme, let component):
            return "Malformed percent-encoding in '\(scheme)://' secret reference component '\(component)'."
        case .optionInjection(let scheme, let segment):
            return "Unsafe '\(scheme)://' secret reference segment '\(segment)': segments starting with '-' are rejected to prevent CLI option injection."
        case .pathTraversal(let scheme, let segment):
            return "Unsafe '\(scheme)://' secret reference segment '\(segment)': relative path traversal segments ('.' or '..') are rejected."
        case .invalidFormat(let scheme, let message):
            return "Invalid '\(scheme)' secret reference: \(message)"
        case .invalidQueryParameter(let scheme, let name, let value):
            return "Invalid query parameter '\(name)=\(value)' in '\(scheme)://' secret reference."
        }
    }

    /// Localized error description matching ``description`` for CLI error reporters.
    public var errorDescription: String? {
        description
    }
}

/// A decoded query parameter attached to a secret URI reference.
public struct SecretQueryItem: Sendable, Equatable, Hashable, Codable {
    /// Decoded query parameter name.
    public let name: String

    /// Decoded query parameter value, or `nil` when supplied without `=`.
    public let value: String?

    /// Creates a decoded query parameter item.
    ///
    /// - Parameters:
    ///   - name: Parameter identifier.
    ///   - value: Optional decoded parameter value.
    public init(name: String, value: String?) {
        self.name = name
        self.value = value
    }
}

/// A parsed 1Password secret reference (`op://<vault>/<item>/[section/]<field>[?account=...]`).
public struct OnePasswordSecretReference: Sendable, Equatable, Hashable {
    /// Vault name or UUID.
    public let vault: String

    /// Item title or UUID.
    public let item: String

    /// Optional section label within the item.
    public let section: String?

    /// Field label or identifier.
    public let field: String

    /// Optional 1Password account shorthand or URL extracted from `?account=...`.
    public let accountHint: String?

    /// Ordered query items attached to the `op://` URI.
    public let queryItems: [SecretQueryItem]

    /// Creates a structured 1Password secret reference.
    ///
    /// - Parameters:
    ///   - vault: Vault name or UUID.
    ///   - item: Item title or UUID.
    ///   - section: Optional section label.
    ///   - field: Field label or identifier.
    ///   - accountHint: Optional account selector for multi-account CLI batching.
    ///   - queryItems: Additional decoded query items.
    public init(
        vault: String,
        item: String,
        section: String? = nil,
        field: String,
        accountHint: String? = nil,
        queryItems: [SecretQueryItem] = []
    ) {
        self.vault = vault
        self.item = item
        self.section = section
        self.field = field
        self.accountHint = accountHint
        self.queryItems = queryItems
    }

    /// Dictionary view of ``queryItems`` where the last occurrence of a key wins.
    public var query: [String: String] {
        var result: [String: String] = [:]
        for item in queryItems {
            result[item.name] = item.value ?? ""
        }
        return result
    }

    /// Canonical `op://` URI suitable for `op read` or `op inject`, stripping the `account` query item
    /// so it can be forwarded via `--account`.
    public var opReadURI: String {
        var path = "op://\(Self.encodeSegment(vault))/\(Self.encodeSegment(item))/"
        if let section {
            path += "\(Self.encodeSegment(section))/"
        }
        path += Self.encodeSegment(field)

        let forwarded = queryItems.filter { $0.name != "account" }
        if !forwarded.isEmpty {
            let queryString = forwarded.map { item in
                if let value = item.value {
                    return "\(Self.encodeQueryComponent(item.name))=\(Self.encodeQueryComponent(value))"
                }
                return Self.encodeQueryComponent(item.name)
            }.joined(separator: "&")
            path += "?\(queryString)"
        }
        return path
    }

    private static let segmentAllowed: CharacterSet = {
        var set = CharacterSet.urlPathAllowed
        set.remove(charactersIn: "/?#")
        return set
    }()

    private static let queryAllowed: CharacterSet = {
        var set = CharacterSet.urlQueryAllowed
        set.remove(charactersIn: "&=?#")
        return set
    }()

    private static func encodeSegment(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: segmentAllowed) ?? value
    }

    private static func encodeQueryComponent(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: queryAllowed) ?? value
    }
}

/// A parsed Apple Keychain secret reference (`keychain://<service>/<account>[?accessGroup=...&synchronizable=...]`).
public struct KeychainSecretReference: Sendable, Equatable, Hashable {
    /// Keychain generic-password service name (`kSecAttrService`).
    public let service: String

    /// Keychain generic-password account name (`kSecAttrAccount`).
    public let account: String

    /// Optional Keychain access group (`kSecAttrAccessGroup`).
    public let accessGroup: String?

    /// Optional iCloud Keychain synchronization flag (`kSecAttrSynchronizable`).
    public let synchronizable: Bool?

    /// Ordered query items attached to the `keychain://` URI.
    public let queryItems: [SecretQueryItem]

    /// Creates a structured Apple Keychain secret reference.
    ///
    /// - Parameters:
    ///   - service: Keychain service identifier (for example, `"com.example.asc"`).
    ///   - account: Keychain account identifier.
    ///   - accessGroup: Optional shared Keychain access group.
    ///   - synchronizable: Optional iCloud Keychain synchronization filter.
    ///   - queryItems: Decoded query items.
    public init(
        service: String,
        account: String,
        accessGroup: String? = nil,
        synchronizable: Bool? = nil,
        queryItems: [SecretQueryItem] = []
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
        self.synchronizable = synchronizable
        self.queryItems = queryItems
    }

    /// Dictionary view of ``queryItems`` where the last occurrence of a key wins.
    public var query: [String: String] {
        var result: [String: String] = [:]
        for item in queryItems {
            result[item.name] = item.value ?? ""
        }
        return result
    }
}

/// A parsed Bitwarden Secrets Manager reference (`bws://<secret-uuid>[?account=...]`).
public struct BitwardenSecretsManagerReference: Sendable, Equatable, Hashable {
    /// Machine-account secret UUID in Bitwarden Secrets Manager.
    public let secretID: String

    /// Optional account/profile hint extracted from `?account=...`.
    public let accountHint: String?

    /// Ordered query items attached to the `bws://` URI.
    public let queryItems: [SecretQueryItem]

    /// Creates a structured Bitwarden Secrets Manager reference.
    ///
    /// - Parameters:
    ///   - secretID: Bitwarden Secrets Manager secret identifier.
    ///   - accountHint: Optional account hint for batch partitioning.
    ///   - queryItems: Decoded query items.
    public init(secretID: String, accountHint: String? = nil, queryItems: [SecretQueryItem] = []) {
        self.secretID = secretID
        self.accountHint = accountHint
        self.queryItems = queryItems
    }

    /// Dictionary view of ``queryItems`` where the last occurrence of a key wins.
    public var query: [String: String] {
        var result: [String: String] = [:]
        for item in queryItems {
            result[item.name] = item.value ?? ""
        }
        return result
    }
}

/// A parsed Bitwarden Vault CLI reference (`bw://<item-id>/<field>[?account=...]`).
public struct BitwardenVaultReference: Sendable, Equatable, Hashable {
    /// Vault item UUID or unique name.
    public let itemID: String

    /// Target field (`"password"`, `"username"`, `"notes"`, or custom field name).
    public let field: String

    /// Optional account/profile hint extracted from `?account=...`.
    public let accountHint: String?

    /// Ordered query items attached to the `bw://` URI.
    public let queryItems: [SecretQueryItem]

    /// Creates a structured Bitwarden Vault reference.
    ///
    /// - Parameters:
    ///   - itemID: Bitwarden vault item UUID or name.
    ///   - field: Field selector within the vault item.
    ///   - accountHint: Optional account hint for batch partitioning.
    ///   - queryItems: Decoded query items.
    public init(
        itemID: String,
        field: String,
        accountHint: String? = nil,
        queryItems: [SecretQueryItem] = []
    ) {
        self.itemID = itemID
        self.field = field
        self.accountHint = accountHint
        self.queryItems = queryItems
    }

    /// Dictionary view of ``queryItems`` where the last occurrence of a key wins.
    public var query: [String: String] {
        var result: [String: String] = [:]
        for item in queryItems {
            result[item.name] = item.value ?? ""
        }
        return result
    }
}

/// A parsed Unix `pass` password-store reference (`pass://<entry-path>[#fragment]`).
public struct PassSecretReference: Sendable, Equatable, Hashable {
    /// Slash-delimited entry path inside `~/.password-store`.
    public let entryPath: String

    /// Optional fragment selector (such as `"password"`, `"line:2"`, or a `key: value` metadata key).
    public let fragment: String?

    /// Optional store/account hint extracted from `?account=...` or `?store=...`.
    public let accountHint: String?

    /// Ordered query items attached to the `pass://` URI.
    public let queryItems: [SecretQueryItem]

    /// Creates a structured Unix `pass` reference.
    ///
    /// - Parameters:
    ///   - entryPath: Relative entry path inside the password store.
    ///   - fragment: Optional `#fragment` line or field selector.
    ///   - accountHint: Optional password-store selector for batch partitioning.
    ///   - queryItems: Decoded query items.
    public init(
        entryPath: String,
        fragment: String? = nil,
        accountHint: String? = nil,
        queryItems: [SecretQueryItem] = []
    ) {
        self.entryPath = entryPath
        self.fragment = fragment
        self.accountHint = accountHint
        self.queryItems = queryItems
    }

    /// Dictionary view of ``queryItems`` where the last occurrence of a key wins.
    public var query: [String: String] {
        var result: [String: String] = [:]
        for item in queryItems {
            result[item.name] = item.value ?? ""
        }
        return result
    }
}

/// A parsed Mozilla SOPS encrypted-file reference (`sops://<file-path>#<json-pointer>`).
public struct SopsSecretReference: Sendable, Equatable, Hashable {
    /// Path to the SOPS-encrypted file.
    public let filePath: String

    /// Optional JSON Pointer or key path fragment after `#`.
    public let jsonPointer: String?

    /// Optional account/profile hint extracted from `?account=...`.
    public let accountHint: String?

    /// Ordered query items attached to the `sops://` URI.
    public let queryItems: [SecretQueryItem]

    /// Creates a structured SOPS secret reference.
    ///
    /// - Parameters:
    ///   - filePath: Path to the encrypted SOPS document.
    ///   - jsonPointer: Optional JSON Pointer fragment.
    ///   - accountHint: Optional account hint for batch partitioning.
    ///   - queryItems: Decoded query items.
    public init(
        filePath: String,
        jsonPointer: String? = nil,
        accountHint: String? = nil,
        queryItems: [SecretQueryItem] = []
    ) {
        self.filePath = filePath
        self.jsonPointer = jsonPointer
        self.accountHint = accountHint
        self.queryItems = queryItems
    }

    /// Dictionary view of ``queryItems`` where the last occurrence of a key wins.
    public var query: [String: String] {
        var result: [String: String] = [:]
        for item in queryItems {
            result[item.name] = item.value ?? ""
        }
        return result
    }
}

/// A parsed local-file secret reference (`file:///abs/path` or `@~/path`, `@/abs/path`, `@./rel/path`).
public struct FileSecretReference: Sendable, Equatable, Hashable {
    /// Lexical syntax used to write the file secret reference.
    public enum Syntax: String, Sendable, Equatable, Hashable, Codable {
        /// Standard `file:///path` URI syntax.
        case fileURI

        /// Shorthand `@~/path`, `@/path`, or `@./path` syntax.
        case atPath
    }

    /// Decoded filesystem path (prior to tilde or working-directory expansion).
    public let path: String

    /// Original notation used to specify the file reference.
    public let syntax: Syntax

    /// Creates a local-file secret reference.
    ///
    /// - Parameters:
    ///   - path: Decoded file path.
    ///   - syntax: Notation style (`.fileURI` or `.atPath`).
    public init(path: String, syntax: Syntax) {
        self.path = path
        self.syntax = syntax
    }
}

/// A parsed indirect environment-variable secret reference (`env://<VAR_NAME>`).
public struct EnvSecretReference: Sendable, Equatable, Hashable {
    /// Validated POSIX environment variable identifier (`[A-Za-z_][A-Za-z0-9_]*`).
    public let variableName: String

    /// Creates an indirect environment-variable secret reference.
    ///
    /// - Parameter variableName: Environment variable identifier.
    public init(variableName: String) {
        self.variableName = variableName
    }
}

/// A parsed extensible URI reference routed to a custom ``SecretProvider`` registered in ``SettingsContext``.
public struct CustomSecretReference: Sendable, Equatable, Hashable {
    /// Lowercase custom URI scheme name (for example, `"vault"` or `"aws-sm"`).
    public let scheme: String

    /// Decoded path portion following `<scheme>://`.
    public let path: String

    /// Optional account/profile hint extracted from `?account=...`.
    public let accountHint: String?

    /// Ordered query items attached to the custom URI.
    public let queryItems: [SecretQueryItem]

    /// Optional decoded `#fragment` component.
    public let fragment: String?

    /// Creates a custom-scheme secret reference.
    ///
    /// - Parameters:
    ///   - scheme: Lowercase URI scheme identifier.
    ///   - path: Decoded URI path.
    ///   - accountHint: Optional account hint for batch partitioning.
    ///   - queryItems: Decoded query items.
    ///   - fragment: Optional decoded fragment.
    public init(
        scheme: String,
        path: String,
        accountHint: String? = nil,
        queryItems: [SecretQueryItem] = [],
        fragment: String? = nil
    ) {
        self.scheme = scheme
        self.path = path
        self.accountHint = accountHint
        self.queryItems = queryItems
        self.fragment = fragment
    }

    /// Dictionary view of ``queryItems`` where the last occurrence of a key wins.
    public var query: [String: String] {
        var result: [String: String] = [:]
        for item in queryItems {
            result[item.name] = item.value ?? ""
        }
        return result
    }
}

/// Parsed representation of a raw secret configuration string prior to provider resolution.
///
/// `SecretReference` distinguishes structured vault URIs (`op://`, `keychain://`, `bws://`, `bw://`,
/// `pass://`, `sops://`, `file://`, `@path`, `env://`, and custom provider schemes) from inline
/// `.literal` values, while rejecting embedded NUL bytes and leading-hyphen option-injection segments
/// before any external CLI binary is invoked.
///
/// ```swift
/// let ref = try SecretReference.parse("op://Engineering/AppStoreConnect/private_key?account=acme")
/// // ref.scheme == "op"
/// // ref.accountHint == "acme"
/// ```
public enum SecretReference: Sendable, Equatable, Hashable, CustomStringConvertible {
    /// A 1Password `op://` reference.
    case onePassword(OnePasswordSecretReference)

    /// An Apple Keychain `keychain://` reference.
    case keychain(KeychainSecretReference)

    /// A Bitwarden Secrets Manager `bws://` reference.
    case bitwardenSecretsManager(BitwardenSecretsManagerReference)

    /// A Bitwarden Vault `bw://` reference.
    case bitwardenVault(BitwardenVaultReference)

    /// A Unix `pass://` password-store reference.
    case pass(PassSecretReference)

    /// A Mozilla SOPS `sops://` encrypted-file reference.
    case sops(SopsSecretReference)

    /// A local file `file://` or `@path` reference.
    case file(FileSecretReference)

    /// An indirect `env://` environment variable reference.
    case env(EnvSecretReference)

    /// A custom URI reference handled by a user-supplied ``SecretProvider``.
    case custom(CustomSecretReference)

    /// An inline literal secret string (redacted as `"<literal>"` in provenance and descriptions).
    case literal(String)

    /// Provider scheme identifier (`"op"`, `"keychain"`, `"bws"`, `"bw"`, `"pass"`, `"sops"`, `"file"`, `"env"`, custom scheme, or `"literal"`).
    public var scheme: String {
        switch self {
        case .onePassword: return "op"
        case .keychain: return "keychain"
        case .bitwardenSecretsManager: return "bws"
        case .bitwardenVault: return "bw"
        case .pass: return "pass"
        case .sops: return "sops"
        case .file: return "file"
        case .env: return "env"
        case .custom(let ref): return ref.scheme
        case .literal: return "literal"
        }
    }

    /// Optional account or profile selector used by ``SecretResolver`` to group batched provider calls.
    public var accountHint: String? {
        switch self {
        case .onePassword(let ref): return ref.accountHint
        case .keychain: return nil
        case .bitwardenSecretsManager(let ref): return ref.accountHint
        case .bitwardenVault(let ref): return ref.accountHint
        case .pass(let ref): return ref.accountHint
        case .sops(let ref): return ref.accountHint
        case .file: return nil
        case .env: return nil
        case .custom(let ref): return ref.accountHint
        case .literal: return nil
        }
    }

    /// Indicates whether this value is an inline `.literal` secret rather than a provider URI.
    public var isLiteral: Bool {
        if case .literal = self { return true }
        return false
    }

    /// Redacted provenance label preserving non-sensitive URI paths while masking `.literal` payloads as `"<literal>"`.
    public var redactedDescription: String {
        switch self {
        case .onePassword(let ref):
            if let section = ref.section {
                return "op://\(ref.vault)/\(ref.item)/\(section)/\(ref.field)"
            }
            return "op://\(ref.vault)/\(ref.item)/\(ref.field)"
        case .keychain(let ref):
            return "keychain://\(ref.service)/\(ref.account)"
        case .bitwardenSecretsManager(let ref):
            return "bws://\(ref.secretID)"
        case .bitwardenVault(let ref):
            return "bw://\(ref.itemID)/\(ref.field)"
        case .pass(let ref):
            if let fragment = ref.fragment {
                return "pass://\(ref.entryPath)#\(fragment)"
            }
            return "pass://\(ref.entryPath)"
        case .sops(let ref):
            if let pointer = ref.jsonPointer {
                return "sops://\(ref.filePath)#\(pointer)"
            }
            return "sops://\(ref.filePath)"
        case .file(let ref):
            switch ref.syntax {
            case .atPath:
                return "@\(ref.path)"
            case .fileURI:
                return "file://\(ref.path)"
            }
        case .env(let ref):
            return "env://\(ref.variableName)"
        case .custom(let ref):
            if let fragment = ref.fragment {
                return "\(ref.scheme)://\(ref.path)#\(fragment)"
            }
            return "\(ref.scheme)://\(ref.path)"
        case .literal:
            return "<literal>"
        }
    }

    /// Safe textual representation matching ``redactedDescription``.
    public var description: String {
        redactedDescription
    }

    /// Parses a raw secret configuration string into a ``SecretReference``.
    ///
    /// - Parameters:
    ///   - raw: Raw configuration string to parse.
    ///   - additionalSchemes: Custom URI schemes registered via ``SettingsContext/secretProviders``.
    /// - Throws: ``SecretReferenceError`` when the URI is malformed or contains unsafe characters.
    public init(parsing raw: String, additionalSchemes: Set<String> = []) throws {
        self = try Self.parse(raw, additionalSchemes: additionalSchemes)
    }

    // MARK: - Parser

    private static let builtInSchemes: Set<String> = [
        "op", "keychain", "bws", "bw", "pass", "sops", "file", "env"
    ]

    /// Parses a raw configuration string into a ``SecretReference``, enforcing strict validation
    /// against embedded NUL bytes, control characters, path traversal, and leading-`-` option injection.
    ///
    /// - Parameters:
    ///   - raw: Raw configuration string to classify and validate.
    ///   - additionalSchemes: Custom URI schemes supported by registered ``SecretProvider`` instances.
    /// - Returns: A validated ``SecretReference``.
    /// - Throws: ``SecretReferenceError`` when a recognized URI scheme has invalid or unsafe syntax.
    public static func parse(
        _ raw: String,
        additionalSchemes: Set<String> = []
    ) throws -> SecretReference {
        if raw.utf8.contains(0) {
            throw SecretReferenceError.containsNullByte
        }

        // Handle @path shorthand (@~/..., @/..., @./..., @../...)
        if raw.hasPrefix("@~/") || raw.hasPrefix("@/") || raw.hasPrefix("@./") || raw.hasPrefix("@../") {
            let path = String(raw.dropFirst())
            try ensureNoControlCharacters(in: path, scheme: "@file")
            let suffixAfterPrefix: Substring
            if path.hasPrefix("~/") {
                suffixAfterPrefix = path.dropFirst(2)
            } else if path.hasPrefix("./") {
                suffixAfterPrefix = path.dropFirst(2)
            } else if path.hasPrefix("../") {
                suffixAfterPrefix = path.dropFirst(3)
            } else {
                suffixAfterPrefix = path.dropFirst(1)
            }
            guard !suffixAfterPrefix.isEmpty else {
                throw SecretReferenceError.invalidFormat(
                    scheme: "@file",
                    message: "File reference '\(raw)' must specify a file path."
                )
            }
            return .file(FileSecretReference(path: path, syntax: .atPath))
        }

        // Check for `<scheme>://` prefix
        if let range = raw.range(of: "://") {
            let candidateScheme = String(raw[..<range.lowerBound]).lowercased()
            let isBuiltIn = builtInSchemes.contains(candidateScheme)
            let isCustom = !isBuiltIn && additionalSchemes.contains(candidateScheme)

            if isBuiltIn || isCustom {
                let remainder = String(raw[range.upperBound...])
                try ensureNoControlCharacters(in: remainder, scheme: candidateScheme)

                switch candidateScheme {
                case "op":
                    return try parseOnePassword(remainder)
                case "keychain":
                    return try parseKeychain(remainder)
                case "bws":
                    return try parseBitwardenSecretsManager(remainder)
                case "bw":
                    return try parseBitwardenVault(remainder)
                case "pass":
                    return try parsePass(remainder)
                case "sops":
                    return try parseSops(remainder)
                case "file":
                    return try parseFileURI(remainder)
                case "env":
                    return try parseEnv(remainder)
                default:
                    return try parseCustom(scheme: candidateScheme, remainder: remainder)
                }
            }
        }

        return .literal(raw)
    }

    // MARK: - Scheme Parsers

    private static func parseOnePassword(_ remainder: String) throws -> SecretReference {
        let parts = try splitURI(remainder, scheme: "op", allowFragment: false)
        let rawSegments = parts.path.split(separator: "/", omittingEmptySubsequences: false)
        guard (3...4).contains(rawSegments.count) else {
            throw SecretReferenceError.invalidFormat(
                scheme: "op",
                message: "Expected 'op://<vault>/<item>/[section/]<field>' (got \(rawSegments.count) path segments)."
            )
        }

        let segments = try rawSegments.map {
            try decodeAndValidateSegment(String($0), scheme: "op")
        }

        let queryItems = try parseQuery(parts.query, scheme: "op")
        let accountHint = queryItems.last(where: { $0.name == "account" })?.value

        if segments.count == 3 {
            return .onePassword(
                OnePasswordSecretReference(
                    vault: segments[0],
                    item: segments[1],
                    section: nil,
                    field: segments[2],
                    accountHint: accountHint,
                    queryItems: queryItems
                )
            )
        } else {
            return .onePassword(
                OnePasswordSecretReference(
                    vault: segments[0],
                    item: segments[1],
                    section: segments[2],
                    field: segments[3],
                    accountHint: accountHint,
                    queryItems: queryItems
                )
            )
        }
    }

    private static func parseKeychain(_ remainder: String) throws -> SecretReference {
        let parts = try splitURI(remainder, scheme: "keychain", allowFragment: false)
        let rawSegments = parts.path.split(separator: "/", omittingEmptySubsequences: false)
        guard rawSegments.count == 2 else {
            throw SecretReferenceError.invalidFormat(
                scheme: "keychain",
                message: "Expected 'keychain://<service>/<account>' (percent-encode '/' as '%2F' inside service or account names)."
            )
        }

        let service = try decodeAndValidateSegment(String(rawSegments[0]), scheme: "keychain")
        let account = try decodeAndValidateSegment(String(rawSegments[1]), scheme: "keychain")
        let queryItems = try parseQuery(parts.query, scheme: "keychain")

        var accessGroup: String?
        var synchronizable: Bool?

        for item in queryItems {
            switch item.name {
            case "accessGroup":
                guard let value = item.value, !value.isEmpty else {
                    throw SecretReferenceError.invalidQueryParameter(
                        scheme: "keychain",
                        name: "accessGroup",
                        value: ""
                    )
                }
                accessGroup = value
            case "synchronizable":
                let rawValue = item.value ?? ""
                switch rawValue.lowercased() {
                case "true", "1", "yes":
                    synchronizable = true
                case "false", "0", "no":
                    synchronizable = false
                default:
                    throw SecretReferenceError.invalidQueryParameter(
                        scheme: "keychain",
                        name: "synchronizable",
                        value: rawValue
                    )
                }
            default:
                break
            }
        }

        return .keychain(
            KeychainSecretReference(
                service: service,
                account: account,
                accessGroup: accessGroup,
                synchronizable: synchronizable,
                queryItems: queryItems
            )
        )
    }

    private static func parseBitwardenSecretsManager(_ remainder: String) throws -> SecretReference {
        let parts = try splitURI(remainder, scheme: "bws", allowFragment: false)
        guard !parts.path.contains("/") else {
            throw SecretReferenceError.invalidFormat(
                scheme: "bws",
                message: "Expected 'bws://<secret-uuid>' with a single identifier segment."
            )
        }

        let secretID = try decodeAndValidateSegment(parts.path, scheme: "bws")
        let queryItems = try parseQuery(parts.query, scheme: "bws")
        let accountHint = queryItems.last(where: { $0.name == "account" })?.value

        return .bitwardenSecretsManager(
            BitwardenSecretsManagerReference(
                secretID: secretID,
                accountHint: accountHint,
                queryItems: queryItems
            )
        )
    }

    private static func parseBitwardenVault(_ remainder: String) throws -> SecretReference {
        let parts = try splitURI(remainder, scheme: "bw", allowFragment: false)
        let rawSegments = parts.path.split(separator: "/", omittingEmptySubsequences: false)
        guard rawSegments.count == 2 else {
            throw SecretReferenceError.invalidFormat(
                scheme: "bw",
                message: "Expected 'bw://<item-id>/<field>'."
            )
        }

        let itemID = try decodeAndValidateSegment(String(rawSegments[0]), scheme: "bw")
        let field = try decodeAndValidateSegment(String(rawSegments[1]), scheme: "bw")
        let queryItems = try parseQuery(parts.query, scheme: "bw")
        let accountHint = queryItems.last(where: { $0.name == "account" })?.value

        return .bitwardenVault(
            BitwardenVaultReference(
                itemID: itemID,
                field: field,
                accountHint: accountHint,
                queryItems: queryItems
            )
        )
    }

    private static func parsePass(_ remainder: String) throws -> SecretReference {
        let parts = try splitURI(remainder, scheme: "pass", allowFragment: true)
        guard !parts.path.isEmpty else {
            throw SecretReferenceError.invalidFormat(
                scheme: "pass",
                message: "Expected 'pass://<entry-path>[#fragment]'."
            )
        }

        let rawSegments = parts.path.split(separator: "/", omittingEmptySubsequences: false)
        var validatedSegments: [String] = []
        validatedSegments.reserveCapacity(rawSegments.count)

        for rawSeg in rawSegments {
            let decoded = try decodeAndValidateSegment(String(rawSeg), scheme: "pass")
            if decoded == "." || decoded == ".." {
                throw SecretReferenceError.pathTraversal(scheme: "pass", segment: decoded)
            }
            validatedSegments.append(decoded)
        }

        var fragment: String?
        if let rawFragment = parts.fragment {
            let decodedFragment = try percentDecode(rawFragment, scheme: "pass")
            guard !decodedFragment.isEmpty else {
                throw SecretReferenceError.invalidFormat(
                    scheme: "pass",
                    message: "Fragment after '#' in 'pass://' reference must not be empty."
                )
            }
            if decodedFragment.hasPrefix("-") {
                throw SecretReferenceError.optionInjection(scheme: "pass", segment: decodedFragment)
            }
            fragment = decodedFragment
        }

        let queryItems = try parseQuery(parts.query, scheme: "pass")
        let accountHint = queryItems.last(where: { $0.name == "account" || $0.name == "store" })?.value

        return .pass(
            PassSecretReference(
                entryPath: validatedSegments.joined(separator: "/"),
                fragment: fragment,
                accountHint: accountHint,
                queryItems: queryItems
            )
        )
    }

    private static func parseSops(_ remainder: String) throws -> SecretReference {
        let parts = try splitURI(remainder, scheme: "sops", allowFragment: true)
        let decodedPath = try percentDecode(parts.path, scheme: "sops")
        guard !decodedPath.isEmpty else {
            throw SecretReferenceError.invalidFormat(
                scheme: "sops",
                message: "Expected 'sops://<file-path>#<json-pointer>'."
            )
        }
        if decodedPath.hasPrefix("-") {
            throw SecretReferenceError.optionInjection(scheme: "sops", segment: decodedPath)
        }
        for segment in decodedPath.split(separator: "/") {
            if segment.hasPrefix("-") {
                throw SecretReferenceError.optionInjection(scheme: "sops", segment: String(segment))
            }
        }

        var pointer: String?
        if let rawFragment = parts.fragment {
            let decodedFragment = try percentDecode(rawFragment, scheme: "sops")
            guard !decodedFragment.isEmpty else {
                throw SecretReferenceError.invalidFormat(
                    scheme: "sops",
                    message: "JSON pointer fragment after '#' in 'sops://' reference must not be empty."
                )
            }
            if decodedFragment.hasPrefix("-") {
                throw SecretReferenceError.optionInjection(scheme: "sops", segment: decodedFragment)
            }
            pointer = decodedFragment
        }

        let queryItems = try parseQuery(parts.query, scheme: "sops")
        let accountHint = queryItems.last(where: { $0.name == "account" })?.value

        return .sops(
            SopsSecretReference(
                filePath: decodedPath,
                jsonPointer: pointer,
                accountHint: accountHint,
                queryItems: queryItems
            )
        )
    }

    private static func parseFileURI(_ remainder: String) throws -> SecretReference {
        if remainder.contains("?") || remainder.contains("#") {
            throw SecretReferenceError.invalidFormat(
                scheme: "file",
                message: "'file://' secret references must not contain query or fragment components."
            )
        }

        let rawPath: String
        if remainder.hasPrefix("localhost/") {
            rawPath = String(remainder.dropFirst("localhost".count))
        } else if remainder.hasPrefix("/") || remainder.hasPrefix("~/") {
            rawPath = remainder
        } else {
            throw SecretReferenceError.invalidFormat(
                scheme: "file",
                message: "Expected an absolute path 'file:///abs/path' (or use '@./relative/path' for relative files)."
            )
        }

        let decodedPath = try percentDecode(rawPath, scheme: "file")
        guard decodedPath != "/" && decodedPath != "~/" && !decodedPath.isEmpty else {
            throw SecretReferenceError.invalidFormat(
                scheme: "file",
                message: "'file://' reference must point to a secret file, not root directory."
            )
        }

        for segment in decodedPath.split(separator: "/") where segment.hasPrefix("-") {
            throw SecretReferenceError.optionInjection(scheme: "file", segment: String(segment))
        }

        return .file(FileSecretReference(path: decodedPath, syntax: .fileURI))
    }

    private static func parseEnv(_ remainder: String) throws -> SecretReference {
        if remainder.contains("/") || remainder.contains("?") || remainder.contains("#") {
            throw SecretReferenceError.invalidFormat(
                scheme: "env",
                message: "Expected 'env://<VAR_NAME>' with a single environment variable identifier."
            )
        }

        let decoded = try decodeAndValidateSegment(remainder, scheme: "env")
        guard isValidEnvironmentVariableName(decoded) else {
            throw SecretReferenceError.invalidFormat(
                scheme: "env",
                message: "Environment variable name '\(decoded)' must match [A-Za-z_][A-Za-z0-9_]*."
            )
        }

        return .env(EnvSecretReference(variableName: decoded))
    }

    private static func parseCustom(scheme: String, remainder: String) throws -> SecretReference {
        let parts = try splitURI(remainder, scheme: scheme, allowFragment: true)
        let decodedPath = try percentDecode(parts.path, scheme: scheme)
        guard !decodedPath.isEmpty else {
            throw SecretReferenceError.invalidFormat(
                scheme: scheme,
                message: "Path in '\(scheme)://' reference must not be empty."
            )
        }
        if decodedPath.hasPrefix("-") {
            throw SecretReferenceError.optionInjection(scheme: scheme, segment: decodedPath)
        }
        for seg in decodedPath.split(separator: "/") where seg.hasPrefix("-") {
            throw SecretReferenceError.optionInjection(scheme: scheme, segment: String(seg))
        }

        var decodedFragment: String?
        if let rawFragment = parts.fragment {
            let frag = try percentDecode(rawFragment, scheme: scheme)
            if frag.hasPrefix("-") {
                throw SecretReferenceError.optionInjection(scheme: scheme, segment: frag)
            }
            decodedFragment = frag
        }

        let queryItems = try parseQuery(parts.query, scheme: scheme)
        let accountHint = queryItems.last(where: { $0.name == "account" })?.value

        return .custom(
            CustomSecretReference(
                scheme: scheme,
                path: decodedPath,
                accountHint: accountHint,
                queryItems: queryItems,
                fragment: decodedFragment
            )
        )
    }

    // MARK: - Low-Level Sanitization Helpers

    private struct URIParts {
        let path: String
        let query: String?
        let fragment: String?
    }

    private static func splitURI(
        _ remainder: String,
        scheme: String,
        allowFragment: Bool
    ) throws -> URIParts {
        var working = remainder
        var fragment: String?

        if let hashIndex = working.firstIndex(of: "#") {
            guard allowFragment else {
                throw SecretReferenceError.invalidFormat(
                    scheme: scheme,
                    message: "Fragment '#' is not supported in '\(scheme)://' secret references."
                )
            }
            fragment = String(working[working.index(after: hashIndex)...])
            working = String(working[..<hashIndex])
        }

        var query: String?
        if let questionIndex = working.firstIndex(of: "?") {
            query = String(working[working.index(after: questionIndex)...])
            working = String(working[..<questionIndex])
        }

        return URIParts(path: working, query: query, fragment: fragment)
    }

    private static func parseQuery(_ rawQuery: String?, scheme: String) throws -> [SecretQueryItem] {
        guard let rawQuery, !rawQuery.isEmpty else { return [] }
        let pairs = rawQuery.split(separator: "&", omittingEmptySubsequences: false)
        var items: [SecretQueryItem] = []
        items.reserveCapacity(pairs.count)

        for pair in pairs {
            guard !pair.isEmpty else {
                throw SecretReferenceError.invalidFormat(
                    scheme: scheme,
                    message: "Empty query parameter in '\(scheme)://' reference."
                )
            }
            if let eqIndex = pair.firstIndex(of: "=") {
                let rawName = String(pair[..<eqIndex])
                let rawValue = String(pair[pair.index(after: eqIndex)...])
                let name = try decodeAndValidateSegment(rawName, scheme: scheme)
                let value = try percentDecode(rawValue, scheme: scheme)
                if value.hasPrefix("-") {
                    throw SecretReferenceError.optionInjection(scheme: scheme, segment: value)
                }
                items.append(SecretQueryItem(name: name, value: value))
            } else {
                let name = try decodeAndValidateSegment(String(pair), scheme: scheme)
                items.append(SecretQueryItem(name: name, value: nil))
            }
        }

        return items
    }

    private static func decodeAndValidateSegment(_ rawSegment: String, scheme: String) throws -> String {
        let decoded = try percentDecode(rawSegment, scheme: scheme)
        guard !decoded.isEmpty else {
            throw SecretReferenceError.invalidFormat(
                scheme: scheme,
                message: "Path or query segment in '\(scheme)://' reference must not be empty."
            )
        }
        if decoded.hasPrefix("-") {
            throw SecretReferenceError.optionInjection(scheme: scheme, segment: decoded)
        }
        return decoded
    }

    private static func percentDecode(_ value: String, scheme: String) throws -> String {
        guard let decoded = value.removingPercentEncoding else {
            throw SecretReferenceError.invalidPercentEncoding(scheme: scheme, component: value)
        }
        if decoded.utf8.contains(0) {
            throw SecretReferenceError.containsNullByte
        }
        try ensureNoControlCharacters(in: decoded, scheme: scheme)
        return decoded
    }

    private static func ensureNoControlCharacters(in value: String, scheme: String) throws {
        for scalar in value.unicodeScalars {
            if scalar.value < 0x20 || scalar.value == 0x7F {
                throw SecretReferenceError.containsControlCharacter(scheme: scheme)
            }
        }
    }

    private static func isValidEnvironmentVariableName(_ name: String) -> Bool {
        guard let first = name.unicodeScalars.first else { return false }
        let isAlphaOrUnderscore = { (s: UnicodeScalar) -> Bool in
            (s.value >= 0x41 && s.value <= 0x5A) ||
            (s.value >= 0x61 && s.value <= 0x7A) ||
            s.value == 0x5F
        }
        let isAlphaNumOrUnderscore = { (s: UnicodeScalar) -> Bool in
            isAlphaOrUnderscore(s) || (s.value >= 0x30 && s.value <= 0x39)
        }
        guard isAlphaOrUnderscore(first) else { return false }
        return name.unicodeScalars.dropFirst().allSatisfy(isAlphaNumOrUnderscore)
    }
}
