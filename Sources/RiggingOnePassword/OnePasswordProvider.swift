import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import RiggingCore

// MARK: - 1Password Connect Configuration & HTTP Transport

/// Configuration for resolving `op://` secret references via a 1Password Connect REST Server
/// instead of the local `op` CLI binary.
///
/// Provide an explicit configuration to ``OnePasswordProvider/init(account:serviceAccountToken:executablePath:searchDirectories:timeout:connect:httpTransport:)``
/// or `SecretProvider.onePasswordConnect(host:token:httpTransport:)`, or export both
/// `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` in the process environment.
public struct OnePasswordConnectConfiguration: Sendable, Equatable {
    /// Base `http://` or `https://` URL of the 1Password Connect REST Server.
    public let host: URL

    /// Bearer access token authenticating requests against the 1Password Connect REST Server.
    public let token: Secret<String>

    /// Creates a 1Password Connect configuration using a redacted `Secret<String>` bearer token.
    ///
    /// - Parameters:
    ///   - host: Base `http://` or `https://` URL of the 1Password Connect server.
    ///   - token: Leak-proof `Secret<String>` wrapping the Connect server access token.
    public init(host: URL, token: Secret<String>) {
        self.host = host
        self.token = token
    }

    /// Creates a 1Password Connect configuration by wrapping a raw token string in `Secret`.
    ///
    /// - Parameters:
    ///   - host: Base `http://` or `https://` URL of the 1Password Connect server.
    ///   - token: Plaintext Connect server access token, immediately wrapped in `Secret<String>`.
    public init(host: URL, token: String) {
        self.host = host
        self.token = Secret(token)
    }
}

#if canImport(Darwin) || canImport(FoundationNetworking)
/// Injectable HTTP transport used by ``OnePasswordProvider`` when operating in 1Password Connect REST mode.
public protocol OnePasswordHTTPTransport: Sendable {
    /// Executes an HTTP request and returns the response payload and HTTP metadata.
    ///
    /// - Parameter request: The configured `URLRequest` targeting the 1Password Connect server.
    /// - Returns: A tuple of raw response `Data` and the `HTTPURLResponse`.
    /// - Throws: A transport error or `SecretResolutionError` if the request fails.
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// Default `URLSession`-backed HTTP transport for 1Password Connect REST requests.
public struct URLSessionOnePasswordHTTPTransport: OnePasswordHTTPTransport, Sendable {
    private let session: URLSession

    /// Creates an HTTP transport backed by the given `URLSession`.
    ///
    /// - Parameter session: The `URLSession` used to execute Connect REST requests. Defaults to `.shared`.
    public init(session: URLSession = .shared) {
        self.session = session
    }

    /// Sends an HTTP request using the underlying `URLSession`.
    ///
    /// - Parameter request: The configured `URLRequest` to execute.
    /// - Returns: A tuple containing the response body `Data` and `HTTPURLResponse`.
    /// - Throws: A `URLError` on network failure, or `SecretResolutionError.providerFailed` if the response is non-HTTP.
    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        #if canImport(FoundationNetworking)
        let (data, response): (Data, URLResponse) = try await withCheckedThrowingContinuation { continuation in
            let task = session.dataTask(with: request) { data, response, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, let response {
                    continuation.resume(returning: (data, response))
                } else {
                    continuation.resume(
                        throwing: SecretResolutionError.providerFailed(
                            scheme: "op",
                            message: "1Password Connect server returned an empty HTTP response."
                        )
                    )
                }
            }
            task.resume()
        }
        #else
        let (data, response) = try await session.data(for: request)
        #endif
        guard let httpResponse = response as? HTTPURLResponse else {
            throw SecretResolutionError.providerFailed(
                scheme: "op",
                message: "1Password Connect server returned a non-HTTP response."
            )
        }
        return (data, httpResponse)
    }
}

/// Closure-backed ``OnePasswordHTTPTransport`` for deterministic, hermetic unit testing.
public struct ClosureOnePasswordHTTPTransport: OnePasswordHTTPTransport, Sendable {
    private let handler: @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

    /// Creates a custom HTTP transport delegating requests to `handler`.
    ///
    /// - Parameter handler: Asynchronous `@Sendable` closure returning mock `(Data, HTTPURLResponse)` tuples.
    public init(
        _ handler: @escaping @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)
    ) {
        self.handler = handler
    }

    /// Invokes the underlying closure handler with `request`.
    ///
    /// - Parameter request: The outgoing `URLRequest`.
    /// - Returns: The simulated response `Data` and `HTTPURLResponse`.
    /// - Throws: Any error thrown by the handler closure.
    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await handler(request)
    }
}
#endif

// MARK: - OnePasswordProvider

/// Batched 1Password (`op://`) secret provider supporting:
/// 1. Single-pass `op inject` over in-memory `stdin`/`stdout` pipes (zero temporary files on disk),
///    with concurrent `op item get --otp` / `op document get` handling for OTP and binary document references.
/// 2. 1Password Service Account (`OP_SERVICE_ACCOUNT_TOKEN`) and multi-account (`--account`) execution.
/// 3. 1Password Connect Server REST mode (`OP_CONNECT_HOST` + `OP_CONNECT_TOKEN` or explicit configuration)
///    with no `op` CLI binary dependency.
public struct OnePasswordProvider: SecretProvider, Sendable {
    /// URI schemes resolved by this provider (`["op"]`).
    public let supportedSchemes: Set<String> = ["op"]

    /// Optional default 1Password account shorthand, sign-in address, or UUID (overridden per-URI by `?account=...`).
    public let account: String?

    /// Optional explicit 1Password Service Account token (`OP_SERVICE_ACCOUNT_TOKEN`).
    public let serviceAccountToken: Secret<String>?

    /// Optional explicit absolute path to the `op` CLI binary. When `nil`, trusted system paths are searched.
    public let executablePath: String?

    /// Trusted absolute directories searched when `executablePath` is `nil`.
    public let searchDirectories: [String]

    /// Subprocess execution timeout per CLI call.
    public let timeout: Duration?

    /// Optional explicit 1Password Connect Server configuration.
    public let connect: OnePasswordConnectConfiguration?

    #if canImport(Darwin) || canImport(FoundationNetworking)
    /// HTTP transport used when operating in 1Password Connect REST mode.
    public let httpTransport: any OnePasswordHTTPTransport

    /// Creates a batched 1Password secret provider.
    ///
    /// - Parameters:
    ///   - account: Optional default 1Password account shorthand, sign-in URL, or UUID.
    ///   - serviceAccountToken: Optional Service Account token forwarded as `OP_SERVICE_ACCOUNT_TOKEN`.
    ///   - executablePath: Explicit absolute path to a trusted `op` binary. When `nil`, `searchDirectories` are checked.
    ///   - searchDirectories: Trusted absolute system directories searched for `op`.
    ///   - timeout: Maximum execution duration per `op` subprocess invocation. Defaults to 30 seconds.
    ///   - connect: Explicit 1Password Connect REST configuration. When `nil`, `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` are inspected.
    ///   - httpTransport: Injectable HTTP transport for 1Password Connect REST requests.
    public init(
        account: String? = nil,
        serviceAccountToken: Secret<String>? = nil,
        executablePath: String? = nil,
        searchDirectories: [String] = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ],
        timeout: Duration? = .seconds(30),
        connect: OnePasswordConnectConfiguration? = nil,
        httpTransport: any OnePasswordHTTPTransport = URLSessionOnePasswordHTTPTransport()
    ) {
        self.account = account
        self.serviceAccountToken = serviceAccountToken
        self.executablePath = executablePath
        self.searchDirectories = searchDirectories
        self.timeout = timeout
        self.connect = connect
        self.httpTransport = httpTransport
    }
    #else
    /// Creates a batched 1Password secret provider on platforms without `FoundationNetworking` (such as WASI).
    ///
    /// - Parameters:
    ///   - account: Optional default 1Password account shorthand, sign-in URL, or UUID.
    ///   - serviceAccountToken: Optional Service Account token forwarded as `OP_SERVICE_ACCOUNT_TOKEN`.
    ///   - executablePath: Explicit absolute path to a trusted `op` binary. When `nil`, `searchDirectories` are checked.
    ///   - searchDirectories: Trusted absolute system directories searched for `op`.
    ///   - timeout: Maximum execution duration per `op` subprocess invocation. Defaults to 30 seconds.
    ///   - connect: Explicit 1Password Connect REST configuration.
    public init(
        account: String? = nil,
        serviceAccountToken: Secret<String>? = nil,
        executablePath: String? = nil,
        searchDirectories: [String] = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ],
        timeout: Duration? = .seconds(30),
        connect: OnePasswordConnectConfiguration? = nil
    ) {
        self.account = account
        self.serviceAccountToken = serviceAccountToken
        self.executablePath = executablePath
        self.searchDirectories = searchDirectories
        self.timeout = timeout
        self.connect = connect
    }
    #endif

    /// Resolves a deduplicated batch of `op://` secret references in minimal unlock passes.
    ///
    /// Standard vault fields are resolved together via a single `op inject` invocation over in-memory
    /// pipes with a per-batch cryptographic boundary nonce, avoiding Touch ID prompt storms and disk files.
    ///
    /// - Parameters:
    ///   - references: The `SecretReference` items to resolve. Non-`op://` references are ignored.
    ///   - context: Active `SettingsContext` supplying environment variables, filesystem, subprocess runner, and redactor.
    /// - Returns: A dictionary mapping each resolved `SecretReference` to its raw secret `Data`.
    /// - Throws: `SecretResolutionError` or `SecretBatchPartialFailureError` if authentication, lookup, or CLI trust verification fails.
    public func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        // Deduplicate incoming `op://` references while preserving request order.
        var uniqueEntries: [(reference: SecretReference, opRef: OnePasswordSecretReference)] = []
        var seen = Set<SecretReference>()

        for reference in references {
            guard case .onePassword(let opRef) = reference else {
                continue
            }
            try Self.validateOnePasswordReference(opRef)
            if seen.insert(reference).inserted {
                uniqueEntries.append((reference, opRef))
            }
        }

        guard !uniqueEntries.isEmpty else {
            return [:]
        }

        // Register ambient auth tokens in DiagnosticRedactor immediately so they never leak in errors.
        if let saToken = serviceAccountToken?.expose(), !saToken.isEmpty {
            context.redactor.register(saToken)
        }
        if let envSAToken = context.environment["OP_SERVICE_ACCOUNT_TOKEN"], !envSAToken.isEmpty {
            context.redactor.register(envSAToken)
        }
        if let envConnectToken = context.environment["OP_CONNECT_TOKEN"], !envConnectToken.isEmpty {
            context.redactor.register(envConnectToken)
        }
        if let explicitConnectToken = connect?.token.expose(), !explicitConnectToken.isEmpty {
            context.redactor.register(explicitConnectToken)
        }

        // Route to 1Password Connect REST API when configured explicitly or via environment variables.
        if let connectConfig = try resolveConnectConfiguration(from: context) {
            #if canImport(Darwin) || canImport(FoundationNetworking)
            return try await resolveViaConnectServer(
                entries: uniqueEntries,
                connect: connectConfig,
                context: context
            )
            #else
            _ = connectConfig
            throw SecretResolutionError.providerFailed(
                scheme: "op",
                message: "1Password Connect HTTP transport is unavailable on this platform (no FoundationNetworking/URLSession)."
            )
            #endif
        }

        return try await resolveViaCLI(entries: uniqueEntries, context: context)
    }

    // MARK: - CLI Resolution (`op inject` + OTP / Document)

    private enum CLIRefKind {
        case standard
        case otp
        case document
    }

    private func resolveViaCLI(
        entries: [(reference: SecretReference, opRef: OnePasswordSecretReference)],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        let resolvedBinaryPath = try resolveTrustedOpExecutable(fileSystem: context.fileSystem)

        var childEnvironment = context.environment
        if let explicitSAToken = serviceAccountToken?.expose(), !explicitSAToken.isEmpty {
            childEnvironment["OP_SERVICE_ACCOUNT_TOKEN"] = explicitSAToken
        }

        // Group by effective account selector (`ref.accountHint ?? self.account`).
        var accountOrder: [String?] = []
        var groupedByAccount: [String?: [(reference: SecretReference, opRef: OnePasswordSecretReference)]] = [:]

        for entry in entries {
            let effectiveAccount = entry.opRef.accountHint ?? account
            if let effectiveAccount {
                try Self.validateSafeCLIValue(effectiveAccount, label: "account")
            }
            if groupedByAccount[effectiveAccount] == nil {
                accountOrder.append(effectiveAccount)
                groupedByAccount[effectiveAccount] = [entry]
            } else {
                groupedByAccount[effectiveAccount]?.append(entry)
            }
        }

        var resolved: [SecretReference: Data] = [:]
        resolved.reserveCapacity(entries.count)

        for effectiveAccount in accountOrder {
            guard let groupEntries = groupedByAccount[effectiveAccount] else { continue }

            var standardEntries: [(reference: SecretReference, opRef: OnePasswordSecretReference)] = []
            var specialEntries: [(reference: SecretReference, opRef: OnePasswordSecretReference, kind: CLIRefKind)] = []

            for entry in groupEntries {
                switch Self.classifyReference(entry.opRef) {
                case .standard:
                    standardEntries.append(entry)
                case .otp:
                    specialEntries.append((entry.reference, entry.opRef, .otp))
                case .document:
                    specialEntries.append((entry.reference, entry.opRef, .document))
                }
            }

            // 1. Resolve all standard `op://` fields in ONE single `op inject` invocation over stdin/stdout pipes.
            if !standardEntries.isEmpty {
                let batchBytes = try await runBatchedOpInject(
                    entries: standardEntries,
                    account: effectiveAccount,
                    executablePath: resolvedBinaryPath,
                    environment: childEnvironment,
                    context: context
                )
                for (ref, bytes) in batchBytes {
                    context.redactor.register(bytes)
                    resolved[ref] = bytes
                }
            }

            // 2. Resolve any OTP (`?attribute=otp`) or document (`?document=true`) references concurrently
            //    after the initial batch unlock.
            if !specialEntries.isEmpty {
                let specialResults = try await runConcurrentSpecialReferences(
                    specialEntries,
                    account: effectiveAccount,
                    executablePath: resolvedBinaryPath,
                    environment: childEnvironment,
                    context: context
                )
                for (ref, bytes) in specialResults {
                    context.redactor.register(bytes)
                    resolved[ref] = bytes
                }
            }
        }

        return resolved
    }

    private func runBatchedOpInject(
        entries: [(reference: SecretReference, opRef: OnePasswordSecretReference)],
        account: String?,
        executablePath: String,
        environment: [String: String],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        // Fresh 128-bit random hex nonce per batch so secret contents can never collide with boundary markers.
        let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()

        var templateLines: [String] = []
        templateLines.reserveCapacity(entries.count)
        for (index, entry) in entries.enumerated() {
            let startMarker = "<<<RIGGING_START_\(nonce)_\(index)>>>"
            let endMarker = "<<<RIGGING_END_\(nonce)_\(index)>>>"
            templateLines.append("\(startMarker){{ \(entry.opRef.opReadURI) }}\(endMarker)")
        }
        let templateData = Data(templateLines.joined(separator: "\n").utf8)

        var arguments = ["inject"]
        if let account, !account.isEmpty {
            arguments.append(contentsOf: ["--account", account])
        }

        let result = try await executeSubprocess(
            executablePath: executablePath,
            arguments: arguments,
            environment: environment,
            stdin: templateData,
            context: context
        )

        guard result.exitCode == 0 else {
            throw Self.classifyCLIFailure(
                exitCode: result.exitCode,
                stderr: result.stderrString,
                reference: entries.count == 1 ? entries[0].reference : nil,
                context: context
            )
        }

        var output: [SecretReference: Data] = [:]
        output.reserveCapacity(entries.count)

        var searchLowerBound = result.stdout.startIndex
        for (index, entry) in entries.enumerated() {
            let startMarkerBytes = Data("<<<RIGGING_START_\(nonce)_\(index)>>>".utf8)
            let endMarkerBytes = Data("<<<RIGGING_END_\(nonce)_\(index)>>>".utf8)

            guard let startRange = result.stdout.range(
                of: startMarkerBytes,
                in: searchLowerBound..<result.stdout.endIndex
            ),
            let endRange = result.stdout.range(
                of: endMarkerBytes,
                in: startRange.upperBound..<result.stdout.endIndex
            ) else {
                throw SecretResolutionError.providerFailed(
                    scheme: "op",
                    message: "1Password 'op inject' output was missing expected boundary markers for '\(entry.reference.redactedDescription)'."
                )
            }

            let slice = Data(result.stdout[startRange.upperBound..<endRange.lowerBound])
            searchLowerBound = endRange.upperBound

            // Guard against silent unexpanded template pass-through.
            let unexpandedToken = "{{ \(entry.opRef.opReadURI) }}"
            if let sliceString = String(data: slice, encoding: .utf8),
               sliceString.trimmingCharacters(in: .whitespacesAndNewlines) == unexpandedToken {
                throw SecretResolutionError.unresolvedReference(
                    referenceRedacted: entry.reference.redactedDescription
                )
            }

            output[entry.reference] = slice
        }

        return output
    }

    private func runConcurrentSpecialReferences(
        _ entries: [(reference: SecretReference, opRef: OnePasswordSecretReference, kind: CLIRefKind)],
        account: String?,
        executablePath: String,
        environment: [String: String],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        try await withThrowingTaskGroup(of: (SecretReference, Data).self) { group in
            for item in entries {
                group.addTask {
                    let data = try await self.resolveSingleSpecialReference(
                        reference: item.reference,
                        opRef: item.opRef,
                        kind: item.kind,
                        account: account,
                        executablePath: executablePath,
                        environment: environment,
                        context: context
                    )
                    return (item.reference, data)
                }
            }

            var collected: [SecretReference: Data] = [:]
            collected.reserveCapacity(entries.count)
            for try await (ref, data) in group {
                collected[ref] = data
            }
            return collected
        }
    }

    private func resolveSingleSpecialReference(
        reference: SecretReference,
        opRef: OnePasswordSecretReference,
        kind: CLIRefKind,
        account: String?,
        executablePath: String,
        environment: [String: String],
        context: SettingsContext
    ) async throws -> Data {
        var arguments: [String]
        switch kind {
        case .otp:
            arguments = ["item", "get", opRef.item, "--vault", opRef.vault, "--otp"]
        case .document:
            arguments = ["document", "get", opRef.item, "--vault", opRef.vault]
        case .standard:
            arguments = ["read", "--no-newline", opRef.opReadURI]
        }

        if let account, !account.isEmpty {
            arguments.append(contentsOf: ["--account", account])
        }

        let result = try await executeSubprocess(
            executablePath: executablePath,
            arguments: arguments,
            environment: environment,
            stdin: nil,
            context: context
        )

        guard result.exitCode == 0 else {
            throw Self.classifyCLIFailure(
                exitCode: result.exitCode,
                stderr: result.stderrString,
                reference: reference,
                context: context
            )
        }

        switch kind {
        case .otp:
            let trimmed = result.stdoutString.trimmingCharacters(in: .whitespacesAndNewlines)
            return Data(trimmed.utf8)
        case .document, .standard:
            return result.stdout
        }
    }

    // MARK: - 1Password Connect Server REST Resolution

    private func resolveConnectConfiguration(
        from context: SettingsContext
    ) throws -> OnePasswordConnectConfiguration? {
        if let connect {
            return connect
        }

        let rawHost = context.environment["OP_CONNECT_HOST"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let rawToken = context.environment["OP_CONNECT_TOKEN"]?.trimmingCharacters(in: .whitespacesAndNewlines)

        let hasHost = (rawHost != nil && !rawHost!.isEmpty)
        let hasToken = (rawToken != nil && !rawToken!.isEmpty)

        guard hasHost || hasToken else {
            return nil
        }

        guard let hostString = rawHost, !hostString.isEmpty,
              let tokenString = rawToken, !tokenString.isEmpty else {
            throw SecretResolutionError.authenticationFailed(
                scheme: "op",
                message: "Incomplete 1Password Connect configuration: both OP_CONNECT_HOST and OP_CONNECT_TOKEN must be set.",
                remediation: "Export both OP_CONNECT_HOST and OP_CONNECT_TOKEN in the environment."
            )
        }

        guard let hostURL = URL(string: hostString),
              let scheme = hostURL.scheme?.lowercased(),
              (scheme == "http" || scheme == "https"),
              hostURL.host != nil else {
            throw SecretResolutionError.providerFailed(
                scheme: "op",
                message: "Invalid OP_CONNECT_HOST URL '\(hostString)'. Expected an http:// or https:// URL."
            )
        }

        return OnePasswordConnectConfiguration(host: hostURL, token: Secret(tokenString))
    }

    private struct ConnectVault: Decodable, Sendable {
        let id: String
        let name: String?
    }

    private struct ConnectSection: Decodable, Sendable {
        let id: String
        let label: String?
    }

    private struct ConnectFieldSectionRef: Decodable, Sendable {
        let id: String?
        let label: String?
    }

    private struct ConnectField: Decodable, Sendable {
        let id: String?
        let label: String?
        let type: String?
        let purpose: String?
        let value: String?
        let otp: String?
        let section: ConnectFieldSectionRef?
    }

    private struct ConnectFile: Decodable, Sendable {
        let id: String
        let name: String?
        let content_path: String?
        let section: ConnectFieldSectionRef?
    }

    private struct ConnectItem: Decodable, Sendable {
        let id: String
        let title: String?
        let sections: [ConnectSection]?
        let fields: [ConnectField]?
        let files: [ConnectFile]?
    }

    #if canImport(Darwin) || canImport(FoundationNetworking)
    private func resolveViaConnectServer(
        entries: [(reference: SecretReference, opRef: OnePasswordSecretReference)],
        connect: OnePasswordConnectConfiguration,
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        let vaultsData = try await sendConnectRequest(
            path: "/v1/vaults",
            connect: connect,
            reference: nil,
            acceptJSON: true
        )
        let vaults: [ConnectVault]
        do {
            vaults = try JSONDecoder().decode([ConnectVault].self, from: vaultsData)
        } catch {
            throw SecretResolutionError.providerFailed(
                scheme: "op",
                message: "Failed to decode 1Password Connect /v1/vaults response."
            )
        }

        var itemsListCache: [String: [ConnectItem]] = [:]
        var fullItemCache: [String: ConnectItem] = [:]
        var resolved: [SecretReference: Data] = [:]
        var failures: [SecretReference: any Error] = [:]
        resolved.reserveCapacity(entries.count)

        for entry in entries {
            do {
                let opRef = entry.opRef
                guard let matchedVault = Self.matchVault(opRef.vault, in: vaults) else {
                    throw SecretResolutionError.itemNotFound(
                        scheme: "op",
                        referenceRedacted: entry.reference.redactedDescription,
                        message: "Vault '\(opRef.vault)' not found on 1Password Connect server."
                    )
                }

                let vaultItems: [ConnectItem]
                if let cached = itemsListCache[matchedVault.id] {
                    vaultItems = cached
                } else {
                    let encodedVaultID = Self.encodeHTTPPathSegment(matchedVault.id)
                    let listData = try await sendConnectRequest(
                        path: "/v1/vaults/\(encodedVaultID)/items",
                        connect: connect,
                        reference: entry.reference,
                        acceptJSON: true
                    )
                    let decodedList: [ConnectItem]
                    do {
                        decodedList = try JSONDecoder().decode([ConnectItem].self, from: listData)
                    } catch {
                        throw SecretResolutionError.providerFailed(
                            scheme: "op",
                            message: "Failed to decode 1Password Connect items list for vault '\(opRef.vault)'."
                        )
                    }
                    itemsListCache[matchedVault.id] = decodedList
                    vaultItems = decodedList
                }

                guard let summaryItem = Self.matchItem(opRef.item, in: vaultItems) else {
                    throw SecretResolutionError.itemNotFound(
                        scheme: "op",
                        referenceRedacted: entry.reference.redactedDescription,
                        message: "Item '\(opRef.item)' not found in vault '\(opRef.vault)'."
                    )
                }

                let kind = Self.classifyReference(opRef)
                let fullItemKey = "\(matchedVault.id)/\(summaryItem.id)"
                let fullItem: ConnectItem

                if let cachedFull = fullItemCache[fullItemKey] {
                    fullItem = cachedFull
                } else if (kind != .document && summaryItem.fields != nil)
                            || (kind == .document && summaryItem.files != nil) {
                    fullItemCache[fullItemKey] = summaryItem
                    fullItem = summaryItem
                } else {
                    let encodedVaultID = Self.encodeHTTPPathSegment(matchedVault.id)
                    let encodedItemID = Self.encodeHTTPPathSegment(summaryItem.id)
                    let detailData = try await sendConnectRequest(
                        path: "/v1/vaults/\(encodedVaultID)/items/\(encodedItemID)",
                        connect: connect,
                        reference: entry.reference,
                        acceptJSON: true
                    )
                    let decodedDetail: ConnectItem
                    do {
                        decodedDetail = try JSONDecoder().decode(ConnectItem.self, from: detailData)
                    } catch {
                        throw SecretResolutionError.providerFailed(
                            scheme: "op",
                            message: "Failed to decode 1Password Connect item detail for '\(entry.reference.redactedDescription)'."
                        )
                    }
                    fullItemCache[fullItemKey] = decodedDetail
                    fullItem = decodedDetail
                }

                let secretBytes: Data
                switch kind {
                case .document:
                    guard let file = Self.matchFile(for: opRef, in: fullItem) else {
                        throw SecretResolutionError.itemNotFound(
                            scheme: "op",
                            referenceRedacted: entry.reference.redactedDescription,
                            message: "Document file '\(opRef.field)' not found in item '\(opRef.item)'."
                        )
                    }
                    let contentPath: String
                    if let explicitContentPath = file.content_path, explicitContentPath.hasPrefix("/") {
                        contentPath = explicitContentPath
                    } else {
                        let vID = Self.encodeHTTPPathSegment(matchedVault.id)
                        let iID = Self.encodeHTTPPathSegment(fullItem.id)
                        let fID = Self.encodeHTTPPathSegment(file.id)
                        contentPath = "/v1/vaults/\(vID)/items/\(iID)/files/\(fID)/content"
                    }
                    secretBytes = try await sendConnectRequest(
                        path: contentPath,
                        connect: connect,
                        reference: entry.reference,
                        acceptJSON: false
                    )

                case .otp:
                    guard let field = Self.matchField(for: opRef, in: fullItem) else {
                        throw SecretResolutionError.itemNotFound(
                            scheme: "op",
                            referenceRedacted: entry.reference.redactedDescription,
                            message: "OTP field '\(opRef.field)' not found in item '\(opRef.item)'."
                        )
                    }
                    if let otp = field.otp, !otp.isEmpty {
                        secretBytes = Data(otp.utf8)
                    } else if field.type?.uppercased() == "OTP", let val = field.value, !val.isEmpty {
                        secretBytes = Data(val.utf8)
                    } else {
                        throw SecretResolutionError.itemNotFound(
                            scheme: "op",
                            referenceRedacted: entry.reference.redactedDescription,
                            message: "Field '\(opRef.field)' in item '\(opRef.item)' does not contain a computed OTP value."
                        )
                    }

                case .standard:
                    guard let field = Self.matchField(for: opRef, in: fullItem),
                          let value = field.value else {
                        throw SecretResolutionError.itemNotFound(
                            scheme: "op",
                            referenceRedacted: entry.reference.redactedDescription,
                            message: "Field '\(opRef.field)' not found in item '\(opRef.item)'."
                        )
                    }
                    secretBytes = Data(value.utf8)
                }

                context.redactor.register(secretBytes)
                resolved[entry.reference] = secretBytes
            } catch {
                if entries.count == 1 {
                    throw error
                }
                failures[entry.reference] = error
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

    private func sendConnectRequest(
        path: String,
        connect: OnePasswordConnectConfiguration,
        reference: SecretReference?,
        acceptJSON: Bool
    ) async throws -> Data {
        var baseString = connect.host.absoluteString
        while baseString.hasSuffix("/") {
            baseString.removeLast()
        }
        let normalizedPath = path.hasPrefix("/") ? path : "/\(path)"
        guard let url = URL(string: baseString + normalizedPath) else {
            throw SecretResolutionError.providerFailed(
                scheme: "op",
                message: "Failed to construct 1Password Connect request URL for path '\(normalizedPath)'."
            )
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(connect.token.expose())", forHTTPHeaderField: "Authorization")
        request.setValue(acceptJSON ? "application/json" : "application/octet-stream", forHTTPHeaderField: "Accept")

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await httpTransport.send(request)
        } catch let secretErr as SecretResolutionError {
            throw secretErr
        } catch {
            throw SecretResolutionError.providerFailed(
                scheme: "op",
                message: "1Password Connect HTTP request failed for '\(normalizedPath)'.",
                remediation: "Verify OP_CONNECT_HOST reachability and TLS configuration."
            )
        }

        switch response.statusCode {
        case 200...299:
            return data
        case 401, 403:
            throw SecretResolutionError.authenticationFailed(
                scheme: "op",
                message: "1Password Connect server rejected authentication (HTTP \(response.statusCode)).",
                remediation: "Verify that OP_CONNECT_TOKEN is valid and has access to the requested vault."
            )
        case 404:
            throw SecretResolutionError.itemNotFound(
                scheme: "op",
                referenceRedacted: reference?.redactedDescription ?? "op://<vault>",
                message: "1Password Connect server returned HTTP 404."
            )
        case 429:
            let retryAfter = Self.parseRetryAfterDeltaSeconds(
                Self.httpHeaderValue("Retry-After", in: response)
            )
            throw SecretResolutionError.rateLimited(
                scheme: "op",
                message: "1Password Connect server rate-limited request (HTTP 429).",
                retryAfter: retryAfter,
                remediation: "Wait before retrying 1Password Connect requests."
            )
        default:
            throw SecretResolutionError.providerFailed(
                scheme: "op",
                message: "1Password Connect server returned HTTP \(response.statusCode) for '\(normalizedPath)'."
            )
        }
    }

    private static func matchVault(_ target: String, in vaults: [ConnectVault]) -> ConnectVault? {
        if let exactID = vaults.first(where: { $0.id == target }) {
            return exactID
        }
        if let exactName = vaults.first(where: { $0.name == target }) {
            return exactName
        }
        let lower = target.lowercased()
        return vaults.first { $0.name?.lowercased() == lower || $0.id.lowercased() == lower }
    }

    private static func matchItem(_ target: String, in items: [ConnectItem]) -> ConnectItem? {
        if let exactID = items.first(where: { $0.id == target }) {
            return exactID
        }
        if let exactTitle = items.first(where: { $0.title == target }) {
            return exactTitle
        }
        let lower = target.lowercased()
        return items.first { $0.title?.lowercased() == lower || $0.id.lowercased() == lower }
    }

    private static func matchField(for opRef: OnePasswordSecretReference, in item: ConnectItem) -> ConnectField? {
        guard let fields = item.fields, !fields.isEmpty else { return nil }

        let sectionsByID: [String: String] = Dictionary(
            uniqueKeysWithValues: (item.sections ?? []).compactMap { sec in
                guard let label = sec.label else { return nil }
                return (sec.id, label)
            }
        )

        let candidateFields: [ConnectField]
        if let requiredSection = opRef.section {
            let lowerSection = requiredSection.lowercased()
            let exactSectionMatches = fields.filter { field in
                let label = field.section?.label ?? field.section?.id.flatMap { sectionsByID[$0] }
                return label == requiredSection || field.section?.id == requiredSection
            }
            if !exactSectionMatches.isEmpty {
                candidateFields = exactSectionMatches
            } else {
                candidateFields = fields.filter { field in
                    let label = field.section?.label ?? field.section?.id.flatMap { sectionsByID[$0] }
                    return label?.lowercased() == lowerSection || field.section?.id?.lowercased() == lowerSection
                }
            }
        } else {
            candidateFields = fields
        }

        if let exactLabel = candidateFields.first(where: { $0.label == opRef.field }) {
            return exactLabel
        }
        if let exactID = candidateFields.first(where: { $0.id == opRef.field }) {
            return exactID
        }
        let lowerField = opRef.field.lowercased()
        if let ciLabelOrID = candidateFields.first(where: {
            $0.label?.lowercased() == lowerField || $0.id?.lowercased() == lowerField
        }) {
            return ciLabelOrID
        }
        return candidateFields.first { $0.purpose?.lowercased() == lowerField }
    }

    private static func matchFile(for opRef: OnePasswordSecretReference, in item: ConnectItem) -> ConnectFile? {
        guard let files = item.files, !files.isEmpty else { return nil }
        if let exact = files.first(where: { $0.name == opRef.field || $0.id == opRef.field }) {
            return exact
        }
        let lower = opRef.field.lowercased()
        if let ci = files.first(where: { $0.name?.lowercased() == lower || $0.id.lowercased() == lower }) {
            return ci
        }
        if lower == "document" || lower == "file" || opRef.field == opRef.item {
            return files.first
        }
        return nil
    }

    /// Percent-encodes a single URL path segment for 1Password Connect HTTP REST requests.
    /// Kept separate from CLI `op://` reference formatting, which preserves literal spaces.
    private static func encodeHTTPPathSegment(_ value: String) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/?#")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }
    #endif

    // MARK: - Trust, Validation, & Safe Error Classification

    private static func classifyReference(_ opRef: OnePasswordSecretReference) -> CLIRefKind {
        let query = opRef.query
        if query["attribute"]?.lowercased() == "otp" {
            return .otp
        }
        if let docFlag = query["document"]?.lowercased(),
           docFlag == "true" || docFlag == "1" || docFlag == "yes" {
            return .document
        }
        if query["type"]?.lowercased() == "document" {
            return .document
        }
        return .standard
    }

    private static let forbiddenCLISegmentCharacters: Set<Character> = ["/", "?", "#", "%", "{", "}"]
    private static let forbiddenCLIQueryCharacters: Set<Character> = ["&", "=", "?", "#", "%", "{", "}", " "]

    private static func validateOnePasswordReference(_ opRef: OnePasswordSecretReference) throws {
        try validateSafeCLISegment(opRef.vault, label: "vault")
        try validateSafeCLISegment(opRef.item, label: "item")
        if let section = opRef.section {
            try validateSafeCLISegment(section, label: "section")
        }
        try validateSafeCLISegment(opRef.field, label: "field")
        if let accountHint = opRef.accountHint {
            try validateSafeCLIValue(accountHint, label: "account")
        }
        for item in opRef.queryItems where item.name != "account" {
            try validateSafeCLIQueryComponent(item.name, label: "query name")
            if let value = item.value {
                try validateSafeCLIQueryComponent(value, label: "query value")
            }
        }
    }

    private static func validateSafeCLISegment(_ value: String, label: String) throws {
        try validateSafeCLIValue(value, label: label)
        if let invalid = value.first(where: { forbiddenCLISegmentCharacters.contains($0) }) {
            throw SecretResolutionError.invalidReference(
                .invalidFormat(scheme: "op", message: "Unsupported character '\(invalid)' in 'op://' \(label) segment.")
            )
        }
    }

    private static func validateSafeCLIQueryComponent(_ value: String, label: String) throws {
        try validateSafeCLIValue(value, label: label)
        if let invalid = value.first(where: { forbiddenCLIQueryCharacters.contains($0) }) {
            throw SecretResolutionError.invalidReference(
                .invalidFormat(scheme: "op", message: "Unsupported character '\(invalid)' in 'op://' \(label).")
            )
        }
    }

    private static func validateSafeCLIValue(_ value: String, label: String) throws {
        if value.utf8.contains(0) {
            throw SecretResolutionError.invalidReference(.containsNullByte)
        }
        guard !value.isEmpty else {
            throw SecretResolutionError.invalidReference(
                .invalidFormat(scheme: "op", message: "1Password '\(label)' segment must not be empty.")
            )
        }
        if value.hasPrefix("-") {
            throw SecretResolutionError.invalidReference(
                .optionInjection(scheme: "op", segment: value)
            )
        }
        for scalar in value.unicodeScalars where scalar.value < 0x20 || scalar.value == 0x7F {
            throw SecretResolutionError.invalidReference(.containsControlCharacter(scheme: "op"))
        }
    }

    private func resolveTrustedOpExecutable(fileSystem: any FileSystem) throws -> String {
        do {
            return try ProcessSubprocessRunner.resolveTrustedExecutable(
                named: "op",
                explicitPath: executablePath,
                searchDirectories: searchDirectories,
                fileSystem: fileSystem
            )
        } catch let securityError as SubprocessSecurityError {
            throw Self.mapSubprocessSecurityError(securityError)
        }
    }

    private func executeSubprocess(
        executablePath: String,
        arguments: [String],
        environment: [String: String],
        stdin: Data?,
        context: SettingsContext
    ) async throws -> SubprocessResult {
        do {
            return try await context.subprocessRunner.run(
                executablePath: executablePath,
                arguments: arguments,
                environment: environment,
                stdin: stdin,
                timeout: timeout
            )
        } catch let securityError as SubprocessSecurityError {
            throw Self.mapSubprocessSecurityError(securityError)
        } catch let secretError as SecretResolutionError {
            throw secretError
        } catch {
            throw SecretResolutionError.providerFailed(
                scheme: "op",
                message: "Failed to invoke 1Password CLI ('op').",
                remediation: "Verify that 1Password CLI is installed and accessible."
            )
        }
    }

    private static func mapSubprocessSecurityError(
        _ error: SubprocessSecurityError
    ) -> SecretResolutionError {
        switch error {
        case .relativeExecutablePath(let path):
            return .unsafeExecutable(
                scheme: "op",
                path: path,
                reason: error.description,
                remediation: "Provide an absolute path to a trusted 'op' binary (e.g. /opt/homebrew/bin/op)."
            )
        case .worldWritableExecutable(let path, _):
            return .unsafeExecutable(
                scheme: "op",
                path: path,
                reason: error.description,
                remediation: "Fix permissions: chmod 755 \(path)"
            )
        case .executableNotFound(let name):
            return .providerFailed(
                scheme: "op",
                message: "1Password CLI executable '\(name)' was not found in trusted system directories.",
                remediation: "Install 1Password CLI (`brew install --cask 1password-cli`) or configure OnePassword Connect."
            )
        case .notExecutable(let path):
            return .providerFailed(
                scheme: "op",
                message: "1Password CLI binary at '\(path)' is not executable.",
                remediation: "Verify installation permissions (`chmod 755 \(path)`)."
            )
        case .timedOut(let path, let duration):
            return .providerFailed(
                scheme: "op",
                message: "1Password CLI ('\(path)') timed out after \(duration).",
                remediation: "Check whether the 1Password desktop app is waiting for biometric approval."
            )
        case .unsupportedPlatform(let message):
            return .providerFailed(
                scheme: "op",
                message: message,
                remediation: "Use 1Password Connect Server mode (OP_CONNECT_HOST + OP_CONNECT_TOKEN) on platforms without subprocess support."
            )
        }
    }

    /// Maximum accepted retry-after interval (7 days) so malformed or overflowing integers
    /// cannot overflow downstream clock arithmetic.
    private static let maxRetryAfterSeconds: Int64 = 7 * 24 * 60 * 60

    private static func httpHeaderValue(_ name: String, in response: HTTPURLResponse) -> String? {
        if let direct = response.value(forHTTPHeaderField: name) {
            return direct
        }
        let target = name.lowercased()
        for (key, value) in response.allHeaderFields {
            if String(describing: key).lowercased() == target {
                return String(describing: value)
            }
        }
        return nil
    }

    private static func parseRetryAfterDeltaSeconds(_ raw: String?) -> Duration? {
        guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty,
              trimmed.unicodeScalars.allSatisfy({ $0.value >= 0x30 && $0.value <= 0x39 }),
              let seconds = Int64(trimmed),
              seconds > 0,
              seconds <= maxRetryAfterSeconds else {
            return nil
        }
        return .seconds(seconds)
    }

    private static func parseCLIRetryAfter(from lowercasedStderr: String) -> Duration? {
        guard let prefixRange = lowercasedStderr.range(of: "try again in ") else {
            return nil
        }
        let afterPrefix = lowercasedStderr[prefixRange.upperBound...]
        guard let unitRange = afterPrefix.range(of: " second") else {
            return nil
        }
        let rawInterval = String(afterPrefix[..<unitRange.lowerBound])
        return parseRetryAfterDeltaSeconds(rawInterval)
    }

    private static func isUnambiguousRateLimitStderr(_ lower: String) -> Bool {
        lower.contains("rate-limited")
            || lower.contains("rate limited")
            || lower.contains("too many requests")
            || lower.contains("rate limit exceeded")
            || lower.contains("exceeded the rate limit")
            || lower.contains("rate limit reached")
            || lower.contains("hit the rate limit")
    }

    private static func makeCLIRateLimitedError(exitCode: Int32, lowercasedStderr: String) -> SecretResolutionError {
        .rateLimited(
            scheme: "op",
            message: "1Password CLI request was rate-limited (exit code \(exitCode)).",
            retryAfter: parseCLIRetryAfter(from: lowercasedStderr),
            remediation: "Wait before retrying 1Password requests, or reduce concurrent vault reads."
        )
    }

    /// Maps non-zero `op` CLI exit codes to structured `SecretResolutionError` (`exitCode = 6`)
    /// without echoing raw `stderr` contents that could contain tokens, keys, or template fragments.
    private static func classifyCLIFailure(
        exitCode: Int32,
        stderr: String,
        reference: SecretReference?,
        context: SettingsContext
    ) -> SecretResolutionError {
        let lower = stderr.lowercased()

        if isUnambiguousRateLimitStderr(lower) {
            return makeCLIRateLimitedError(exitCode: exitCode, lowercasedStderr: lower)
        }

        if lower.contains("not currently signed in")
            || lower.contains("not signed in")
            || lower.contains("session expired")
            || lower.contains("authentication required")
            || lower.contains("biometric")
            || lower.contains("service account")
            || lower.contains("unauthorized")
            || lower.contains("401")
            || lower.contains("invalid token")
            || lower.contains("account is not signed in") {
            return .authenticationFailed(
                scheme: "op",
                message: context.redactor.scrub("1Password CLI is not signed in or authentication failed (exit code \(exitCode))."),
                remediation: "Unlock the 1Password desktop app, run `eval $(op signin)`, or export `OP_SERVICE_ACCOUNT_TOKEN`."
            )
        }

        if lower.contains("isn't an item")
            || lower.contains("isn't a vault")
            || lower.contains("not found")
            || lower.contains("could not find")
            || lower.contains("does not have a field")
            || lower.contains("no item found")
            || lower.contains("doesn't exist") {
            return .itemNotFound(
                scheme: "op",
                referenceRedacted: reference?.redactedDescription ?? "op://<batch>",
                message: "1Password CLI could not find the requested vault, item, or field (exit code \(exitCode))."
            )
        }

        if lower.contains("rate limit")
            || lower.contains("http 429")
            || lower.contains("status 429") {
            return makeCLIRateLimitedError(exitCode: exitCode, lowercasedStderr: lower)
        }

        return .providerFailed(
            scheme: "op",
            message: context.redactor.scrub("1Password CLI exited with status \(exitCode)."),
            remediation: "Run `op whoami` to verify 1Password CLI connectivity and vault permissions."
        )
    }
}

// MARK: - Convenience Static Factory

extension SecretProvider where Self == OnePasswordProvider {
    /// Creates a batched 1Password (`op://`) secret provider backed by the local `op` CLI
    /// (or `OP_CONNECT_HOST` + `OP_CONNECT_TOKEN` when present in the environment).
    ///
    /// - Parameters:
    ///   - account: Optional default 1Password account shorthand, sign-in address, or UUID.
    ///   - serviceAccountToken: Optional Service Account token forwarded as `OP_SERVICE_ACCOUNT_TOKEN`.
    ///   - executablePath: Optional explicit absolute path to a trusted `op` executable.
    ///   - timeout: Maximum execution duration per CLI invocation. Defaults to 30 seconds.
    /// - Returns: A configured ``OnePasswordProvider``.
    public static func onePassword(
        account: String? = nil,
        serviceAccountToken: Secret<String>? = nil,
        executablePath: String? = nil,
        timeout: Duration? = .seconds(30)
    ) -> OnePasswordProvider {
        OnePasswordProvider(
            account: account,
            serviceAccountToken: serviceAccountToken,
            executablePath: executablePath,
            timeout: timeout
        )
    }

    #if canImport(Darwin) || canImport(FoundationNetworking)
    /// Creates a 1Password Connect REST Server provider resolving `op://` references over HTTP
    /// with zero `op` CLI binary dependency.
    ///
    /// - Parameters:
    ///   - host: Base `http://` or `https://` URL of the 1Password Connect server.
    ///   - token: Leak-proof `Secret<String>` wrapping the Connect server access token.
    ///   - httpTransport: HTTP transport used to execute REST calls. Defaults to ``URLSessionOnePasswordHTTPTransport``.
    /// - Returns: A configured ``OnePasswordProvider`` operating in Connect REST mode.
    public static func onePasswordConnect(
        host: URL,
        token: Secret<String>,
        httpTransport: any OnePasswordHTTPTransport = URLSessionOnePasswordHTTPTransport()
    ) -> OnePasswordProvider {
        OnePasswordProvider(
            connect: OnePasswordConnectConfiguration(host: host, token: token),
            httpTransport: httpTransport
        )
    }
    #endif
}
