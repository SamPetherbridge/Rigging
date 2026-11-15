import Foundation
import RiggingCore

/// Bitwarden secret provider supporting both:
/// - **Bitwarden Secrets Manager (`bws://<secret-uuid>`)** via trusted `bws` CLI (`bws secret get <uuid> --output json`, forwarding `BWS_ACCESS_TOKEN`).
/// - **Bitwarden Vault CLI (`bw://<item-id>/<field>`)** via trusted `bw` CLI (`bw get item <item-id>`, forwarding `BW_SESSION`).
public struct BitwardenProvider: SecretProvider, Sendable {
    /// URI schemes resolved by this provider (`["bws", "bw"]`).
    public let supportedSchemes: Set<String> = ["bws", "bw"]

    /// Optional explicit absolute path to the `bws` CLI binary.
    public let bwsExecutablePath: String?

    /// Optional explicit absolute path to the `bw` CLI binary.
    public let bwExecutablePath: String?

    /// Optional explicit Bitwarden Secrets Manager access token (`BWS_ACCESS_TOKEN`).
    public let bwsAccessToken: Secret<String>?

    /// Optional explicit Bitwarden Vault session key (`BW_SESSION`).
    public let bwSession: Secret<String>?

    /// Trusted absolute directories searched when an explicit executable path is `nil`.
    public let searchDirectories: [String]

    /// Subprocess execution timeout per CLI call.
    public let timeout: Duration?

    /// Creates a Bitwarden secret provider supporting both `bws://` (Secrets Manager) and `bw://` (Vault CLI).
    ///
    /// - Parameters:
    ///   - bwsExecutablePath: Optional explicit absolute path to a trusted `bws` executable.
    ///   - bwExecutablePath: Optional explicit absolute path to a trusted `bw` executable.
    ///   - bwsAccessToken: Optional explicit machine access token forwarded as `BWS_ACCESS_TOKEN`.
    ///   - bwSession: Optional explicit Vault session key forwarded as `BW_SESSION`.
    ///   - searchDirectories: Trusted absolute system directories searched when executable paths are `nil`.
    ///   - timeout: Maximum execution duration per CLI invocation. Defaults to 30 seconds.
    public init(
        bwsExecutablePath: String? = nil,
        bwExecutablePath: String? = nil,
        bwsAccessToken: Secret<String>? = nil,
        bwSession: Secret<String>? = nil,
        searchDirectories: [String] = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ],
        timeout: Duration? = .seconds(30)
    ) {
        self.bwsExecutablePath = bwsExecutablePath
        self.bwExecutablePath = bwExecutablePath
        self.bwsAccessToken = bwsAccessToken
        self.bwSession = bwSession
        self.searchDirectories = searchDirectories
        self.timeout = timeout
    }

    /// Resolves a batch of `bws://` and `bw://` secret references, deduplicating `bw get item` calls by item ID.
    ///
    /// - Parameters:
    ///   - references: The `SecretReference` items to resolve. Non-Bitwarden schemes are ignored.
    ///   - context: Active `SettingsContext` supplying environment variables, filesystem, subprocess runner, and redactor.
    /// - Returns: A dictionary mapping each resolved `SecretReference` to its UTF-8 secret `Data`.
    /// - Throws: `SecretResolutionError` or `SecretBatchPartialFailureError` on missing binaries, locked vaults, or missing fields.
    public func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        var bwsEntries: [(reference: SecretReference, ref: BitwardenSecretsManagerReference)] = []
        var bwEntries: [(reference: SecretReference, ref: BitwardenVaultReference)] = []
        var seen = Set<SecretReference>()

        for reference in references {
            switch reference {
            case .bitwardenSecretsManager(let bwsRef):
                try Self.validateSegment(bwsRef.secretID, scheme: "bws", label: "secretID")
                if seen.insert(reference).inserted {
                    bwsEntries.append((reference, bwsRef))
                }
            case .bitwardenVault(let bwRef):
                try Self.validateSegment(bwRef.itemID, scheme: "bw", label: "itemID")
                try Self.validateSegment(bwRef.field, scheme: "bw", label: "field")
                if seen.insert(reference).inserted {
                    bwEntries.append((reference, bwRef))
                }
            default:
                continue
            }
        }

        guard !bwsEntries.isEmpty || !bwEntries.isEmpty else {
            return [:]
        }

        // Register ambient auth tokens in DiagnosticRedactor so they can never leak in error messages.
        if let token = bwsAccessToken?.expose(), !token.isEmpty {
            context.redactor.register(token)
        }
        if let envToken = context.environment["BWS_ACCESS_TOKEN"], !envToken.isEmpty {
            context.redactor.register(envToken)
        }
        if let session = bwSession?.expose(), !session.isEmpty {
            context.redactor.register(session)
        }
        if let envSession = context.environment["BW_SESSION"], !envSession.isEmpty {
            context.redactor.register(envSession)
        }

        var childEnvironment = context.environment
        if let token = bwsAccessToken?.expose(), !token.isEmpty {
            childEnvironment["BWS_ACCESS_TOKEN"] = token
        }
        if let session = bwSession?.expose(), !session.isEmpty {
            childEnvironment["BW_SESSION"] = session
        }

        let totalCount = bwsEntries.count + bwEntries.count
        var resolved: [SecretReference: Data] = [:]
        var failures: [SecretReference: any Error] = [:]
        resolved.reserveCapacity(totalCount)

        // 1. Resolve `bws://` references via trusted `bws` CLI.
        if !bwsEntries.isEmpty {
            let resolvedBwsPath: String
            do {
                resolvedBwsPath = try resolveTrustedBinary(
                    named: "bws",
                    explicitPath: bwsExecutablePath,
                    scheme: "bws",
                    fileSystem: context.fileSystem
                )
            } catch {
                if totalCount == 1 || bwEntries.isEmpty {
                    throw error
                }
                for entry in bwsEntries {
                    failures[entry.reference] = error
                }
                resolvedBwsPath = ""
            }

            if !resolvedBwsPath.isEmpty {
                for entry in bwsEntries {
                    do {
                        let secretData = try await resolveBwsSecret(
                            entry.ref,
                            reference: entry.reference,
                            executablePath: resolvedBwsPath,
                            environment: childEnvironment,
                            context: context
                        )
                        context.redactor.register(secretData)
                        resolved[entry.reference] = secretData
                    } catch {
                        if totalCount == 1 {
                            throw error
                        }
                        failures[entry.reference] = error
                    }
                }
            }
        }

        // 2. Resolve `bw://` references via trusted `bw` CLI (caching decoded items by `itemID`).
        if !bwEntries.isEmpty {
            let resolvedBwPath: String
            do {
                resolvedBwPath = try resolveTrustedBinary(
                    named: "bw",
                    explicitPath: bwExecutablePath,
                    scheme: "bw",
                    fileSystem: context.fileSystem
                )
            } catch {
                if totalCount == 1 || resolved.isEmpty && failures.isEmpty {
                    throw error
                }
                for entry in bwEntries {
                    failures[entry.reference] = error
                }
                resolvedBwPath = ""
            }

            if !resolvedBwPath.isEmpty {
                var itemCache: [String: Result<VaultItemPayload, any Error>] = [:]

                for entry in bwEntries {
                    let itemResult: Result<VaultItemPayload, any Error>
                    if let cached = itemCache[entry.ref.itemID] {
                        itemResult = cached
                    } else {
                        let fetched = await Result {
                            try await fetchVaultItem(
                                itemID: entry.ref.itemID,
                                reference: entry.reference,
                                executablePath: resolvedBwPath,
                                environment: childEnvironment,
                                context: context
                            )
                        }
                        itemCache[entry.ref.itemID] = fetched
                        itemResult = fetched
                    }

                    do {
                        let itemPayload = try itemResult.get()
                        guard let extracted = Self.extractField(entry.ref.field, from: itemPayload) else {
                            throw SecretResolutionError.itemNotFound(
                                scheme: "bw",
                                referenceRedacted: entry.reference.redactedDescription,
                                message: "Field '\(entry.ref.field)' was not found on Bitwarden item '\(entry.ref.itemID)'."
                            )
                        }
                        let bytes = Data(extracted.utf8)
                        context.redactor.register(bytes)
                        resolved[entry.reference] = bytes
                    } catch {
                        if totalCount == 1 {
                            throw error
                        }
                        failures[entry.reference] = error
                    }
                }
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

    // MARK: - `bws` Secrets Manager Execution

    private struct BwsSecretResponse: Decodable, Sendable {
        let id: String?
        let key: String?
        let value: String?
    }

    private func resolveBwsSecret(
        _ bwsRef: BitwardenSecretsManagerReference,
        reference: SecretReference,
        executablePath: String,
        environment: [String: String],
        context: SettingsContext
    ) async throws -> Data {
        let result = try await executeSubprocess(
            executablePath: executablePath,
            arguments: ["secret", "get", bwsRef.secretID, "--output", "json"],
            environment: environment,
            scheme: "bws",
            context: context
        )

        guard result.exitCode == 0 else {
            throw Self.classifyCLIFailure(
                scheme: "bws",
                exitCode: result.exitCode,
                stderr: result.stderrString,
                stdout: result.stdoutString,
                reference: reference,
                context: context
            )
        }

        let payload: BwsSecretResponse
        do {
            payload = try JSONDecoder().decode(BwsSecretResponse.self, from: result.stdout)
        } catch {
            throw SecretResolutionError.providerFailed(
                scheme: "bws",
                message: "Bitwarden Secrets Manager ('bws') returned malformed JSON for '\(reference.redactedDescription)'."
            )
        }

        guard let value = payload.value else {
            throw SecretResolutionError.itemNotFound(
                scheme: "bws",
                referenceRedacted: reference.redactedDescription,
                message: "Bitwarden secret '\(bwsRef.secretID)' did not contain a 'value' field."
            )
        }

        return Data(value.utf8)
    }

    // MARK: - `bw` Vault CLI Execution

    private struct VaultLoginURI: Decodable, Sendable {
        let uri: String?
    }

    private struct VaultLogin: Decodable, Sendable {
        let username: String?
        let password: String?
        let totp: String?
        let uris: [VaultLoginURI]?
    }

    private struct VaultCustomField: Decodable, Sendable {
        let name: String?
        let value: String?
    }

    private struct VaultItemPayload: Decodable, Sendable {
        let id: String?
        let name: String?
        let notes: String?
        let login: VaultLogin?
        let fields: [VaultCustomField]?
    }

    private func fetchVaultItem(
        itemID: String,
        reference: SecretReference,
        executablePath: String,
        environment: [String: String],
        context: SettingsContext
    ) async throws -> VaultItemPayload {
        let result = try await executeSubprocess(
            executablePath: executablePath,
            arguments: ["get", "item", itemID],
            environment: environment,
            scheme: "bw",
            context: context
        )

        guard result.exitCode == 0 else {
            throw Self.classifyCLIFailure(
                scheme: "bw",
                exitCode: result.exitCode,
                stderr: result.stderrString,
                stdout: result.stdoutString,
                reference: reference,
                context: context
            )
        }

        do {
            return try JSONDecoder().decode(VaultItemPayload.self, from: result.stdout)
        } catch {
            throw SecretResolutionError.providerFailed(
                scheme: "bw",
                message: "Bitwarden CLI ('bw') returned malformed item JSON for '\(reference.redactedDescription)'."
            )
        }
    }

    private static func extractField(_ field: String, from item: VaultItemPayload) -> String? {
        switch field.lowercased() {
        case "password", "login.password":
            if let password = item.login?.password {
                return password
            }
        case "username", "login.username":
            if let username = item.login?.username {
                return username
            }
        case "totp", "login.totp":
            if let totp = item.login?.totp {
                return totp
            }
        case "uri", "login.uri":
            if let uri = item.login?.uris?.first(where: { $0.uri != nil })?.uri {
                return uri
            }
        case "notes":
            if let notes = item.notes {
                return notes
            }
        default:
            break
        }

        guard let customFields = item.fields, !customFields.isEmpty else {
            return nil
        }

        if let exact = customFields.first(where: { $0.name == field })?.value {
            return exact
        }

        let lower = field.lowercased()
        return customFields.first(where: { $0.name?.lowercased() == lower })?.value
    }

    // MARK: - Trust, Validation, & Safe Error Classification

    private static func validateSegment(_ value: String, scheme: String, label: String) throws {
        if value.utf8.contains(0) {
            throw SecretResolutionError.invalidReference(.containsNullByte)
        }
        guard !value.isEmpty else {
            throw SecretResolutionError.invalidReference(
                .invalidFormat(scheme: scheme, message: "Bitwarden '\(label)' segment must not be empty.")
            )
        }
        if value.hasPrefix("-") {
            throw SecretResolutionError.invalidReference(
                .optionInjection(scheme: scheme, segment: value)
            )
        }
        for scalar in value.unicodeScalars where scalar.value < 0x20 || scalar.value == 0x7F {
            throw SecretResolutionError.invalidReference(.containsControlCharacter(scheme: scheme))
        }
    }

    private func resolveTrustedBinary(
        named binaryName: String,
        explicitPath: String?,
        scheme: String,
        fileSystem: any FileSystem
    ) throws -> String {
        do {
            return try ProcessSubprocessRunner.resolveTrustedExecutable(
                named: binaryName,
                explicitPath: explicitPath,
                searchDirectories: searchDirectories,
                fileSystem: fileSystem
            )
        } catch let securityError as SubprocessSecurityError {
            throw Self.mapSubprocessSecurityError(securityError, scheme: scheme, binaryName: binaryName)
        }
    }

    private func executeSubprocess(
        executablePath: String,
        arguments: [String],
        environment: [String: String],
        scheme: String,
        context: SettingsContext
    ) async throws -> SubprocessResult {
        do {
            return try await context.subprocessRunner.run(
                executablePath: executablePath,
                arguments: arguments,
                environment: environment,
                stdin: nil,
                timeout: timeout
            )
        } catch let securityError as SubprocessSecurityError {
            throw Self.mapSubprocessSecurityError(securityError, scheme: scheme, binaryName: scheme)
        } catch let secretError as SecretResolutionError {
            throw secretError
        } catch {
            throw SecretResolutionError.providerFailed(
                scheme: scheme,
                message: "Failed to invoke Bitwarden CLI ('\(scheme)')."
            )
        }
    }

    private static func mapSubprocessSecurityError(
        _ error: SubprocessSecurityError,
        scheme: String,
        binaryName: String
    ) -> SecretResolutionError {
        switch error {
        case .relativeExecutablePath(let path):
            return .unsafeExecutable(
                scheme: scheme,
                path: path,
                reason: error.description,
                remediation: "Provide an absolute path to a trusted '\(binaryName)' binary."
            )
        case .worldWritableExecutable(let path, _):
            return .unsafeExecutable(
                scheme: scheme,
                path: path,
                reason: error.description,
                remediation: "Fix permissions: chmod 755 \(path)"
            )
        case .executableNotFound(let name):
            return .providerFailed(
                scheme: scheme,
                message: "Bitwarden CLI executable '\(name)' was not found in trusted system directories.",
                remediation: "Install '\(binaryName)' into /opt/homebrew/bin or /usr/local/bin."
            )
        case .notExecutable(let path):
            return .providerFailed(
                scheme: scheme,
                message: "Bitwarden CLI binary at '\(path)' is not executable.",
                remediation: "Verify installation permissions (`chmod 755 \(path)`)."
            )
        case .timedOut(let path, let duration):
            return .providerFailed(
                scheme: scheme,
                message: "Bitwarden CLI ('\(path)') timed out after \(duration)."
            )
        case .unsupportedPlatform(let message):
            return .providerFailed(scheme: scheme, message: message)
        }
    }

    private static func classifyCLIFailure(
        scheme: String,
        exitCode: Int32,
        stderr: String,
        stdout: String,
        reference: SecretReference,
        context: SettingsContext
    ) -> SecretResolutionError {
        let combinedLower = "\(stderr)\n\(stdout)".lowercased()

        if combinedLower.contains("vault is locked")
            || combinedLower.contains("you are not logged in")
            || combinedLower.contains("not logged in")
            || combinedLower.contains("invalid master password")
            || combinedLower.contains("session key is invalid")
            || combinedLower.contains("access token")
            || combinedLower.contains("unauthorized")
            || combinedLower.contains("401")
            || combinedLower.contains("unauthenticated") {
            let hint = scheme == "bws"
                ? "Export a valid `BWS_ACCESS_TOKEN` environment variable."
                : "Unlock Bitwarden CLI (`export BW_SESSION=\"$(bw unlock --raw)\"`)."
            return .authenticationFailed(
                scheme: scheme,
                message: context.redactor.scrub("Bitwarden CLI ('\(scheme)') authentication failed or vault is locked (exit code \(exitCode))."),
                remediation: hint
            )
        }

        if combinedLower.contains("not found")
            || combinedLower.contains("404")
            || combinedLower.contains("does not exist") {
            return .itemNotFound(
                scheme: scheme,
                referenceRedacted: reference.redactedDescription,
                message: "Bitwarden item was not found (exit code \(exitCode))."
            )
        }

        return .providerFailed(
            scheme: scheme,
            message: context.redactor.scrub("Bitwarden CLI ('\(scheme)') exited with status \(exitCode).")
        )
    }
}

extension SecretProvider where Self == BitwardenProvider {
    /// Creates a Bitwarden secret provider supporting both `bws://<secret-uuid>` and `bw://<item-id>/<field>`.
    ///
    /// - Parameters:
    ///   - bwsExecutablePath: Optional explicit absolute path to a trusted `bws` executable.
    ///   - bwExecutablePath: Optional explicit absolute path to a trusted `bw` executable.
    ///   - bwsAccessToken: Optional explicit Secrets Manager token forwarded as `BWS_ACCESS_TOKEN`.
    ///   - bwSession: Optional explicit Vault session key forwarded as `BW_SESSION`.
    ///   - timeout: Maximum execution duration per CLI invocation. Defaults to 30 seconds.
    /// - Returns: A configured ``BitwardenProvider``.
    public static func bitwarden(
        bwsExecutablePath: String? = nil,
        bwExecutablePath: String? = nil,
        bwsAccessToken: Secret<String>? = nil,
        bwSession: Secret<String>? = nil,
        timeout: Duration? = .seconds(30)
    ) -> BitwardenProvider {
        BitwardenProvider(
            bwsExecutablePath: bwsExecutablePath,
            bwExecutablePath: bwExecutablePath,
            bwsAccessToken: bwsAccessToken,
            bwSession: bwSession,
            timeout: timeout
        )
    }
}
