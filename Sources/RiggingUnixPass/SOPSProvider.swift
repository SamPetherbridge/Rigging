import Foundation
#if canImport(ObjectiveC) && canImport(CoreFoundation)
import CoreFoundation
#endif
import RiggingCore

/// Mozilla SOPS (`sops://<file-path>#<json-pointer-or-key>`) encrypted file secret provider.
///
/// Decrypts SOPS-encrypted YAML, JSON, ENV, or INI files into JSON over `stdout` via a trusted `sops` CLI binary
/// (`["--decrypt", "--output-type", "json", resolvedPath]`) and traverses RFC 6901 JSON Pointers (`/a/b/0`)
/// or key paths strictly in-memory so arbitrary key names can never inject SOPS Python-style `--extract` slice syntax.
public struct SOPSProvider: SecretProvider, Sendable {
    /// URI schemes resolved by this provider (`["sops"]`).
    public let supportedSchemes: Set<String> = ["sops"]

    /// Optional explicit absolute path to the `sops` CLI binary.
    public let executablePath: String?

    /// Optional explicit path to an `age` secret key file (`SOPS_AGE_KEY_FILE`).
    public let ageKeyFile: String?

    /// Trusted absolute directories searched when `executablePath` is `nil`.
    public let searchDirectories: [String]

    /// Subprocess execution timeout per CLI call.
    public let timeout: Duration?

    /// Creates a Mozilla SOPS encrypted-file secret provider (`sops://<file-path>#<json-pointer-or-key>`).
    ///
    /// - Parameters:
    ///   - executablePath: Optional explicit absolute path to a trusted `sops` executable.
    ///   - ageKeyFile: Optional path to an `age` private key file forwarded as `SOPS_AGE_KEY_FILE`.
    ///   - searchDirectories: Trusted absolute system directories searched when `executablePath` is `nil`.
    ///   - timeout: Maximum execution duration per `sops` invocation. Defaults to 30 seconds.
    public init(
        executablePath: String? = nil,
        ageKeyFile: String? = nil,
        searchDirectories: [String] = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ],
        timeout: Duration? = .seconds(30)
    ) {
        self.executablePath = executablePath
        self.ageKeyFile = ageKeyFile
        self.searchDirectories = searchDirectories
        self.timeout = timeout
    }

    /// Resolves a batch of `sops://` references, decrypting each unique encrypted file at most once per batch.
    ///
    /// - Parameters:
    ///   - references: The `SecretReference` items to resolve. Non-`sops://` items are ignored.
    ///   - context: Active `SettingsContext` supplying working/home directories, environment, subprocess runner, and redactor.
    /// - Returns: A dictionary mapping each resolved `SecretReference` to its extracted secret `Data`.
    /// - Throws: `SecretResolutionError` or `SecretBatchPartialFailureError` if file decryption, key access, or JSON pointer lookup fails.
    public func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        var sopsEntries: [(reference: SecretReference, ref: SopsSecretReference, resolvedPath: String)] = []
        var seen = Set<SecretReference>()

        for reference in references {
            guard case .sops(let sopsRef) = reference else {
                continue
            }
            try Self.validateSopsReference(sopsRef)

            let resolvedPath = FileSecretProvider.resolvePath(
                sopsRef.filePath,
                workingDirectory: context.workingDirectory,
                homeDirectory: context.homeDirectory
            )
            if resolvedPath.hasPrefix("-") {
                throw SecretResolutionError.invalidReference(
                    .optionInjection(scheme: "sops", segment: resolvedPath)
                )
            }

            if seen.insert(reference).inserted {
                sopsEntries.append((reference, sopsRef, resolvedPath))
            }
        }

        guard !sopsEntries.isEmpty else {
            return [:]
        }

        if let ambientAgeKey = context.environment["SOPS_AGE_KEY"], !ambientAgeKey.isEmpty {
            context.redactor.register(ambientAgeKey)
        }

        let resolvedBinaryPath = try resolveTrustedSopsExecutable(fileSystem: context.fileSystem)

        var childEnvironment = context.environment
        if let ageKeyFile, !ageKeyFile.isEmpty {
            childEnvironment["SOPS_AGE_KEY_FILE"] = ageKeyFile
        }

        // Deduplicate `sops --decrypt` calls across multiple pointers referencing the same encrypted file.
        struct DecryptKey: Hashable {
            let resolvedPath: String
            let rawMode: Bool
        }

        var decryptedCache: [DecryptKey: Result<Data, any Error>] = [:]
        var resolved: [SecretReference: Data] = [:]
        var failures: [SecretReference: any Error] = [:]
        resolved.reserveCapacity(sopsEntries.count)

        for entry in sopsEntries {
            let rawMode = entry.ref.jsonPointer == nil
                && (entry.ref.query["raw"]?.lowercased() == "true" || entry.ref.query["raw"] == "1")
            let cacheKey = DecryptKey(resolvedPath: entry.resolvedPath, rawMode: rawMode)

            let decryptedResult: Result<Data, any Error>
            if let cached = decryptedCache[cacheKey] {
                decryptedResult = cached
            } else {
                let fetched: Result<Data, any Error>
                do {
                    let data = try await decryptFile(
                        resolvedPath: entry.resolvedPath,
                        rawMode: rawMode,
                        reference: entry.reference,
                        executablePath: resolvedBinaryPath,
                        environment: childEnvironment,
                        context: context
                    )
                    fetched = .success(data)
                } catch {
                    fetched = .failure(error)
                }
                decryptedCache[cacheKey] = fetched
                decryptedResult = fetched
            }

            do {
                let decryptedBytes = try decryptedResult.get()
                let secretBytes: Data
                if let pointer = entry.ref.jsonPointer {
                    secretBytes = try Self.extractJSONValue(
                        from: decryptedBytes,
                        pointer: pointer,
                        reference: entry.reference
                    )
                } else {
                    secretBytes = decryptedBytes
                }
                context.redactor.register(secretBytes)
                resolved[entry.reference] = secretBytes
            } catch {
                if sopsEntries.count == 1 {
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

    // MARK: - Decryption & In-Memory RFC 6901 JSON Pointer Traversal

    private func decryptFile(
        resolvedPath: String,
        rawMode: Bool,
        reference: SecretReference,
        executablePath: String,
        environment: [String: String],
        context: SettingsContext
    ) async throws -> Data {
        let arguments = rawMode
            ? ["--decrypt", resolvedPath]
            : ["--decrypt", "--output-type", "json", resolvedPath]

        let result: SubprocessResult
        do {
            result = try await context.subprocessRunner.run(
                executablePath: executablePath,
                arguments: arguments,
                environment: environment,
                stdin: nil,
                timeout: timeout
            )
        } catch let securityError as SubprocessSecurityError {
            throw Self.mapSubprocessSecurityError(securityError)
        } catch let secretError as SecretResolutionError {
            throw secretError
        } catch {
            throw SecretResolutionError.providerFailed(
                scheme: "sops",
                message: "Failed to invoke 'sops' CLI."
            )
        }

        guard result.exitCode == 0 else {
            throw Self.classifyCLIFailure(
                exitCode: result.exitCode,
                stderr: result.stderrString,
                resolvedPath: resolvedPath,
                reference: reference,
                context: context
            )
        }

        return result.stdout
    }

    internal static func extractJSONValue(
        from jsonData: Data,
        pointer: String,
        reference: SecretReference
    ) throws -> Data {
        let rootObject: Any
        do {
            rootObject = try JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed])
        } catch {
            throw SecretResolutionError.providerFailed(
                scheme: "sops",
                message: "'sops' decrypted output for '\(reference.redactedDescription)' is not valid JSON."
            )
        }

        let targetValue: Any
        if pointer.hasPrefix("/") {
            let tokens = try parseRFC6901Tokens(pointer)
            targetValue = try traverseTokens(tokens, in: rootObject, pointer: pointer, reference: reference)
        } else {
            // Support direct top-level key first (even if key contains dots), then dotted path fallback.
            if let rootDict = rootObject as? [String: Any], let direct = rootDict[pointer] {
                targetValue = direct
            } else {
                let tokens = pointer.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
                targetValue = try traverseTokens(tokens, in: rootObject, pointer: pointer, reference: reference)
            }
        }

        return try serializeLeafValue(targetValue, pointer: pointer, reference: reference)
    }

    private static func parseRFC6901Tokens(_ pointer: String) throws -> [String] {
        let withoutLeadingSlash = String(pointer.dropFirst())
        let rawSegments = withoutLeadingSlash.split(separator: "/", omittingEmptySubsequences: false)
        var tokens: [String] = []
        tokens.reserveCapacity(rawSegments.count)

        for rawSegment in rawSegments {
            var unescaped = ""
            unescaped.reserveCapacity(rawSegment.count)
            var idx = rawSegment.startIndex

            while idx < rawSegment.endIndex {
                let ch = rawSegment[idx]
                if ch == "~" {
                    let next = rawSegment.index(after: idx)
                    guard next < rawSegment.endIndex else {
                        throw SecretResolutionError.invalidReference(
                            .invalidFormat(
                                scheme: "sops",
                                message: "Invalid trailing '~' in RFC 6901 JSON pointer '\(pointer)'."
                            )
                        )
                    }
                    switch rawSegment[next] {
                    case "0":
                        unescaped.append("~")
                    case "1":
                        unescaped.append("/")
                    default:
                        throw SecretResolutionError.invalidReference(
                            .invalidFormat(
                                scheme: "sops",
                                message: "Invalid escape '~\(rawSegment[next])' in RFC 6901 JSON pointer '\(pointer)' (expected '~0' or '~1')."
                            )
                        )
                    }
                    idx = rawSegment.index(after: next)
                } else {
                    unescaped.append(ch)
                    idx = rawSegment.index(after: idx)
                }
            }

            tokens.append(unescaped)
        }

        return tokens
    }

    private static func traverseTokens(
        _ tokens: [String],
        in root: Any,
        pointer: String,
        reference: SecretReference
    ) throws -> Any {
        var current: Any = root

        for token in tokens {
            if let dict = current as? [String: Any] {
                guard let next = dict[token] else {
                    throw SecretResolutionError.itemNotFound(
                        scheme: "sops",
                        referenceRedacted: reference.redactedDescription,
                        message: "Key '\(token)' in pointer '\(pointer)' was not found in decrypted SOPS document."
                    )
                }
                current = next
            } else if let array = current as? [Any] {
                // Per RFC 6901 Section 4, array indices must be "0" or a non-zero-prefixed unsigned integer.
                guard (token == "0" || (!token.hasPrefix("0") && token.allSatisfy(\.isNumber))),
                      let index = Int(token),
                      index >= 0,
                      index < array.count else {
                    throw SecretResolutionError.itemNotFound(
                        scheme: "sops",
                        referenceRedacted: reference.redactedDescription,
                        message: "Array index '\(token)' in pointer '\(pointer)' is out of bounds in decrypted SOPS document."
                    )
                }
                current = array[index]
            } else {
                throw SecretResolutionError.itemNotFound(
                    scheme: "sops",
                    referenceRedacted: reference.redactedDescription,
                    message: "Cannot traverse token '\(token)' on scalar value in pointer '\(pointer)'."
                )
            }
        }

        return current
    }

    private static func serializeLeafValue(
        _ value: Any,
        pointer: String,
        reference: SecretReference
    ) throws -> Data {
        if value is NSNull {
            throw SecretResolutionError.itemNotFound(
                scheme: "sops",
                referenceRedacted: reference.redactedDescription,
                message: "JSON pointer '\(pointer)' resolved to null in decrypted SOPS document."
            )
        }

        if let str = value as? String {
            return Data(str.utf8)
        }

        #if canImport(ObjectiveC) && canImport(CoreFoundation)
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return Data((number.boolValue ? "true" : "false").utf8)
            }
            return Data(number.stringValue.utf8)
        }
        #else
        if type(of: value) == Bool.self, let boolValue = value as? Bool {
            return Data((boolValue ? "true" : "false").utf8)
        }
        if let number = value as? NSNumber {
            let boolType = type(of: NSNumber(value: true))
            let intType = type(of: NSNumber(value: 1))
            let cType = String(cString: number.objCType)
            if (boolType != intType && type(of: number) == boolType) || cType == "B" {
                return Data((number.boolValue ? "true" : "false").utf8)
            }
            return Data(number.stringValue.utf8)
        }
        #endif

        if JSONSerialization.isValidJSONObject(value) {
            return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        }

        return Data(String(describing: value).utf8)
    }

    // MARK: - Validation & Security Helpers

    private static func validateSopsReference(_ sopsRef: SopsSecretReference) throws {
        if sopsRef.filePath.utf8.contains(0) {
            throw SecretResolutionError.invalidReference(.containsNullByte)
        }
        guard !sopsRef.filePath.isEmpty else {
            throw SecretResolutionError.invalidReference(
                .invalidFormat(scheme: "sops", message: "File path in 'sops://' reference must not be empty.")
            )
        }
        if sopsRef.filePath.hasPrefix("-") {
            throw SecretResolutionError.invalidReference(
                .optionInjection(scheme: "sops", segment: sopsRef.filePath)
            )
        }
        for seg in sopsRef.filePath.split(separator: "/") where seg.hasPrefix("-") {
            throw SecretResolutionError.invalidReference(
                .optionInjection(scheme: "sops", segment: String(seg))
            )
        }
        for scalar in sopsRef.filePath.unicodeScalars where scalar.value < 0x20 || scalar.value == 0x7F {
            throw SecretResolutionError.invalidReference(.containsControlCharacter(scheme: "sops"))
        }

        if let pointer = sopsRef.jsonPointer {
            if pointer.utf8.contains(0) {
                throw SecretResolutionError.invalidReference(.containsNullByte)
            }
            guard !pointer.isEmpty else {
                throw SecretResolutionError.invalidReference(
                    .invalidFormat(scheme: "sops", message: "JSON pointer in 'sops://' reference must not be empty.")
                )
            }
            if pointer.hasPrefix("-") {
                throw SecretResolutionError.invalidReference(
                    .optionInjection(scheme: "sops", segment: pointer)
                )
            }
            for scalar in pointer.unicodeScalars where scalar.value < 0x20 || scalar.value == 0x7F {
                throw SecretResolutionError.invalidReference(.containsControlCharacter(scheme: "sops"))
            }
        }
    }

    private func resolveTrustedSopsExecutable(fileSystem: any FileSystem) throws -> String {
        do {
            return try ProcessSubprocessRunner.resolveTrustedExecutable(
                named: "sops",
                explicitPath: executablePath,
                searchDirectories: searchDirectories,
                fileSystem: fileSystem
            )
        } catch let securityError as SubprocessSecurityError {
            throw Self.mapSubprocessSecurityError(securityError)
        }
    }

    private static func mapSubprocessSecurityError(_ error: SubprocessSecurityError) -> SecretResolutionError {
        switch error {
        case .relativeExecutablePath(let path):
            return .unsafeExecutable(
                scheme: "sops",
                path: path,
                reason: error.description,
                remediation: "Provide an absolute path to a trusted 'sops' binary."
            )
        case .worldWritableExecutable(let path, _):
            return .unsafeExecutable(
                scheme: "sops",
                path: path,
                reason: error.description,
                remediation: "Fix permissions: chmod 755 \(path)"
            )
        case .executableNotFound(let name):
            return .providerFailed(
                scheme: "sops",
                message: "Mozilla SOPS executable '\(name)' was not found in trusted system directories.",
                remediation: "Install 'sops' (`brew install sops`)."
            )
        case .notExecutable(let path):
            return .providerFailed(
                scheme: "sops",
                message: "'sops' binary at '\(path)' is not executable.",
                remediation: "Verify installation permissions (`chmod 755 \(path)`)."
            )
        case .timedOut(let path, let duration):
            return .providerFailed(
                scheme: "sops",
                message: "'sops' ('\(path)') timed out after \(duration)."
            )
        case .unsupportedPlatform(let message):
            return .providerFailed(scheme: "sops", message: message)
        }
    }

    private static func classifyCLIFailure(
        exitCode: Int32,
        stderr: String,
        resolvedPath: String,
        reference: SecretReference,
        context: SettingsContext
    ) -> SecretResolutionError {
        let lower = stderr.lowercased()

        if lower.contains("no such file")
            || lower.contains("cannot find the file")
            || lower.contains("file does not exist") {
            return .itemNotFound(
                scheme: "sops",
                referenceRedacted: reference.redactedDescription,
                message: "Encrypted SOPS file '\(resolvedPath)' was not found (exit code \(exitCode))."
            )
        }

        if lower.contains("failed to get the data key")
            || lower.contains("cannot decrypt")
            || lower.contains("could not decrypt")
            || lower.contains("age:")
            || lower.contains("kms")
            || lower.contains("pgp")
            || lower.contains("accessdenied") {
            return .authenticationFailed(
                scheme: "sops",
                message: context.redactor.scrub("SOPS failed to decrypt data key for '\(reference.redactedDescription)' (exit code \(exitCode))."),
                remediation: "Verify `SOPS_AGE_KEY_FILE`, `SOPS_AGE_KEY`, GPG agent, or cloud KMS credentials."
            )
        }

        return .providerFailed(
            scheme: "sops",
            message: context.redactor.scrub("'sops' CLI exited with status \(exitCode).")
        )
    }
}

extension SecretProvider where Self == SOPSProvider {
    /// Creates a Mozilla SOPS encrypted-file secret provider (`sops://<file-path>#<json-pointer-or-key>`).
    ///
    /// - Parameters:
    ///   - executablePath: Optional explicit absolute path to a trusted `sops` binary.
    ///   - ageKeyFile: Optional path to an `age` secret key file forwarded as `SOPS_AGE_KEY_FILE`.
    ///   - timeout: Maximum execution duration per CLI invocation. Defaults to 30 seconds.
    /// - Returns: A configured ``SOPSProvider``.
    public static func sops(
        executablePath: String? = nil,
        ageKeyFile: String? = nil,
        timeout: Duration? = .seconds(30)
    ) -> SOPSProvider {
        SOPSProvider(
            executablePath: executablePath,
            ageKeyFile: ageKeyFile,
            timeout: timeout
        )
    }
}
