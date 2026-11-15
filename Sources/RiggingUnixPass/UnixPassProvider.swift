import Foundation
import RiggingCore

/// Unix `pass` (`~/.password-store`) secret provider resolving `pass://<entry-path>[#fragment]` references.
///
/// Supported fragment selectors:
/// - No fragment: returns line 1 (standard `pass` convention), or the full entry when `?full=true` or `fullEntryByDefault == true`.
/// - `#full`: returns the full decrypted entry text.
/// - `#line:<N>`: returns 1-based line `N` (e.g. `pass://prod/db#line:2`).
/// - `#<key>`: extracts metadata value from `key: value` lines (e.g. `pass://prod/db#username`).
public struct UnixPassProvider: SecretProvider, Sendable {
    /// URI schemes resolved by this provider (`["pass"]`).
    public let supportedSchemes: Set<String> = ["pass"]

    /// Optional explicit absolute path to the `pass` CLI binary.
    public let executablePath: String?

    /// Optional explicit `PASSWORD_STORE_DIR` override. When `nil`, `context.environment["PASSWORD_STORE_DIR"]` is forwarded if set.
    public let storeDirectory: String?

    /// When `true`, references without a `#fragment` return the entire entry instead of line 1.
    public let fullEntryByDefault: Bool

    /// Trusted absolute directories searched when `executablePath` is `nil`.
    public let searchDirectories: [String]

    /// Subprocess execution timeout per CLI call.
    public let timeout: Duration?

    /// Creates a Unix `pass` secret provider (`pass://<entry-path>[#fragment]`).
    ///
    /// - Parameters:
    ///   - executablePath: Optional explicit absolute path to a trusted `pass` executable.
    ///   - storeDirectory: Optional `PASSWORD_STORE_DIR` override directory.
    ///   - fullEntryByDefault: Whether fragment-less `pass://` URIs return the full decrypted file rather than line 1. Defaults to `false`.
    ///   - searchDirectories: Trusted absolute system directories searched when `executablePath` is `nil`.
    ///   - timeout: Maximum execution duration per `pass` invocation. Defaults to 30 seconds.
    public init(
        executablePath: String? = nil,
        storeDirectory: String? = nil,
        fullEntryByDefault: Bool = false,
        searchDirectories: [String] = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ],
        timeout: Duration? = .seconds(30)
    ) {
        self.executablePath = executablePath
        self.storeDirectory = storeDirectory
        self.fullEntryByDefault = fullEntryByDefault
        self.searchDirectories = searchDirectories
        self.timeout = timeout
    }

    /// Resolves a batch of `pass://` references, deduplicating `pass show` calls when multiple fragments target the same entry.
    ///
    /// - Parameters:
    ///   - references: The `SecretReference` items to resolve. Non-`pass://` items are ignored.
    ///   - context: Active `SettingsContext` supplying environment variables, filesystem, subprocess runner, and redactor.
    /// - Returns: A dictionary mapping each resolved `SecretReference` to its extracted UTF-8 secret `Data`.
    /// - Throws: `SecretResolutionError` or `SecretBatchPartialFailureError` if GPG decryption, binary verification, or fragment lookup fails.
    public func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        var passEntries: [(reference: SecretReference, ref: PassSecretReference)] = []
        var seen = Set<SecretReference>()

        for reference in references {
            guard case .pass(let passRef) = reference else {
                continue
            }
            try Self.validatePassReference(passRef)
            if seen.insert(reference).inserted {
                passEntries.append((reference, passRef))
            }
        }

        guard !passEntries.isEmpty else {
            return [:]
        }

        let resolvedBinaryPath = try resolveTrustedPassExecutable(fileSystem: context.fileSystem)

        var baseEnvironment = context.environment
        if let storeDirectory, !storeDirectory.isEmpty {
            baseEnvironment["PASSWORD_STORE_DIR"] = storeDirectory
        }

        // Deduplicate `pass show <entryPath>` invocations when multiple fields/lines come from the same entry.
        struct EntryKey: Hashable {
            let entryPath: String
            let storeOverride: String?
        }

        var entryCache: [EntryKey: Result<String, any Error>] = [:]
        var resolved: [SecretReference: Data] = [:]
        var failures: [SecretReference: any Error] = [:]
        resolved.reserveCapacity(passEntries.count)

        for item in passEntries {
            let storeOverride = item.ref.query["store"]
            let cacheKey = EntryKey(entryPath: item.ref.entryPath, storeOverride: storeOverride)

            let rawEntryResult: Result<String, any Error>
            if let cached = entryCache[cacheKey] {
                rawEntryResult = cached
            } else {
                var callEnvironment = baseEnvironment
                if let storeOverride, !storeOverride.isEmpty {
                    callEnvironment["PASSWORD_STORE_DIR"] = storeOverride
                }
                let fetched = await Result {
                    try await fetchPassEntry(
                        entryPath: item.ref.entryPath,
                        reference: item.reference,
                        executablePath: resolvedBinaryPath,
                        environment: callEnvironment,
                        context: context
                    )
                }
                entryCache[cacheKey] = fetched
                rawEntryResult = fetched
            }

            do {
                let fullRawOutput = try rawEntryResult.get()
                let extracted = try extractValue(from: fullRawOutput, for: item.ref, reference: item.reference)
                let bytes = Data(extracted.utf8)
                context.redactor.register(bytes)
                resolved[item.reference] = bytes
            } catch {
                if passEntries.count == 1 {
                    throw error
                }
                failures[item.reference] = error
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

    // MARK: - Subprocess & Parsing

    private func fetchPassEntry(
        entryPath: String,
        reference: SecretReference,
        executablePath: String,
        environment: [String: String],
        context: SettingsContext
    ) async throws -> String {
        let result: SubprocessResult
        do {
            result = try await context.subprocessRunner.run(
                executablePath: executablePath,
                arguments: ["show", entryPath],
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
                scheme: "pass",
                message: "Failed to invoke 'pass' CLI."
            )
        }

        guard result.exitCode == 0 else {
            throw Self.classifyCLIFailure(
                exitCode: result.exitCode,
                stderr: result.stderrString,
                reference: reference,
                context: context
            )
        }

        guard let text = String(data: result.stdout, encoding: .utf8) else {
            throw SecretResolutionError.providerFailed(
                scheme: "pass",
                message: "Decrypted 'pass' entry '\(reference.redactedDescription)' is not valid UTF-8 text."
            )
        }

        return text
    }

    private func extractValue(
        from rawOutput: String,
        for passRef: PassSecretReference,
        reference: SecretReference
    ) throws -> String {
        var normalized = rawOutput
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        if normalized.hasSuffix("\n") {
            normalized.removeLast()
        }

        let wantsFullFromQuery: Bool = {
            guard let rawFull = passRef.query["full"]?.lowercased() else { return false }
            return rawFull == "true" || rawFull == "1" || rawFull == "yes"
        }()

        guard let fragment = passRef.fragment else {
            if fullEntryByDefault || wantsFullFromQuery {
                return normalized
            }
            let firstLine = normalized.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false).first
            return firstLine.map(String.init) ?? ""
        }

        if fragment == "full" {
            return normalized
        }

        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)

        if fragment.hasPrefix("line:") {
            let numberPart = String(fragment.dropFirst("line:".count))
            guard let lineNumber = Int(numberPart), lineNumber >= 1 else {
                throw SecretResolutionError.invalidReference(
                    .invalidFormat(
                        scheme: "pass",
                        message: "Expected positive 1-based integer in '#\(fragment)'."
                    )
                )
            }
            guard lineNumber <= lines.count else {
                throw SecretResolutionError.itemNotFound(
                    scheme: "pass",
                    referenceRedacted: reference.redactedDescription,
                    message: "Line \(lineNumber) does not exist in pass entry '\(passRef.entryPath)' (entry has \(lines.count) line(s))."
                )
            }
            return lines[lineNumber - 1]
        }

        // Parse `key: value` metadata lines (preferring lines 2+ per standard `pass` layout, with fallback to line 1).
        let metadataSearchOrder: [String] = lines.count > 1
            ? Array(lines.dropFirst()) + [lines[0]]
            : lines

        if let exactMatch = Self.findMetadataValue(forKey: fragment, caseSensitive: true, in: metadataSearchOrder) {
            return exactMatch
        }
        if let ciMatch = Self.findMetadataValue(forKey: fragment, caseSensitive: false, in: metadataSearchOrder) {
            return ciMatch
        }

        throw SecretResolutionError.itemNotFound(
            scheme: "pass",
            referenceRedacted: reference.redactedDescription,
            message: "Metadata key '\(fragment)' was not found in pass entry '\(passRef.entryPath)'."
        )
    }

    private static func findMetadataValue(
        forKey targetKey: String,
        caseSensitive: Bool,
        in lines: [String]
    ) -> String? {
        let normalizedTarget = caseSensitive ? targetKey : targetKey.lowercased()
        for line in lines {
            guard let colonIndex = line.firstIndex(of: ":") else { continue }
            let rawKey = line[..<colonIndex].trimmingCharacters(in: .whitespaces)
            guard !rawKey.isEmpty else { continue }
            let comparableKey = caseSensitive ? rawKey : rawKey.lowercased()
            if comparableKey == normalizedTarget {
                let valueSlice = line[line.index(after: colonIndex)...]
                return valueSlice.trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    // MARK: - Validation & Security Helpers

    private static func validatePassReference(_ passRef: PassSecretReference) throws {
        if passRef.entryPath.utf8.contains(0) {
            throw SecretResolutionError.invalidReference(.containsNullByte)
        }
        guard !passRef.entryPath.isEmpty else {
            throw SecretResolutionError.invalidReference(
                .invalidFormat(scheme: "pass", message: "Entry path in 'pass://' must not be empty.")
            )
        }
        if passRef.entryPath.hasPrefix("-") {
            throw SecretResolutionError.invalidReference(
                .optionInjection(scheme: "pass", segment: passRef.entryPath)
            )
        }
        for rawSeg in passRef.entryPath.split(separator: "/", omittingEmptySubsequences: false) {
            let seg = String(rawSeg)
            guard !seg.isEmpty else {
                throw SecretResolutionError.invalidReference(
                    .invalidFormat(scheme: "pass", message: "Empty path segment in 'pass://' reference.")
                )
            }
            if seg.hasPrefix("-") {
                throw SecretResolutionError.invalidReference(.optionInjection(scheme: "pass", segment: seg))
            }
            if seg == "." || seg == ".." {
                throw SecretResolutionError.invalidReference(.pathTraversal(scheme: "pass", segment: seg))
            }
            for scalar in seg.unicodeScalars where scalar.value < 0x20 || scalar.value == 0x7F {
                throw SecretResolutionError.invalidReference(.containsControlCharacter(scheme: "pass"))
            }
        }

        if let fragment = passRef.fragment {
            if fragment.utf8.contains(0) {
                throw SecretResolutionError.invalidReference(.containsNullByte)
            }
            if fragment.hasPrefix("-") {
                throw SecretResolutionError.invalidReference(.optionInjection(scheme: "pass", segment: fragment))
            }
            for scalar in fragment.unicodeScalars where scalar.value < 0x20 || scalar.value == 0x7F {
                throw SecretResolutionError.invalidReference(.containsControlCharacter(scheme: "pass"))
            }
        }
    }

    private func resolveTrustedPassExecutable(fileSystem: any FileSystem) throws -> String {
        do {
            return try ProcessSubprocessRunner.resolveTrustedExecutable(
                named: "pass",
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
                scheme: "pass",
                path: path,
                reason: error.description,
                remediation: "Provide an absolute path to a trusted 'pass' binary."
            )
        case .worldWritableExecutable(let path, _):
            return .unsafeExecutable(
                scheme: "pass",
                path: path,
                reason: error.description,
                remediation: "Fix permissions: chmod 755 \(path)"
            )
        case .executableNotFound(let name):
            return .providerFailed(
                scheme: "pass",
                message: "Unix 'pass' executable '\(name)' was not found in trusted system directories.",
                remediation: "Install 'pass' (`brew install pass` or `apt install pass`)."
            )
        case .notExecutable(let path):
            return .providerFailed(
                scheme: "pass",
                message: "'pass' binary at '\(path)' is not executable.",
                remediation: "Verify installation permissions (`chmod 755 \(path)`)."
            )
        case .timedOut(let path, let duration):
            return .providerFailed(
                scheme: "pass",
                message: "'pass' ('\(path)') timed out after \(duration).",
                remediation: "Check whether gpg-agent is waiting for a passphrase prompt."
            )
        case .unsupportedPlatform(let message):
            return .providerFailed(scheme: "pass", message: message)
        }
    }

    private static func classifyCLIFailure(
        exitCode: Int32,
        stderr: String,
        reference: SecretReference,
        context: SettingsContext
    ) -> SecretResolutionError {
        let lower = stderr.lowercased()

        if lower.contains("is not in the password store")
            || lower.contains("not found")
            || lower.contains("no such file") {
            return .itemNotFound(
                scheme: "pass",
                referenceRedacted: reference.redactedDescription,
                message: "Entry was not found in the password store (exit code \(exitCode))."
            )
        }

        if lower.contains("gpg") && (lower.contains("decryption failed") || lower.contains("no secret key") || lower.contains("bad passphrase") || lower.contains("pinentry")) {
            return .authenticationFailed(
                scheme: "pass",
                message: context.redactor.scrub("GPG decryption failed while reading 'pass' entry (exit code \(exitCode))."),
                remediation: "Unlock your GPG key in `gpg-agent` and verify `PASSWORD_STORE_DIR`."
            )
        }

        return .providerFailed(
            scheme: "pass",
            message: context.redactor.scrub("'pass' CLI exited with status \(exitCode).")
        )
    }
}

extension SecretProvider where Self == UnixPassProvider {
    /// Creates a Unix `pass` (`~/.password-store`) secret provider (`pass://<entry-path>[#fragment]`).
    ///
    /// - Parameters:
    ///   - executablePath: Optional explicit absolute path to a trusted `pass` binary.
    ///   - storeDirectory: Optional `PASSWORD_STORE_DIR` override path.
    ///   - fullEntryByDefault: When `true`, fragment-less references return the full entry instead of line 1.
    ///   - timeout: Maximum execution duration per CLI invocation. Defaults to 30 seconds.
    /// - Returns: A configured ``UnixPassProvider``.
    public static func unixPass(
        executablePath: String? = nil,
        storeDirectory: String? = nil,
        fullEntryByDefault: Bool = false,
        timeout: Duration? = .seconds(30)
    ) -> UnixPassProvider {
        UnixPassProvider(
            executablePath: executablePath,
            storeDirectory: storeDirectory,
            fullEntryByDefault: fullEntryByDefault,
            timeout: timeout
        )
    }
}
