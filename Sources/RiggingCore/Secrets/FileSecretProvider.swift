import Foundation

/// Built-in ``SecretProvider`` resolving `file:///abs/path` and `@~/path` / `@/abs/path` / `@./rel/path`
/// references via ``SettingsContext/fileSystem`` while enforcing strict POSIX file permissions.
///
/// By default, `FileSecretProvider` requires secret files to forbid group and world permissions
/// (`0o600` mask; any `perms & 0o077 != 0` triggers ``SecretResolutionError/insecureFilePermissions(path:actualPermissions:requiredPermissions:)``
/// with exit code `4` and a copy-pasteable `chmod 600 <path>` remediation).
///
/// ```swift
/// let provider = FileSecretProvider(requiredPermissions: 0o600)
/// ```
public struct FileSecretProvider: SecretProvider, Sendable {
    /// Supported URI schemes (`["file"]`).
    public let supportedSchemes: Set<String> = ["file"]

    /// Maximum allowed POSIX permission mask (`0o600` by default), or `nil` when permission checks are disabled.
    public let requiredPermissions: UInt16?

    /// Creates a local-file secret provider.
    ///
    /// - Parameter requiredPermissions: Maximum allowed POSIX permission mask (`0o600` by default),
    ///   or `nil` to disable POSIX mode verification.
    public init(requiredPermissions: UInt16? = 0o600) {
        self.requiredPermissions = requiredPermissions
    }

    /// Resolves a batch of `.file(...)` secret references against ``SettingsContext/fileSystem``.
    ///
    /// - Parameters:
    ///   - references: Deduplicated ``SecretReference`` items to read.
    ///   - context: Execution context providing filesystem, path resolution, and redactor access.
    /// - Returns: Dictionary mapping each resolved ``SecretReference`` to its raw file `Data`.
    /// - Throws: ``SecretResolutionError`` on missing or over-permissive files, or ``SecretBatchPartialFailureError``
    ///   when a multi-file batch partially succeeds.
    public func resolveBatch(
        _ references: [SecretReference],
        context: SettingsContext
    ) async throws -> [SecretReference: Data] {
        var resolved: [SecretReference: Data] = [:]
        var failures: [SecretReference: any Error] = [:]
        resolved.reserveCapacity(references.count)

        for reference in references {
            guard case .file(let fileRef) = reference else {
                continue
            }
            do {
                let loaded = try Self.loadSecretFile(
                    rawPath: fileRef.path,
                    requiredPermissions: requiredPermissions,
                    context: context
                )
                context.redactor.register(loaded.data)
                resolved[reference] = loaded.data
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
    }

    // MARK: - Shared Path Resolution & Permission Verification

    internal static func loadSecretFile(
        rawPath: String,
        requiredPermissions: UInt16?,
        context: SettingsContext
    ) throws -> (resolvedPath: String, data: Data) {
        let resolvedPath = resolvePath(
            rawPath,
            workingDirectory: context.workingDirectory,
            homeDirectory: context.homeDirectory
        )

        guard context.fileSystem.fileExists(atPath: resolvedPath),
              !context.fileSystem.isDirectory(atPath: resolvedPath) else {
            throw SecretResolutionError.secretFileNotFound(path: resolvedPath)
        }

        if let required = requiredPermissions {
            let perms: UInt16
            do {
                perms = try context.fileSystem.posixPermissions(atPath: resolvedPath) & 0o777
            } catch {
                throw SecretResolutionError.secretFileReadFailed(
                    path: resolvedPath,
                    reason: error.localizedDescription
                )
            }

            // Default `required = 0o600` sets `disallowedMask = 0o077`, rejecting any group or world bits (`perms & 0o077 != 0`).
            let disallowedMask = (~required) & 0o077
            if (perms & disallowedMask) != 0 {
                throw SecretResolutionError.insecureFilePermissions(
                    path: resolvedPath,
                    actualPermissions: perms,
                    requiredPermissions: required
                )
            }
        }

        let data: Data
        do {
            data = try context.fileSystem.readFile(atPath: resolvedPath)
        } catch {
            throw SecretResolutionError.secretFileReadFailed(
                path: resolvedPath,
                reason: error.localizedDescription
            )
        }

        return (resolvedPath, data)
    }

    /// Expands leading `~` against `homeDirectory`, resolves relative paths against `workingDirectory`,
    /// and lexically normalizes `.` and `..` segments.
    ///
    /// - Parameters:
    ///   - rawPath: Raw path string to normalize.
    ///   - workingDirectory: Base directory for relative paths.
    ///   - homeDirectory: Home directory substituted for leading `~` or `~/`.
    /// - Returns: Normalized filesystem path string.
    public static func resolvePath(
        _ rawPath: String,
        workingDirectory: String,
        homeDirectory: String
    ) -> String {
        SourcePathResolver.resolve(
            path: rawPath,
            workingDirectory: workingDirectory,
            homeDirectory: homeDirectory
        )
    }

    /// Expands a leading `~` or `~/` prefix using `homeDirectory`.
    ///
    /// - Parameters:
    ///   - path: Input path that may start with `~`.
    ///   - homeDirectory: Home directory path (for example, `"/Users/jane"`).
    /// - Returns: Path with any leading tilde expanded.
    public static func expandHome(_ path: String, homeDirectory: String) -> String {
        let cleanHome = (homeDirectory.hasSuffix("/") || homeDirectory.hasSuffix("\\")) && homeDirectory.count > 1
            ? String(homeDirectory.dropLast())
            : homeDirectory
        if path == "~" {
            return cleanHome
        }
        if path.hasPrefix("~/") || path.hasPrefix("~\\") {
            return "\(cleanHome)/\(path.dropFirst(2))"
        }
        return path
    }
}

extension SecretProvider where Self == FileSecretProvider {
    /// Creates a local-file ``FileSecretProvider`` enforcing the given POSIX permission mask.
    ///
    /// - Parameter requiredPermissions: Maximum allowed POSIX permission mask (`0o600` by default).
    /// - Returns: Configured ``FileSecretProvider``.
    public static func file(requiredPermissions: UInt16? = 0o600) -> FileSecretProvider {
        FileSecretProvider(requiredPermissions: requiredPermissions)
    }
}
