import Foundation

/// Built-in `SecretProvider` resolving `file:///abs/path` and `@~/path` / `@/abs/path` / `@./rel/path`
/// references via `SettingsContext.fileSystem` while enforcing strict POSIX file permissions (`0600` by default).
public struct FileSecretProvider: SecretProvider, Sendable {
    public let supportedSchemes: Set<String> = ["file"]

    /// Required maximum POSIX permission mask (`0o600` by default, rejecting any group or world access `perms & 0o077 != 0`).
    /// Pass `nil` only to disable POSIX permission checks explicitly.
    public let requiredPermissions: UInt16?

    public init(requiredPermissions: UInt16? = 0o600) {
        self.requiredPermissions = requiredPermissions
    }

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

    /// Expands `~` / `~/` against `homeDirectory`, resolves relative paths against `workingDirectory`,
    /// and lexically normalizes `.` and `..` segments so both `LocalFileSystem` and in-memory mock filesystems
    /// behave identically.
    public static func resolvePath(
        _ rawPath: String,
        workingDirectory: String,
        homeDirectory: String
    ) -> String {
        let homeExpanded = expandHome(rawPath, homeDirectory: homeDirectory)
        let combined: String
        if homeExpanded.hasPrefix("/") {
            combined = homeExpanded
        } else {
            let cleanWorkDir = workingDirectory.hasSuffix("/") && workingDirectory.count > 1
                ? String(workingDirectory.dropLast())
                : workingDirectory
            combined = "\(cleanWorkDir)/\(homeExpanded)"
        }
        return normalizeLexicalPath(combined)
    }

    public static func expandHome(_ path: String, homeDirectory: String) -> String {
        let cleanHome = homeDirectory.hasSuffix("/") && homeDirectory.count > 1
            ? String(homeDirectory.dropLast())
            : homeDirectory
        if path == "~" {
            return cleanHome
        }
        if path.hasPrefix("~/") {
            return "\(cleanHome)/\(path.dropFirst(2))"
        }
        return path
    }

    private static func normalizeLexicalPath(_ path: String) -> String {
        let isAbsolute = path.hasPrefix("/")
        var stack: [Substring] = []

        for segment in path.split(separator: "/", omittingEmptySubsequences: true) {
            if segment == "." {
                continue
            } else if segment == ".." {
                if let last = stack.last, last != ".." {
                    stack.removeLast()
                } else if !isAbsolute {
                    stack.append("..")
                }
            } else {
                stack.append(segment)
            }
        }

        if isAbsolute {
            return "/" + stack.joined(separator: "/")
        }
        return stack.isEmpty ? "." : stack.joined(separator: "/")
    }
}

extension SecretProvider where Self == FileSecretProvider {
    public static func file(requiredPermissions: UInt16? = 0o600) -> FileSecretProvider {
        FileSecretProvider(requiredPermissions: requiredPermissions)
    }
}
