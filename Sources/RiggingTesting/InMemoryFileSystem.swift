import Foundation
import RiggingCore
import Synchronization

/// Hermetic, thread-safe in-memory `FileSystem` implementation for unit testing configuration
/// sources, upward project config discovery, POSIX permission checks, and executable trust checks
/// without touching host disk.
public final class InMemoryFileSystem: FileSystem, Sendable {
    private struct State: Sendable {
        var files: [String: Data] = [:]
        var directories: Set<String> = ["/"]
        var permissions: [String: UInt16] = ["/": 0o755]
        var executables: Set<String> = []
        var defaultFilePermissions: UInt16?
    }

    private let state: Mutex<State>

    /// Creates an in-memory filesystem populated with UTF-8 text files, binary files,
    /// explicit directories (such as `"/repo/.git"`), custom POSIX permissions, and executable paths.
    ///
    /// - Parameters:
    ///   - files: UTF-8 string file contents keyed by absolute path.
    ///   - binaryFiles: Raw `Data` file contents keyed by absolute path.
    ///   - directories: Explicit directories to create (including empty marker directories like `"/repo/.git"`).
    ///   - permissions: Explicit POSIX permission overrides (e.g. `0o644` or `0o600`) keyed by path.
    ///   - executables: File paths marked as executable binaries (created as empty `0o755` files if not present in `files` or `binaryFiles`).
    ///   - defaultFilePermissions: Optional global default file mode; when `nil`, secret-like files default to `0o600` and regular files default to `0o644`.
    public init(
        files: [String: String] = [:],
        binaryFiles: [String: Data] = [:],
        directories: Set<String> = [],
        permissions: [String: UInt16] = [:],
        executables: Set<String> = [],
        defaultFilePermissions: UInt16? = nil
    ) {
        var initial = State(defaultFilePermissions: defaultFilePermissions)

        for rawDir in directories {
            let norm = Self.normalizePath(rawDir)
            Self.insertAncestors(of: norm, includeSelf: true, into: &initial)
        }

        for (rawPath, content) in files {
            let norm = Self.normalizePath(rawPath)
            Self.insertAncestors(of: norm, includeSelf: false, into: &initial)
            initial.directories.remove(norm)
            initial.files[norm] = Data(content.utf8)
            if initial.permissions[norm] == nil {
                initial.permissions[norm] = defaultFilePermissions ?? Self.inferredPermissions(forFilePath: norm, isExecutable: false)
            }
        }

        for (rawPath, data) in binaryFiles {
            let norm = Self.normalizePath(rawPath)
            Self.insertAncestors(of: norm, includeSelf: false, into: &initial)
            initial.directories.remove(norm)
            initial.files[norm] = data
            if initial.permissions[norm] == nil {
                initial.permissions[norm] = defaultFilePermissions ?? Self.inferredPermissions(forFilePath: norm, isExecutable: false)
            }
        }

        for rawExec in executables {
            let norm = Self.normalizePath(rawExec)
            Self.insertAncestors(of: norm, includeSelf: false, into: &initial)
            initial.directories.remove(norm)
            initial.executables.insert(norm)
            if initial.files[norm] == nil {
                initial.files[norm] = Data()
            }
            initial.permissions[norm] = 0o755
        }

        for (rawPath, mode) in permissions {
            let norm = Self.normalizePath(rawPath)
            initial.permissions[norm] = mode & 0o7777
            if initial.files[norm] != nil && (mode & 0o111) != 0 {
                initial.executables.insert(norm)
            }
        }

        self.state = Mutex(initial)
    }

    // MARK: - FileSystem Conformance

    public func fileExists(atPath path: String) -> Bool {
        let norm = Self.normalizePath(path)
        return state.withLock { s in
            s.files[norm] != nil || s.directories.contains(norm)
        }
    }

    public func isDirectory(atPath path: String) -> Bool {
        let norm = Self.normalizePath(path)
        return state.withLock { s in
            s.directories.contains(norm)
        }
    }

    public func readFile(atPath path: String) throws -> Data {
        let norm = Self.normalizePath(path)
        return try state.withLock { s in
            if s.directories.contains(norm) {
                throw CocoaError(.fileReadUnknown, userInfo: [NSFilePathErrorKey: path])
            }
            guard let data = s.files[norm] else {
                throw CocoaError(.fileReadNoSuchFile, userInfo: [NSFilePathErrorKey: path])
            }
            return data
        }
    }

    public func contentsOfDirectory(atPath path: String) throws -> [String] {
        let norm = Self.normalizePath(path)
        return try state.withLock { s in
            guard s.directories.contains(norm) else {
                throw CocoaError(.fileReadNoSuchFile, userInfo: [NSFilePathErrorKey: path])
            }

            var children: Set<String> = []
            let prefix = norm == "/" ? "/" : "\(norm)/"

            for filePath in s.files.keys where filePath.hasPrefix(prefix) {
                let remainder = filePath.dropFirst(prefix.count)
                if let firstSegment = remainder.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: true).first {
                    children.insert(String(firstSegment))
                }
            }

            for dirPath in s.directories where dirPath != norm && dirPath.hasPrefix(prefix) {
                let remainder = dirPath.dropFirst(prefix.count)
                if let firstSegment = remainder.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: true).first {
                    children.insert(String(firstSegment))
                }
            }

            return children.sorted()
        }
    }

    public func posixPermissions(atPath path: String) throws -> UInt16 {
        let norm = Self.normalizePath(path)
        return try state.withLock { s in
            if let explicit = s.permissions[norm] {
                return explicit & 0o7777
            }
            if s.directories.contains(norm) {
                return 0o755
            }
            if s.files[norm] != nil {
                let isExec = s.executables.contains(norm)
                return s.defaultFilePermissions ?? Self.inferredPermissions(forFilePath: norm, isExecutable: isExec)
            }
            throw POSIXError(.ENOENT)
        }
    }

    public func isExecutableFile(atPath path: String) -> Bool {
        let norm = Self.normalizePath(path)
        return state.withLock { s in
            guard s.files[norm] != nil, !s.directories.contains(norm) else {
                return false
            }
            if s.executables.contains(norm) {
                if let perms = s.permissions[norm] {
                    return (perms & 0o111) != 0
                }
                return true
            }
            if let perms = s.permissions[norm] {
                return (perms & 0o111) != 0
            }
            return false
        }
    }

    // MARK: - Dynamic Mutation Helpers (for Watcher & Live-Reload Tests)

    /// Writes or overwrites a UTF-8 file in memory, creating parent directories automatically.
    public func writeString(_ content: String, atPath path: String, permissions: UInt16? = nil) {
        writeFile(Data(content.utf8), atPath: path, permissions: permissions)
    }

    /// Writes or overwrites a binary file in memory, creating parent directories automatically.
    public func writeFile(_ data: Data, atPath path: String, permissions: UInt16? = nil) {
        let norm = Self.normalizePath(path)
        state.withLock { s in
            Self.insertAncestors(of: norm, includeSelf: false, into: &s)
            s.directories.remove(norm)
            s.files[norm] = data
            if let permissions {
                s.permissions[norm] = permissions & 0o7777
                if (permissions & 0o111) != 0 {
                    s.executables.insert(norm)
                }
            } else if s.permissions[norm] == nil {
                s.permissions[norm] = s.defaultFilePermissions
                    ?? Self.inferredPermissions(forFilePath: norm, isExecutable: s.executables.contains(norm))
            }
        }
    }

    /// Creates a directory and all ancestor directories in memory.
    public func makeDirectory(atPath path: String, permissions: UInt16 = 0o755) {
        let norm = Self.normalizePath(path)
        state.withLock { s in
            s.files.removeValue(forKey: norm)
            s.executables.remove(norm)
            Self.insertAncestors(of: norm, includeSelf: true, into: &s)
            s.permissions[norm] = permissions & 0o7777
        }
    }

    /// Updates POSIX permissions for an existing file or directory.
    public func setPermissions(_ permissions: UInt16, atPath path: String) {
        let norm = Self.normalizePath(path)
        state.withLock { s in
            s.permissions[norm] = permissions & 0o7777
            if s.files[norm] != nil {
                if (permissions & 0o111) != 0 {
                    s.executables.insert(norm)
                } else {
                    s.executables.remove(norm)
                }
            }
        }
    }

    /// Marks or unmarks a path as an executable file (creating an empty `0o755` file if needed).
    public func setExecutable(_ isExecutable: Bool, atPath path: String) {
        let norm = Self.normalizePath(path)
        state.withLock { s in
            if isExecutable {
                Self.insertAncestors(of: norm, includeSelf: false, into: &s)
                s.directories.remove(norm)
                if s.files[norm] == nil {
                    s.files[norm] = Data()
                }
                s.executables.insert(norm)
                if let current = s.permissions[norm], (current & 0o111) != 0 {
                    // Keep existing executable mode (e.g. 0o777 for world-writable tests)
                } else {
                    s.permissions[norm] = 0o755
                }
            } else {
                s.executables.remove(norm)
                if let current = s.permissions[norm] {
                    s.permissions[norm] = current & ~0o111
                }
            }
        }
    }

    /// Removes a file or directory tree from the in-memory filesystem.
    public func removeItem(atPath path: String) {
        let norm = Self.normalizePath(path)
        guard norm != "/" else { return }
        let prefix = "\(norm)/"
        state.withLock { s in
            s.files.removeValue(forKey: norm)
            s.directories.remove(norm)
            s.permissions.removeValue(forKey: norm)
            s.executables.remove(norm)

            for key in Array(s.files.keys) where key.hasPrefix(prefix) {
                s.files.removeValue(forKey: key)
                s.permissions.removeValue(forKey: key)
                s.executables.remove(key)
            }
            for dir in Array(s.directories) where dir.hasPrefix(prefix) {
                s.directories.remove(dir)
                s.permissions.removeValue(forKey: dir)
            }
        }
    }

    // MARK: - Path & Permission Helpers

    public static func normalizePath(_ rawPath: String) -> String {
        guard !rawPath.isEmpty else { return "/" }
        let isAbsolute = rawPath.hasPrefix("/")
        var stack: [Substring] = []

        for segment in rawPath.split(separator: "/", omittingEmptySubsequences: true) {
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

    private static func insertAncestors(of normalizedPath: String, includeSelf: Bool, into state: inout State) {
        state.directories.insert("/")
        if state.permissions["/"] == nil {
            state.permissions["/"] = 0o755
        }

        let segments = normalizedPath.split(separator: "/", omittingEmptySubsequences: true)
        guard !segments.isEmpty else { return }

        let limit = includeSelf ? segments.count : (segments.count - 1)
        guard limit > 0 else { return }

        var current = ""
        for idx in 0..<limit {
            current += "/\(segments[idx])"
            state.directories.insert(current)
            if state.permissions[current] == nil {
                state.permissions[current] = isLikelySecretDirectory(current) ? 0o700 : 0o755
            }
        }
    }

    private static func isLikelySecretDirectory(_ path: String) -> Bool {
        let lower = path.lowercased()
        return lower.hasSuffix("/.ssh")
            || lower.hasSuffix("/.keys")
            || lower.hasSuffix("/.gnupg")
            || lower.hasSuffix("/secrets")
            || lower.contains("/.ssh/")
            || lower.contains("/.keys/")
            || lower.contains("/.gnupg/")
            || lower.contains("/run/secrets")
    }

    private static func inferredPermissions(forFilePath path: String, isExecutable: Bool) -> UInt16 {
        if isExecutable {
            return 0o755
        }

        let lower = path.lowercased()
        let fileName = (lower.split(separator: "/").last).map(String.init) ?? lower

        // Standard structured configuration files default to 0o644 unless inside a secret directory.
        let configExtensions = [".json", ".toml", ".yaml", ".yml", ".plist", ".example", ".md"]
        let isConfigFile = fileName == ".env"
            || fileName.hasPrefix(".env.")
            || configExtensions.contains(where: { fileName.hasSuffix($0) })

        if lower.contains("/secrets/")
            || lower.contains("/.keys/")
            || lower.contains("/.ssh/")
            || lower.contains("/.gnupg/")
            || lower.contains("/.password-store/")
        {
            return 0o600
        }

        if isConfigFile {
            return 0o644
        }

        let secretExtensions = [".p8", ".pem", ".key", ".p12", ".pfx", ".gpg", ".age", ".secret", ".cer", ".crt"]
        if secretExtensions.contains(where: { fileName.hasSuffix($0) }) {
            return 0o600
        }

        let secretKeywords = ["secret", "token", "password", "passwd", "credential", "private", "authkey", "apikey", "api_key", "id_rsa", "id_ed25519"]
        if secretKeywords.contains(where: { fileName.contains($0) }) {
            return 0o600
        }

        return 0o644
    }
}
