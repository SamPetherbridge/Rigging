import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Errors thrown when materializing or cleaning up a temporary secret file on disk.
public enum EphemeralSecretFileError: Error, Sendable, Equatable, Hashable, CustomStringConvertible, LocalizedError {
    /// Prefix or suffix contained a path separator (`/`), NUL byte, or `..` traversal sequence.
    case invalidFileNameAffix(String)

    /// Failed to create the private mode-`0700` temporary directory via `mkdtemp`.
    case directoryCreationFailed(errno: Int32)

    /// Failed to atomically create the secret file with `O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW`.
    case fileOpenFailed(errno: Int32)

    /// Failed to write the secret bytes to the file descriptor.
    case fileWriteFailed(errno: Int32)

    /// Failed to flush the secret file descriptor to storage via `fsync`.
    case fileSyncFailed(errno: Int32)

    /// Human-readable diagnostic describing the POSIX failure without exposing secret contents.
    public var description: String {
        switch self {
        case .invalidFileNameAffix(let affix):
            return "Invalid ephemeral secret file affix '\(affix)': path separators, NUL bytes, and '..' are forbidden."
        case .directoryCreationFailed(let code):
            return "Failed to create private 0700 temporary directory for ephemeral secret (errno \(code))."
        case .fileOpenFailed(let code):
            return "Failed to atomically create ephemeral secret file with O_EXCL | O_NOFOLLOW (errno \(code))."
        case .fileWriteFailed(let code):
            return "Failed to write bytes to ephemeral secret file (errno \(code))."
        case .fileSyncFailed(let code):
            return "Failed to fsync ephemeral secret file (errno \(code))."
        }
    }

    /// Localized error description matching ``description`` for CLI error reporters.
    public var errorDescription: String? {
        description
    }
}

extension Secret where Value == String {
    /// Materializes the UTF-8 bytes of the secret string into an atomic mode-`0600` file inside a
    /// private mode-`0700` temporary directory for the duration of `body`, then overwrites with zeros
    /// and unlinks both file and directory on exit.
    ///
    /// Use this API only when bridging to legacy tools (such as `ssh -i` or `openssl`) that require
    /// a filesystem path instead of in-memory bytes or standard input pipes.
    ///
    /// ```swift
    /// try await settings.signingKey.withEphemeralFile(suffix: ".p8") { keyURL in
    ///     try await signArchive(usingKeyAt: keyURL)
    /// }
    /// ```
    ///
    /// - Parameters:
    ///   - prefix: File name prefix (must not contain `/`, `..`, or NUL bytes).
    ///   - suffix: File name suffix or extension such as `".pem"` or `".p8"`.
    ///   - permissions: POSIX mode applied to the created file (defaults to `0o600`).
    ///   - body: Scoped async closure receiving the temporary file `URL`.
    /// - Returns: Value returned by `body`.
    /// - Throws: ``EphemeralSecretFileError`` if file creation fails, or any error thrown by `body`.
    public func withEphemeralFile<R>(
        prefix: String = "secret-",
        suffix: String = "",
        permissions: UInt16 = 0o600,
        _ body: @Sendable (URL) async throws -> R
    ) async throws -> R {
        var bytes = withExposedUTF8 { Array($0) }
        defer { zeroMemory(&bytes) }
        return try await materializeEphemeralSecretFile(
            bytes: bytes,
            prefix: prefix,
            suffix: suffix,
            permissions: permissions,
            body: body
        )
    }
}

extension Secret where Value == Data {
    /// Materializes the secret `Data` into an atomic mode-`0600` file inside a private mode-`0700`
    /// temporary directory for the duration of `body`, then overwrites with zeros and unlinks on exit.
    ///
    /// - Parameters:
    ///   - prefix: File name prefix (must not contain `/`, `..`, or NUL bytes).
    ///   - suffix: File name suffix or extension such as `".p12"` or `".der"`.
    ///   - permissions: POSIX mode applied to the created file (defaults to `0o600`).
    ///   - body: Scoped async closure receiving the temporary file `URL`.
    /// - Returns: Value returned by `body`.
    /// - Throws: ``EphemeralSecretFileError`` if file creation fails, or any error thrown by `body`.
    public func withEphemeralFile<R>(
        prefix: String = "secret-",
        suffix: String = "",
        permissions: UInt16 = 0o600,
        _ body: @Sendable (URL) async throws -> R
    ) async throws -> R {
        var bytes = withExposedBytes { Array($0) }
        defer { zeroMemory(&bytes) }
        return try await materializeEphemeralSecretFile(
            bytes: bytes,
            prefix: prefix,
            suffix: suffix,
            permissions: permissions,
            body: body
        )
    }
}

extension Secret where Value == [UInt8] {
    /// Materializes the secret byte array into an atomic mode-`0600` file inside a private mode-`0700`
    /// temporary directory for the duration of `body`, then overwrites with zeros and unlinks on exit.
    ///
    /// - Parameters:
    ///   - prefix: File name prefix (must not contain `/`, `..`, or NUL bytes).
    ///   - suffix: File name suffix or extension.
    ///   - permissions: POSIX mode applied to the created file (defaults to `0o600`).
    ///   - body: Scoped async closure receiving the temporary file `URL`.
    /// - Returns: Value returned by `body`.
    /// - Throws: ``EphemeralSecretFileError`` if file creation fails, or any error thrown by `body`.
    public func withEphemeralFile<R>(
        prefix: String = "secret-",
        suffix: String = "",
        permissions: UInt16 = 0o600,
        _ body: @Sendable (URL) async throws -> R
    ) async throws -> R {
        var bytes = expose()
        defer { zeroMemory(&bytes) }
        return try await materializeEphemeralSecretFile(
            bytes: bytes,
            prefix: prefix,
            suffix: suffix,
            permissions: permissions,
            body: body
        )
    }
}

// MARK: - Hardened POSIX Materialization & Zeroing Cleanup

private func materializeEphemeralSecretFile<R>(
    bytes: [UInt8],
    prefix: String,
    suffix: String,
    permissions: UInt16,
    body: @Sendable (URL) async throws -> R
) async throws -> R {
    try validateAffix(prefix)
    try validateAffix(suffix)

    let baseTmpDir: String = {
        let candidate = ProcessInfo.processInfo.environment["TMPDIR"]
            .flatMap { $0.isEmpty ? nil : $0 } ?? NSTemporaryDirectory()
        if candidate.count > 1 && candidate.hasSuffix("/") {
            return String(candidate.dropLast())
        }
        return candidate
    }()

    let templateString = "\(baseTmpDir)/rigging-secret.XXXXXXXXXX"
    var templateCChars = Array(templateString.utf8CString)
    guard let createdDirPtr = mkdtemp(&templateCChars) else {
        throw EphemeralSecretFileError.directoryCreationFailed(errno: errno)
    }

    let dirPath = String(cString: createdDirPtr)
    _ = chmod(dirPath, mode_t(0o700))

    let randomToken = generateRandomHex(byteCount: 8)
    let fileName = "\(prefix)\(randomToken)\(suffix)"
    let filePath = "\(dirPath)/\(fileName)"
    let fileURL = URL(fileURLWithPath: filePath, isDirectory: false)

    let writtenByteCount = bytes.count
    var fileCreated = false

    defer {
        scrubAndRemoveEphemeralArtifacts(
            filePath: filePath,
            dirPath: dirPath,
            expectedByteCount: writtenByteCount,
            fileCreated: fileCreated
        )
    }

    let openFlags: Int32 = O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW
    let fd = open(filePath, openFlags, mode_t(permissions))
    guard fd >= 0 else {
        throw EphemeralSecretFileError.fileOpenFailed(errno: errno)
    }
    fileCreated = true

    do {
        // Ensure exact requested permissions regardless of restrictive process umask.
        _ = fchmod(fd, mode_t(permissions))

        try writeAllBytes(bytes, to: fd)

        if fsync(fd) != 0 {
            throw EphemeralSecretFileError.fileSyncFailed(errno: errno)
        }
        _ = close(fd)
    } catch {
        _ = close(fd)
        throw error
    }

    return try await body(fileURL)
}

private func validateAffix(_ affix: String) throws {
    if affix.utf8.contains(0) || affix.contains("/") || affix.contains("..") {
        throw EphemeralSecretFileError.invalidFileNameAffix(affix)
    }
}

private func generateRandomHex(byteCount: Int) -> String {
    var generator = SystemRandomNumberGenerator()
    let hexDigits: [Character] = Array("0123456789abcdef")
    var result = ""
    result.reserveCapacity(byteCount * 2)
    for _ in 0..<byteCount {
        let byte = UInt8.random(in: 0...255, using: &generator)
        result.append(hexDigits[Int(byte >> 4)])
        result.append(hexDigits[Int(byte & 0x0F)])
    }
    return result
}

private func writeAllBytes(_ bytes: [UInt8], to fd: Int32) throws {
    guard !bytes.isEmpty else { return }
    try bytes.withUnsafeBytes { rawBuffer in
        guard let baseAddress = rawBuffer.baseAddress else { return }
        var offset = 0
        while offset < rawBuffer.count {
            let written = write(fd, baseAddress.advanced(by: offset), rawBuffer.count - offset)
            if written > 0 {
                offset += written
            } else if written < 0 && errno == EINTR {
                continue
            } else {
                throw EphemeralSecretFileError.fileWriteFailed(errno: errno)
            }
        }
    }
}

private func scrubAndRemoveEphemeralArtifacts(
    filePath: String,
    dirPath: String,
    expectedByteCount: Int,
    fileCreated: Bool
) {
    if fileCreated {
        var wfd = open(filePath, O_WRONLY | O_NOFOLLOW)
        if wfd < 0 && errno == EACCES {
            // If caller requested read-only permissions (e.g. 0400), restore owner write on the
            // open file descriptor without following symlinks so zero-wipe still succeeds.
            let rfd = open(filePath, O_RDONLY | O_NOFOLLOW)
            if rfd >= 0 {
                _ = fchmod(rfd, mode_t(0o600))
                _ = close(rfd)
            }
            wfd = open(filePath, O_WRONLY | O_NOFOLLOW)
        }

        if wfd >= 0 {
            var statBuf = stat()
            let currentSize = fstat(wfd, &statBuf) == 0 ? max(0, Int(statBuf.st_size)) : 0
            let wipeLength = max(expectedByteCount, currentSize)

            if wipeLength > 0 {
                _ = lseek(wfd, 0, SEEK_SET)
                let zeroChunk = [UInt8](repeating: 0, count: min(4096, wipeLength))
                var remaining = wipeLength
                zeroChunk.withUnsafeBytes { rawChunk in
                    guard let base = rawChunk.baseAddress else { return }
                    while remaining > 0 {
                        let count = min(rawChunk.count, remaining)
                        let written = write(wfd, base, count)
                        if written > 0 {
                            remaining -= written
                        } else if written < 0 && errno == EINTR {
                            continue
                        } else {
                            break
                        }
                    }
                }
            }

            _ = fsync(wfd)
            _ = close(wfd)
        }

        _ = unlink(filePath)
    }

    if rmdir(dirPath) != 0 {
        // Remove any auxiliary files dropped inside our private directory before retrying rmdir.
        if let dirStream = opendir(dirPath) {
            defer { closedir(dirStream) }
            while let entry = readdir(dirStream) {
                let name = withUnsafeBytes(of: entry.pointee.d_name) { rawBuf in
                    String(decoding: rawBuf.prefix(while: { $0 != 0 }), as: UTF8.self)
                }
                if !name.isEmpty && name != "." && name != ".." {
                    _ = unlink("\(dirPath)/\(name)")
                }
            }
        }
        _ = rmdir(dirPath)
    }
}

private func zeroMemory(_ bytes: inout [UInt8]) {
    guard !bytes.isEmpty else { return }
    bytes.withUnsafeMutableBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress else { return }
        #if canImport(Darwin)
        _ = memset_s(base, rawBuffer.count, 0, rawBuffer.count)
        #else
        for index in 0..<rawBuffer.count {
            rawBuffer.storeBytes(of: UInt8(0), toByteOffset: index, as: UInt8.self)
        }
        #endif
    }
}
