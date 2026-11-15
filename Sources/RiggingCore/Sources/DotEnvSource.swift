import Foundation

/// Loads configuration values from one or more `.env` files in sequential order.
///
/// Later files in ``files`` (or ``SettingsConfiguration/dotEnvFiles``) override values defined in
/// earlier files while preserving displaced ``SettingOrigin/dotEnv(path:line:variable:)`` line
/// provenance in ``RawNode/overriddenOrigins``. Variable interpolation (`${VAR}`, `${VAR:-default}`)
/// resolves against ``SettingsContext/environment`` first and earlier `.env` entries second.
///
/// ```swift
/// let source = DotEnvSource(files: [".env", ".env.local"])
/// ```
public struct DotEnvSource: SettingsSource, Sendable {
    /// Optional explicit `.env` file paths overriding ``SettingsConfiguration/dotEnvFiles``.
    public let files: [String]?

    /// Whether `${VAR}`, `${VAR:-default}`, and `${VAR-default}` expressions are expanded.
    public let expandVariables: Bool

    /// Whether lines without `=` or unexpected trailing characters throw ``DotEnvParseError``.
    public let strictSyntax: Bool

    /// Whether missing `.env` files throw a file-not-found error instead of being skipped.
    public let requireFiles: Bool

    /// Human-readable name identifying this source in diagnostics (`"DotEnvSource"`).
    public var sourceName: String { "DotEnvSource" }

    /// Creates a `.env` file configuration source.
    ///
    /// - Parameters:
    ///   - files: Optional explicit list of `.env` paths overriding ``SettingsConfiguration/dotEnvFiles``.
    ///   - expandVariables: Whether `${...}` variable interpolation is enabled.
    ///   - strictSyntax: Whether malformed lines without `=` throw ``DotEnvParseError``.
    ///   - requireFiles: Whether missing `.env` files throw an error rather than being ignored.
    public init(
        files: [String]? = nil,
        expandVariables: Bool = true,
        strictSyntax: Bool = false,
        requireFiles: Bool = false
    ) {
        self.files = files
        self.expandVariables = expandVariables
        self.strictSyntax = strictSyntax
        self.requireFiles = requireFiles
    }

    /// Reads and parses configured `.env` files into a ``RawConfigTree`` with 1-based line provenance.
    ///
    /// - Parameters:
    ///   - configuration: Settings configuration controlling `dotEnvFiles`, prefixes, and delimiters.
    ///   - context: Execution context providing filesystem, working directory, and environment access.
    /// - Returns: A ``RawConfigTree`` tagged with ``SettingOrigin/dotEnv(path:line:variable:)`` provenance.
    /// - Throws: ``DotEnvParseError`` when a `.env` file contains invalid syntax, or `CocoaError` when
    ///   ``requireFiles`` is `true` and a configured file does not exist.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        let candidateFiles = files ?? configuration.dotEnvFiles
        guard !candidateFiles.isEmpty else { return .empty }

        var tree = RawConfigTree()
        var accumulatedDotEnvEntries: [String: String] = [:]

        for rawPath in candidateFiles {
            let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }

            let resolvedPath = SourcePathResolver.resolve(
                path: trimmed,
                workingDirectory: context.workingDirectory,
                homeDirectory: context.homeDirectory
            )

            guard context.fileSystem.fileExists(atPath: resolvedPath),
                  !context.fileSystem.isDirectory(atPath: resolvedPath) else {
                if requireFiles {
                    throw CocoaError(
                        .fileNoSuchFile,
                        userInfo: [NSFilePathErrorKey: resolvedPath]
                    )
                }
                continue
            }

            let data = try context.fileSystem.readFile(atPath: resolvedPath)
            let parsedEntries = try DotEnvParser.parse(
                data: data,
                environment: context.environment,
                existingEntries: accumulatedDotEnvEntries,
                expandVariables: expandVariables,
                strict: strictSyntax,
                path: resolvedPath
            )

            for entry in parsedEntries {
                accumulatedDotEnvEntries[entry.key] = entry.value
                let origin = SettingOrigin.dotEnv(
                    path: resolvedPath,
                    line: entry.line,
                    variable: entry.key
                )
                EnvironmentKeyMapper.insert(
                    variable: entry.key,
                    rawString: entry.value,
                    origin: origin,
                    configuration: configuration,
                    into: &tree
                )
            }
        }

        return tree
    }
}

/// Lexical path normalization and tilde/relative-path resolution shared across file-based sources.
enum SourcePathResolver {
    static func resolve(
        path: String,
        workingDirectory: String,
        homeDirectory: String
    ) -> String {
        if path == "~" {
            return normalizeLexicalPath(homeDirectory)
        }
        if path.hasPrefix("~/") {
            let suffix = String(path.dropFirst(2))
            return normalizeLexicalPath(joinPath(homeDirectory, suffix))
        }
        if path.hasPrefix("/") {
            return normalizeLexicalPath(path)
        }
        return normalizeLexicalPath(joinPath(workingDirectory, path))
    }

    static func joinPath(_ base: String, _ component: String) -> String {
        if base.isEmpty { return component }
        if component.isEmpty { return base }
        if base == "/" { return "/\(component)" }
        let cleanBase = base.hasSuffix("/") ? String(base.dropLast()) : base
        let cleanComp = component.hasPrefix("/") ? String(component.dropFirst()) : component
        return "\(cleanBase)/\(cleanComp)"
    }

    static func normalizeLexicalPath(_ path: String) -> String {
        guard !path.isEmpty else { return "." }
        let isAbsolute = path.hasPrefix("/")
        let parts = path.split(separator: "/", omittingEmptySubsequences: true)
        var stack: [Substring] = []

        for part in parts {
            if part == "." {
                continue
            } else if part == ".." {
                if let last = stack.last, last != ".." {
                    stack.removeLast()
                } else if !isAbsolute {
                    stack.append("..")
                }
            } else {
                stack.append(part)
            }
        }

        if isAbsolute {
            return "/" + stack.joined(separator: "/")
        }
        return stack.isEmpty ? "." : stack.joined(separator: "/")
    }

    static func parentDirectory(of normalizedAbsolutePath: String) -> String? {
        let clean = normalizeLexicalPath(normalizedAbsolutePath)
        guard clean != "/" && clean != "." else { return nil }
        guard let slashIndex = clean.lastIndex(of: "/") else { return nil }
        if slashIndex == clean.startIndex {
            return "/"
        }
        return String(clean[..<slashIndex])
    }
}
