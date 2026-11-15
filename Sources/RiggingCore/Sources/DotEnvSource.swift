import Foundation

/// Loads configuration values from one or more `.env` files in order (`configuration.dotEnvFiles`),
/// where later files override earlier files while preserving overridden `.dotEnv` origins.
public struct DotEnvSource: SettingsSource, Sendable {
    /// Optional explicit list of `.env` file paths overriding `configuration.dotEnvFiles`.
    public let files: [String]?
    /// Whether `${VAR}`, `${VAR:-default}`, and `${VAR-default}` expressions are expanded.
    public let expandVariables: Bool
    /// Whether syntax errors in `.env` lines without `=` throw `DotEnvParseError`.
    public let strictSyntax: Bool
    /// Whether missing `.env` files throw an error instead of being silently skipped.
    public let requireFiles: Bool

    public var sourceName: String { "DotEnvSource" }

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
