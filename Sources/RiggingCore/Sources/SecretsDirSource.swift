import Foundation

/// Reads mounted secret files from `configuration.secretsDirectory` (such as Docker/Kubernetes
/// `/run/secrets`), skipping dotfiles, optionally recursing into subdirectories, and trimming
/// a single trailing newline when `trimSecretTrailingNewline` is enabled.
public struct SecretsDirSource: SettingsSource, Sendable {
    /// Optional explicit directory path overriding `configuration.secretsDirectory`.
    public let directory: String?
    /// When `true`, only filenames beginning with `configuration.envPrefix` are loaded.
    /// Defaults to `false` so both prefixed (`ASC_API_KEY`) and unprefixed (`api_key`) secret files work.
    public let requireEnvPrefix: Bool

    public var sourceName: String { "SecretsDirSource" }

    public init(directory: String? = nil, requireEnvPrefix: Bool = false) {
        self.directory = directory
        self.requireEnvPrefix = requireEnvPrefix
    }

    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        guard let rawDir = directory ?? configuration.secretsDirectory else {
            return .empty
        }
        let trimmedDir = rawDir.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedDir.isEmpty else {
            return .empty
        }

        let rootPath = SourcePathResolver.resolve(
            path: trimmedDir,
            workingDirectory: context.workingDirectory,
            homeDirectory: context.homeDirectory
        )

        guard context.fileSystem.fileExists(atPath: rootPath),
              context.fileSystem.isDirectory(atPath: rootPath) else {
            return .empty
        }

        var tree = RawConfigTree()
        try scanDirectory(
            atPath: rootPath,
            prefixSegments: [],
            configuration: configuration,
            context: context,
            into: &tree
        )
        return tree
    }

    private func scanDirectory(
        atPath directoryPath: String,
        prefixSegments: [String],
        configuration: SettingsConfiguration,
        context: SettingsContext,
        into tree: inout RawConfigTree
    ) throws {
        let entries = try context.fileSystem.contentsOfDirectory(atPath: directoryPath).sorted()

        for entry in entries {
            // Skip hidden dotfiles (`.DS_Store`, Kubernetes `..data`, `..2026_...`, etc.)
            if entry.isEmpty || entry.hasPrefix(".") {
                continue
            }

            let entryPath = SourcePathResolver.joinPath(directoryPath, entry)

            if context.fileSystem.isDirectory(atPath: entryPath) {
                if configuration.secretsNestedSubdir {
                    let subdirSegment: String
                    if prefixSegments.isEmpty,
                       let stripped = EnvironmentKeyMapper.stripPrefix(
                           from: entry,
                           prefix: configuration.envPrefix,
                           caseSensitive: configuration.caseSensitive
                       ),
                       !stripped.isEmpty {
                        subdirSegment = stripped
                    } else if prefixSegments.isEmpty && requireEnvPrefix && !configuration.envPrefix.isEmpty {
                        continue
                    } else {
                        subdirSegment = entry
                    }

                    try scanDirectory(
                        atPath: entryPath,
                        prefixSegments: prefixSegments + [subdirSegment],
                        configuration: configuration,
                        context: context,
                        into: &tree
                    )
                }
                continue
            }

            guard context.fileSystem.fileExists(atPath: entryPath) else {
                continue
            }

            let effectiveFileName: String
            if prefixSegments.isEmpty {
                if let stripped = EnvironmentKeyMapper.stripPrefix(
                    from: entry,
                    prefix: configuration.envPrefix,
                    caseSensitive: configuration.caseSensitive
                ) {
                    guard !stripped.isEmpty else { continue }
                    effectiveFileName = stripped
                } else if requireEnvPrefix && !configuration.envPrefix.isEmpty {
                    continue
                } else {
                    effectiveFileName = entry
                }
            } else {
                effectiveFileName = entry
            }

            let fileSegments = EnvironmentKeyMapper.splitKeyPath(
                effectiveFileName,
                delimiter: configuration.envNestedDelimiter,
                maxSplits: prefixSegments.isEmpty ? configuration.envNestedMaxSplit : nil,
                caseSensitive: configuration.caseSensitive
            )

            let fullKeyPath = prefixSegments + fileSegments
            guard !fullKeyPath.isEmpty else { continue }

            let data = try context.fileSystem.readFile(atPath: entryPath)
            let origin = SettingOrigin.secretsDirectory(path: entryPath)
            let rawValue: RawValue

            if let text = String(data: data, encoding: .utf8) {
                let normalizedText = configuration.trimSecretTrailingNewline
                    ? Self.trimSingleTrailingNewline(text)
                    : text
                if configuration.envIgnoreEmpty && normalizedText.isEmpty {
                    continue
                }
                rawValue = .string(normalizedText)
            } else {
                rawValue = .data(data)
            }

            if prefixSegments.isEmpty {
                tree.setEnvironmentEntry(
                    entry,
                    value: rawValue,
                    origin: origin,
                    caseSensitive: configuration.caseSensitive
                )
            }

            tree.set(
                path: fullKeyPath,
                value: rawValue,
                origin: origin,
                caseSensitive: configuration.caseSensitive
            )
        }
    }

    /// Trims at most one trailing `\r\n` or `\n` sequence, preserving intentional internal
    /// or additional trailing newlines.
    static func trimSingleTrailingNewline(_ value: String) -> String {
        if value.hasSuffix("\r\n") {
            // Note: in Swift String, "\r\n" is a single extended grapheme cluster Character.
            return String(value.dropLast())
        }
        if value.hasSuffix("\n") {
            return String(value.dropLast())
        }
        return value
    }
}
