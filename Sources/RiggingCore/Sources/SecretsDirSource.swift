import Foundation

/// Loads mounted secret files from a directory such as `/run/secrets` in Docker or Kubernetes pods.
///
/// Hidden dotfiles (including `.DS_Store` and Kubernetes `..data` symlink directories) are ignored
/// automatically. When ``SettingsConfiguration/trimSecretTrailingNewline`` is enabled, a single
/// trailing `\n` or `\r\n` added by tools or volume mounts is stripped while preserving multiline
/// PEM or certificate content.
///
/// ```swift
/// let source = SecretsDirSource(directory: "/run/secrets")
/// ```
public struct SecretsDirSource: SettingsSource, Sendable {
    /// Optional explicit directory path overriding ``SettingsConfiguration/secretsDirectory``.
    public let directory: String?

    /// When `true`, only files whose names begin with ``SettingsConfiguration/envPrefix`` are loaded.
    public let requireEnvPrefix: Bool

    /// Human-readable name identifying this source in diagnostics (`"SecretsDirSource"`).
    public var sourceName: String { "SecretsDirSource" }

    /// Creates a mounted secrets-directory configuration source.
    ///
    /// - Parameters:
    ///   - directory: Optional explicit path overriding ``SettingsConfiguration/secretsDirectory``.
    ///   - requireEnvPrefix: Whether filenames without ``SettingsConfiguration/envPrefix`` are ignored.
    public init(directory: String? = nil, requireEnvPrefix: Bool = false) {
        self.directory = directory
        self.requireEnvPrefix = requireEnvPrefix
    }

    /// Scans the secrets directory and maps file contents into a ``RawConfigTree``.
    ///
    /// - Parameters:
    ///   - configuration: Settings configuration controlling `secretsDirectory`, `secretsNestedSubdir`,
    ///     and `trimSecretTrailingNewline`.
    ///   - context: Execution context providing filesystem and path resolution context.
    /// - Returns: A ``RawConfigTree`` tagged with ``SettingOrigin/secretsDirectory(path:)`` provenance.
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

    static func trimSingleTrailingNewline(_ value: String) -> String {
        if value.hasSuffix("\r\n") {
            return String(value.dropLast())
        }
        if value.hasSuffix("\n") {
            return String(value.dropLast())
        }
        return value
    }
}
