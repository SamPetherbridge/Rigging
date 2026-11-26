import Foundation
import RiggingCore
#if canImport(Yams)
import Yams
#endif

/// Classifies the provenance category assigned to settings loaded from a YAML configuration file.
///
/// Selecting ``projectConfig`` marks loaded keys with `SettingOrigin.projectConfig`, ensuring
/// Rigging's repo-committed plaintext guard rejects literal secrets committed to `.yaml` / `.yml`
/// project files unless explicitly permitted.
public enum YAMLSourceOriginStyle: Sendable, Equatable, Hashable {
    /// Marks loaded keys with `SettingOrigin.projectConfig(path:keyPath:profile:)`.
    case projectConfig

    /// Marks loaded keys with `SettingOrigin.userConfig(path:keyPath:profile:)`.
    case userConfig

    /// Marks loaded keys with `SettingOrigin.customSource(name:detail:)` using `sourceName`.
    case custom(sourceName: String)
}

/// Type alias matching `pydantic-settings` naming conventions for ``YAMLFileSource``.
public typealias YAMLFileSettingsSource = YAMLFileSource

/// Loads configuration values from one or more explicit YAML files into a `RawConfigTree`.
///
/// `YAMLFileSource` parses YAML 1.2 documents via `Yams`, resolves YAML anchors, aliases, and
/// `<<` merge keys, preserves exact scalar/sequence/mapping types, strips reserved `"$schema"` and
/// `"profiles"` root metadata keys, and overlays `profiles.<active>` when a profile is active.
///
/// ```swift
/// static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
///     [
///         defaults.initOverrides,
///         defaults.environment,
///         YAMLFileSource(path: "/etc/myapp/config.yaml", optional: true),
///     ]
/// }
/// ```
public struct YAMLFileSource: SettingsSource, Sendable {
    /// Ordered list of YAML file paths to load, where later paths override earlier paths.
    public let paths: [String]

    /// Whether missing files are silently ignored (`true`) or throw a file-not-found error (`false`).
    public let optional: Bool

    /// An explicit profile name overriding `--profile`, `<ENV_PREFIX>PROFILE`, and `SettingsConfiguration.profile`.
    public let profile: String?

    /// The provenance classification applied to every key loaded by this source.
    public let originStyle: YAMLSourceOriginStyle

    /// The human-readable name of this configuration source.
    public var sourceName: String {
        switch originStyle {
        case .projectConfig:
            return "YAMLProjectConfigSource"
        case .userConfig:
            return "YAMLUserConfigSource"
        case .custom(let name):
            return name
        }
    }

    /// Creates a YAML file source backed by a single file path.
    ///
    /// - Parameters:
    ///   - path: Absolute, `~`-prefixed, or working-directory-relative path to the YAML file.
    ///   - optional: When `true` (the default), missing files yield an empty tree without throwing.
    ///   - profile: Optional explicit profile overlay name.
    ///   - originStyle: Provenance classification assigned to loaded keys.
    public init(
        path: String,
        optional: Bool = true,
        profile: String? = nil,
        originStyle: YAMLSourceOriginStyle = .custom(sourceName: "YAMLFileSource")
    ) {
        self.paths = [path]
        self.optional = optional
        self.profile = profile
        self.originStyle = originStyle
    }

    /// Creates a YAML file source backed by an ordered list of file paths.
    ///
    /// - Parameters:
    ///   - paths: Ordered YAML file paths; later files override earlier files.
    ///   - optional: When `true` (the default), missing files are skipped without throwing.
    ///   - profile: Optional explicit profile overlay name.
    ///   - originStyle: Provenance classification assigned to loaded keys.
    public init(
        paths: [String],
        optional: Bool = true,
        profile: String? = nil,
        originStyle: YAMLSourceOriginStyle = .custom(sourceName: "YAMLFileSource")
    ) {
        self.paths = paths
        self.optional = optional
        self.profile = profile
        self.originStyle = originStyle
    }

    /// Loads and merges all configured YAML files against `configuration` and `context`.
    ///
    /// - Parameters:
    ///   - configuration: Model-level settings configuration controlling case sensitivity and profile defaults.
    ///   - context: Execution context providing the filesystem, working directory, home directory, and CLI/env state.
    /// - Returns: A merged `RawConfigTree` annotated with per-key provenance.
    /// - Throws: `CocoaError(.fileNoSuchFile)` when `optional` is `false` and a path is missing, or `ConfigFileParseError` on invalid YAML.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        guard !paths.isEmpty else { return .empty }
        let activeProfile = YAMLProfileResolver.resolveActiveProfile(
            explicitProfile: profile,
            configuration: configuration,
            context: context
        )

        var accumulated = RawConfigTree.empty
        for rawPath in paths {
            let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let resolvedPath = YAMLPathResolver.resolve(
                path: trimmed,
                workingDirectory: context.workingDirectory,
                homeDirectory: context.homeDirectory
            )

            guard context.fileSystem.fileExists(atPath: resolvedPath),
                  !context.fileSystem.isDirectory(atPath: resolvedPath) else {
                if !optional {
                    throw CocoaError(
                        .fileNoSuchFile,
                        userInfo: [NSFilePathErrorKey: resolvedPath]
                    )
                }
                continue
            }

            let fileTree = try YAMLConfigLoader.loadFile(
                atPath: resolvedPath,
                activeProfile: activeProfile,
                originStyle: originStyle,
                caseSensitive: configuration.caseSensitive,
                fileSystem: context.fileSystem
            )
            accumulated = fileTree.merging(
                lowerPriority: accumulated,
                caseSensitive: configuration.caseSensitive
            )
        }
        return accumulated
    }
}

/// Discovers project-scoped `.yaml` and `.yml` configuration files by walking upward from the
/// working directory to the nearest `.git` repository root or user home directory boundary.
///
/// `YAMLProjectConfigSource` mirrors `ProjectConfigSource` for YAML files, automatically checking
/// both `.yml` and `.yaml` siblings when derived from `configuration.projectConfigFiles`, stopping
/// inclusively at any `.git` directory or git-worktree file, and never walking above
/// `context.homeDirectory`.
///
/// ```swift
/// static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
///     [
///         defaults.initOverrides,
///         defaults.environment,
///         defaults.dotEnv,
///         YAMLProjectConfigSource(),
///         YAMLUserConfigSource(),
///     ]
/// }
/// ```
public struct YAMLProjectConfigSource: SettingsSource, Sendable {
    /// Optional explicit filenames overriding `configuration.projectConfigFiles`.
    public let fileNames: [String]?

    /// Optional explicit profile overriding `configuration.profile` and `<ENV_PREFIX>PROFILE`.
    public let profile: String?

    /// Whether upward directory traversal stops at the nearest directory containing a matching YAML file.
    public let stopAtFirstFound: Bool

    /// The canonical source identifier (`"YAMLProjectConfigSource"`).
    public var sourceName: String { "YAMLProjectConfigSource" }

    /// Creates a project YAML configuration source searching for `fileNames` (or `configuration.projectConfigFiles` when `nil`).
    ///
    /// - Parameters:
    ///   - fileNames: Optional explicit candidate filenames per directory; later names override earlier names.
    ///   - profile: Optional explicit profile overlay name.
    ///   - stopAtFirstFound: When `true`, stops walking upward after the nearest directory containing a match.
    public init(
        fileNames: [String]? = nil,
        profile: String? = nil,
        stopAtFirstFound: Bool = false
    ) {
        self.fileNames = fileNames
        self.profile = profile
        self.stopAtFirstFound = stopAtFirstFound
    }

    /// Creates a project YAML configuration source searching for a single filename.
    ///
    /// - Parameters:
    ///   - fileName: Candidate YAML filename to search for (for example, `".myapp.yml"`).
    ///   - profile: Optional explicit profile overlay name.
    ///   - stopAtFirstFound: When `true`, stops walking upward after the nearest directory containing `fileName`.
    public init(
        fileName: String,
        profile: String? = nil,
        stopAtFirstFound: Bool = false
    ) {
        self.fileNames = [fileName]
        self.profile = profile
        self.stopAtFirstFound = stopAtFirstFound
    }

    /// Discovers, parses, and merges project YAML configuration files from the directory hierarchy.
    ///
    /// - Parameters:
    ///   - configuration: Model-level settings configuration providing candidate filenames and case sensitivity.
    ///   - context: Execution context providing working/home directories, environment, and filesystem access.
    /// - Returns: A merged `RawConfigTree` with `.projectConfig` provenance on every entry.
    /// - Throws: `ConfigFileParseError` if any discovered YAML file fails to parse or is not a top-level mapping.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        let candidateNames = Self.resolveCandidateNames(
            explicitFileNames: fileNames,
            configuration: configuration
        )
        guard !candidateNames.isEmpty else { return .empty }

        let activeProfile = YAMLProfileResolver.resolveActiveProfile(
            explicitProfile: profile,
            configuration: configuration,
            context: context
        )

        let searchDirectories = YAMLPathResolver.discoverDirectories(
            workingDirectory: context.workingDirectory,
            homeDirectory: context.homeDirectory,
            fileSystem: context.fileSystem
        )

        var discoveredTreesNearestFirst: [RawConfigTree] = []

        for dir in searchDirectories {
            var dirTree: RawConfigTree?
            for rawName in candidateNames {
                let cleanName = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !cleanName.isEmpty else { continue }

                let candidatePath: String
                if cleanName.hasPrefix("/") || cleanName.hasPrefix("~/") {
                    candidatePath = YAMLPathResolver.resolve(
                        path: cleanName,
                        workingDirectory: dir,
                        homeDirectory: context.homeDirectory
                    )
                } else {
                    candidatePath = YAMLPathResolver.normalizeLexicalPath(
                        YAMLPathResolver.joinPath(dir, cleanName)
                    )
                }

                guard context.fileSystem.fileExists(atPath: candidatePath),
                      !context.fileSystem.isDirectory(atPath: candidatePath) else {
                    continue
                }

                let loaded = try YAMLConfigLoader.loadFile(
                    atPath: candidatePath,
                    activeProfile: activeProfile,
                    originStyle: .projectConfig,
                    caseSensitive: configuration.caseSensitive,
                    fileSystem: context.fileSystem
                )
                if let existingDirTree = dirTree {
                    dirTree = loaded.merging(
                        lowerPriority: existingDirTree,
                        caseSensitive: configuration.caseSensitive
                    )
                } else {
                    dirTree = loaded
                }
            }

            if let dirTree {
                discoveredTreesNearestFirst.append(dirTree)
                if stopAtFirstFound {
                    break
                }
            }
        }

        var merged = RawConfigTree.empty
        for tree in discoveredTreesNearestFirst.reversed() {
            merged = tree.merging(
                lowerPriority: merged,
                caseSensitive: configuration.caseSensitive
            )
        }
        return merged
    }

    private static func resolveCandidateNames(
        explicitFileNames: [String]?,
        configuration: SettingsConfiguration
    ) -> [String] {
        if let explicitFileNames {
            return explicitFileNames
        }

        let nonForeign = configuration.projectConfigFiles.filter { name in
            let lower = name.lowercased()
            return !lower.hasSuffix(".json")
                && !lower.hasSuffix(".toml")
                && !lower.hasSuffix(".plist")
        }

        if !nonForeign.isEmpty {
            var expanded: [String] = []
            for item in nonForeign {
                let lower = item.lowercased()
                if lower.hasSuffix(".yaml") {
                    let ymlSibling = String(item.dropLast(5)) + ".yml"
                    if !nonForeign.contains(ymlSibling) && !expanded.contains(ymlSibling) {
                        expanded.append(ymlSibling)
                    }
                    if !expanded.contains(item) {
                        expanded.append(item)
                    }
                } else if lower.hasSuffix(".yml") {
                    let yamlSibling = String(item.dropLast(4)) + ".yaml"
                    if !nonForeign.contains(yamlSibling) && !expanded.contains(yamlSibling) {
                        expanded.append(yamlSibling)
                    }
                    if !expanded.contains(item) {
                        expanded.append(item)
                    }
                } else if !expanded.contains(item) {
                    expanded.append(item)
                }
            }
            return expanded
        }

        if let app = configuration.xdgAppName?.trimmingCharacters(in: .whitespacesAndNewlines),
           !app.isEmpty {
            return [
                ".\(app).yml",
                ".\(app).yaml",
                "\(app).yml",
                "\(app).yaml",
                "config.yml",
                "config.yaml",
            ]
        }
        return ["config.yml", "config.yaml"]
    }
}

/// Loads user-scoped YAML configuration from `$XDG_CONFIG_HOME/<app>/config.{yml,yaml}`
/// (or `~/.config/<app>/config.{yml,yaml}`) with optional macOS Application Support fallback.
///
/// Within each directory, later filenames in ``fileNames`` override earlier filenames, and XDG
/// configuration files take precedence over `~/Library/Application Support/<app>/` fallback files.
public struct YAMLUserConfigSource: SettingsSource, Sendable {
    /// Optional explicit application subdirectory name overriding `configuration.xdgAppName`.
    public let appName: String?

    /// Ordered filenames checked in each user configuration directory (later files override earlier files).
    public let fileNames: [String]

    /// Optional explicit profile overriding `configuration.profile` and `<ENV_PREFIX>PROFILE`.
    public let profile: String?

    /// Whether `<homeDirectory>/Library/Application Support/<app>/` is checked as a lower-priority fallback.
    public let includeApplicationSupportFallback: Bool

    /// The canonical source identifier (`"YAMLUserConfigSource"`).
    public var sourceName: String { "YAMLUserConfigSource" }

    /// Creates a user-scoped YAML configuration source checking multiple candidate filenames.
    ///
    /// - Parameters:
    ///   - appName: Optional explicit application folder name overriding `configuration.xdgAppName`.
    ///   - fileNames: Ordered filenames checked in each directory (defaults to `["config.yml", "config.yaml"]`).
    ///   - profile: Optional explicit profile overlay name.
    ///   - includeApplicationSupportFallback: When `true` (the default), checks `~/Library/Application Support/<app>/` beneath XDG.
    public init(
        appName: String? = nil,
        fileNames: [String] = ["config.yml", "config.yaml"],
        profile: String? = nil,
        includeApplicationSupportFallback: Bool = true
    ) {
        self.appName = appName
        self.fileNames = fileNames
        self.profile = profile
        self.includeApplicationSupportFallback = includeApplicationSupportFallback
    }

    /// Creates a user-scoped YAML configuration source checking a single filename.
    ///
    /// - Parameters:
    ///   - appName: Optional explicit application folder name overriding `configuration.xdgAppName`.
    ///   - fileName: Single YAML filename to look up inside each user config directory.
    ///   - profile: Optional explicit profile overlay name.
    ///   - includeApplicationSupportFallback: When `true` (the default), checks `~/Library/Application Support/<app>/` beneath XDG.
    public init(
        appName: String? = nil,
        fileName: String,
        profile: String? = nil,
        includeApplicationSupportFallback: Bool = true
    ) {
        self.appName = appName
        self.fileNames = [fileName]
        self.profile = profile
        self.includeApplicationSupportFallback = includeApplicationSupportFallback
    }

    /// Loads user-scoped YAML configuration files and applies any active profile overlay.
    ///
    /// - Parameters:
    ///   - configuration: Model-level settings configuration providing `xdgAppName`, `profile`, and `caseSensitive`.
    ///   - context: Execution context providing environment variables, home directory, and filesystem access.
    /// - Returns: A merged `RawConfigTree` with `.userConfig` provenance, or `.empty` when `xdgAppName` is unset.
    /// - Throws: `ConfigFileParseError` if a present user YAML configuration file contains invalid syntax.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        guard let rawApp = appName ?? configuration.xdgAppName else {
            return .empty
        }
        let cleanApp = rawApp.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanApp.isEmpty, !fileNames.isEmpty else {
            return .empty
        }

        let activeProfile = YAMLProfileResolver.resolveActiveProfile(
            explicitProfile: profile,
            configuration: configuration,
            context: context
        )

        let xdgBaseDir: String
        if let rawXDG = context.environment["XDG_CONFIG_HOME"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawXDG.isEmpty {
            xdgBaseDir = YAMLPathResolver.resolve(
                path: rawXDG,
                workingDirectory: context.workingDirectory,
                homeDirectory: context.homeDirectory
            )
        } else {
            xdgBaseDir = YAMLPathResolver.normalizeLexicalPath(
                YAMLPathResolver.joinPath(context.homeDirectory, ".config")
            )
        }

        let xdgAppDir = YAMLPathResolver.normalizeLexicalPath(
            YAMLPathResolver.joinPath(xdgBaseDir, cleanApp)
        )

        var baseDirsLowestFirst: [String] = []
        if includeApplicationSupportFallback {
            let appSupportDir = YAMLPathResolver.normalizeLexicalPath(
                YAMLPathResolver.joinPath(
                    YAMLPathResolver.joinPath(context.homeDirectory, "Library/Application Support"),
                    cleanApp
                )
            )
            if appSupportDir != xdgAppDir {
                baseDirsLowestFirst.append(appSupportDir)
            }
        }
        baseDirsLowestFirst.append(xdgAppDir)

        var merged = RawConfigTree.empty
        for baseDir in baseDirsLowestFirst {
            for fileName in fileNames {
                let cleanFile = fileName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !cleanFile.isEmpty else { continue }
                let path = YAMLPathResolver.normalizeLexicalPath(
                    YAMLPathResolver.joinPath(baseDir, cleanFile)
                )
                guard context.fileSystem.fileExists(atPath: path),
                      !context.fileSystem.isDirectory(atPath: path) else {
                    continue
                }
                let loaded = try YAMLConfigLoader.loadFile(
                    atPath: path,
                    activeProfile: activeProfile,
                    originStyle: .userConfig,
                    caseSensitive: configuration.caseSensitive,
                    fileSystem: context.fileSystem
                )
                merged = loaded.merging(
                    lowerPriority: merged,
                    caseSensitive: configuration.caseSensitive
                )
            }
        }

        return merged
    }
}

// MARK: - Internal YAML Node -> RawConfigTree Converter

enum YAMLConfigLoader {
    #if canImport(Yams)
    static func loadFile(
        atPath path: String,
        activeProfile: String?,
        originStyle: YAMLSourceOriginStyle,
        caseSensitive: Bool,
        fileSystem: any FileSystem
    ) throws -> RawConfigTree {
        let data = try fileSystem.readFile(atPath: path)
        guard let yamlText = String(data: data, encoding: .utf8) else {
            throw ConfigFileParseError(
                path: path,
                format: "YAML",
                reason: "File contents are not valid UTF-8."
            )
        }

        let rootNode: Yams.Node?
        do {
            rootNode = try Yams.compose(yaml: yamlText)
        } catch {
            throw ConfigFileParseError(
                path: path,
                format: "YAML",
                reason: String(describing: error)
            )
        }

        guard let rootNode else {
            return .empty
        }

        if case .scalar(let scalar) = rootNode,
           Yams.Tag.Name(rawValue: rootNode.tag.rawValue) == .null,
           scalar.style == .plain {
            return .empty
        }

        guard case .mapping(let rootMapping) = rootNode else {
            throw ConfigFileParseError(
                path: path,
                format: "YAML",
                reason: "Top-level YAML document must be a mapping."
            )
        }

        let pairs = try flattenMappingPairs(rootMapping, path: path)
        let profilesMapping = extractProfilesMapping(from: pairs, caseSensitive: caseSensitive)

        var basePairs: [(key: String, value: Yams.Node)] = []
        for pair in pairs {
            if isReservedRootKey(pair.key, caseSensitive: caseSensitive) {
                continue
            }
            basePairs.append(pair)
        }

        let baseTree = try buildTree(
            from: basePairs,
            path: path,
            caseSensitive: caseSensitive
        ) { keyPath in
            makeOrigin(style: originStyle, path: path, keyPath: keyPath, profile: nil)
        }

        guard let activeProfile,
              !activeProfile.isEmpty,
              let profilesMapping else {
            return baseTree
        }

        let profilePairs = try flattenMappingPairs(profilesMapping, path: path)
        guard let selectedProfileNode = findProfileNode(
            named: activeProfile,
            in: profilePairs,
            caseSensitive: caseSensitive
        ), case .mapping(let selectedMapping) = selectedProfileNode else {
            return baseTree
        }

        let flattenedSelected = try flattenMappingPairs(selectedMapping, path: path)
            .filter { $0.key != "$schema" }

        let profileTree = try buildTree(
            from: flattenedSelected,
            path: path,
            caseSensitive: caseSensitive
        ) { keyPath in
            makeOrigin(style: originStyle, path: path, keyPath: keyPath, profile: activeProfile)
        }

        return profileTree.merging(lowerPriority: baseTree, caseSensitive: caseSensitive)
    }

    private static func isReservedRootKey(_ key: String, caseSensitive: Bool) -> Bool {
        if key == "$schema" || key == "profiles" {
            return true
        }
        if !caseSensitive && key.lowercased() == "profiles" {
            return true
        }
        return false
    }

    private static func extractProfilesMapping(
        from pairs: [(key: String, value: Yams.Node)],
        caseSensitive: Bool
    ) -> Yams.Node.Mapping? {
        if let exact = pairs.last(where: { $0.key == "profiles" })?.value.mapping {
            return exact
        }
        guard !caseSensitive else { return nil }
        return pairs.last(where: { $0.key.lowercased() == "profiles" })?.value.mapping
    }

    private static func findProfileNode(
        named profileName: String,
        in pairs: [(key: String, value: Yams.Node)],
        caseSensitive: Bool
    ) -> Yams.Node? {
        if let exact = pairs.last(where: { $0.key == profileName })?.value {
            return exact
        }
        guard !caseSensitive else { return nil }
        let lowered = profileName.lowercased()
        return pairs.last(where: { $0.key.lowercased() == lowered })?.value
    }

    private static func buildTree(
        from pairs: [(key: String, value: Yams.Node)],
        path: String,
        caseSensitive: Bool,
        originForKeyPath: ([String]) -> SettingOrigin
    ) throws -> RawConfigTree {
        guard !pairs.isEmpty else { return .empty }
        var tree = RawConfigTree()
        for (key, yamlNode) in pairs {
            let rawNode = try convertNode(
                yamlNode,
                keyPath: [key],
                path: path,
                originForKeyPath: originForKeyPath
            )
            tree.set(path: [key], node: rawNode, caseSensitive: caseSensitive)
        }
        return tree
    }

    private static func convertNode(
        _ node: Yams.Node,
        keyPath: [String],
        path: String,
        originForKeyPath: ([String]) -> SettingOrigin
    ) throws -> RawNode {
        let origin = originForKeyPath(keyPath)
        let rawValue: RawValue

        switch node {
        case .scalar(let scalar):
            rawValue = convertScalar(scalar, resolvedTag: Yams.Tag.Name(rawValue: node.tag.rawValue))

        case .sequence(let sequence):
            var elements: [RawNode] = []
            elements.reserveCapacity(sequence.count)
            for (index, child) in sequence.enumerated() {
                elements.append(
                    try convertNode(
                        child,
                        keyPath: keyPath + [String(index)],
                        path: path,
                        originForKeyPath: originForKeyPath
                    )
                )
            }
            rawValue = .array(elements)

        case .mapping(let mapping):
            let pairs = try flattenMappingPairs(mapping, path: path)
            var children: [String: RawNode] = [:]
            for (key, childNode) in pairs where key != "$schema" {
                children[key] = try convertNode(
                    childNode,
                    keyPath: keyPath + [key],
                    path: path,
                    originForKeyPath: originForKeyPath
                )
            }
            rawValue = .object(children)

        case .alias(let alias):
            let anchorName = alias.anchor.rawValue
            throw ConfigFileParseError(
                path: path,
                format: "YAML",
                reason: "Unresolved YAML alias '*\(anchorName)' at '\(keyPath.joined(separator: "."))'."
            )
        }

        return RawNode(value: rawValue, origin: origin)
    }

    private static func convertScalar(
        _ scalar: Yams.Node.Scalar,
        resolvedTag: Yams.Tag.Name
    ) -> RawValue {
        switch resolvedTag {
        case .null:
            return .null

        case .bool:
            if let boolVal = Bool.construct(from: scalar) {
                return .bool(boolVal)
            }
            return .string(scalar.string)

        case .int:
            if let intVal = Int.construct(from: scalar) {
                return .int(Int64(intVal))
            }
            let cleaned = scalar.string.replacingOccurrences(of: "_", with: "")
            if let int64Val = Int64(cleaned) {
                return .int(int64Val)
            }
            return .string(scalar.string)

        case .float:
            if let doubleVal = Double.construct(from: scalar) {
                return .double(doubleVal)
            }
            return .string(scalar.string)

        case .binary:
            if let data = Data.construct(from: scalar) {
                return .data(data)
            }
            return .string(scalar.string)

        case .timestamp:
            return .string(normalizeYAMLTimestamp(scalar.string))

        default:
            return .string(scalar.string)
        }
    }

    private static func normalizeYAMLTimestamp(_ text: String) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let scalars = Array(trimmed.unicodeScalars)
        // Normalize `YYYY-MM-DD HH:MM:SS...` to `YYYY-MM-DDTHH:MM:SS...` for ISO8601DateFormatter compatibility
        if scalars.count >= 19,
           scalars[4] == "-",
           scalars[7] == "-",
           scalars[10] == " ",
           scalars[13] == ":" {
            var copy = scalars
            copy[10] = "T"
            return String(String.UnicodeScalarView(copy))
        }
        return trimmed
    }

    /// Resolves YAML `<<` merge keys and validates string-convertible mapping keys.
    private static func flattenMappingPairs(
        _ mapping: Yams.Node.Mapping,
        path: String
    ) throws -> [(key: String, value: Yams.Node)] {
        var mergedEntries: [(key: String, value: Yams.Node)] = []
        var explicitEntries: [(key: String, value: Yams.Node)] = []

        for pair in mapping {
            if Yams.Tag.Name(rawValue: pair.key.tag.rawValue) == .merge {
                switch pair.value {
                case .mapping(let subMap):
                    mergedEntries.append(contentsOf: try flattenMappingPairs(subMap, path: path))
                case .sequence(let seq):
                    // In YAML merge sequences `<<: [*a, *b]`, earlier items take priority over later items
                    for item in seq.reversed() {
                        guard case .mapping(let subMap) = item else {
                            throw ConfigFileParseError(
                                path: path,
                                format: "YAML",
                                reason: "YAML '<<' merge sequence elements must be mappings."
                            )
                        }
                        mergedEntries.append(contentsOf: try flattenMappingPairs(subMap, path: path))
                    }
                default:
                    throw ConfigFileParseError(
                        path: path,
                        format: "YAML",
                        reason: "YAML '<<' merge value must be a mapping or sequence of mappings."
                    )
                }
            } else {
                guard let keyString = extractKeyString(from: pair.key) else {
                    throw ConfigFileParseError(
                        path: path,
                        format: "YAML",
                        reason: "YAML mapping keys must be scalar strings."
                    )
                }
                explicitEntries.append((key: keyString, value: pair.value))
            }
        }

        // Deduplicate keeping last occurrence so explicit keys override merged keys
        let combined = mergedEntries + explicitEntries
        var indexByKey: [String: Int] = [:]
        var deduplicated: [(key: String, value: Yams.Node)] = []
        for entry in combined {
            if let existingIdx = indexByKey[entry.key] {
                deduplicated[existingIdx] = entry
            } else {
                indexByKey[entry.key] = deduplicated.count
                deduplicated.append(entry)
            }
        }
        return deduplicated
    }

    private static func extractKeyString(from keyNode: Yams.Node) -> String? {
        if case .scalar(let scalar) = keyNode {
            return scalar.string
        }
        return keyNode.string
    }

    private static func makeOrigin(
        style: YAMLSourceOriginStyle,
        path: String,
        keyPath: [String],
        profile: String?
    ) -> SettingOrigin {
        switch style {
        case .projectConfig:
            return .projectConfig(path: path, keyPath: keyPath, profile: profile)
        case .userConfig:
            return .userConfig(path: path, keyPath: keyPath, profile: profile)
        case .custom(let sourceName):
            let suffix = profile.map { " [profile: \($0)]" } ?? ""
            return .customSource(
                name: sourceName,
                detail: "\(path)\(suffix) → \(keyPath.joined(separator: "."))"
            )
        }
    }
    #else
    static func loadFile(
        atPath path: String,
        activeProfile: String?,
        originStyle: YAMLSourceOriginStyle,
        caseSensitive: Bool,
        fileSystem: any FileSystem
    ) throws -> RawConfigTree {
        _ = (activeProfile, originStyle, caseSensitive, fileSystem)
        throw ConfigFileParseError(
            path: path,
            format: "YAML",
            reason: "YAML parsing via Yams is unavailable on this platform."
        )
    }
    #endif
}

enum YAMLProfileResolver {
    static func resolveActiveProfile(
        explicitProfile: String?,
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) -> String? {
        if let explicitProfile {
            let trimmed = explicitProfile.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                return trimmed
            }
        }

        for override in context.cliOverrides.reversed() {
            let isProfilePath = override.keyPath.count == 1
                && RawConfigTree.keysMatch(
                    override.keyPath[0],
                    "profile",
                    caseSensitive: configuration.caseSensitive
                )
            let isProfileFlag = override.flag == "--profile"
            if isProfilePath || isProfileFlag,
               case .string(let val) = override.value {
                let trimmed = val.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty {
                    return trimmed
                }
            }
        }

        let envCandidates = profileEnvVariableNames(envPrefix: configuration.envPrefix)
        for candidate in envCandidates {
            if let value = lookupEnv(
                candidate,
                in: context.environment,
                caseSensitive: configuration.caseSensitive
            ) {
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty {
                    return trimmed
                }
            }
        }

        if let configProfile = configuration.profile?.trimmingCharacters(in: .whitespacesAndNewlines),
           !configProfile.isEmpty {
            return configProfile
        }

        return nil
    }

    private static func profileEnvVariableNames(envPrefix: String) -> [String] {
        if envPrefix.isEmpty {
            return ["RIGGING_PROFILE", "PROFILE"]
        }
        if envPrefix.hasSuffix("_") {
            return ["\(envPrefix)PROFILE"]
        }
        return ["\(envPrefix)_PROFILE", "\(envPrefix)PROFILE"]
    }

    private static func lookupEnv(
        _ target: String,
        in environment: [String: String],
        caseSensitive: Bool
    ) -> String? {
        if let exact = environment[target] {
            return exact
        }
        guard !caseSensitive else { return nil }
        let lowered = target.lowercased()
        for key in environment.keys.sorted() where key.lowercased() == lowered {
            return environment[key]
        }
        return nil
    }
}

enum YAMLPathResolver {
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

    static func discoverDirectories(
        workingDirectory: String,
        homeDirectory: String,
        fileSystem: any FileSystem
    ) -> [String] {
        let startDir = normalizeLexicalPath(workingDirectory)
        let normalizedHome = normalizeLexicalPath(homeDirectory)

        var directories: [String] = []
        var current = startDir
        var visited = Set<String>()

        while !visited.contains(current) {
            visited.insert(current)
            directories.append(current)

            if current == normalizedHome {
                break
            }

            let gitMarker = joinPath(current, ".git")
            if fileSystem.fileExists(atPath: gitMarker) {
                break
            }

            guard let parent = parentDirectory(of: current), parent != current else {
                break
            }
            current = parent
        }

        return directories
    }
}
