import Foundation
import RiggingCore

/// Classifies the provenance category assigned to settings loaded from a TOML configuration file.
///
/// The chosen origin style controls both human-readable provenance output and security enforcement:
/// literal `@SecretSetting` values originating from ``projectConfig`` trigger Rigging's
/// repo-committed plaintext guard (exit code `4`) unless explicitly opted in.
public enum TOMLSourceOriginStyle: Sendable, Equatable, Hashable {
    /// Marks loaded keys with `SettingOrigin.projectConfig(path:keyPath:profile:)`.
    case projectConfig

    /// Marks loaded keys with `SettingOrigin.userConfig(path:keyPath:profile:)`.
    case userConfig

    /// Marks loaded keys with `SettingOrigin.customSource(name:detail:)` using `sourceName`.
    case custom(sourceName: String)
}

/// Type alias matching `pydantic-settings` naming conventions for ``TOMLFileSource``.
public typealias TOMLFileSettingsSource = TOMLFileSource

/// Loads configuration values from one or more explicit TOML v1.0 files into a `RawConfigTree`.
///
/// `TOMLFileSource` parses each file using ``TOMLParser``, strips reserved `"$schema"` and
/// `"profiles"` root metadata keys, and overlays `[profiles.<active>]` when an active profile is
/// selected via `profile`, `--profile`, `<ENV_PREFIX>PROFILE`, or `SettingsConfiguration.profile`.
/// When multiple paths are supplied, later files in ``paths`` override earlier files.
///
/// ```swift
/// static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
///     [
///         defaults.initOverrides,
///         defaults.environment,
///         TOMLFileSource(path: "/etc/myapp/config.toml", optional: true),
///     ]
/// }
/// ```
public struct TOMLFileSource: SettingsSource, Sendable {
    /// Ordered list of file paths to load, where later paths override earlier paths.
    public let paths: [String]

    /// Whether missing files are silently ignored (`true`) or throw a file-not-found error (`false`).
    public let optional: Bool

    /// An explicit profile name overriding `--profile`, `<ENV_PREFIX>PROFILE`, and `SettingsConfiguration.profile`.
    public let profile: String?

    /// The provenance classification applied to every key loaded by this source.
    public let originStyle: TOMLSourceOriginStyle

    /// The human-readable name of this configuration source.
    public var sourceName: String {
        switch originStyle {
        case .projectConfig:
            return "TOMLProjectConfigSource"
        case .userConfig:
            return "TOMLUserConfigSource"
        case .custom(let name):
            return name
        }
    }

    /// Creates a TOML file source backed by a single file path.
    ///
    /// - Parameters:
    ///   - path: Absolute, `~`-prefixed, or working-directory-relative path to the TOML file.
    ///   - optional: When `true` (the default), missing files yield an empty tree without throwing.
    ///   - profile: Optional explicit profile overlay name.
    ///   - originStyle: Provenance classification assigned to loaded keys.
    public init(
        path: String,
        optional: Bool = true,
        profile: String? = nil,
        originStyle: TOMLSourceOriginStyle = .custom(sourceName: "TOMLFileSource")
    ) {
        self.paths = [path]
        self.optional = optional
        self.profile = profile
        self.originStyle = originStyle
    }

    /// Creates a TOML file source backed by an ordered list of file paths.
    ///
    /// - Parameters:
    ///   - paths: Ordered TOML file paths; later files override earlier files.
    ///   - optional: When `true` (the default), missing files are skipped without throwing.
    ///   - profile: Optional explicit profile overlay name.
    ///   - originStyle: Provenance classification assigned to loaded keys.
    public init(
        paths: [String],
        optional: Bool = true,
        profile: String? = nil,
        originStyle: TOMLSourceOriginStyle = .custom(sourceName: "TOMLFileSource")
    ) {
        self.paths = paths
        self.optional = optional
        self.profile = profile
        self.originStyle = originStyle
    }

    /// Loads and merges all configured TOML files against `configuration` and `context`.
    ///
    /// - Parameters:
    ///   - configuration: Model-level settings configuration controlling case sensitivity and profile defaults.
    ///   - context: Execution context providing the filesystem, working directory, home directory, and CLI/env state.
    /// - Returns: A merged `RawConfigTree` annotated with per-key provenance.
    /// - Throws: `CocoaError(.fileNoSuchFile)` when `optional` is `false` and a path is missing, or `ConfigFileParseError` on invalid TOML.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        guard !paths.isEmpty else { return .empty }
        let activeProfile = TOMLProfileResolver.resolveActiveProfile(
            explicitProfile: profile,
            configuration: configuration,
            context: context
        )

        var accumulated = RawConfigTree.empty
        for rawPath in paths {
            let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let resolvedPath = TOMLPathResolver.resolve(
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

            let fileTree = try TOMLConfigLoader.loadFile(
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

/// Discovers project-scoped TOML configuration files by walking upward from the working directory
/// to the nearest `.git` repository root or user home directory boundary.
///
/// `TOMLProjectConfigSource` mirrors `ProjectConfigSource` for TOML files (such as `".myapp.toml"`
/// or `"config.toml"`), stopping inclusively at any directory containing a `.git` directory or
/// git-worktree file and never walking above `context.homeDirectory`. Nearer directories take
/// precedence over ancestor directories, and keys are tagged with `.projectConfig` provenance so
/// repo-committed literal secrets are rejected with exit code `4`.
///
/// ```swift
/// static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
///     [
///         defaults.initOverrides,
///         defaults.environment,
///         defaults.dotEnv,
///         TOMLProjectConfigSource(),
///         TOMLUserConfigSource(),
///     ]
/// }
/// ```
public struct TOMLProjectConfigSource: SettingsSource, Sendable {
    /// Optional explicit filenames overriding `configuration.projectConfigFiles`.
    public let fileNames: [String]?

    /// Optional explicit profile overriding `configuration.profile` and `<ENV_PREFIX>PROFILE`.
    public let profile: String?

    /// Whether upward directory traversal stops at the nearest directory containing a matching TOML file.
    public let stopAtFirstFound: Bool

    /// The canonical source identifier (`"TOMLProjectConfigSource"`).
    public var sourceName: String { "TOMLProjectConfigSource" }

    /// Creates a project TOML configuration source searching for `fileNames` (or `configuration.projectConfigFiles` when `nil`).
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

    /// Creates a project TOML configuration source searching for a single filename.
    ///
    /// - Parameters:
    ///   - fileName: Candidate TOML filename to search for (for example, `".myapp.toml"`).
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

    /// Discovers, parses, and merges project TOML configuration files from the directory hierarchy.
    ///
    /// - Parameters:
    ///   - configuration: Model-level settings configuration providing candidate filenames and case sensitivity.
    ///   - context: Execution context providing working/home directories, environment, and filesystem access.
    /// - Returns: A merged `RawConfigTree` with `.projectConfig` provenance on every entry.
    /// - Throws: `ConfigFileParseError` if any discovered TOML file fails to parse.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        let candidateNames = Self.resolveCandidateNames(
            explicitFileNames: fileNames,
            configuration: configuration
        )
        guard !candidateNames.isEmpty else { return .empty }

        let activeProfile = TOMLProfileResolver.resolveActiveProfile(
            explicitProfile: profile,
            configuration: configuration,
            context: context
        )

        let searchDirectories = TOMLPathResolver.discoverDirectories(
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
                    candidatePath = TOMLPathResolver.resolve(
                        path: cleanName,
                        workingDirectory: dir,
                        homeDirectory: context.homeDirectory
                    )
                } else {
                    candidatePath = TOMLPathResolver.normalizeLexicalPath(
                        TOMLPathResolver.joinPath(dir, cleanName)
                    )
                }

                guard context.fileSystem.fileExists(atPath: candidatePath),
                      !context.fileSystem.isDirectory(atPath: candidatePath) else {
                    continue
                }

                let loaded = try TOMLConfigLoader.loadFile(
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
                && !lower.hasSuffix(".yaml")
                && !lower.hasSuffix(".yml")
                && !lower.hasSuffix(".plist")
        }
        if !nonForeign.isEmpty {
            return nonForeign
        }
        if let app = configuration.xdgAppName?.trimmingCharacters(in: .whitespacesAndNewlines),
           !app.isEmpty {
            return [".\(app).toml", "\(app).toml", "config.toml"]
        }
        return ["config.toml"]
    }
}

/// Loads user-scoped TOML configuration from the XDG Base Directory Specification path
/// (`$XDG_CONFIG_HOME/<app>/config.toml` or `~/.config/<app>/config.toml`) with optional
/// macOS Application Support fallback.
///
/// When both `~/Library/Application Support/<app>/config.toml` and `~/.config/<app>/config.toml`
/// exist, the XDG config file takes precedence over the Application Support fallback while deep-merging
/// non-overlapping nested tables.
public struct TOMLUserConfigSource: SettingsSource, Sendable {
    /// Optional explicit application subdirectory name overriding `configuration.xdgAppName`.
    public let appName: String?

    /// The TOML filename looked up inside each user configuration directory (defaults to `"config.toml"`).
    public let fileName: String

    /// Optional explicit profile overriding `configuration.profile` and `<ENV_PREFIX>PROFILE`.
    public let profile: String?

    /// Whether `<homeDirectory>/Library/Application Support/<app>/<fileName>` is checked as a lower-priority fallback.
    public let includeApplicationSupportFallback: Bool

    /// The canonical source identifier (`"TOMLUserConfigSource"`).
    public var sourceName: String { "TOMLUserConfigSource" }

    /// Creates a user-scoped TOML configuration source.
    ///
    /// - Parameters:
    ///   - appName: Optional explicit application folder name overriding `configuration.xdgAppName`.
    ///   - fileName: Filename inside the user config directory (defaults to `"config.toml"`).
    ///   - profile: Optional explicit profile overlay name.
    ///   - includeApplicationSupportFallback: When `true` (the default), checks `~/Library/Application Support/<app>/<fileName>` beneath XDG.
    public init(
        appName: String? = nil,
        fileName: String = "config.toml",
        profile: String? = nil,
        includeApplicationSupportFallback: Bool = true
    ) {
        self.appName = appName
        self.fileName = fileName
        self.profile = profile
        self.includeApplicationSupportFallback = includeApplicationSupportFallback
    }

    /// Loads user-scoped TOML configuration files and applies any active profile overlay.
    ///
    /// - Parameters:
    ///   - configuration: Model-level settings configuration providing `xdgAppName`, `profile`, and `caseSensitive`.
    ///   - context: Execution context providing environment variables, home directory, and filesystem access.
    /// - Returns: A merged `RawConfigTree` with `.userConfig` provenance, or `.empty` when `xdgAppName` is unset.
    /// - Throws: `ConfigFileParseError` if a present user TOML configuration file contains invalid syntax.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        guard let rawApp = appName ?? configuration.xdgAppName else {
            return .empty
        }
        let cleanApp = rawApp.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanApp.isEmpty else {
            return .empty
        }

        let activeProfile = TOMLProfileResolver.resolveActiveProfile(
            explicitProfile: profile,
            configuration: configuration,
            context: context
        )

        let xdgBaseDir: String
        if let rawXDG = context.environment["XDG_CONFIG_HOME"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawXDG.isEmpty {
            xdgBaseDir = TOMLPathResolver.resolve(
                path: rawXDG,
                workingDirectory: context.workingDirectory,
                homeDirectory: context.homeDirectory
            )
        } else {
            xdgBaseDir = TOMLPathResolver.normalizeLexicalPath(
                TOMLPathResolver.joinPath(context.homeDirectory, ".config")
            )
        }

        let xdgConfigPath = TOMLPathResolver.normalizeLexicalPath(
            TOMLPathResolver.joinPath(TOMLPathResolver.joinPath(xdgBaseDir, cleanApp), fileName)
        )

        var candidatePathsLowestFirst: [String] = []
        if includeApplicationSupportFallback {
            let appSupportBase = TOMLPathResolver.joinPath(
                TOMLPathResolver.joinPath(context.homeDirectory, "Library/Application Support"),
                cleanApp
            )
            let appSupportPath = TOMLPathResolver.normalizeLexicalPath(
                TOMLPathResolver.joinPath(appSupportBase, fileName)
            )
            if appSupportPath != xdgConfigPath {
                candidatePathsLowestFirst.append(appSupportPath)
            }
        }
        candidatePathsLowestFirst.append(xdgConfigPath)

        var merged = RawConfigTree.empty
        for path in candidatePathsLowestFirst {
            guard context.fileSystem.fileExists(atPath: path),
                  !context.fileSystem.isDirectory(atPath: path) else {
                continue
            }
            let loaded = try TOMLConfigLoader.loadFile(
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

        return merged
    }
}

// MARK: - Internal TOML Loader & Helpers

enum TOMLConfigLoader {
    static func loadFile(
        atPath path: String,
        activeProfile: String?,
        originStyle: TOMLSourceOriginStyle,
        caseSensitive: Bool,
        fileSystem: any FileSystem
    ) throws -> RawConfigTree {
        let data = try fileSystem.readFile(atPath: path)
        let rootTable: [String: TOMLValue]
        do {
            rootTable = try TOMLParser.parse(data: data, path: path)
        } catch let parseError as TOMLParseError {
            throw ConfigFileParseError(
                path: path,
                format: "TOML",
                reason: "line \(parseError.line), column \(parseError.column): \(parseError.reason)"
            )
        } catch {
            throw ConfigFileParseError(
                path: path,
                format: "TOML",
                reason: error.localizedDescription
            )
        }

        return buildTreeFromRootTable(
            rootTable,
            path: path,
            activeProfile: activeProfile,
            originStyle: originStyle,
            caseSensitive: caseSensitive
        )
    }

    static func buildTreeFromRootTable(
        _ rootTable: [String: TOMLValue],
        path: String,
        activeProfile: String?,
        originStyle: TOMLSourceOriginStyle,
        caseSensitive: Bool
    ) -> RawConfigTree {
        let profilesTable = extractProfilesTable(from: rootTable, caseSensitive: caseSensitive)

        var strippedBase: [String: TOMLValue] = [:]
        for (key, value) in rootTable {
            if isReservedRootKey(key, caseSensitive: caseSensitive) {
                continue
            }
            strippedBase[key] = value
        }

        let baseTree = convertTableToTree(
            strippedBase,
            caseSensitive: caseSensitive
        ) { keyPath in
            makeOrigin(style: originStyle, path: path, keyPath: keyPath, profile: nil)
        }

        guard let activeProfile,
              !activeProfile.isEmpty,
              let profilesTable,
              let selectedProfile = findProfile(
                  named: activeProfile,
                  in: profilesTable,
                  caseSensitive: caseSensitive
              ) else {
            return baseTree
        }

        var strippedProfile: [String: TOMLValue] = [:]
        for (key, value) in selectedProfile where key != "$schema" {
            strippedProfile[key] = value
        }

        let profileTree = convertTableToTree(
            strippedProfile,
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

    private static func extractProfilesTable(
        from rootTable: [String: TOMLValue],
        caseSensitive: Bool
    ) -> [String: TOMLValue]? {
        if case .table(let exact) = rootTable["profiles"] {
            return exact
        }
        guard !caseSensitive else { return nil }
        for key in rootTable.keys.sorted() where key.lowercased() == "profiles" {
            if case .table(let dict) = rootTable[key] {
                return dict
            }
        }
        return nil
    }

    private static func findProfile(
        named profileName: String,
        in profilesTable: [String: TOMLValue],
        caseSensitive: Bool
    ) -> [String: TOMLValue]? {
        if case .table(let exact) = profilesTable[profileName] {
            return exact
        }
        guard !caseSensitive else { return nil }
        let lowered = profileName.lowercased()
        for key in profilesTable.keys.sorted() where key.lowercased() == lowered {
            if case .table(let dict) = profilesTable[key] {
                return dict
            }
        }
        return nil
    }

    private static func convertTableToTree(
        _ table: [String: TOMLValue],
        caseSensitive: Bool,
        originForKeyPath: ([String]) -> SettingOrigin
    ) -> RawConfigTree {
        guard !table.isEmpty else { return .empty }
        var tree = RawConfigTree()
        for key in table.keys.sorted() {
            guard let tomlVal = table[key] else { continue }
            let node = convertNode(
                tomlVal,
                keyPath: [key],
                originForKeyPath: originForKeyPath
            )
            tree.set(path: [key], node: node, caseSensitive: caseSensitive)
        }
        return tree
    }

    private static func convertNode(
        _ tomlValue: TOMLValue,
        keyPath: [String],
        originForKeyPath: ([String]) -> SettingOrigin
    ) -> RawNode {
        let origin = originForKeyPath(keyPath)
        let rawValue: RawValue
        switch tomlValue {
        case .string(let s):
            rawValue = .string(s)
        case .int(let i):
            rawValue = .int(i)
        case .float(let d):
            rawValue = .double(d)
        case .bool(let b):
            rawValue = .bool(b)
        case .datetime(let dt):
            rawValue = .string(dt)
        case .array(let items):
            let mapped = items.enumerated().map { idx, item in
                convertNode(
                    item,
                    keyPath: keyPath + [String(idx)],
                    originForKeyPath: originForKeyPath
                )
            }
            rawValue = .array(mapped)
        case .table(let subTable):
            var children: [String: RawNode] = [:]
            for key in subTable.keys.sorted() where key != "$schema" {
                guard let childVal = subTable[key] else { continue }
                children[key] = convertNode(
                    childVal,
                    keyPath: keyPath + [key],
                    originForKeyPath: originForKeyPath
                )
            }
            rawValue = .object(children)
        }
        return RawNode(value: rawValue, origin: origin)
    }

    private static func makeOrigin(
        style: TOMLSourceOriginStyle,
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
}

enum TOMLProfileResolver {
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

enum TOMLPathResolver {
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
