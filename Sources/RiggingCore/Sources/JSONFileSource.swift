import Foundation
#if canImport(CoreFoundation)
import CoreFoundation
#endif

/// Error thrown when a configuration file (JSON or Property List) cannot be parsed or its root
/// value is not a key-value dictionary.
public struct ConfigFileParseError: Error, Sendable, Equatable, Hashable, CustomStringConvertible, LocalizedError {
    public let path: String
    public let format: String
    public let reason: String

    public init(path: String, format: String, reason: String) {
        self.path = path
        self.format = format
        self.reason = reason
    }

    public var description: String {
        "Failed to parse \(format) configuration file '\(path)': \(reason)"
    }

    public var errorDescription: String? {
        description
    }
}

/// Origin classification for JSON-backed configuration files.
public enum JSONSourceOriginStyle: Sendable, Equatable, Hashable {
    case projectConfig
    case userConfig
    case custom(sourceName: String)
}

/// Loads one or more JSON configuration files into a `RawConfigTree`, stripping `"$schema"` and
/// `"profiles"` metadata keys and applying named profile overlays when active.
public struct JSONFileSource: SettingsSource, Sendable {
    public let paths: [String]
    public let optional: Bool
    public let profile: String?
    public let originStyle: JSONSourceOriginStyle

    public var sourceName: String {
        switch originStyle {
        case .projectConfig:
            return "ProjectConfigSource"
        case .userConfig:
            return "UserConfigSource"
        case .custom(let name):
            return name
        }
    }

    public init(
        path: String,
        optional: Bool = true,
        profile: String? = nil,
        originStyle: JSONSourceOriginStyle = .custom(sourceName: "JSONFileSource")
    ) {
        self.paths = [path]
        self.optional = optional
        self.profile = profile
        self.originStyle = originStyle
    }

    public init(
        paths: [String],
        optional: Bool = true,
        profile: String? = nil,
        originStyle: JSONSourceOriginStyle = .custom(sourceName: "JSONFileSource")
    ) {
        self.paths = paths
        self.optional = optional
        self.profile = profile
        self.originStyle = originStyle
    }

    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        guard !paths.isEmpty else { return .empty }
        let activeProfile = ProfileSelectionResolver.resolveActiveProfile(
            explicitProfile: profile,
            configuration: configuration,
            context: context
        )

        // Later paths in `paths` override earlier paths.
        var accumulated = RawConfigTree.empty
        for rawPath in paths {
            let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let resolvedPath = SourcePathResolver.resolve(
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

            let fileTree = try JSONConfigLoader.loadFile(
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

/// Discovers project configuration files (`configuration.projectConfigFiles`, e.g. `[".asc.json"]`)
/// by walking upward from `context.workingDirectory` until reaching a `.git` directory/file boundary
/// (inclusive of the repository root) or `context.homeDirectory` (never walking above `$HOME`).
public struct ProjectConfigSource: SettingsSource, Sendable {
    /// Optional explicit filenames overriding `configuration.projectConfigFiles`.
    public let fileNames: [String]?
    /// Optional explicit profile overriding `configuration.profile` / `<ENV_PREFIX>PROFILE`.
    public let profile: String?
    /// When `true`, stops upward search at the nearest directory containing a matching config file.
    /// Defaults to `false`, merging nearer directory configs over ancestor directory configs up to `.git`/`$HOME`.
    public let stopAtFirstFound: Bool

    public var sourceName: String { "ProjectConfigSource" }

    public init(
        fileNames: [String]? = nil,
        profile: String? = nil,
        stopAtFirstFound: Bool = false
    ) {
        self.fileNames = fileNames
        self.profile = profile
        self.stopAtFirstFound = stopAtFirstFound
    }

    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        let candidateNames = fileNames ?? configuration.projectConfigFiles
        guard !candidateNames.isEmpty else { return .empty }

        let activeProfile = ProfileSelectionResolver.resolveActiveProfile(
            explicitProfile: profile,
            configuration: configuration,
            context: context
        )

        let searchDirectories = Self.discoverDirectories(
            workingDirectory: context.workingDirectory,
            homeDirectory: context.homeDirectory,
            fileSystem: context.fileSystem
        )

        // `searchDirectories` is ordered nearest-first (workingDirectory -> ... -> repo root / $HOME).
        // Within a single directory, later filenames in `candidateNames` override earlier filenames.
        // Across directories, nearer directories override ancestor directories.
        var discoveredTreesNearestFirst: [RawConfigTree] = []

        for dir in searchDirectories {
            var dirTree: RawConfigTree?
            for rawName in candidateNames {
                let cleanName = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !cleanName.isEmpty else { continue }

                let candidatePath: String
                if cleanName.hasPrefix("/") || cleanName.hasPrefix("~/") {
                    candidatePath = SourcePathResolver.resolve(
                        path: cleanName,
                        workingDirectory: dir,
                        homeDirectory: context.homeDirectory
                    )
                } else {
                    candidatePath = SourcePathResolver.normalizeLexicalPath(
                        SourcePathResolver.joinPath(dir, cleanName)
                    )
                }

                guard context.fileSystem.fileExists(atPath: candidatePath),
                      !context.fileSystem.isDirectory(atPath: candidatePath) else {
                    continue
                }

                let loaded = try JSONConfigLoader.loadFile(
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

        // Fold from ancestor (lowest priority) to nearest (highest priority).
        var merged = RawConfigTree.empty
        for tree in discoveredTreesNearestFirst.reversed() {
            merged = tree.merging(
                lowerPriority: merged,
                caseSensitive: configuration.caseSensitive
            )
        }
        return merged
    }

    /// Returns directories from `workingDirectory` upward, stopping inclusively at any directory
    /// containing `.git` (directory or git-worktree file) or at `homeDirectory` (never above `$HOME`).
    static func discoverDirectories(
        workingDirectory: String,
        homeDirectory: String,
        fileSystem: any FileSystem
    ) -> [String] {
        let startDir = SourcePathResolver.normalizeLexicalPath(workingDirectory)
        let normalizedHome = SourcePathResolver.normalizeLexicalPath(homeDirectory)

        var directories: [String] = []
        var current = startDir
        var visited = Set<String>()

        while !visited.contains(current) {
            visited.insert(current)
            directories.append(current)

            // Stop at $HOME boundary (never walk above $HOME).
            if current == normalizedHome {
                break
            }

            // Stop at .git directory or file boundary (inclusive of repo root).
            let gitMarker = SourcePathResolver.joinPath(current, ".git")
            if fileSystem.fileExists(atPath: gitMarker) {
                break
            }

            guard let parent = SourcePathResolver.parentDirectory(of: current),
                  parent != current else {
                break
            }
            current = parent
        }

        return directories
    }
}

/// Loads user-scoped JSON configuration from `$XDG_CONFIG_HOME/<xdgAppName>/config.json`
/// (or `<homeDirectory>/.config/<xdgAppName>/config.json`), with optional macOS fallback to
/// `<homeDirectory>/Library/Application Support/<xdgAppName>/config.json`.
public struct UserConfigSource: SettingsSource, Sendable {
    /// Optional explicit app name overriding `configuration.xdgAppName`.
    public let appName: String?
    /// Config file name inside the user config directory (defaults to `"config.json"`).
    public let fileName: String
    /// Optional explicit profile overriding `configuration.profile` / `<ENV_PREFIX>PROFILE`.
    public let profile: String?
    /// Whether to check `<homeDirectory>/Library/Application Support/<appName>/<fileName>` as a fallback.
    public let includeApplicationSupportFallback: Bool

    public var sourceName: String { "UserConfigSource" }

    public init(
        appName: String? = nil,
        fileName: String = "config.json",
        profile: String? = nil,
        includeApplicationSupportFallback: Bool = true
    ) {
        self.appName = appName
        self.fileName = fileName
        self.profile = profile
        self.includeApplicationSupportFallback = includeApplicationSupportFallback
    }

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

        let activeProfile = ProfileSelectionResolver.resolveActiveProfile(
            explicitProfile: profile,
            configuration: configuration,
            context: context
        )

        let xdgBaseDir: String
        if let rawXDG = context.environment["XDG_CONFIG_HOME"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawXDG.isEmpty {
            xdgBaseDir = SourcePathResolver.resolve(
                path: rawXDG,
                workingDirectory: context.workingDirectory,
                homeDirectory: context.homeDirectory
            )
        } else {
            xdgBaseDir = SourcePathResolver.normalizeLexicalPath(
                SourcePathResolver.joinPath(context.homeDirectory, ".config")
            )
        }

        let xdgConfigPath = SourcePathResolver.normalizeLexicalPath(
            SourcePathResolver.joinPath(SourcePathResolver.joinPath(xdgBaseDir, cleanApp), fileName)
        )

        var candidatePathsLowestFirst: [String] = []
        if includeApplicationSupportFallback {
            let appSupportBase = SourcePathResolver.joinPath(
                SourcePathResolver.joinPath(context.homeDirectory, "Library/Application Support"),
                cleanApp
            )
            let appSupportPath = SourcePathResolver.normalizeLexicalPath(
                SourcePathResolver.joinPath(appSupportBase, fileName)
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
            let loaded = try JSONConfigLoader.loadFile(
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

// MARK: - Internal JSON & Profile Helpers

enum ProfileSelectionResolver {
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

        // Check CLI overrides (`--profile` or keyPath `["profile"]`)
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

        // Check `<ENV_PREFIX>PROFILE` in `context.environment`
        let candidateEnvNames = profileEnvVariableNames(envPrefix: configuration.envPrefix)
        for candidate in candidateEnvNames {
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

enum JSONConfigLoader {
    private static let reservedRootMetadataKeys: Set<String> = ["$schema", "profiles"]

    static func loadFile(
        atPath path: String,
        activeProfile: String?,
        originStyle: JSONSourceOriginStyle,
        caseSensitive: Bool,
        fileSystem: any FileSystem
    ) throws -> RawConfigTree {
        let data = try fileSystem.readFile(atPath: path)
        let jsonObject: Any
        do {
            jsonObject = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            throw ConfigFileParseError(
                path: path,
                format: "JSON",
                reason: error.localizedDescription
            )
        }

        guard let rootDict = jsonObject as? [String: Any] else {
            throw ConfigFileParseError(
                path: path,
                format: "JSON",
                reason: "Top-level JSON value must be an object dictionary."
            )
        }

        return try buildTreeFromRootDictionary(
            rootDict,
            path: path,
            activeProfile: activeProfile,
            originStyle: originStyle,
            caseSensitive: caseSensitive
        )
    }

    static func buildTreeFromRootDictionary(
        _ rootDict: [String: Any],
        path: String,
        activeProfile: String?,
        originStyle: JSONSourceOriginStyle,
        caseSensitive: Bool
    ) throws -> RawConfigTree {
        let profilesContainer = extractProfilesDictionary(from: rootDict, caseSensitive: caseSensitive)

        var strippedBase: [String: Any] = [:]
        for (key, value) in rootDict {
            if isReservedMetadataKey(key) {
                continue
            }
            strippedBase[key] = value
        }

        let baseTree = FoundationObjectConverter.buildConfigTree(
            from: strippedBase,
            caseSensitive: caseSensitive
        ) { keyPath in
            makeOrigin(style: originStyle, path: path, keyPath: keyPath, profile: nil)
        }

        guard let activeProfile,
              !activeProfile.isEmpty,
              let profilesContainer,
              let selectedProfileDict = findProfile(
                  named: activeProfile,
                  in: profilesContainer,
                  path: path,
                  caseSensitive: caseSensitive
              ) else {
            return baseTree
        }

        var strippedProfile: [String: Any] = [:]
        for (key, value) in selectedProfileDict where key != "$schema" {
            strippedProfile[key] = value
        }

        let profileTree = FoundationObjectConverter.buildConfigTree(
            from: strippedProfile,
            caseSensitive: caseSensitive
        ) { keyPath in
            makeOrigin(style: originStyle, path: path, keyPath: keyPath, profile: activeProfile)
        }

        return profileTree.merging(lowerPriority: baseTree, caseSensitive: caseSensitive)
    }

    private static func isReservedMetadataKey(_ key: String) -> Bool {
        if key == "$schema" || key == "profiles" {
            return true
        }
        return reservedRootMetadataKeys.contains(key.lowercased()) && key == "$schema"
    }

    private static func extractProfilesDictionary(
        from rootDict: [String: Any],
        caseSensitive: Bool
    ) -> [String: Any]? {
        if let exact = rootDict["profiles"] as? [String: Any] {
            return exact
        }
        guard !caseSensitive else { return nil }
        for key in rootDict.keys.sorted() where key.lowercased() == "profiles" {
            if let dict = rootDict[key] as? [String: Any] {
                return dict
            }
        }
        return nil
    }

    private static func findProfile(
        named profileName: String,
        in profilesDict: [String: Any],
        path: String,
        caseSensitive: Bool
    ) -> [String: Any]? {
        if let exactVal = profilesDict[profileName] {
            return exactVal as? [String: Any]
        }
        guard !caseSensitive else { return nil }
        let lowered = profileName.lowercased()
        for key in profilesDict.keys.sorted() where key.lowercased() == lowered {
            return profilesDict[key] as? [String: Any]
        }
        return nil
    }

    private static func makeOrigin(
        style: JSONSourceOriginStyle,
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

/// Shared converter transforming untyped `Foundation` plist / JSON / `CFPreferences` objects
/// into typed `RawNode` / `RawConfigTree` hierarchies with exact per-key `SettingOrigin`s.
enum FoundationObjectConverter {
    static func buildConfigTree(
        from dictionary: [String: Any],
        caseSensitive: Bool,
        originForKeyPath: ([String]) -> SettingOrigin
    ) -> RawConfigTree {
        guard !dictionary.isEmpty else { return .empty }
        var rootNodes: [String: RawNode] = [:]

        for key in dictionary.keys.sorted() {
            guard let rawVal = dictionary[key] else { continue }
            let keyPath = [key]
            let node = convertNode(
                rawVal,
                keyPath: keyPath,
                originForKeyPath: originForKeyPath
            )
            rootNodes[key] = node
        }

        // Normalize via RawConfigTree.set if case-insensitive collisions exist in the same dict.
        if !caseSensitive {
            var tree = RawConfigTree()
            for key in dictionary.keys.sorted() {
                if let node = rootNodes[key] {
                    tree.set(path: [key], node: node, caseSensitive: false)
                }
            }
            return tree
        }

        return RawConfigTree(root: rootNodes)
    }

    static func convertNode(
        _ anyValue: Any,
        keyPath: [String],
        originForKeyPath: ([String]) -> SettingOrigin
    ) -> RawNode {
        let origin = originForKeyPath(keyPath)
        let rawValue = convertValue(
            anyValue,
            keyPath: keyPath,
            originForKeyPath: originForKeyPath
        )
        return RawNode(value: rawValue, origin: origin)
    }

    static func convertValue(
        _ anyValue: Any,
        keyPath: [String],
        originForKeyPath: ([String]) -> SettingOrigin
    ) -> RawValue {
        if anyValue is NSNull {
            return .null
        }

        if let subDict = anyValue as? [String: Any] {
            var children: [String: RawNode] = [:]
            for key in subDict.keys.sorted() where key != "$schema" {
                guard let childAny = subDict[key] else { continue }
                children[key] = convertNode(
                    childAny,
                    keyPath: keyPath + [key],
                    originForKeyPath: originForKeyPath
                )
            }
            return .object(children)
        }

        if let array = anyValue as? [Any] {
            let elements = array.enumerated().map { index, elem in
                convertNode(
                    elem,
                    keyPath: keyPath + [String(index)],
                    originForKeyPath: originForKeyPath
                )
            }
            return .array(elements)
        }

        if let string = anyValue as? String {
            return .string(string)
        }

        if let data = anyValue as? Data {
            return .data(data)
        }

        if let date = anyValue as? Date {
            return .string(date.ISO8601Format())
        }

        #if canImport(CoreFoundation)
        if let number = anyValue as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return .bool(number.boolValue)
            }
            let cType = String(cString: number.objCType)
            if cType == "d" || cType == "f" {
                return .double(number.doubleValue)
            }
            if cType == "Q" && number.uint64Value > UInt64(Int64.max) {
                return .double(number.doubleValue)
            }
            return .int(number.int64Value)
        }
        #else
        if let boolVal = anyValue as? Bool {
            return .bool(boolVal)
        }
        if let int64Val = anyValue as? Int64 {
            return .int(int64Val)
        }
        if let intVal = anyValue as? Int {
            return .int(Int64(intVal))
        }
        if let doubleVal = anyValue as? Double {
            return .double(doubleVal)
        }
        if let number = anyValue as? NSNumber {
            let cType = String(cString: number.objCType)
            if cType == "B" || cType == "c" {
                return .bool(number.boolValue)
            }
            if cType == "d" || cType == "f" {
                return .double(number.doubleValue)
            }
            return .int(number.int64Value)
        }
        #endif

        return .string(String(describing: anyValue))
    }
}
