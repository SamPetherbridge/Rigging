import Foundation
#if canImport(ObjectiveC)
import CoreFoundation
#endif

/// An error thrown when a structured configuration file (such as JSON or Property List) fails syntax
/// parsing or does not contain a top-level dictionary object.
public struct ConfigFileParseError: Error, Sendable, Equatable, Hashable, CustomStringConvertible, LocalizedError {
    /// Filesystem path of the configuration file that failed to parse.
    public let path: String

    /// Format name of the parser (for example, `"JSON"` or `"PropertyList"`).
    public let format: String

    /// Underlying diagnostic message describing the failure.
    public let reason: String

    /// Creates a structured configuration-file parse error.
    ///
    /// - Parameters:
    ///   - path: Path to the configuration file.
    ///   - format: Human-readable format name.
    ///   - reason: Explanation of why parsing failed.
    public init(path: String, format: String, reason: String) {
        self.path = path
        self.format = format
        self.reason = reason
    }

    /// Human-readable error message citing format, path, and failure reason.
    public var description: String {
        "Failed to parse \(format) configuration file '\(path)': \(reason)"
    }

    /// Localized error description matching ``description`` for CLI error reporters.
    public var errorDescription: String? {
        description
    }
}

/// Classifies the ``SettingOrigin`` recorded for keys loaded from a structured configuration file.
public enum JSONSourceOriginStyle: Sendable, Equatable, Hashable, Codable {
    /// Emits ``SettingOrigin/projectConfig(path:keyPath:profile:)``, activating repo-committed plaintext secret guards.
    case projectConfig

    /// Emits ``SettingOrigin/userConfig(path:keyPath:profile:)`` for per-user configuration files.
    case userConfig

    /// Emits ``SettingOrigin/customSource(name:detail:)`` with the specified source name.
    case custom(sourceName: String)
}

/// Loads one or more JSON configuration files into a ``RawConfigTree``, stripping `$schema` and
/// `profiles` metadata keys and overlaying named environment profiles when active.
///
/// ```swift
/// let source = JSONFileSource(path: "/etc/myapp/config.json", optional: false)
/// ```
public struct JSONFileSource: SettingsSource, Sendable {
    /// Ordered JSON file paths to load (later paths override earlier paths).
    public let paths: [String]

    /// Whether missing files are silently skipped (`true`) or throw a file-not-found error (`false`).
    public let optional: Bool

    /// Optional explicit profile name overriding ``SettingsConfiguration/profile``.
    public let profile: String?

    /// Origin classification applied to keys loaded by this source.
    public let originStyle: JSONSourceOriginStyle

    /// Human-readable name identifying this source in diagnostics.
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

    /// Creates a JSON configuration source for a single file path.
    ///
    /// - Parameters:
    ///   - path: Relative, tilde-prefixed, or absolute path to a JSON file.
    ///   - optional: When `true`, missing files are ignored; when `false`, missing files throw an error.
    ///   - profile: Optional explicit profile name to overlay from `"profiles"`.
    ///   - originStyle: Provenance classification applied to loaded keys.
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

    /// Creates a JSON configuration source for multiple file paths merged in order.
    ///
    /// - Parameters:
    ///   - paths: Ordered JSON file paths where later files override earlier files.
    ///   - optional: When `true`, missing files are ignored; when `false`, missing files throw an error.
    ///   - profile: Optional explicit profile name to overlay from `"profiles"`.
    ///   - originStyle: Provenance classification applied to loaded keys.
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

    /// Loads and merges all configured JSON files into a ``RawConfigTree``.
    ///
    /// - Parameters:
    ///   - configuration: Settings configuration controlling profile selection and case sensitivity.
    ///   - context: Execution context providing filesystem and path resolution context.
    /// - Returns: A ``RawConfigTree`` populated from the JSON document(s) and active profile overlay.
    /// - Throws: ``ConfigFileParseError`` if a file contains invalid JSON or a non-dictionary root,
    ///   or `CocoaError` when ``optional`` is `false` and a file is missing.
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

/// Discovers and merges project-scoped JSON configuration files (such as `.asc.json`) by walking
/// upward from ``SettingsContext/workingDirectory`` to the nearest `.git` boundary or ``SettingsContext/homeDirectory``.
///
/// Nearer directory configuration files take precedence over ancestor directory files, and the upward
/// walk never traverses above ``SettingsContext/homeDirectory``. Every loaded key carries
/// ``SettingOrigin/projectConfig(path:keyPath:profile:)`` provenance so ``SecretResolver`` automatically
/// blocks accidental plaintext secrets committed to version control.
public struct ProjectConfigSource: SettingsSource, Sendable {
    /// Optional explicit filenames overriding ``SettingsConfiguration/projectConfigFiles``.
    public let fileNames: [String]?

    /// Optional explicit profile name overriding ``SettingsConfiguration/profile`` and `<ENV_PREFIX>PROFILE`.
    public let profile: String?

    /// When `true`, stops upward directory discovery at the nearest directory containing a matching file.
    public let stopAtFirstFound: Bool

    /// Human-readable name identifying this source in diagnostics (`"ProjectConfigSource"`).
    public var sourceName: String { "ProjectConfigSource" }

    /// Creates a project configuration discovery source.
    ///
    /// - Parameters:
    ///   - fileNames: Optional explicit filenames overriding ``SettingsConfiguration/projectConfigFiles``.
    ///   - profile: Optional explicit profile overlay name.
    ///   - stopAtFirstFound: When `true`, stops at the closest matching directory instead of merging up to `.git`.
    public init(
        fileNames: [String]? = nil,
        profile: String? = nil,
        stopAtFirstFound: Bool = false
    ) {
        self.fileNames = fileNames
        self.profile = profile
        self.stopAtFirstFound = stopAtFirstFound
    }

    /// Discovers project configuration files upward from the working directory and merges them.
    ///
    /// - Parameters:
    ///   - configuration: Settings configuration providing `projectConfigFiles`, `profile`, and `caseSensitive`.
    ///   - context: Execution context providing `workingDirectory`, `homeDirectory`, and `fileSystem`.
    /// - Returns: Merged ``RawConfigTree`` with ``SettingOrigin/projectConfig(path:keyPath:profile:)`` provenance.
    /// - Throws: ``ConfigFileParseError`` if a discovered JSON file is malformed.
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

            if current == normalizedHome {
                break
            }

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

/// Loads user-scoped JSON configuration from `$XDG_CONFIG_HOME/<appName>/config.json`
/// (or `~/.config/<appName>/config.json`) with an optional macOS `~/Library/Application Support/<appName>/config.json` fallback.
///
/// When both the XDG configuration file and the `Application Support` fallback exist, keys in the
/// XDG file take higher priority while preserving displaced origins.
public struct UserConfigSource: SettingsSource, Sendable {
    /// Optional application directory name overriding ``SettingsConfiguration/xdgAppName``.
    public let appName: String?

    /// File name within the user configuration directory (defaults to `"config.json"`).
    public let fileName: String

    /// Optional explicit profile name overriding ``SettingsConfiguration/profile``.
    public let profile: String?

    /// Whether `~/Library/Application Support/<appName>/<fileName>` is checked as a lower-priority fallback.
    public let includeApplicationSupportFallback: Bool

    /// Human-readable name identifying this source in diagnostics (`"UserConfigSource"`).
    public var sourceName: String { "UserConfigSource" }

    /// Creates a user-scoped XDG JSON configuration source.
    ///
    /// - Parameters:
    ///   - appName: Optional application directory name overriding ``SettingsConfiguration/xdgAppName``.
    ///   - fileName: Configuration file name inside the directory (defaults to `"config.json"`).
    ///   - profile: Optional explicit profile overlay name.
    ///   - includeApplicationSupportFallback: Whether to check `Library/Application Support` beneath `homeDirectory`.
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

    /// Loads user-scoped JSON configuration files into a ``RawConfigTree``.
    ///
    /// - Parameters:
    ///   - configuration: Settings configuration providing `xdgAppName`, `profile`, and `caseSensitive`.
    ///   - context: Execution context providing `environment`, `homeDirectory`, and `fileSystem`.
    /// - Returns: Merged ``RawConfigTree`` with ``SettingOrigin/userConfig(path:keyPath:profile:)`` provenance.
    /// - Throws: ``ConfigFileParseError`` if an existing user configuration file contains invalid JSON.
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

        #if canImport(ObjectiveC)
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
        if type(of: anyValue) == Bool.self, let boolVal = anyValue as? Bool {
            return .bool(boolVal)
        }
        if let number = anyValue as? NSNumber {
            let boolType = type(of: NSNumber(value: true))
            let intType = type(of: NSNumber(value: 1))
            let cType = String(cString: number.objCType)
            if (boolType != intType && type(of: number) == boolType) || cType == "B" {
                return .bool(number.boolValue)
            }
            if cType == "d" || cType == "f" {
                return .double(number.doubleValue)
            }
            if cType == "Q" && number.uint64Value > UInt64(Int64.max) {
                return .double(number.doubleValue)
            }
            return .int(number.int64Value)
        }
        if let int64Val = anyValue as? Int64 {
            return .int(int64Val)
        }
        if let intVal = anyValue as? Int {
            return .int(Int64(intVal))
        }
        if let uint64Val = anyValue as? UInt64 {
            if uint64Val <= UInt64(Int64.max) {
                return .int(Int64(uint64Val))
            }
            return .double(Double(uint64Val))
        }
        if let doubleVal = anyValue as? Double {
            return .double(doubleVal)
        }
        #endif

        return .string(String(describing: anyValue))
    }
}
