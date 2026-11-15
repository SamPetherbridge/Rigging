import Foundation

/// Reads XML or binary Apple Property List (`.plist`) configuration files via
/// `PropertyListSerialization` and `context.fileSystem` into a `RawConfigTree`.
public struct PlistFileSource: SettingsSource, Sendable {
    public let paths: [String]
    public let optional: Bool
    public let profile: String?
    public let originStyle: JSONSourceOriginStyle

    public var sourceName: String { "PlistFileSource" }

    public init(
        path: String,
        optional: Bool = true,
        profile: String? = nil,
        originStyle: JSONSourceOriginStyle = .custom(sourceName: "PlistFileSource")
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
        originStyle: JSONSourceOriginStyle = .custom(sourceName: "PlistFileSource")
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

            let data = try context.fileSystem.readFile(atPath: resolvedPath)
            var format = PropertyListSerialization.PropertyListFormat.xml
            let plistObject: Any
            do {
                plistObject = try PropertyListSerialization.propertyList(
                    from: data,
                    options: [],
                    format: &format
                )
            } catch {
                throw ConfigFileParseError(
                    path: resolvedPath,
                    format: "PropertyList",
                    reason: error.localizedDescription
                )
            }

            guard let rootDict = plistObject as? [String: Any] else {
                throw ConfigFileParseError(
                    path: resolvedPath,
                    format: "PropertyList",
                    reason: "Top-level property list must be a dictionary."
                )
            }

            let fileTree = try JSONConfigLoader.buildTreeFromRootDictionary(
                rootDict,
                path: resolvedPath,
                activeProfile: activeProfile,
                originStyle: originStyle,
                caseSensitive: configuration.caseSensitive
            )

            accumulated = fileTree.merging(
                lowerPriority: accumulated,
                caseSensitive: configuration.caseSensitive
            )
        }

        return accumulated
    }
}
