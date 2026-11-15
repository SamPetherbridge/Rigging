import Foundation

/// Loads XML or binary Apple Property List (`.plist`) configuration files into a ``RawConfigTree``.
///
/// `PlistFileSource` parses property lists via `PropertyListSerialization` from ``SettingsContext/fileSystem``
/// and supports the same named `"profiles"` overlay mechanism as ``JSONFileSource``.
///
/// ```swift
/// let source = PlistFileSource(path: "~/Library/Preferences/com.example.asc.plist")
/// ```
public struct PlistFileSource: SettingsSource, Sendable {
    /// Ordered `.plist` file paths to load (later files override earlier files).
    public let paths: [String]

    /// Whether missing `.plist` files are silently skipped (`true`) or throw an error (`false`).
    public let optional: Bool

    /// Optional explicit profile name overriding ``SettingsConfiguration/profile``.
    public let profile: String?

    /// Provenance classification applied to keys loaded from the property list.
    public let originStyle: JSONSourceOriginStyle

    /// Human-readable name identifying this source in diagnostics (`"PlistFileSource"`).
    public var sourceName: String { "PlistFileSource" }

    /// Creates a Property List configuration source for a single `.plist` path.
    ///
    /// - Parameters:
    ///   - path: Relative, tilde-prefixed, or absolute path to a `.plist` file.
    ///   - optional: When `true`, missing files are ignored; when `false`, missing files throw an error.
    ///   - profile: Optional explicit profile overlay name.
    ///   - originStyle: Provenance classification applied to loaded keys.
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

    /// Creates a Property List configuration source for multiple `.plist` paths merged in order.
    ///
    /// - Parameters:
    ///   - paths: Ordered `.plist` file paths where later files override earlier files.
    ///   - optional: When `true`, missing files are ignored; when `false`, missing files throw an error.
    ///   - profile: Optional explicit profile overlay name.
    ///   - originStyle: Provenance classification applied to loaded keys.
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

    /// Reads and parses all configured `.plist` files into a ``RawConfigTree``.
    ///
    /// - Parameters:
    ///   - configuration: Settings configuration controlling profile selection and case sensitivity.
    ///   - context: Execution context providing filesystem and path resolution context.
    /// - Returns: Merged ``RawConfigTree`` populated from the property list document(s).
    /// - Throws: ``ConfigFileParseError`` if a file is not a valid dictionary property list,
    ///   or `CocoaError` when ``optional`` is `false` and a file does not exist.
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
