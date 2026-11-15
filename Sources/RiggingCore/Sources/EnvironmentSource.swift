import Foundation

/// Reads configuration values from process environment variables (`context.environment`),
/// supporting `envPrefix`, `envNestedDelimiter`, `envNestedMaxSplit`, `caseSensitive`,
/// `envIgnoreEmpty`, `envNullStrings`, and direct `.env(...)` alias lookups.
public struct EnvironmentSource: SettingsSource, Sendable {
    /// Optional explicit environment dictionary overriding `context.environment`.
    public let environment: [String: String]?

    public var sourceName: String { "EnvironmentSource" }

    public init(environment: [String: String]? = nil) {
        self.environment = environment
    }

    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        let env = environment ?? context.environment
        guard !env.isEmpty else { return .empty }

        var tree = RawConfigTree()
        for variable in env.keys.sorted() {
            guard let rawString = env[variable] else { continue }
            EnvironmentKeyMapper.insert(
                variable: variable,
                rawString: rawString,
                origin: .environment(variable: variable),
                configuration: configuration,
                into: &tree
            )
        }
        return tree
    }
}

/// Shared key-mapping and value normalization rules used by `EnvironmentSource` and `DotEnvSource`.
enum EnvironmentKeyMapper {
    static func insert(
        variable: String,
        rawString: String,
        origin: SettingOrigin,
        configuration: SettingsConfiguration,
        into tree: inout RawConfigTree
    ) {
        let trimmedVar = variable.trimmingCharacters(in: .whitespaces)
        guard !trimmedVar.isEmpty else { return }

        if configuration.envIgnoreEmpty && rawString.isEmpty {
            return
        }

        let value = decodeRawScalarOrNull(
            rawString,
            nullStrings: configuration.envNullStrings,
            caseSensitive: configuration.caseSensitive
        )

        // Always populate directEnvironment so explicit `@Setting(aliases: [.env("...")])`
        // lookups succeed even when the variable name does not start with `envPrefix`.
        tree.setEnvironmentEntry(
            trimmedVar,
            value: value,
            origin: origin,
            caseSensitive: configuration.caseSensitive
        )

        // Only populate hierarchical `tree.root` when the variable matches `envPrefix`.
        guard let strippedKey = stripPrefix(
            from: trimmedVar,
            prefix: configuration.envPrefix,
            caseSensitive: configuration.caseSensitive
        ), !strippedKey.isEmpty else {
            return
        }

        let segments = splitKeyPath(
            strippedKey,
            delimiter: configuration.envNestedDelimiter,
            maxSplits: configuration.envNestedMaxSplit,
            caseSensitive: configuration.caseSensitive
        )

        guard !segments.isEmpty else { return }
        tree.set(
            path: segments,
            value: value,
            origin: origin,
            caseSensitive: configuration.caseSensitive
        )
    }

    static func decodeRawScalarOrNull(
        _ rawString: String,
        nullStrings: Set<String>,
        caseSensitive: Bool
    ) -> RawValue {
        if nullStrings.isEmpty {
            return .string(rawString)
        }
        if caseSensitive {
            return nullStrings.contains(rawString) ? .null : .string(rawString)
        }
        let lowered = rawString.lowercased()
        let isNull = nullStrings.contains { $0.lowercased() == lowered }
        return isNull ? .null : .string(rawString)
    }

    static func stripPrefix(
        from variable: String,
        prefix: String,
        caseSensitive: Bool
    ) -> String? {
        guard !prefix.isEmpty else {
            return variable
        }

        let matches: Bool
        if caseSensitive {
            matches = variable.hasPrefix(prefix)
        } else {
            matches = variable.lowercased().hasPrefix(prefix.lowercased())
        }

        guard matches else {
            return nil
        }

        var remainder = String(variable.dropFirst(prefix.count))
        if !prefix.hasSuffix("_"), remainder.hasPrefix("_"), !remainder.hasPrefix("__") {
            remainder.removeFirst()
        }
        return remainder
    }

    static func splitKeyPath(
        _ key: String,
        delimiter: String,
        maxSplits: Int?,
        caseSensitive: Bool
    ) -> [String] {
        guard !delimiter.isEmpty else {
            return key.isEmpty ? [] : [key]
        }

        if let maxSplits, maxSplits <= 0 {
            return key.isEmpty ? [] : [key]
        }

        let compareOptions: String.CompareOptions = caseSensitive ? [] : [.caseInsensitive]
        var segments: [String] = []
        var searchStart = key.startIndex
        var splitsPerformed = 0

        while searchStart < key.endIndex {
            if let maxSplits, splitsPerformed >= maxSplits {
                break
            }
            guard let range = key.range(
                of: delimiter,
                options: compareOptions,
                range: searchStart..<key.endIndex
            ) else {
                break
            }

            let segment = String(key[searchStart..<range.lowerBound])
            if !segment.isEmpty {
                segments.append(segment)
            }
            searchStart = range.upperBound
            splitsPerformed += 1
        }

        let tail = String(key[searchStart..<key.endIndex])
        if !tail.isEmpty {
            segments.append(tail)
        }

        return segments
    }
}
