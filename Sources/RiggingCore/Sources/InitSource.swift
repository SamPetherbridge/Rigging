import Foundation

/// Highest-priority configuration source translating explicit programmatic values and non-nil
/// CLI argument overrides into a `RawConfigTree` without clobbering lower layers on `nil`.
public struct InitSource: SettingsSource, Sendable {
    public let overrides: [SettingOverride]

    public var sourceName: String { "InitSource" }

    /// Creates an `InitSource` backed by explicit overrides merged with `context.cliOverrides`.
    public init(overrides: [SettingOverride] = []) {
        self.overrides = overrides
    }

    /// Creates an `InitSource` from top-level key/value pairs, omitting any `nil` entries so
    /// unset optional parameters never clobber lower-priority configuration layers.
    public init(values: [String: RawValue?]) {
        var collected: [SettingOverride] = []
        for key in values.keys.sorted() {
            if let wrapped = values[key], let rawValue = wrapped {
                collected.append(.initValue(keyPath: [key], value: rawValue))
            }
        }
        self.overrides = collected
    }

    /// Creates an `InitSource` from nested key-path overrides, omitting any `nil` entries.
    public init(keyPathValues: [[String]: RawValue?]) {
        let sortedKeys = keyPathValues.keys.sorted {
            $0.joined(separator: ".") < $1.joined(separator: ".")
        }
        var collected: [SettingOverride] = []
        for keyPath in sortedKeys {
            if let wrapped = keyPathValues[keyPath], let rawValue = wrapped {
                collected.append(.initValue(keyPath: keyPath, value: rawValue))
            }
        }
        self.overrides = collected
    }

    /// Helper that builds a `.cliArgument` override only when `value` is non-nil.
    public static func optionalCLI(
        flag: String,
        keyPath: [String],
        value: RawValue?
    ) -> SettingOverride? {
        guard let value else { return nil }
        return .cli(flag: flag, keyPath: keyPath, value: value)
    }

    /// Helper that builds an `.initOverride` only when `value` is non-nil.
    public static func optionalInit(
        keyPath: [String],
        value: RawValue?
    ) -> SettingOverride? {
        guard let value else { return nil }
        return .initValue(keyPath: keyPath, value: value)
    }

    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        var tree = RawConfigTree()

        // Apply source-level programmatic overrides first, then context CLI overrides so
        // explicit context.cliOverrides win (preserving overridden provenance if both set the same path).
        for override in overrides {
            let cleanPath = override.keyPath.filter { !$0.isEmpty }
            guard !cleanPath.isEmpty else { continue }
            tree.set(
                path: cleanPath,
                value: override.value,
                origin: override.origin,
                caseSensitive: configuration.caseSensitive
            )
        }

        for override in context.cliOverrides {
            let cleanPath = override.keyPath.filter { !$0.isEmpty }
            guard !cleanPath.isEmpty else { continue }
            tree.set(
                path: cleanPath,
                value: override.value,
                origin: override.origin,
                caseSensitive: configuration.caseSensitive
            )
        }

        return tree
    }
}
