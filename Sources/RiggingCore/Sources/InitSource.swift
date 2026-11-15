import Foundation

/// Highest-precedence configuration source applying explicit programmatic values and non-`nil`
/// command-line flag overrides without clobbering lower-priority sources when values are unset.
///
/// `InitSource` merges its own ``overrides`` first and then applies ``SettingsContext/cliOverrides``
/// so explicit command-line flags take precedence over programmatic defaults while preserving
/// displaced origins in ``RawNode/overriddenOrigins``.
///
/// ```swift
/// let source = InitSource(overrides: [
///     .cli(flag: "--port", keyPath: ["port"], value: .int(9090)),
/// ])
/// ```
public struct InitSource: SettingsSource, Sendable {
    /// Programmatic or CLI setting overrides owned directly by this source instance.
    public let overrides: [SettingOverride]

    /// Human-readable name identifying this source in diagnostics (`"InitSource"`).
    public var sourceName: String { "InitSource" }

    /// Creates an initialization source backed by explicit setting overrides.
    ///
    /// - Parameter overrides: Ordered overrides applied before ``SettingsContext/cliOverrides``.
    public init(overrides: [SettingOverride] = []) {
        self.overrides = overrides
    }

    /// Creates an initialization source from top-level key-value pairs, omitting any `nil` entries.
    ///
    /// - Parameter values: Dictionary of top-level field names to optional ``RawValue`` payloads.
    ///   Entries whose value is `nil` are ignored so unset optional flags never shadow `.env` or
    ///   environment variables.
    public init(values: [String: RawValue?]) {
        var collected: [SettingOverride] = []
        for key in values.keys.sorted() {
            if let wrapped = values[key], let rawValue = wrapped {
                collected.append(.initValue(keyPath: [key], value: rawValue))
            }
        }
        self.overrides = collected
    }

    /// Creates an initialization source from hierarchical key-path overrides, omitting any `nil` entries.
    ///
    /// - Parameter keyPathValues: Dictionary mapping hierarchical key paths to optional ``RawValue`` payloads.
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

    /// Constructs a ``SettingOrigin/cliArgument(flag:)`` override only when `value` is non-`nil`.
    ///
    /// - Parameters:
    ///   - flag: Command-line flag name (for example, `"--timeout"`).
    ///   - keyPath: Target setting key path.
    ///   - value: Parsed raw CLI value, or `nil` when the flag was not supplied on the command line.
    /// - Returns: A ``SettingOverride`` when `value` is non-`nil`, or `nil` otherwise.
    public static func optionalCLI(
        flag: String,
        keyPath: [String],
        value: RawValue?
    ) -> SettingOverride? {
        guard let value else { return nil }
        return .cli(flag: flag, keyPath: keyPath, value: value)
    }

    /// Constructs a ``SettingOrigin/initOverride(keyPath:)`` override only when `value` is non-`nil`.
    ///
    /// - Parameters:
    ///   - keyPath: Target setting key path.
    ///   - value: Explicit raw override value, or `nil` when unset.
    /// - Returns: A ``SettingOverride`` when `value` is non-`nil`, or `nil` otherwise.
    public static func optionalInit(
        keyPath: [String],
        value: RawValue?
    ) -> SettingOverride? {
        guard let value else { return nil }
        return .initValue(keyPath: keyPath, value: value)
    }

    /// Loads programmatic ``overrides`` followed by ``SettingsContext/cliOverrides`` into a ``RawConfigTree``.
    ///
    /// - Parameters:
    ///   - configuration: Settings configuration controlling key case sensitivity.
    ///   - context: Execution context containing CLI argument overrides.
    /// - Returns: A ``RawConfigTree`` populated with `.initOverride` and `.cliArgument` nodes.
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
