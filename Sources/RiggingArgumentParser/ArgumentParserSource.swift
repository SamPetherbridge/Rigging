import ArgumentParser
import Foundation
import RiggingCore

// MARK: - CLI Raw Value Conversion

/// A type whose parsed command-line argument value can be converted into a `RiggingCore` `RawValue`.
///
/// Standard Swift scalars (`String`, `Bool`, fixed-width integers, floating-point types),
/// `Foundation` value types (`Decimal`, `URL`, `UUID`), arrays of `CLIRawValueRepresentable`
/// elements, and `RawRepresentable` enumerations conform out of the box.
public protocol CLIRawValueRepresentable {
    /// Converts this value into a `RawValue`, tagging nested collection elements with `origin`.
    ///
    /// - Parameter origin: The `SettingOrigin` recorded for any nested array elements.
    /// - Returns: The untyped `RawValue` representation for configuration merging.
    func cliRawValue(origin: SettingOrigin) -> RawValue
}

extension CLIRawValueRepresentable {
    /// Converts this value into a `RawValue` using `.defaultValue` element provenance.
    public var cliRawValue: RawValue {
        cliRawValue(origin: .defaultValue)
    }
}

extension String: CLIRawValueRepresentable {
    /// Converts this string into `RawValue.string`.
    ///
    /// - Parameter origin: Unused for scalar string values.
    /// - Returns: `.string(self)`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(self) }
}

extension Substring: CLIRawValueRepresentable {
    /// Converts this substring into `RawValue.string`.
    ///
    /// - Parameter origin: Unused for scalar substring values.
    /// - Returns: `.string(String(self))`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(String(self)) }
}

extension Bool: CLIRawValueRepresentable {
    /// Converts this boolean into `RawValue.bool`.
    ///
    /// - Parameter origin: Unused for scalar boolean values.
    /// - Returns: `.bool(self)`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .bool(self) }
}

extension Int: CLIRawValueRepresentable {
    /// Converts this integer into `RawValue.int`.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int(Int64(self))`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension Int8: CLIRawValueRepresentable {
    /// Converts this 8-bit signed integer into `RawValue.int`.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int(Int64(self))`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension Int16: CLIRawValueRepresentable {
    /// Converts this 16-bit signed integer into `RawValue.int`.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int(Int64(self))`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension Int32: CLIRawValueRepresentable {
    /// Converts this 32-bit signed integer into `RawValue.int`.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int(Int64(self))`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension Int64: CLIRawValueRepresentable {
    /// Converts this 64-bit signed integer into `RawValue.int`.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int(self)`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(self) }
}

extension UInt: CLIRawValueRepresentable {
    /// Converts this unsigned integer into `RawValue.int` when representable in `Int64`, or `.string` otherwise.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int` or `.string` preserving full precision for values above `Int64.max`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue {
        Int64(exactly: self).map(RawValue.int) ?? .string(String(self))
    }
}

extension UInt8: CLIRawValueRepresentable {
    /// Converts this 8-bit unsigned integer into `RawValue.int`.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int(Int64(self))`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension UInt16: CLIRawValueRepresentable {
    /// Converts this 16-bit unsigned integer into `RawValue.int`.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int(Int64(self))`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension UInt32: CLIRawValueRepresentable {
    /// Converts this 32-bit unsigned integer into `RawValue.int`.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int(Int64(self))`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension UInt64: CLIRawValueRepresentable {
    /// Converts this 64-bit unsigned integer into `RawValue.int` when representable in `Int64`, or `.string` otherwise.
    ///
    /// - Parameter origin: Unused for scalar integer values.
    /// - Returns: `.int` or `.string` preserving full precision for values above `Int64.max`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue {
        Int64(exactly: self).map(RawValue.int) ?? .string(String(self))
    }
}

extension Double: CLIRawValueRepresentable {
    /// Converts this double-precision floating-point value into `RawValue.double`.
    ///
    /// - Parameter origin: Unused for scalar floating-point values.
    /// - Returns: `.double(self)`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .double(self) }
}

extension Float: CLIRawValueRepresentable {
    /// Converts this single-precision floating-point value into `RawValue.double`.
    ///
    /// - Parameter origin: Unused for scalar floating-point values.
    /// - Returns: `.double(Double(self))`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .double(Double(self)) }
}

extension Decimal: CLIRawValueRepresentable {
    /// Converts this decimal value into an exact base-10 string `RawValue`.
    ///
    /// - Parameter origin: Unused for scalar decimal values.
    /// - Returns: `.string` preserving exact base-10 decimal digits.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(description) }
}

extension URL: CLIRawValueRepresentable {
    /// Converts this URL into `RawValue.string(absoluteString)`.
    ///
    /// - Parameter origin: Unused for scalar URL values.
    /// - Returns: `.string(absoluteString)`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(absoluteString) }
}

extension UUID: CLIRawValueRepresentable {
    /// Converts this UUID into `RawValue.string(uuidString)`.
    ///
    /// - Parameter origin: Unused for scalar UUID values.
    /// - Returns: `.string(uuidString)`.
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(uuidString) }
}

extension Array: CLIRawValueRepresentable where Element: CLIRawValueRepresentable {
    /// Converts this array into `RawValue.array`, tagging every element `RawNode` with `origin`.
    ///
    /// - Parameter origin: The `SettingOrigin` assigned to each element node.
    /// - Returns: `.array` of converted `RawNode` elements.
    public func cliRawValue(origin: SettingOrigin) -> RawValue {
        .array(map { RawNode(value: $0.cliRawValue(origin: origin), origin: origin) })
    }
}

extension RawRepresentable where RawValue: CLIRawValueRepresentable {
    /// Converts this `RawRepresentable` value into a `RiggingCore` `RawValue` using its underlying `rawValue`.
    ///
    /// - Parameter origin: The `SettingOrigin` assigned to any nested elements.
    /// - Returns: The `RawValue` produced by `rawValue.cliRawValue(origin:)`.
    public func cliRawValue(origin: SettingOrigin) -> RiggingCore.RawValue {
        rawValue.cliRawValue(origin: origin)
    }
}

// MARK: - Explicit Builder DSL

/// Declarative builder that accumulates explicit `[SettingOverride]` entries from parsed command-line
/// options while omitting `nil` optionals so unset CLI flags never clobber lower-priority sources.
///
/// ```swift
/// var builder = CLIOverridesBuilder()
/// builder.add(options.keyId, key: "keyId")
/// builder.add(options.team, keyPath: ["signing", "teamId"], flag: "--team")
/// builder.addNonEmpty(options.tags, key: "tags", flag: "--tag")
/// ```
public struct CLIOverridesBuilder: Sendable {
    /// The ordered list of explicit CLI overrides collected by this builder.
    public private(set) var overrides: [SettingOverride] = []

    /// Creates an empty CLI overrides builder.
    public init() {}

    /// Appends a CLI override when `value` is non-`nil`; performs no action when `value` is `nil`.
    ///
    /// - Parameters:
    ///   - value: Optional parsed CLI value; omitted when `nil`.
    ///   - keyPath: Target setting key-path segments in the `@Settings` model.
    ///   - flag: Optional explicit CLI flag label (inferred as `--<kebab-case>` from the leaf key when `nil`).
    public mutating func add<V: CLIRawValueRepresentable>(
        _ value: V?,
        keyPath: [String],
        flag: String? = nil
    ) {
        guard let value else { return }
        let cleanPath = keyPath.filter { !$0.isEmpty }
        guard let leaf = cleanPath.last else { return }
        let resolvedFlag = flag ?? Self.defaultFlagName(forProperty: leaf)
        let origin = SettingOrigin.cliArgument(flag: resolvedFlag)
        overrides.append(.cli(flag: resolvedFlag, keyPath: cleanPath, value: value.cliRawValue(origin: origin)))
    }

    /// Appends a CLI override for a top-level or dot-separated key path (such as `"signing.teamId"`) when `value` is non-`nil`.
    ///
    /// - Parameters:
    ///   - value: Optional parsed CLI value; omitted when `nil`.
    ///   - key: Top-level key or dot-separated key path.
    ///   - flag: Optional explicit CLI flag label.
    public mutating func add<V: CLIRawValueRepresentable>(
        _ value: V?,
        key: String,
        flag: String? = nil
    ) {
        let segments = key.split(separator: ".").map(String.init)
        add(value, keyPath: segments, flag: flag)
    }

    /// Appends a CLI collection override only when `values` is non-empty, preventing unset `@Option var items: [T] = []` defaults from clobbering config files.
    ///
    /// - Parameters:
    ///   - values: Parsed array of CLI values; omitted when empty.
    ///   - keyPath: Target setting key-path segments in the `@Settings` model.
    ///   - flag: Optional explicit CLI flag label.
    public mutating func addNonEmpty<Element: CLIRawValueRepresentable>(
        _ values: [Element],
        keyPath: [String],
        flag: String? = nil
    ) {
        guard !values.isEmpty else { return }
        add(values, keyPath: keyPath, flag: flag)
    }

    /// Appends a CLI collection override for a top-level or dot-separated key only when `values` is non-empty.
    ///
    /// - Parameters:
    ///   - values: Parsed array of CLI values; omitted when empty.
    ///   - key: Top-level key or dot-separated key path.
    ///   - flag: Optional explicit CLI flag label.
    public mutating func addNonEmpty<Element: CLIRawValueRepresentable>(
        _ values: [Element],
        key: String,
        flag: String? = nil
    ) {
        guard !values.isEmpty else { return }
        add(values, key: key, flag: flag)
    }

    /// Appends a preconstructed `SettingOverride` directly.
    ///
    /// - Parameter override: The override to append.
    public mutating func append(_ override: SettingOverride) {
        overrides.append(override)
    }

    /// Appends all overrides produced by a nested ``CLIOverridesConvertible`` option group.
    ///
    /// - Parameters:
    ///   - group: The nested option group to extract overrides from.
    ///   - prefix: Optional key-path prefix prepended to every extracted override.
    public mutating func include(
        _ group: some CLIOverridesConvertible,
        prefix: [String] = []
    ) {
        for item in group.cliSettingOverrides() {
            overrides.append(
                SettingOverride(
                    keyPath: prefix + item.keyPath,
                    value: item.value,
                    flag: item.flag
                )
            )
        }
    }

    /// Converts a Swift camelCase property identifier (such as `readOnly` or `ascKeyID`) into a `--kebab-case` CLI flag.
    ///
    /// - Parameter propertyName: The Swift property identifier.
    /// - Returns: The canonical `--kebab-case` flag string (for example, `"--read-only"`).
    public static func defaultFlagName(forProperty propertyName: String) -> String {
        let trimmed = propertyName.trimmingCharacters(in: CharacterSet(charactersIn: "_"))
        guard !trimmed.isEmpty else { return "--option" }
        return "--\(camelToKebabCase(trimmed))"
    }

    static func camelToKebabCase(_ input: String) -> String {
        let scalars = Array(input.unicodeScalars)
        guard !scalars.isEmpty else { return input }

        var result = ""
        result.reserveCapacity(scalars.count + 4)

        for index in scalars.indices {
            let current = scalars[index]
            if CharacterSet.uppercaseLetters.contains(current) {
                if index > 0 {
                    let prev = scalars[index - 1]
                    let prevIsUpper = CharacterSet.uppercaseLetters.contains(prev)
                    let prevIsSeparator = prev == "_" || prev == "-"
                    let nextIsLower: Bool = {
                        guard index + 1 < scalars.count else { return false }
                        return CharacterSet.lowercaseLetters.contains(scalars[index + 1])
                    }()
                    if !prevIsSeparator && (!prevIsUpper || nextIsLower) {
                        result.append("-")
                    }
                }
                result.append(String(current).lowercased())
            } else if current == "_" {
                if !result.hasSuffix("-") && !result.isEmpty {
                    result.append("-")
                }
            } else {
                result.append(Character(current))
            }
        }

        return result
    }
}

// MARK: - CLIOverridesConvertible & RiggingCLIOptions

/// A type that converts explicitly supplied command-line arguments into `[SettingOverride]` entries.
public protocol CLIOverridesConvertible {
    /// Extracts `[SettingOverride]` values for every CLI option or flag explicitly supplied by the user.
    ///
    /// - Returns: An ordered list of non-clobbering CLI setting overrides.
    func cliSettingOverrides() -> [SettingOverride]
}

/// Zero-boilerplate protocol combining `ParsableArguments`, `Sendable`, and ``CLIOverridesConvertible``.
///
/// Conforming types automatically reflect over `@Option`, `@Flag` (including
/// `FlagInversion.prefixedNo` and `FlagInversion.prefixedEnableDisable`), `@Argument`, and
/// `@OptionGroup` properties, omitting `nil` optionals and empty default arrays so unset CLI flags
/// never clobber environment variables or configuration files.
///
/// ```swift
/// struct GlobalCLIOptions: RiggingCLIOptions {
///     static var cliKeyMap: [String: CLIFieldTarget] {
///         ["team": .key("signing", "teamId", flag: "--team")]
///     }
///
///     @Option(name: .long) var keyId: String?
///     @Option(name: .customLong("team")) var team: String?
///     @Flag(inversion: .prefixedNo) var readOnly: Bool?
/// }
/// ```
public protocol RiggingCLIOptions: ParsableArguments, CLIOverridesConvertible, Sendable {
    /// Optional mapping from Swift property name to explicit `(keyPath, flag)` override targets.
    static var cliKeyMap: [String: CLIFieldTarget] { get }

    /// Customization hook for building `[SettingOverride]` values explicitly or augmenting reflection.
    ///
    /// - Parameter builder: The mutable ``CLIOverridesBuilder`` collecting CLI overrides.
    func buildCLIOverrides(_ builder: inout CLIOverridesBuilder)
}

/// Target setting key-path and optional CLI flag label override for a `ParsableArguments` property.
public struct CLIFieldTarget: Sendable, Equatable, Hashable {
    /// Destination key-path segments in the `@Settings` model (or prefix segments for an `@OptionGroup`).
    public let keyPath: [String]

    /// Optional explicit CLI flag string recorded in `SettingOrigin.cliArgument(flag:)`.
    public let flag: String?

    /// Creates a CLI field mapping target.
    ///
    /// - Parameters:
    ///   - keyPath: Destination setting key-path segments.
    ///   - flag: Optional explicit CLI flag string (such as `"--team"`).
    public init(keyPath: [String], flag: String? = nil) {
        self.keyPath = keyPath
        self.flag = flag
    }

    /// Creates a CLI field mapping target from variadic path segments.
    ///
    /// - Parameters:
    ///   - path: Variadic destination setting key-path segments.
    ///   - flag: Optional explicit CLI flag string.
    /// - Returns: A configured ``CLIFieldTarget``.
    public static func key(_ path: String..., flag: String? = nil) -> CLIFieldTarget {
        CLIFieldTarget(keyPath: path, flag: flag)
    }

    /// Creates a CLI field mapping target from an array of path segments.
    ///
    /// - Parameters:
    ///   - path: Destination setting key-path segments.
    ///   - flag: Optional explicit CLI flag string.
    /// - Returns: A configured ``CLIFieldTarget``.
    public static func key(_ path: [String], flag: String? = nil) -> CLIFieldTarget {
        CLIFieldTarget(keyPath: path, flag: flag)
    }
}

extension RiggingCLIOptions {
    /// Default empty key map using each Swift property's name and `--kebab-case` flag.
    public static var cliKeyMap: [String: CLIFieldTarget] { [:] }

    /// Default reflection-backed implementation appending all `riggingOverrides(keyMap: Self.cliKeyMap)` items.
    ///
    /// - Parameter builder: The mutable ``CLIOverridesBuilder`` collecting CLI overrides.
    public func buildCLIOverrides(_ builder: inout CLIOverridesBuilder) {
        for item in riggingOverrides(keyMap: Self.cliKeyMap) {
            builder.append(item)
        }
    }

    /// Builds and returns `[SettingOverride]` entries by invoking ``buildCLIOverrides(_:)``.
    ///
    /// - Returns: An array of explicit CLI setting overrides.
    public func cliSettingOverrides() -> [SettingOverride] {
        var builder = CLIOverridesBuilder()
        buildCLIOverrides(&builder)
        return builder.overrides
    }
}

// MARK: - Automatic Reflection for Any ParsableArguments

extension ParsableArguments {
    /// Extracts `[SettingOverride]` entries from any parsed `ParsableArguments` value without clobbering lower-priority sources.
    ///
    /// - Unset optional properties (`String? = nil`, `Bool? = nil`) are omitted completely.
    /// - Unset repeating array options (`@Option var tags: [String] = []`), unset counter flags
    ///   (`@Flag var verbose: Int`), and unset non-inverted boolean flags (`@Flag var debug = false`)
    ///   are omitted so defaults on the CLI struct never shadow environment variables or config files.
    /// - Inverted boolean flags (`FlagInversion.prefixedNo` and `FlagInversion.prefixedEnableDisable`)
    ///   record their exact `--no-<name>` or `--enable-<name>` / `--disable-<name>` provenance.
    /// - Unparsed `ParsableArguments` instances in `.definition` state are safely skipped without trapping.
    ///
    /// - Parameters:
    ///   - keyMap: Optional mapping from Swift property name to custom ``CLIFieldTarget`` paths and flag names.
    ///   - prefix: Optional key-path prefix prepended to extracted overrides.
    /// - Returns: Ordered `[SettingOverride]` entries for explicitly supplied CLI arguments.
    public func riggingOverrides(
        keyMap: [String: CLIFieldTarget] = [:],
        prefix: [String] = []
    ) -> [SettingOverride] {
        ParsableArgumentsMirrorExtractor.extractOverrides(
            from: self,
            keyMap: keyMap,
            prefix: prefix
        )
    }
}

// MARK: - ArgumentParserSource

/// High-precedence `SettingsSource` bridging `swift-argument-parser` `ParsableArguments` into
/// Rigging's configuration cascade.
///
/// Use `ArgumentParserSource` inside `customizeSources(_:)` when embedding parsed CLI options
/// directly into a custom source pipeline, or use `RiggedSettings.load(cliArguments:...)` for the
/// standard cascade.
///
/// ```swift
/// let source = ArgumentParserSource(parsedCLIOptions)
/// ```
public struct ArgumentParserSource: SettingsSource, Sendable {
    /// Explicit CLI overrides emitted by this source.
    public let overrides: [SettingOverride]

    /// Whether overrides already stored in `SettingsContext.cliOverrides` are also merged on top.
    public let includeContextCLIOverrides: Bool

    /// The canonical source identifier (`"ArgumentParserSource"`).
    public var sourceName: String { "ArgumentParserSource" }

    /// Creates a source from precomputed `[SettingOverride]` entries.
    ///
    /// - Parameters:
    ///   - overrides: Explicit CLI overrides to apply.
    ///   - includeContextCLIOverrides: When `true` (the default), merges `context.cliOverrides` after `overrides`.
    public init(
        overrides: [SettingOverride],
        includeContextCLIOverrides: Bool = true
    ) {
        self.overrides = overrides
        self.includeContextCLIOverrides = includeContextCLIOverrides
    }

    /// Creates a source directly from any parsed `ParsableArguments` value.
    ///
    /// - Parameters:
    ///   - arguments: A parsed `ParsableArguments` or ``RiggingCLIOptions`` value.
    ///   - keyMap: Optional mapping from property names to custom ``CLIFieldTarget`` destinations.
    ///   - prefix: Optional key-path prefix prepended to extracted overrides.
    ///   - includeContextCLIOverrides: When `true` (the default), merges `context.cliOverrides` after `arguments`.
    public init<Arguments: ParsableArguments>(
        _ arguments: Arguments,
        keyMap: [String: CLIFieldTarget] = [:],
        prefix: [String] = [],
        includeContextCLIOverrides: Bool = true
    ) {
        if let convertible = arguments as? any CLIOverridesConvertible,
           keyMap.isEmpty,
           prefix.isEmpty {
            self.overrides = convertible.cliSettingOverrides()
        } else {
            self.overrides = arguments.riggingOverrides(keyMap: keyMap, prefix: prefix)
        }
        self.includeContextCLIOverrides = includeContextCLIOverrides
    }

    /// Creates a source using the declarative ``CLIOverridesBuilder`` DSL.
    ///
    /// - Parameters:
    ///   - includeContextCLIOverrides: When `true` (the default), merges `context.cliOverrides` after builder items.
    ///   - build: A closure that populates a ``CLIOverridesBuilder``.
    public init(
        includeContextCLIOverrides: Bool = true,
        _ build: (inout CLIOverridesBuilder) -> Void
    ) {
        var builder = CLIOverridesBuilder()
        build(&builder)
        self.overrides = builder.overrides
        self.includeContextCLIOverrides = includeContextCLIOverrides
    }

    /// Materializes the extracted CLI overrides (and optional `context.cliOverrides`) into a `RawConfigTree`.
    ///
    /// - Parameters:
    ///   - configuration: Model-level settings configuration controlling case sensitivity.
    ///   - context: Execution context containing optional `cliOverrides`.
    /// - Returns: A `RawConfigTree` populated with `.cliArgument` provenance nodes.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        var tree = RawConfigTree()

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

        if includeContextCLIOverrides {
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
        }

        return tree
    }
}

// MARK: - RiggedSettings Convenience Overloads

extension RiggedSettings {
    /// Loads and validates settings while applying explicitly supplied options and flags from `cliArguments` at highest precedence.
    ///
    /// Unset optional properties (`nil`) and empty default repeating `@Option` arrays on `cliArguments`
    /// are omitted automatically so environment variables, `.env` files, and configuration files
    /// remain intact unless overridden on the command line.
    ///
    /// ```swift
    /// let settings = try await AppSettings.load(cliArguments: parsedOptions)
    /// ```
    ///
    /// - Parameters:
    ///   - cliArguments: A parsed `ParsableArguments` or ``RiggingCLIOptions`` instance.
    ///   - keyMap: Optional property-to-key-path remapping table.
    ///   - context: Execution context providing environment variables, filesystem, and secret providers.
    ///   - additionalOverrides: Extra programmatic overrides appended after extracted CLI arguments.
    /// - Returns: A fully validated, secret-resolved settings instance.
    /// - Throws: `SettingsValidationError` if validation, secret safety checks, or secret resolution fails.
    public static func load<Arguments: ParsableArguments>(
        cliArguments: Arguments,
        keyMap: [String: CLIFieldTarget] = [:],
        context: SettingsContext = SettingsContext(),
        additionalOverrides: [SettingOverride] = []
    ) async throws -> Self {
        let cliExtracted: [SettingOverride]
        if let convertible = cliArguments as? any CLIOverridesConvertible, keyMap.isEmpty {
            cliExtracted = convertible.cliSettingOverrides()
        } else {
            cliExtracted = cliArguments.riggingOverrides(keyMap: keyMap)
        }
        return try await load(
            context: context,
            overrides: cliExtracted + additionalOverrides
        )
    }
}

// MARK: - Internal Reflection & ToolInfo Metadata Machinery

private protocol OptionalUnwrapping {
    var unwrappedOptionalValue: Any? { get }
}

extension Optional: OptionalUnwrapping {
    var unwrappedOptionalValue: Any? {
        switch self {
        case .some(let wrapped):
            if let nested = wrapped as? any OptionalUnwrapping {
                return nested.unwrappedOptionalValue
            }
            return wrapped
        case .none:
            return nil
        }
    }
}

private struct DumpedToolInfoEnvelope: Decodable {
    struct CommandInfo: Decodable {
        let arguments: [ArgumentInfo]?
    }

    struct ArgumentInfo: Decodable {
        struct NameInfo: Decodable {
            let kind: String
            let name: String

            var formattedFlag: String {
                switch kind {
                case "short", "longWithSingleDash":
                    return "-\(name)"
                default:
                    return "--\(name)"
                }
            }
        }

        let kind: String
        let names: [NameInfo]?
    }

    let command: CommandInfo
}

enum ParsableArgumentsMirrorExtractor {
    private enum WrapperKind {
        case option
        case flag
        case argument
        case optionGroup
    }

    static func extractOverrides(
        from arguments: any ParsableArguments,
        keyMap: [String: CLIFieldTarget],
        prefix: [String]
    ) -> [SettingOverride] {
        var collected: [SettingOverride] = []
        let declaredFlags = extractDeclaredFlags(for: type(of: arguments))
        let mirror = Mirror(reflecting: arguments)

        for child in mirror.children {
            guard let rawLabel = child.label else { continue }
            let propertyName = rawLabel.hasPrefix("_")
                ? String(rawLabel.dropFirst())
                : rawLabel
            guard !propertyName.isEmpty else { continue }

            guard let (kind, parsedValue) = unwrapArgumentParserProperty(child.value) else {
                continue
            }

            let isOptionalWrapper = parsedValue is any OptionalUnwrapping

            // Unwrap Optional<T>: if nil, the CLI flag/option was not supplied -> omit completely!
            let nonNilValue: Any
            if let optional = parsedValue as? any OptionalUnwrapping {
                guard let unwrapped = optional.unwrappedOptionalValue else {
                    continue
                }
                nonNilValue = unwrapped
            } else {
                nonNilValue = parsedValue
            }

            switch kind {
            case .optionGroup:
                if let nestedArgs = nonNilValue as? any ParsableArguments {
                    let groupPrefix = keyMap[propertyName]?.keyPath ?? prefix
                    if let convertible = nestedArgs as? any CLIOverridesConvertible {
                        for item in convertible.cliSettingOverrides() {
                            collected.append(
                                SettingOverride(
                                    keyPath: groupPrefix + item.keyPath,
                                    value: item.value,
                                    flag: item.flag
                                )
                            )
                        }
                    } else {
                        var forwardedKeyMap = keyMap
                        forwardedKeyMap.removeValue(forKey: propertyName)
                        collected.append(
                            contentsOf: extractOverrides(
                                from: nestedArgs,
                                keyMap: forwardedKeyMap,
                                prefix: groupPrefix
                            )
                        )
                    }
                }

            case .option, .flag, .argument:
                // Non-optional repeating collections (`@Option var tags: [String] = []`) default to `[]`
                // when unset on the command line; omit empty defaults so lower-priority config is preserved.
                if !isOptionalWrapper && isEmptyCollection(nonNilValue) {
                    continue
                }

                // Non-optional counter flags (`@Flag var verbose: Int`) default to `0` when unset.
                if kind == .flag && !isOptionalWrapper && (nonNilValue as? Int) == 0 {
                    continue
                }

                let kebab = CLIOverridesBuilder.camelToKebabCase(propertyName)

                // Non-optional plain boolean flags (`@Flag var verbose = false` without inversion)
                // cannot be set to `false` on the CLI; omit `false` so lower-priority config is preserved.
                if kind == .flag,
                   !isOptionalWrapper,
                   (nonNilValue as? Bool) == false,
                   !hasNegativeFlagVariant(kebab: kebab, declaredFlags: declaredFlags) {
                    continue
                }

                let target = keyMap[propertyName]
                let keyPath = target?.keyPath ?? (prefix + [propertyName])
                let flag = resolveFlagName(
                    kind: kind,
                    propertyName: propertyName,
                    kebab: kebab,
                    isOptionalWrapper: isOptionalWrapper,
                    nonNilValue: nonNilValue,
                    explicitFlag: target?.flag,
                    declaredFlags: declaredFlags
                )

                let origin = SettingOrigin.cliArgument(flag: flag)
                guard let rawVal = convertToRawValue(nonNilValue, origin: origin) else {
                    continue
                }

                collected.append(.cli(flag: flag, keyPath: keyPath, value: rawVal))
            }
        }

        return collected
    }

    private static func resolveFlagName(
        kind: WrapperKind,
        propertyName: String,
        kebab: String,
        isOptionalWrapper: Bool,
        nonNilValue: Any,
        explicitFlag: String?,
        declaredFlags: Set<String>
    ) -> String {
        if let explicitFlag {
            return explicitFlag
        }

        if kind == .flag, let boolValue = nonNilValue as? Bool {
            // FlagInversion.prefixedEnableDisable (`--enable-<name>` / `--disable-<name>`)
            let enableLong = "--enable-\(kebab)"
            let disableLong = "--disable-\(kebab)"
            if declaredFlags.contains(enableLong) || declaredFlags.contains(disableLong) {
                return boolValue ? enableLong : disableLong
            }

            let enableSingle = "-enable-\(kebab)"
            let disableSingle = "-disable-\(kebab)"
            if declaredFlags.contains(enableSingle) || declaredFlags.contains(disableSingle) {
                return boolValue ? enableSingle : disableSingle
            }

            // FlagInversion.prefixedNo (`--<name>` / `--no-<name>`)
            if !boolValue && (isOptionalWrapper || declaredFlags.contains("--no-\(kebab)")) {
                return "--no-\(kebab)"
            }
            if !boolValue && declaredFlags.contains("-no-\(kebab)") {
                return "-no-\(kebab)"
            }
        }

        return CLIOverridesBuilder.defaultFlagName(forProperty: propertyName)
    }

    private static func hasNegativeFlagVariant(kebab: String, declaredFlags: Set<String>) -> Bool {
        declaredFlags.contains("--no-\(kebab)")
            || declaredFlags.contains("--disable-\(kebab)")
            || declaredFlags.contains("-no-\(kebab)")
            || declaredFlags.contains("-disable-\(kebab)")
    }

    private static func extractDeclaredFlags(for type: any ParsableArguments.Type) -> Set<String> {
        let json = type._dumpHelp()
        guard let data = json.data(using: .utf8),
              let decoded = try? JSONDecoder().decode(DumpedToolInfoEnvelope.self, from: data),
              let arguments = decoded.command.arguments else {
            return []
        }

        var flags = Set<String>()
        for arg in arguments {
            for name in arg.names ?? [] {
                flags.insert(name.formattedFlag)
            }
        }
        return flags
    }

    private static func isEmptyCollection(_ value: Any) -> Bool {
        let mirror = Mirror(reflecting: value)
        guard mirror.displayStyle == .collection || mirror.displayStyle == .set else {
            return false
        }
        return mirror.children.isEmpty
    }

    private static func unwrapArgumentParserProperty(_ wrapper: Any) -> (WrapperKind, Any)? {
        let typeName = String(describing: type(of: wrapper))
        let kind: WrapperKind
        if typeName.hasPrefix("Option<") {
            kind = .option
        } else if typeName.hasPrefix("Flag<") {
            kind = .flag
        } else if typeName.hasPrefix("Argument<") {
            kind = .argument
        } else if typeName.hasPrefix("OptionGroup<") {
            kind = .optionGroup
        } else {
            return nil
        }

        let wrapperMirror = Mirror(reflecting: wrapper)
        guard let parsedChild = wrapperMirror.children.first(where: { $0.label == "_parsedValue" }) else {
            return nil
        }

        let parsedMirror = Mirror(reflecting: parsedChild.value)
        guard parsedMirror.displayStyle == .enum,
              let enumCase = parsedMirror.children.first,
              enumCase.label == "value" else {
            // Unparsed (.definition) state -> skip safely without trapping!
            return nil
        }

        return (kind, enumCase.value)
    }

    private static func convertToRawValue(_ value: Any, origin: SettingOrigin) -> RawValue? {
        if let direct = value as? any CLIRawValueRepresentable {
            return direct.cliRawValue(origin: origin)
        }

        let mirror = Mirror(reflecting: value)
        if mirror.displayStyle == .collection || mirror.displayStyle == .set {
            var elements: [RawNode] = []
            for element in mirror.children {
                guard let converted = convertToRawValue(element.value, origin: origin) else {
                    return nil
                }
                elements.append(RawNode(value: converted, origin: origin))
            }
            return .array(elements)
        }

        if let argConvertible = value as? any ExpressibleByArgument {
            return .string(argConvertible.defaultValueDescription)
        }

        if mirror.displayStyle == .enum {
            return .string(String(describing: value))
        }

        if let customString = value as? any CustomStringConvertible {
            return .string(customString.description)
        }

        return nil
    }
}
