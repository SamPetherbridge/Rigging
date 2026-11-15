import ArgumentParser
import Foundation
import RiggingCore

// MARK: - CLI Raw Value Conversion

/// Converts a parsed command-line option or flag value into a `RiggingCore.RawValue`.
public protocol CLIRawValueRepresentable {
    func cliRawValue(origin: SettingOrigin) -> RawValue
}

extension CLIRawValueRepresentable {
    public var cliRawValue: RawValue {
        cliRawValue(origin: .defaultValue)
    }
}

extension String: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(self) }
}

extension Substring: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(String(self)) }
}

extension Bool: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .bool(self) }
}

extension Int: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension Int8: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension Int16: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension Int32: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension Int64: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(self) }
}

extension UInt: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue {
        Int64(exactly: self).map(RawValue.int) ?? .string(String(self))
    }
}

extension UInt8: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension UInt16: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension UInt32: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .int(Int64(self)) }
}

extension UInt64: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue {
        Int64(exactly: self).map(RawValue.int) ?? .string(String(self))
    }
}

extension Double: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .double(self) }
}

extension Float: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .double(Double(self)) }
}

extension Decimal: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(NSDecimalNumber(decimal: self).stringValue) }
}

extension URL: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(absoluteString) }
}

extension UUID: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue { .string(uuidString) }
}

extension Array: CLIRawValueRepresentable where Element: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RawValue {
        .array(map { RawNode(value: $0.cliRawValue(origin: origin), origin: origin) })
    }
}

extension RawRepresentable where RawValue: CLIRawValueRepresentable {
    public func cliRawValue(origin: SettingOrigin) -> RiggingCore.RawValue {
        rawValue.cliRawValue(origin: origin)
    }
}

// MARK: - Explicit Builder DSL

/// Declarative builder for constructing `[SettingOverride]` from CLI argument structs while
/// automatically omitting `nil` optionals so unset CLI flags never clobber lower-priority sources.
public struct CLIOverridesBuilder: Sendable {
    public private(set) var overrides: [SettingOverride] = []

    public init() {}

    /// Appends a CLI override when `value` is non-`nil`. If `value` is `nil`, this is a no-op.
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

    /// Appends a CLI override for a single top-level or dot-separated key (`"signing.teamId"`).
    public mutating func add<V: CLIRawValueRepresentable>(
        _ value: V?,
        key: String,
        flag: String? = nil
    ) {
        let segments = key.split(separator: ".").map(String.init)
        add(value, keyPath: segments, flag: flag)
    }

    /// Appends a raw `SettingOverride` directly.
    public mutating func append(_ override: SettingOverride) {
        overrides.append(override)
    }

    /// Appends all overrides from a nested `CLIOverridesConvertible` option group.
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

    /// Converts a camelCase Swift identifier (`readOnly`, `ascKeyID`) into a `--kebab-case` CLI flag.
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

/// Protocol adopted by CLI argument containers that convert explicitly supplied arguments
/// into `Rigging` `[SettingOverride]` values.
public protocol CLIOverridesConvertible {
    func cliSettingOverrides() -> [SettingOverride]
}

/// Zero-boilerplate protocol combining `ParsableArguments`, `Sendable`, and `CLIOverridesConvertible`.
///
/// Conforming types automatically reflect over `@Option`, `@Flag`, `@Argument`, and `@OptionGroup`
/// properties, omitting `nil` optionals so unset CLI flags never override environment variables
/// or configuration files. Types needing custom key paths or flag names may override
/// `buildCLIOverrides(_:)` or `cliKeyMap`.
public protocol RiggingCLIOptions: ParsableArguments, CLIOverridesConvertible, Sendable {
    /// Optional mapping from Swift property name to explicit `(keyPath, flag)` targets.
    static var cliKeyMap: [String: CLIFieldTarget] { get }

    /// Customization hook for building `[SettingOverride]` values explicitly or augmenting reflection.
    func buildCLIOverrides(_ builder: inout CLIOverridesBuilder)
}

/// Target key-path and optional CLI flag name override for a `ParsableArguments` property.
public struct CLIFieldTarget: Sendable, Equatable, Hashable {
    public let keyPath: [String]
    public let flag: String?

    public init(keyPath: [String], flag: String? = nil) {
        self.keyPath = keyPath
        self.flag = flag
    }

    public static func key(_ path: String..., flag: String? = nil) -> CLIFieldTarget {
        CLIFieldTarget(keyPath: path, flag: flag)
    }
}

extension RiggingCLIOptions {
    public static var cliKeyMap: [String: CLIFieldTarget] { [:] }

    public func buildCLIOverrides(_ builder: inout CLIOverridesBuilder) {
        for item in riggingOverrides(keyMap: Self.cliKeyMap) {
            builder.append(item)
        }
    }

    public func cliSettingOverrides() -> [SettingOverride] {
        var builder = CLIOverridesBuilder()
        buildCLIOverrides(&builder)
        return builder.overrides
    }
}

// MARK: - Automatic Reflection for Any ParsableArguments

extension ParsableArguments {
    /// Extracts `[SettingOverride]` from any parsed `ParsableArguments` instance by inspecting
    /// `@Option`, `@Flag`, `@Argument`, and nested `@OptionGroup` wrappers.
    ///
    /// - Unset optional properties (`String? = nil`, `Bool? = nil`, `[String]? = nil`) are
    ///   **completely omitted**, ensuring unset CLI flags never clobber environment variables,
    ///   `.env`, or configuration files.
    /// - Unparsed `ParsableArguments` definitions (in `.definition` state) are safely skipped
    ///   without triggering `ArgumentParser`'s fatal precondition.
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

/// High-precedence `SettingsSource` bridging `swift-argument-parser` `ParsableArguments`
/// into `Rigging`'s configuration cascade.
public struct ArgumentParserSource: SettingsSource, Sendable {
    public let overrides: [SettingOverride]
    public let includeContextCLIOverrides: Bool

    public var sourceName: String { "ArgumentParserSource" }

    /// Creates a source from precomputed `[SettingOverride]` entries.
    public init(
        overrides: [SettingOverride],
        includeContextCLIOverrides: Bool = true
    ) {
        self.overrides = overrides
        self.includeContextCLIOverrides = includeContextCLIOverrides
    }

    /// Creates a source directly from any `ParsableArguments` instance.
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

    /// Creates a source using the declarative `CLIOverridesBuilder` DSL.
    public init(
        includeContextCLIOverrides: Bool = true,
        _ build: (inout CLIOverridesBuilder) -> Void
    ) {
        var builder = CLIOverridesBuilder()
        build(&builder)
        self.overrides = builder.overrides
        self.includeContextCLIOverrides = includeContextCLIOverrides
    }

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
    /// Loads settings applying explicitly supplied options/flags from a `ParsableArguments` struct
    /// at highest priority while omitting `nil` optionals.
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

// MARK: - Internal Reflection Machinery

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
                    if let convertible = nestedArgs as? any CLIOverridesConvertible {
                        let groupPrefix = keyMap[propertyName]?.keyPath ?? prefix
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
                        let groupPrefix = keyMap[propertyName]?.keyPath ?? prefix
                        collected.append(
                            contentsOf: extractOverrides(
                                from: nestedArgs,
                                keyMap: [:],
                                prefix: groupPrefix
                            )
                        )
                    }
                }

            case .option, .flag, .argument:
                let target = keyMap[propertyName]
                let keyPath = target?.keyPath ?? (prefix + [propertyName])
                let preliminaryBoolFalse = (nonNilValue as? Bool) == false
                let flag: String
                if let explicitFlag = target?.flag {
                    flag = explicitFlag
                } else if kind == .flag,
                          parsedValue is any OptionalUnwrapping,
                          preliminaryBoolFalse {
                    // Inverted optional @Flag(inversion: .prefixedNo) supplied as --no-<name>
                    let kebab = CLIOverridesBuilder.camelToKebabCase(propertyName)
                    flag = "--no-\(kebab)"
                } else {
                    flag = CLIOverridesBuilder.defaultFlagName(forProperty: propertyName)
                }

                let origin = SettingOrigin.cliArgument(flag: flag)
                guard let rawVal = convertToRawValue(nonNilValue, origin: origin) else {
                    continue
                }

                collected.append(.cli(flag: flag, keyPath: keyPath, value: rawVal))
            }
        }

        return collected
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
