@_exported import Foundation
@_exported import RiggingCore

// MARK: - Field Value Transforms (`@Setting(transforms:)`)

/// Composable, `Sendable` value transformation applied to decoded `@Setting` values prior to validation.
public struct SettingTransform<Value: Sendable>: Sendable {
    private let evaluator: @Sendable (Value, SettingsContext) throws -> Value

    public init(_ evaluator: @escaping @Sendable (Value, SettingsContext) throws -> Value) {
        self.evaluator = evaluator
    }

    public init(_ evaluator: @escaping @Sendable (Value) throws -> Value) {
        self.evaluator = { value, _ in
            try evaluator(value)
        }
    }

    public func apply(_ value: Value, context: SettingsContext = SettingsContext()) throws -> Value {
        try evaluator(value, context)
    }

    public static func custom(
        _ transform: @escaping @Sendable (Value) throws -> Value
    ) -> SettingTransform<Value> {
        SettingTransform(transform)
    }

    public static func custom(
        _ transform: @escaping @Sendable (Value, SettingsContext) throws -> Value
    ) -> SettingTransform<Value> {
        SettingTransform(transform)
    }
}

extension SettingTransform where Value == String {
    /// Trims leading and trailing whitespace and newlines.
    public static var trimWhitespace: SettingTransform<String> {
        SettingTransform { value, _ in
            value.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    /// Normalizes text to lowercase.
    public static var lowercased: SettingTransform<String> {
        SettingTransform { value, _ in
            value.lowercased()
        }
    }

    /// Normalizes text to uppercase.
    public static var uppercased: SettingTransform<String> {
        SettingTransform { value, _ in
            value.uppercased()
        }
    }

    /// Expands leading `~` or `~/` against `context.homeDirectory`.
    public static var expandTilde: SettingTransform<String> {
        SettingTransform { value, context in
            FileSecretProvider.expandHome(value, homeDirectory: context.homeDirectory)
        }
    }
}

extension SettingTransform where Value == URL {
    /// Expands leading `~` or `~/` on file/path URLs against `context.homeDirectory`.
    public static var expandTilde: SettingTransform<URL> {
        SettingTransform { url, context in
            let raw = url.isFileURL ? url.path(percentEncoded: false) : url.absoluteString
            guard raw == "~" || raw.hasPrefix("~/") else {
                return url
            }
            let expanded = FileSecretProvider.expandHome(raw, homeDirectory: context.homeDirectory)
            return URL(fileURLWithPath: expanded)
        }
    }
}

// MARK: - Scoped Secret Convenience & Automatic RawRepresentable Enum Decoding

extension Secret {
    /// Scoped convenience closure unwrapping the underlying secret value.
    public func expose<R>(_ body: (Value) throws -> R) rethrows -> R {
        try body(expose())
    }
}

private struct _StringCaseIterableEnumBox<E: RawRepresentable & CaseIterable & Sendable>: SettingValueDecodable, CustomStringConvertible
where E.RawValue == String {
    let value: E

    var description: String {
        String(describing: value)
    }

    static var settingTypeDisplayName: String {
        String(describing: E.self)
    }

    static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Self {
        let decodedRaw = try String.decodeSettingValue(from: rawValue, context: context)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        if let exact = E(rawValue: decodedRaw) {
            return Self(value: exact)
        }

        if !context.caseSensitive {
            let lower = decodedRaw.lowercased()
            if let matched = E.allCases.first(where: { $0.rawValue.lowercased() == lower }) {
                return Self(value: matched)
            }
        }

        let validOptions = E.allCases.map(\.rawValue).joined(separator: ", ")
        throw ValueDecodingError(
            expectedType: settingTypeDisplayName,
            reason: "Expected one of [\(validOptions)], got '\(decodedRaw)'."
        )
    }
}

private struct _RawRepresentableBox<E: RawRepresentable & Sendable>: SettingValueDecodable, CustomStringConvertible
where E.RawValue: SettingValueDecodable {
    let value: E

    var description: String {
        String(describing: value)
    }

    static var settingTypeDisplayName: String {
        String(describing: E.self)
    }

    static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Self {
        let decodedRaw = try E.RawValue.decodeSettingValue(from: rawValue, context: context)
        if let exact = E(rawValue: decodedRaw) {
            return Self(value: exact)
        }
        throw ValueDecodingError(
            expectedType: settingTypeDisplayName,
            reason: "Unsupported \(settingTypeDisplayName) value '\(decodedRaw)'."
        )
    }
}

extension SettingsLoader {
    @_disfavoredOverload
    public mutating func decodeRequired<Value: RawRepresentable & CaseIterable & Sendable>(
        _ type: Value.Type = Value.self,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        envListStrategy: EnvCollectionStrategy? = nil,
        resolveSecrets: Bool = false,
        transform: ((Value) throws -> Value)? = nil,
        validators: [SettingValidator<Value>] = []
    ) -> SettingMetadata<Value>? where Value.RawValue == String {
        let boxedTransform: ((_StringCaseIterableEnumBox<Value>) throws -> _StringCaseIterableEnumBox<Value>)? = transform.map { fn in
            { box in _StringCaseIterableEnumBox(value: try fn(box.value)) }
        }
        let boxedValidators = validators.map { validator in
            SettingValidator<_StringCaseIterableEnumBox<Value>> { box, ctx in
                validator.validate(box.value, context: ctx)
            }
        }
        guard let boxed = decodeRequired(
            _StringCaseIterableEnumBox<Value>.self,
            keyPath: keyPath,
            aliases: aliases,
            envListStrategy: envListStrategy,
            resolveSecrets: resolveSecrets,
            transform: boxedTransform,
            validators: boxedValidators
        ) else {
            return nil
        }
        return SettingMetadata(
            keyPath: boxed.keyPath,
            value: boxed.value.value,
            isSecret: boxed.isSecret,
            origin: boxed.origin,
            overriddenOrigins: boxed.overriddenOrigins
        )
    }

    @_disfavoredOverload
    public mutating func decodeDefaulted<Value: RawRepresentable & CaseIterable & Sendable>(
        _ type: Value.Type = Value.self,
        default defaultValue: @autoclosure () -> Value,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        envListStrategy: EnvCollectionStrategy? = nil,
        resolveSecrets: Bool = false,
        transform: ((Value) throws -> Value)? = nil,
        validators: [SettingValidator<Value>] = []
    ) -> SettingMetadata<Value>? where Value.RawValue == String {
        let boxedTransform: ((_StringCaseIterableEnumBox<Value>) throws -> _StringCaseIterableEnumBox<Value>)? = transform.map { fn in
            { box in _StringCaseIterableEnumBox(value: try fn(box.value)) }
        }
        let boxedValidators = validators.map { validator in
            SettingValidator<_StringCaseIterableEnumBox<Value>> { box, ctx in
                validator.validate(box.value, context: ctx)
            }
        }
        guard let boxed = decodeDefaulted(
            _StringCaseIterableEnumBox<Value>.self,
            default: _StringCaseIterableEnumBox(value: defaultValue()),
            keyPath: keyPath,
            aliases: aliases,
            envListStrategy: envListStrategy,
            resolveSecrets: resolveSecrets,
            transform: boxedTransform,
            validators: boxedValidators
        ) else {
            return nil
        }
        return SettingMetadata(
            keyPath: boxed.keyPath,
            value: boxed.value.value,
            isSecret: boxed.isSecret,
            origin: boxed.origin,
            overriddenOrigins: boxed.overriddenOrigins
        )
    }

    @_disfavoredOverload
    public mutating func decodeOptional<Wrapped: RawRepresentable & CaseIterable & Sendable>(
        _ type: Wrapped.Type = Wrapped.self,
        default defaultValue: Wrapped? = nil,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        envListStrategy: EnvCollectionStrategy? = nil,
        resolveSecrets: Bool = false,
        transform: ((Wrapped) throws -> Wrapped)? = nil,
        validators: [SettingValidator<Wrapped>] = []
    ) -> SettingMetadata<Wrapped?>? where Wrapped.RawValue == String {
        let boxedTransform: ((_StringCaseIterableEnumBox<Wrapped>) throws -> _StringCaseIterableEnumBox<Wrapped>)? = transform.map { fn in
            { box in _StringCaseIterableEnumBox(value: try fn(box.value)) }
        }
        let boxedValidators = validators.map { validator in
            SettingValidator<_StringCaseIterableEnumBox<Wrapped>> { box, ctx in
                validator.validate(box.value, context: ctx)
            }
        }
        guard let boxed = decodeOptional(
            _StringCaseIterableEnumBox<Wrapped>.self,
            default: defaultValue.map(_StringCaseIterableEnumBox.init(value:)),
            keyPath: keyPath,
            aliases: aliases,
            envListStrategy: envListStrategy,
            resolveSecrets: resolveSecrets,
            transform: boxedTransform,
            validators: boxedValidators
        ) else {
            return nil
        }
        return SettingMetadata(
            keyPath: boxed.keyPath,
            value: boxed.value?.value,
            isSecret: boxed.isSecret,
            origin: boxed.origin,
            overriddenOrigins: boxed.overriddenOrigins
        )
    }

    @_disfavoredOverload
    public mutating func decodeRequired<Value: RawRepresentable & Sendable>(
        _ type: Value.Type = Value.self,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        envListStrategy: EnvCollectionStrategy? = nil,
        resolveSecrets: Bool = false,
        transform: ((Value) throws -> Value)? = nil,
        validators: [SettingValidator<Value>] = []
    ) -> SettingMetadata<Value>? where Value.RawValue: SettingValueDecodable {
        let boxedTransform: ((_RawRepresentableBox<Value>) throws -> _RawRepresentableBox<Value>)? = transform.map { fn in
            { box in _RawRepresentableBox(value: try fn(box.value)) }
        }
        let boxedValidators = validators.map { validator in
            SettingValidator<_RawRepresentableBox<Value>> { box, ctx in
                validator.validate(box.value, context: ctx)
            }
        }
        guard let boxed = decodeRequired(
            _RawRepresentableBox<Value>.self,
            keyPath: keyPath,
            aliases: aliases,
            envListStrategy: envListStrategy,
            resolveSecrets: resolveSecrets,
            transform: boxedTransform,
            validators: boxedValidators
        ) else {
            return nil
        }
        return SettingMetadata(
            keyPath: boxed.keyPath,
            value: boxed.value.value,
            isSecret: boxed.isSecret,
            origin: boxed.origin,
            overriddenOrigins: boxed.overriddenOrigins
        )
    }

    @_disfavoredOverload
    public mutating func decodeDefaulted<Value: RawRepresentable & Sendable>(
        _ type: Value.Type = Value.self,
        default defaultValue: @autoclosure () -> Value,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        envListStrategy: EnvCollectionStrategy? = nil,
        resolveSecrets: Bool = false,
        transform: ((Value) throws -> Value)? = nil,
        validators: [SettingValidator<Value>] = []
    ) -> SettingMetadata<Value>? where Value.RawValue: SettingValueDecodable {
        let boxedTransform: ((_RawRepresentableBox<Value>) throws -> _RawRepresentableBox<Value>)? = transform.map { fn in
            { box in _RawRepresentableBox(value: try fn(box.value)) }
        }
        let boxedValidators = validators.map { validator in
            SettingValidator<_RawRepresentableBox<Value>> { box, ctx in
                validator.validate(box.value, context: ctx)
            }
        }
        guard let boxed = decodeDefaulted(
            _RawRepresentableBox<Value>.self,
            default: _RawRepresentableBox(value: defaultValue()),
            keyPath: keyPath,
            aliases: aliases,
            envListStrategy: envListStrategy,
            resolveSecrets: resolveSecrets,
            transform: boxedTransform,
            validators: boxedValidators
        ) else {
            return nil
        }
        return SettingMetadata(
            keyPath: boxed.keyPath,
            value: boxed.value.value,
            isSecret: boxed.isSecret,
            origin: boxed.origin,
            overriddenOrigins: boxed.overriddenOrigins
        )
    }

    @_disfavoredOverload
    public mutating func decodeOptional<Wrapped: RawRepresentable & Sendable>(
        _ type: Wrapped.Type = Wrapped.self,
        default defaultValue: Wrapped? = nil,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        envListStrategy: EnvCollectionStrategy? = nil,
        resolveSecrets: Bool = false,
        transform: ((Wrapped) throws -> Wrapped)? = nil,
        validators: [SettingValidator<Wrapped>] = []
    ) -> SettingMetadata<Wrapped?>? where Wrapped.RawValue: SettingValueDecodable {
        let boxedTransform: ((_RawRepresentableBox<Wrapped>) throws -> _RawRepresentableBox<Wrapped>)? = transform.map { fn in
            { box in _RawRepresentableBox(value: try fn(box.value)) }
        }
        let boxedValidators = validators.map { validator in
            SettingValidator<_RawRepresentableBox<Wrapped>> { box, ctx in
                validator.validate(box.value, context: ctx)
            }
        }
        guard let boxed = decodeOptional(
            _RawRepresentableBox<Wrapped>.self,
            default: defaultValue.map(_RawRepresentableBox.init(value:)),
            keyPath: keyPath,
            aliases: aliases,
            envListStrategy: envListStrategy,
            resolveSecrets: resolveSecrets,
            transform: boxedTransform,
            validators: boxedValidators
        ) else {
            return nil
        }
        return SettingMetadata(
            keyPath: boxed.keyPath,
            value: boxed.value?.value,
            isSecret: boxed.isSecret,
            origin: boxed.origin,
            overriddenOrigins: boxed.overriddenOrigins
        )
    }
}

// MARK: - Ergonomic `RiggedSettings.load` Overloads

extension RiggedSettings {
    /// Loads, resolves batched secrets, and validates settings with ergonomic top-level parameters.
    @_disfavoredOverload
    public static func load(
        cliOverrides: [SettingOverride] = [],
        environment: [String: String] = ProcessInfo.processInfo.environment,
        workingDirectory: String = FileManager.default.currentDirectoryPath,
        homeDirectory: String = NSHomeDirectory(),
        fileSystem: any FileSystem = LocalFileSystem(),
        subprocessRunner: any SubprocessRunner = ProcessSubprocessRunner(),
        secretProviders: [any SecretProvider] = [
            FileSecretProvider(),
            IndirectEnvProvider(),
        ],
        redactor: DiagnosticRedactor = DiagnosticRedactor(),
        secretCache: SecretResolutionCache? = nil
    ) async throws -> Self {
        let context = SettingsContext(
            environment: environment,
            workingDirectory: workingDirectory,
            homeDirectory: homeDirectory,
            cliOverrides: cliOverrides,
            fileSystem: fileSystem,
            subprocessRunner: subprocessRunner,
            secretProviders: secretProviders,
            redactor: redactor,
            secretCache: secretCache
        )
        return try await load(context: context, overrides: [])
    }
}

// MARK: - Macro Declarations (`@Settings` & `@Rigged`)

/// Synthesizes multi-source configuration loading, two-phase batched secret resolution,
/// `$field` provenance accessors, and JSON Schema / `.env` documentation exporters.
@attached(member, names: arbitrary)
@attached(extension, conformances: RiggedSettings, RiggedNestedSettings, Sendable)
public macro Settings(
    envPrefix: String = "",
    envNestedDelimiter: String = "__",
    envNestedMaxSplit: Int? = nil,
    caseSensitive: Bool = false,
    envIgnoreEmpty: Bool = true,
    envNullStrings: Set<String> = ["null", "none", "~"],
    dotEnvFiles: [String] = [".env"],
    projectConfigFiles: [String] = [],
    xdgAppName: String? = nil,
    profile: String? = nil,
    secretsDirectory: String? = nil,
    secretsNestedSubdir: Bool = false,
    trimSecretTrailingNewline: Bool = true,
    envListStrategy: EnvCollectionStrategy = .jsonOrCommaSeparated,
    managedPreferencesDomain: String? = nil,
    extraKeys: ExtraKeysPolicy = .ignore
) = #externalMacro(module: "RiggingMacros", type: "SettingsMacro")

/// Overload accepting `extraKeys` prior to `dotEnvFiles` (matching `SettingsConfiguration.init` parameter order).
@attached(member, names: arbitrary)
@attached(extension, conformances: RiggedSettings, RiggedNestedSettings, Sendable)
public macro Settings(
    envPrefix: String = "",
    envNestedDelimiter: String = "__",
    envNestedMaxSplit: Int? = nil,
    caseSensitive: Bool = false,
    envIgnoreEmpty: Bool = true,
    envNullStrings: Set<String> = ["null", "none", "~"],
    extraKeys: ExtraKeysPolicy,
    dotEnvFiles: [String],
    projectConfigFiles: [String] = [],
    xdgAppName: String? = nil,
    profile: String? = nil,
    secretsDirectory: String? = nil,
    secretsNestedSubdir: Bool = false,
    trimSecretTrailingNewline: Bool = true,
    envListStrategy: EnvCollectionStrategy = .jsonOrCommaSeparated,
    managedPreferencesDomain: String? = nil
) = #externalMacro(module: "RiggingMacros", type: "SettingsMacro")

/// SwiftUI-safe alias for `@Settings` (avoids symbol collision with `SwiftUI.Settings`).
@attached(member, names: arbitrary)
@attached(extension, conformances: RiggedSettings, RiggedNestedSettings, Sendable)
public macro Rigged(
    envPrefix: String = "",
    envNestedDelimiter: String = "__",
    envNestedMaxSplit: Int? = nil,
    caseSensitive: Bool = false,
    envIgnoreEmpty: Bool = true,
    envNullStrings: Set<String> = ["null", "none", "~"],
    dotEnvFiles: [String] = [".env"],
    projectConfigFiles: [String] = [],
    xdgAppName: String? = nil,
    profile: String? = nil,
    secretsDirectory: String? = nil,
    secretsNestedSubdir: Bool = false,
    trimSecretTrailingNewline: Bool = true,
    envListStrategy: EnvCollectionStrategy = .jsonOrCommaSeparated,
    managedPreferencesDomain: String? = nil,
    extraKeys: ExtraKeysPolicy = .ignore
) = #externalMacro(module: "RiggingMacros", type: "SettingsMacro")

/// SwiftUI-safe alias overload accepting `extraKeys` prior to `dotEnvFiles`.
@attached(member, names: arbitrary)
@attached(extension, conformances: RiggedSettings, RiggedNestedSettings, Sendable)
public macro Rigged(
    envPrefix: String = "",
    envNestedDelimiter: String = "__",
    envNestedMaxSplit: Int? = nil,
    caseSensitive: Bool = false,
    envIgnoreEmpty: Bool = true,
    envNullStrings: Set<String> = ["null", "none", "~"],
    extraKeys: ExtraKeysPolicy,
    dotEnvFiles: [String],
    projectConfigFiles: [String] = [],
    xdgAppName: String? = nil,
    profile: String? = nil,
    secretsDirectory: String? = nil,
    secretsNestedSubdir: Bool = false,
    trimSecretTrailingNewline: Bool = true,
    envListStrategy: EnvCollectionStrategy = .jsonOrCommaSeparated,
    managedPreferencesDomain: String? = nil
) = #externalMacro(module: "RiggingMacros", type: "SettingsMacro")

// MARK: - `@Setting` Macro Overloads

/// Declares a typed configuration field on a `@Settings` or `@Rigged` struct.
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Overload accepting `deprecated` prior to `help`.
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    deprecated: String,
    help: String,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with a single `String` validator (favored default for untyped `.nonEmpty`, `.url()`, etc.).
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    validate: SettingValidator<String>,
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with a single typed `SettingValidator<T>`.
@attached(peer)
public macro Setting<T: Sendable>(
    aliases: [SettingAlias] = [],
    validate: SettingValidator<T>,
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with multiple `String` validators.
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    validate: [SettingValidator<String>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with multiple typed `SettingValidator<T>` rules.
@attached(peer)
public macro Setting<T: Sendable>(
    aliases: [SettingAlias] = [],
    validate: [SettingValidator<T>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with `String` value transforms.
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    transforms: [SettingTransform<String>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with typed value transforms.
@attached(peer)
public macro Setting<T: Sendable>(
    aliases: [SettingAlias] = [],
    transforms: [SettingTransform<T>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with a single `String` value transform.
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    transforms: SettingTransform<String>,
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with a single typed value transform.
@attached(peer)
public macro Setting<T: Sendable>(
    aliases: [SettingAlias] = [],
    transforms: SettingTransform<T>,
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with `validate` and `transforms` (`String` specialization).
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    validate: SettingValidator<String>,
    transforms: [SettingTransform<String>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with `validate` and `transforms` (generic `<T>`).
@attached(peer)
public macro Setting<T: Sendable>(
    aliases: [SettingAlias] = [],
    validate: SettingValidator<T>,
    transforms: [SettingTransform<T>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with array `validate` and `transforms` (`String` specialization).
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    validate: [SettingValidator<String>],
    transforms: [SettingTransform<String>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with array `validate` and `transforms` (generic `<T>`).
@attached(peer)
public macro Setting<T: Sendable>(
    aliases: [SettingAlias] = [],
    validate: [SettingValidator<T>],
    transforms: [SettingTransform<T>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with `transforms` preceding `validate` (`String` specialization).
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    transforms: [SettingTransform<String>],
    validate: SettingValidator<String>,
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with `transforms` preceding `validate` (generic `<T>`).
@attached(peer)
public macro Setting<T: Sendable>(
    aliases: [SettingAlias] = [],
    transforms: [SettingTransform<T>],
    validate: SettingValidator<T>,
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with `transforms` preceding array `validate` (`String` specialization).
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    transforms: [SettingTransform<String>],
    validate: [SettingValidator<String>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `@Setting` with `transforms` preceding array `validate` (generic `<T>`).
@attached(peer)
public macro Setting<T: Sendable>(
    aliases: [SettingAlias] = [],
    transforms: [SettingTransform<T>],
    validate: [SettingValidator<T>],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

// MARK: - `@SecretSetting` Macro Overloads

/// Declares a leak-proof `Secret<T>` configuration field participating in two-phase batched secret resolution.
@attached(peer)
public macro SecretSetting(
    aliases: [SettingAlias] = [],
    transforms: [SecretTransform] = [],
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

/// Declares a `@SecretSetting` with a single `String` validator.
@attached(peer)
public macro SecretSetting(
    aliases: [SettingAlias] = [],
    transforms: [SecretTransform] = [],
    validate: SettingValidator<String>,
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

/// Declares a `@SecretSetting` with a single typed `SettingValidator<T>`.
@attached(peer)
public macro SecretSetting<T: Sendable>(
    aliases: [SettingAlias] = [],
    transforms: [SecretTransform] = [],
    validate: SettingValidator<T>,
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

/// Declares a `@SecretSetting` with multiple `String` validators.
@attached(peer)
public macro SecretSetting(
    aliases: [SettingAlias] = [],
    transforms: [SecretTransform] = [],
    validate: [SettingValidator<String>],
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

/// Declares a `@SecretSetting` with multiple typed `SettingValidator<T>` rules.
@attached(peer)
public macro SecretSetting<T: Sendable>(
    aliases: [SettingAlias] = [],
    transforms: [SecretTransform] = [],
    validate: [SettingValidator<T>],
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

// MARK: - `@NestedSettings` Macro

/// Embeds a nested `@Settings` / `RiggedNestedSettings` struct into a parent settings model.
@attached(peer)
public macro NestedSettings() = #externalMacro(module: "RiggingMacros", type: "NestedSettingsMacro")

// MARK: - Synthesized Backing Storage & Support Helpers

/// Internal backing storage synthesized into `@Settings` and `@Rigged` structs.
///
/// `Equatable` and `Hashable` intentionally ignore transient provenance/redactor state so that
/// user-declared `Equatable` / `Hashable` conformances on `@Settings` structs compare field values cleanly.
public struct _RiggingStorage: Sendable, Equatable, Hashable, Codable {
    public struct FieldRecord: Sendable, Equatable, Hashable, Codable {
        public let keyPath: [String]
        public let origin: SettingOrigin
        public let overriddenOrigins: [SettingOrigin]

        public init(
            keyPath: [String],
            origin: SettingOrigin,
            overriddenOrigins: [SettingOrigin] = []
        ) {
            self.keyPath = keyPath
            self.origin = origin
            self.overriddenOrigins = overriddenOrigins
        }
    }

    public var fields: [String: FieldRecord]
    public var provenanceReport: ProvenanceReport?
    public var redactor: DiagnosticRedactor

    public init(
        fields: [String: FieldRecord] = [:],
        provenanceReport: ProvenanceReport? = nil,
        redactor: DiagnosticRedactor = DiagnosticRedactor()
    ) {
        self.fields = fields
        self.provenanceReport = provenanceReport
        self.redactor = redactor
    }

    public mutating func recordField<Value: Sendable>(
        _ name: String,
        metadata: SettingMetadata<Value>
    ) {
        fields[name] = FieldRecord(
            keyPath: metadata.keyPath,
            origin: metadata.origin,
            overriddenOrigins: metadata.overriddenOrigins
        )
    }

    public func metadata<Value: Sendable>(
        for name: String,
        defaultKeyPath: [String],
        value: Value,
        isSecret: Bool
    ) -> SettingMetadata<Value> {
        if let record = fields[name] {
            return SettingMetadata<Value>(
                keyPath: record.keyPath,
                value: value,
                isSecret: isSecret,
                origin: record.origin,
                overriddenOrigins: record.overriddenOrigins
            )
        }
        return SettingMetadata<Value>(
            keyPath: defaultKeyPath,
            value: value,
            isSecret: isSecret,
            origin: .defaultValue,
            overriddenOrigins: []
        )
    }

    public static func == (lhs: _RiggingStorage, rhs: _RiggingStorage) -> Bool {
        true
    }

    public func hash(into hasher: inout Hasher) {}

    public init(from decoder: any Decoder) throws {
        self.init()
    }

    public func encode(to encoder: any Encoder) throws {}
}

/// Compile-time and runtime helpers called by macro-synthesized `@Settings` members.
public enum _RiggingMacroSupport {
    @_disfavoredOverload
    public static func schemaType<T>(
        for _: T.Type,
        fallback: JSONSchemaFieldType
    ) -> JSONSchemaFieldType {
        fallback
    }

    public static func schemaType<T: CaseIterable & RawRepresentable>(
        for _: T.Type,
        fallback: JSONSchemaFieldType
    ) -> JSONSchemaFieldType where T.RawValue == String {
        .enumValues(T.allCases.map(\.rawValue))
    }

    public static func validators<T: Sendable>(
        as _: T.Type,
        _ single: SettingValidator<T>
    ) -> [SettingValidator<T>] {
        [single]
    }

    public static func validators<T: Sendable>(
        as _: T.Type,
        _ list: [SettingValidator<T>]
    ) -> [SettingValidator<T>] {
        list
    }

    public static func transforms<T: Sendable>(
        as _: T.Type,
        context: SettingsContext,
        _ single: SettingTransform<T>
    ) -> (@Sendable (T) throws -> T)? {
        { value in
            try single.apply(value, context: context)
        }
    }

    public static func transforms<T: Sendable>(
        as _: T.Type,
        context: SettingsContext,
        _ list: [SettingTransform<T>]
    ) -> (@Sendable (T) throws -> T)? {
        guard !list.isEmpty else { return nil }
        return { initial in
            var current = initial
            for step in list {
                current = try step.apply(current, context: context)
            }
            return current
        }
    }

    public static func rebaseAliases(
        _ aliases: [SettingAlias],
        prefix: [String]
    ) -> [SettingAlias] {
        guard !prefix.isEmpty else { return aliases }
        var rebased: [SettingAlias] = []
        rebased.reserveCapacity(aliases.count)
        for alias in aliases {
            switch alias {
            case .configPath(let altPath):
                if altPath.starts(with: prefix) {
                    rebased.append(alias)
                } else {
                    rebased.append(.configPath(prefix + altPath))
                    rebased.append(alias)
                }
            case .env, .cli:
                rebased.append(alias)
            }
        }
        return rebased
    }

    public static func rebaseIssues(
        _ issues: [ValidationIssue],
        prefix: [String]
    ) -> [ValidationIssue] {
        guard !prefix.isEmpty, !issues.isEmpty else { return issues }
        return issues.map { issue in
            let path = issue.keyPath.starts(with: prefix) ? issue.keyPath : (prefix + issue.keyPath)
            return ValidationIssue(
                keyPath: path,
                kind: issue.kind,
                message: issue.message,
                origin: issue.origin,
                expectedType: issue.expectedType,
                envVariableHint: issue.envVariableHint,
                remediation: issue.remediation
            )
        }
    }

    public static func shouldEnqueueOptionalNested(
        in loader: SettingsLoader,
        at keyPath: [String]
    ) -> Bool {
        guard let node = loader.mergedTree.lookup(
            path: keyPath,
            caseSensitive: loader.configuration.caseSensitive
        ) else {
            return false
        }
        return !ValueDecodingContext(configuration: loader.configuration).representsNull(node.value)
    }

    public static func decodeOptionalNestedWithDefault<Nested: RiggedNestedSettings>(
        _ type: Nested.Type = Nested.self,
        from loader: inout SettingsLoader,
        keyPath: [String],
        default defaultValue: @autoclosure () -> Nested?
    ) -> Nested?? {
        if loader.mergedTree.lookup(
            path: keyPath,
            caseSensitive: loader.configuration.caseSensitive
        ) == nil {
            return .some(defaultValue())
        }
        return loader.decodeOptionalNested(Nested.self, keyPath: keyPath)
    }

    public static func registerDirectSecret<Value: Sendable>(
        _ secret: Secret<Value>,
        into redactor: DiagnosticRedactor
    ) {
        let exposed = secret.expose()
        if let str = exposed as? String {
            redactor.register(str)
        } else if let data = exposed as? Data {
            redactor.register(data)
        } else if let bytes = exposed as? [UInt8] {
            redactor.register(bytes)
        }
    }

    public static func registerDirectSecret<Value: Sendable>(
        _ secret: Secret<Value>?,
        into redactor: DiagnosticRedactor
    ) {
        guard let secret else { return }
        registerDirectSecret(secret, into: redactor)
    }

    public static func fallbackProvenanceEntry<Wrapped: Sendable>(
        metadata: SettingMetadata<Wrapped?>,
        prefix: [String],
        typeName: String
    ) -> ProvenanceEntry {
        let fullPath = metadata.keyPath.starts(with: prefix) ? metadata.keyPath : (prefix + metadata.keyPath)
        let display: String
        if metadata.isSecret {
            display = Secret<String>.redactedPlaceholder
        } else if let unwrapped = metadata.value {
            display = String(describing: unwrapped)
        } else {
            display = "nil"
        }
        return ProvenanceEntry(
            keyPath: fullPath,
            typeName: typeName,
            isSecret: metadata.isSecret,
            displayValue: display,
            origin: metadata.origin,
            overriddenOrigins: metadata.overriddenOrigins
        )
    }

    @_disfavoredOverload
    public static func fallbackProvenanceEntry<Value: Sendable>(
        metadata: SettingMetadata<Value>,
        prefix: [String],
        typeName: String
    ) -> ProvenanceEntry {
        let fullPath = metadata.keyPath.starts(with: prefix) ? metadata.keyPath : (prefix + metadata.keyPath)
        let display = metadata.isSecret
            ? Secret<String>.redactedPlaceholder
            : String(describing: metadata.value)
        return ProvenanceEntry(
            keyPath: fullPath,
            typeName: typeName,
            isSecret: metadata.isSecret,
            displayValue: display,
            origin: metadata.origin,
            overriddenOrigins: metadata.overriddenOrigins
        )
    }

    public static func nestedFallbackEntries<Nested: RiggedSettings>(
        from nested: Nested,
        prefix: [String]
    ) -> [ProvenanceEntry] {
        nested.provenance.entries.map { entry in
            let fullPath = entry.keyPath.starts(with: prefix) ? entry.keyPath : (prefix + entry.keyPath)
            return ProvenanceEntry(
                keyPath: fullPath,
                typeName: entry.typeName,
                isSecret: entry.isSecret,
                displayValue: entry.displayValue,
                origin: entry.origin,
                overriddenOrigins: entry.overriddenOrigins
            )
        }
    }

    @_disfavoredOverload
    public static func nestedFallbackEntries<Nested>(
        from _: Nested,
        prefix _: [String]
    ) -> [ProvenanceEntry] {
        []
    }

    // MARK: - Default Display Formatting

    public static func defaultDisplay(as _: String.Type, _ value: String?) -> String? {
        value
    }

    public static func defaultDisplay(as _: Bool.Type, _ value: Bool?) -> String? {
        guard let value else { return nil }
        return value ? "true" : "false"
    }

    public static func defaultDisplay<I: BinaryInteger>(as _: I.Type, _ value: I?) -> String? {
        guard let value else { return nil }
        return String(value)
    }

    public static func defaultDisplay(as _: Double.Type, _ value: Double?) -> String? {
        guard let value else { return nil }
        return String(value)
    }

    public static func defaultDisplay(as _: Float.Type, _ value: Float?) -> String? {
        guard let value else { return nil }
        return String(value)
    }

    public static func defaultDisplay(as _: Decimal.Type, _ value: Decimal?) -> String? {
        guard let value else { return nil }
        return NSDecimalNumber(decimal: value).stringValue
    }

    public static func defaultDisplay(as _: UUID.Type, _ value: UUID?) -> String? {
        value?.uuidString
    }

    public static func defaultDisplay(as _: URL.Type, _ value: URL?) -> String? {
        value?.absoluteString
    }

    public static func defaultDisplay(as _: ByteCount.Type, _ value: ByteCount?) -> String? {
        guard let value else { return nil }
        return String(value.bytes)
    }

    public static func defaultDisplay(as _: Duration.Type, _ value: Duration?) -> String? {
        guard let value else { return nil }
        let (seconds, attoseconds) = value.components
        if attoseconds == 0 {
            return "\(seconds)s"
        }
        let ms = (Double(seconds) * 1_000.0) + (Double(attoseconds) / 1e15)
        if ms.rounded() == ms {
            return "\(Int64(ms))ms"
        }
        let totalSec = Double(seconds) + (Double(attoseconds) / 1e18)
        return "\(totalSec)s"
    }

    public static func defaultDisplay<E: RawRepresentable>(as _: E.Type, _ value: E?) -> String? {
        guard let value else { return nil }
        return String(describing: value.rawValue)
    }

    public static func defaultDisplay<Element>(as _: [Element].Type, _ value: [Element]?) -> String? {
        guard let value else { return nil }
        if value.isEmpty { return "[]" }
        return value.map { String(describing: $0) }.joined(separator: ",")
    }

    public static func defaultDisplay<K, V>(as _: [K: V].Type, _ value: [K: V]?) -> String? {
        guard let value else { return nil }
        if value.isEmpty { return "{}" }
        return String(describing: value)
    }

    @_disfavoredOverload
    public static func defaultDisplay<T>(as _: T.Type, _ value: T?) -> String? {
        guard let value else { return nil }
        return String(describing: value)
    }
}
