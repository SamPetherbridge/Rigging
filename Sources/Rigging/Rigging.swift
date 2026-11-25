@_exported import Foundation
@_exported import RiggingCore

// MARK: - Field Value Transforms (`@Setting(transforms:)`)

/// A composable, thread-safe value transformation applied to decoded `@Setting` values prior to validation.
///
/// Use `SettingTransform` on `@Setting(transforms:)` to normalize raw inputs—such as trimming
/// surrounding whitespace, normalizing casing, or expanding `~` home directory prefixes—before
/// field-level `SettingValidator` rules execute.
///
/// ```swift
/// @Settings(envPrefix: "APP_")
/// public struct ServerSettings {
///     @Setting(transforms: [.trimWhitespace, .lowercased])
///     public var environment: String = "production"
///
///     @Setting(transforms: .expandTilde)
///     public var cacheDirectory: String = "~/.cache/my-service"
/// }
/// ```
public struct SettingTransform<Value: Sendable>: Sendable {
    private let evaluator: @Sendable (Value, SettingsContext) throws -> Value

    /// Creates a context-aware value transform from a `@Sendable` closure.
    ///
    /// - Parameter evaluator: Closure receiving the decoded value and active `SettingsContext`, returning the transformed value.
    public init(_ evaluator: @escaping @Sendable (Value, SettingsContext) throws -> Value) {
        self.evaluator = evaluator
    }

    /// Creates a context-independent value transform from a `@Sendable` closure.
    ///
    /// - Parameter evaluator: Closure receiving the decoded value and returning the transformed value.
    public init(_ evaluator: @escaping @Sendable (Value) throws -> Value) {
        self.evaluator = { value, _ in
            try evaluator(value)
        }
    }

    /// Evaluates the transform against `value` within `context`.
    ///
    /// - Parameters:
    ///   - value: The decoded setting value to transform.
    ///   - context: Active `SettingsContext` supplying home and working directories.
    /// - Returns: The transformed setting value.
    /// - Throws: Any error raised by the underlying transformation closure.
    public func apply(_ value: Value, context: SettingsContext = SettingsContext()) throws -> Value {
        try evaluator(value, context)
    }

    /// Creates a custom context-independent `SettingTransform`.
    ///
    /// - Parameter transform: Closure transforming `Value` before validation.
    /// - Returns: A `SettingTransform` wrapping `transform`.
    public static func custom(
        _ transform: @escaping @Sendable (Value) throws -> Value
    ) -> SettingTransform<Value> {
        SettingTransform(transform)
    }

    /// Creates a custom context-aware `SettingTransform`.
    ///
    /// - Parameter transform: Closure transforming `Value` with access to `SettingsContext`.
    /// - Returns: A `SettingTransform` wrapping `transform`.
    public static func custom(
        _ transform: @escaping @Sendable (Value, SettingsContext) throws -> Value
    ) -> SettingTransform<Value> {
        SettingTransform(transform)
    }
}

extension SettingTransform where Value == String {
    /// Trims leading and trailing whitespace and newline characters from the string.
    public static var trimWhitespace: SettingTransform<String> {
        SettingTransform { value, _ in
            value.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    /// Converts all characters in the string to lowercase.
    public static var lowercased: SettingTransform<String> {
        SettingTransform { value, _ in
            value.lowercased()
        }
    }

    /// Converts all characters in the string to uppercase.
    public static var uppercased: SettingTransform<String> {
        SettingTransform { value, _ in
            value.uppercased()
        }
    }

    /// Expands a leading `~` or `~/` prefix against `context.homeDirectory`.
    public static var expandTilde: SettingTransform<String> {
        SettingTransform { value, context in
            FileSecretProvider.expandHome(value, homeDirectory: context.homeDirectory)
        }
    }
}

extension SettingTransform where Value == URL {
    /// Expands a leading `~` or `~/` prefix on file or path URLs against `context.homeDirectory`.
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
    /// Invokes a scoped closure with the unwrapped plaintext secret value and returns its result.
    ///
    /// Prefer scoped access over storing unwrapped plaintext in long-lived variables:
    /// ```swift
    /// let authHeader = settings.apiToken.expose { token in
    ///     "Bearer \(token)"
    /// }
    /// ```
    ///
    /// - Parameter body: A closure that receives the unwrapped secret `Value`.
    /// - Returns: The value returned by `body`.
    /// - Throws: Rethrows any error thrown by `body`.
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
    /// Decodes a required `String`-backed `CaseIterable` enum setting without requiring explicit `SettingValueDecodable` conformance.
    ///
    /// - Parameters:
    ///   - type: The target `RawRepresentable & CaseIterable` enum type.
    ///   - keyPath: Canonical setting key path segments.
    ///   - aliases: Optional alternate environment, CLI, or file key path aliases.
    ///   - envListStrategy: Optional collection decoding strategy override.
    ///   - resolveSecrets: Whether secret reference URIs (`op://`, `keychain://`, etc.) are resolved on this field.
    ///   - transform: Optional post-decode transformation closure.
    ///   - validators: Field-level validators evaluated against the decoded enum case.
    /// - Returns: Resolved `SettingMetadata<Value>`, or `nil` if missing or invalid (recording an issue on the loader).
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

    /// Decodes a defaulted `String`-backed `CaseIterable` enum setting without requiring explicit `SettingValueDecodable` conformance.
    ///
    /// - Parameters:
    ///   - type: The target `RawRepresentable & CaseIterable` enum type.
    ///   - defaultValue: Fallback enum value evaluated when no configuration source supplies the key.
    ///   - keyPath: Canonical setting key path segments.
    ///   - aliases: Optional alternate environment, CLI, or file key path aliases.
    ///   - envListStrategy: Optional collection decoding strategy override.
    ///   - resolveSecrets: Whether secret reference URIs (`op://`, `keychain://`, etc.) are resolved on this field.
    ///   - transform: Optional post-decode transformation closure.
    ///   - validators: Field-level validators evaluated against the decoded or default enum case.
    /// - Returns: Resolved `SettingMetadata<Value>`, or `nil` if decoding or validation failed.
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

    /// Decodes an optional `String`-backed `CaseIterable` enum setting without requiring explicit `SettingValueDecodable` conformance.
    ///
    /// - Parameters:
    ///   - type: The wrapped `RawRepresentable & CaseIterable` enum type.
    ///   - defaultValue: Optional fallback value used when the key is absent. Defaults to `nil`.
    ///   - keyPath: Canonical setting key path segments.
    ///   - aliases: Optional alternate environment, CLI, or file key path aliases.
    ///   - envListStrategy: Optional collection decoding strategy override.
    ///   - resolveSecrets: Whether secret reference URIs (`op://`, `keychain://`, etc.) are resolved on this field.
    ///   - transform: Optional post-decode transformation closure.
    ///   - validators: Field-level validators evaluated when the resolved value is non-`nil`.
    /// - Returns: Resolved `SettingMetadata<Wrapped?>`, or `nil` if decoding or validation failed.
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

    /// Decodes a required `RawRepresentable` setting whose `RawValue` conforms to `SettingValueDecodable`.
    ///
    /// - Parameters:
    ///   - type: The target `RawRepresentable` type.
    ///   - keyPath: Canonical setting key path segments.
    ///   - aliases: Optional alternate environment, CLI, or file key path aliases.
    ///   - envListStrategy: Optional collection decoding strategy override.
    ///   - resolveSecrets: Whether secret reference URIs (`op://`, `keychain://`, etc.) are resolved on this field.
    ///   - transform: Optional post-decode transformation closure.
    ///   - validators: Field-level validators evaluated against the decoded value.
    /// - Returns: Resolved `SettingMetadata<Value>`, or `nil` if missing or invalid.
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

    /// Decodes a defaulted `RawRepresentable` setting whose `RawValue` conforms to `SettingValueDecodable`.
    ///
    /// - Parameters:
    ///   - type: The target `RawRepresentable` type.
    ///   - defaultValue: Fallback value evaluated when no configuration source supplies the key.
    ///   - keyPath: Canonical setting key path segments.
    ///   - aliases: Optional alternate environment, CLI, or file key path aliases.
    ///   - envListStrategy: Optional collection decoding strategy override.
    ///   - resolveSecrets: Whether secret reference URIs (`op://`, `keychain://`, etc.) are resolved on this field.
    ///   - transform: Optional post-decode transformation closure.
    ///   - validators: Field-level validators evaluated against the decoded or default value.
    /// - Returns: Resolved `SettingMetadata<Value>`, or `nil` if decoding or validation failed.
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

    /// Decodes an optional `RawRepresentable` setting whose `RawValue` conforms to `SettingValueDecodable`.
    ///
    /// - Parameters:
    ///   - type: The wrapped `RawRepresentable` type.
    ///   - defaultValue: Optional fallback value used when the key is absent. Defaults to `nil`.
    ///   - keyPath: Canonical setting key path segments.
    ///   - aliases: Optional alternate environment, CLI, or file key path aliases.
    ///   - envListStrategy: Optional collection decoding strategy override.
    ///   - resolveSecrets: Whether secret reference URIs (`op://`, `keychain://`, etc.) are resolved on this field.
    ///   - transform: Optional post-decode transformation closure.
    ///   - validators: Field-level validators evaluated when the resolved value is non-`nil`.
    /// - Returns: Resolved `SettingMetadata<Wrapped?>`, or `nil` if decoding or validation failed.
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
    /// Loads, resolves batched secrets, and validates settings using ergonomic top-level parameters.
    ///
    /// Use this convenience overload to pass `secretProviders`, `cliOverrides`, or a custom
    /// `environment` directly without manually constructing a `SettingsContext`:
    ///
    /// ```swift
    /// let settings = try await AppSettings.load(
    ///     secretProviders: [
    ///         .file(),
    ///         .env(),
    ///         .onePassword(),
    ///         .keychain(),
    ///     ]
    /// )
    /// ```
    ///
    /// > Note: Passing `secretProviders` replaces ``RiggedSettings/defaultSecretProviders`` for this call.
    /// > Include `.file()` and `.env()` (or `AppSettings.defaultSecretProviders + [...]`) if you also resolve
    /// > `file://` or `env://` references.
    ///
    /// - Parameters:
    ///   - cliOverrides: Explicit command-line or programmatic overrides evaluated at highest priority.
    ///   - environment: Process environment dictionary. Defaults to `ProcessInfo.processInfo.environment`.
    ///   - workingDirectory: Starting directory for `.env` and upward repo-config discovery.
    ///   - homeDirectory: User home directory for `~` expansion and `~/.config/<app>/` lookup.
    ///   - fileSystem: Filesystem implementation used to inspect and read configuration files.
    ///   - subprocessRunner: Subprocess runner used by CLI-backed secret providers.
    ///   - secretProviders: Registered `SecretProvider` backends for resolving secret URIs. Defaults to `Self.defaultSecretProviders`.
    ///   - redactor: Thread-safe `DiagnosticRedactor` scrubbing secret plaintext from diagnostics.
    ///   - secretCache: Optional actor-isolated `SecretResolutionCache` for long-running processes.
    /// - Returns: A fully resolved and validated instance of `Self`.
    /// - Throws: `SettingsValidationError` when one or more required, type, secret, or cross-field checks fail.
    @_disfavoredOverload
    public static func load(
        cliOverrides: [SettingOverride] = [],
        environment: [String: String] = ProcessInfo.processInfo.environment,
        workingDirectory: String = FileManager.default.currentDirectoryPath,
        homeDirectory: String = SettingsContext.defaultHomeDirectory,
        fileSystem: any FileSystem = LocalFileSystem(),
        subprocessRunner: any SubprocessRunner = ProcessSubprocessRunner(),
        secretProviders: [any SecretProvider] = Self.defaultSecretProviders,
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
/// `$field` provenance accessors, and JSON Schema / `.env` documentation exporters on a struct.
///
/// Apply `@Settings` to a `public`, `package`, or `internal` struct and annotate its stored
/// properties with ``Setting(aliases:envListStrategy:resolveSecrets:help:deprecated:examples:)``,
/// ``SecretSetting(aliases:transforms:allowLiteralInProjectConfig:help:deprecated:examples:)``,
/// or ``NestedSettings()``. In SwiftUI targets where `SwiftUI.Settings` is imported, use the
/// identical ``Rigged(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)``
/// alias instead.
///
/// ```swift
/// @Settings(
///     envPrefix: "APP_",
///     dotEnvFiles: [".env", ".env.local"],
///     projectConfigFiles: [".app.json"],
///     xdgAppName: "my-app",
///     extraKeys: .forbid
/// )
/// public struct AppSettings: Sendable, Equatable {
///     /// TCP port to listen on.
///     @Setting(validate: .range(1...65535))
///     public var port: Int = 8080
///
///     /// Primary database connection password (`op://`, `keychain://`, or `.env`).
///     @SecretSetting
///     public var databasePassword: Secret<String>
/// }
/// ```
///
/// - Parameters:
///   - envPrefix: Prefix prepended to `SCREAMING_SNAKE_CASE` environment variable names (for example `"APP_"`).
///   - envNestedDelimiter: Delimiter separating nested struct or dictionary key segments in environment variables. Defaults to `"__"`.
///   - envNestedMaxSplit: Optional maximum number of delimiter splits performed on nested environment keys.
///   - caseSensitive: Whether environment and configuration file key matching is case-sensitive. Defaults to `false`.
///   - envIgnoreEmpty: When `true`, empty string environment variables (`FOO=""`) are ignored so lower-priority sources or defaults apply.
///   - envNullStrings: Case-insensitive string tokens interpreted as `nil` for optional settings. Defaults to `["null", "none", "~"]`.
///   - dotEnvFiles: Ordered list of `.env` files loaded relative to `workingDirectory` (later entries override earlier ones).
///   - projectConfigFiles: Repository configuration filenames discovered upward to the nearest `.git` root (for example `[".asc.json"]`).
///   - xdgAppName: Application directory name under `$XDG_CONFIG_HOME/<app>/` or `~/.config/<app>/`.
///   - profile: Active named profile overlay (`profiles.<name>`) merged over base configuration files.
///   - secretsDirectory: Optional directory of file-per-secret mounts (such as `/run/secrets`).
///   - secretsNestedSubdir: Whether subdirectories inside `secretsDirectory` map to nested setting groups.
///   - trimSecretTrailingNewline: Whether trailing `\n` / `\r\n` bytes are stripped from `secretsDirectory` files.
///   - envListStrategy: Default decoding strategy for array and set fields read from environment strings.
///   - managedPreferencesDomain: Optional macOS Managed Preferences / MDM bundle domain (`CFPreferencesCopyAppValue`).
///   - extraKeys: Policy governing unknown keys encountered in configuration files (`.ignore`, `.allow`, `.warn`, or `.forbid`).
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

/// Synthesizes multi-source configuration loading on a struct when `extraKeys` is specified prior to `dotEnvFiles`.
///
/// - Parameters:
///   - envPrefix: Prefix prepended to `SCREAMING_SNAKE_CASE` environment variable names.
///   - envNestedDelimiter: Delimiter separating nested struct or dictionary key segments in environment variables.
///   - envNestedMaxSplit: Optional maximum number of delimiter splits performed on nested environment keys.
///   - caseSensitive: Whether environment and configuration file key matching is case-sensitive.
///   - envIgnoreEmpty: When `true`, empty string environment variables are ignored.
///   - envNullStrings: Case-insensitive string tokens interpreted as `nil` for optional settings.
///   - extraKeys: Policy governing unknown keys encountered in configuration files.
///   - dotEnvFiles: Ordered list of `.env` files loaded relative to `workingDirectory`.
///   - projectConfigFiles: Repository configuration filenames discovered upward to `.git`.
///   - xdgAppName: Application directory name under `$XDG_CONFIG_HOME` or `~/.config`.
///   - profile: Active named profile overlay (`profiles.<name>`).
///   - secretsDirectory: Optional directory of file-per-secret mounts.
///   - secretsNestedSubdir: Whether subdirectories inside `secretsDirectory` map to nested setting groups.
///   - trimSecretTrailingNewline: Whether trailing newlines are stripped from `secretsDirectory` files.
///   - envListStrategy: Default decoding strategy for collection fields read from environment strings.
///   - managedPreferencesDomain: Optional macOS Managed Preferences / MDM bundle domain.
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

/// SwiftUI-safe alias for ``Settings(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)``
/// that avoids symbol ambiguity with `SwiftUI.Settings`.
///
/// `@Rigged` expands to the exact same `RiggedSettings`, `RiggedNestedSettings`, and `Sendable`
/// implementation as `@Settings`, making it ideal for macOS and iOS app targets that import `SwiftUI`.
///
/// ```swift
/// import Rigging
/// import SwiftUI
///
/// @Rigged(envPrefix: "MYAPP_", managedPreferencesDomain: "com.example.myapp")
/// public struct AppConfiguration: Equatable {
///     @Setting public var telemetryEnabled: Bool = false
///     @SecretSetting public var crashReporterToken: Secret<String>?
/// }
/// ```
///
/// - Parameters:
///   - envPrefix: Prefix prepended to `SCREAMING_SNAKE_CASE` environment variable names.
///   - envNestedDelimiter: Delimiter separating nested struct or dictionary key segments in environment variables.
///   - envNestedMaxSplit: Optional maximum number of delimiter splits performed on nested environment keys.
///   - caseSensitive: Whether environment and configuration file key matching is case-sensitive.
///   - envIgnoreEmpty: When `true`, empty string environment variables are ignored.
///   - envNullStrings: Case-insensitive string tokens interpreted as `nil` for optional settings.
///   - dotEnvFiles: Ordered list of `.env` files loaded relative to `workingDirectory`.
///   - projectConfigFiles: Repository configuration filenames discovered upward to `.git`.
///   - xdgAppName: Application directory name under `$XDG_CONFIG_HOME` or `~/.config`.
///   - profile: Active named profile overlay (`profiles.<name>`).
///   - secretsDirectory: Optional directory of file-per-secret mounts.
///   - secretsNestedSubdir: Whether subdirectories inside `secretsDirectory` map to nested setting groups.
///   - trimSecretTrailingNewline: Whether trailing newlines are stripped from `secretsDirectory` files.
///   - envListStrategy: Default decoding strategy for collection fields read from environment strings.
///   - managedPreferencesDomain: Optional macOS Managed Preferences / MDM bundle domain.
///   - extraKeys: Policy governing unknown keys encountered in configuration files.
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
///
/// - Parameters:
///   - envPrefix: Prefix prepended to `SCREAMING_SNAKE_CASE` environment variable names.
///   - envNestedDelimiter: Delimiter separating nested struct or dictionary key segments in environment variables.
///   - envNestedMaxSplit: Optional maximum number of delimiter splits performed on nested environment keys.
///   - caseSensitive: Whether environment and configuration file key matching is case-sensitive.
///   - envIgnoreEmpty: When `true`, empty string environment variables are ignored.
///   - envNullStrings: Case-insensitive string tokens interpreted as `nil` for optional settings.
///   - extraKeys: Policy governing unknown keys encountered in configuration files.
///   - dotEnvFiles: Ordered list of `.env` files loaded relative to `workingDirectory`.
///   - projectConfigFiles: Repository configuration filenames discovered upward to `.git`.
///   - xdgAppName: Application directory name under `$XDG_CONFIG_HOME` or `~/.config`.
///   - profile: Active named profile overlay (`profiles.<name>`).
///   - secretsDirectory: Optional directory of file-per-secret mounts.
///   - secretsNestedSubdir: Whether subdirectories inside `secretsDirectory` map to nested setting groups.
///   - trimSecretTrailingNewline: Whether trailing newlines are stripped from `secretsDirectory` files.
///   - envListStrategy: Default decoding strategy for collection fields read from environment strings.
///   - managedPreferencesDomain: Optional macOS Managed Preferences / MDM bundle domain.
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

/// Declares a typed configuration field on a ``Settings(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)``
/// or ``Rigged(envPrefix:envNestedDelimiter:envNestedMaxSplit:caseSensitive:envIgnoreEmpty:envNullStrings:dotEnvFiles:projectConfigFiles:xdgAppName:profile:secretsDirectory:secretsNestedSubdir:trimSecretTrailingNewline:envListStrategy:managedPreferencesDomain:extraKeys:)`` struct.
///
/// `@Setting` synthesizes a `$property` `SettingMetadata` projection exposing the
/// winning `SettingOrigin` (`$field.source`) and shadowed lower-priority origins
/// (`$field.overriddenSources`). Leading `///` doc comments on the property are automatically
/// extracted into JSON Schema `description`, `.env` template comments, and Markdown documentation.
///
/// ```swift
/// @Settings(envPrefix: "APP_")
/// public struct DatabaseSettings {
///     /// Primary PostgreSQL hostname.
///     @Setting(aliases: [.env("PGHOST"), .configPath(["db", "host"])])
///     public var host: String = "localhost"
///
///     /// Allowed CORS origins.
///     @Setting(envListStrategy: .separator(","))
///     public var corsOrigins: [String] = []
/// }
/// ```
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - envListStrategy: Collection decoding strategy override when parsing string environment values.
///   - resolveSecrets: When `true`, secret URI schemes (`op://`, `keychain://`, etc.) in this non-secret field are resolved in Phase 1 batching.
///   - help: Explicit documentation override (defaults to the property's `///` doc comment).
///   - deprecated: Optional deprecation notice surfaced by `config doctor` when the setting is actively configured.
///   - examples: Example values included in generated JSON Schema and starter templates.
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a typed configuration field accepting `deprecated` prior to `help`.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - envListStrategy: Collection decoding strategy override when parsing string environment values.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - deprecated: Deprecation message surfaced when the setting is actively configured.
///   - help: Explicit documentation description for schema and `.env` exports.
///   - examples: Example values included in generated documentation.
@attached(peer)
public macro Setting(
    aliases: [SettingAlias] = [],
    envListStrategy: EnvCollectionStrategy? = nil,
    resolveSecrets: Bool = false,
    deprecated: String,
    help: String,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SettingMacro")

/// Declares a `String` `@Setting` validated by a single `SettingValidator<String>` rule.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Field-level `String` validator (such as `.nonEmpty`, `.regex(...)`, or `.url()`).
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `@Setting` validated by a single typed `SettingValidator<T>` rule.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Field-level typed validator (such as `.range(1...65535)` or `.oneOf(...)`).
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `String` `@Setting` validated by multiple `SettingValidator<String>` rules.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Ordered array of `String` validators evaluated against the decoded value.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `@Setting` validated by multiple typed `SettingValidator<T>` rules.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Ordered array of typed validators evaluated against the decoded value.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `String` `@Setting` normalized by an array of `SettingTransform<String>` steps.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Ordered `String` transforms applied prior to validation.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `@Setting` normalized by an array of typed `SettingTransform<T>` steps.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Ordered typed transforms applied prior to validation.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `String` `@Setting` normalized by a single `SettingTransform<String>`.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Single `String` transform applied prior to validation (for example `.expandTilde`).
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `@Setting` normalized by a single typed `SettingTransform<T>`.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Single typed transform applied prior to validation.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `String` `@Setting` with a single validator followed by value transforms.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Single `String` validator evaluated after `transforms`.
///   - transforms: Ordered `String` transforms applied prior to validation.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `@Setting` with a single typed validator followed by value transforms.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Single typed validator evaluated after `transforms`.
///   - transforms: Ordered typed transforms applied prior to validation.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `String` `@Setting` with multiple validators followed by value transforms.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Array of `String` validators evaluated after `transforms`.
///   - transforms: Ordered `String` transforms applied prior to validation.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `@Setting` with multiple typed validators followed by value transforms.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Array of typed validators evaluated after `transforms`.
///   - transforms: Ordered typed transforms applied prior to validation.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `String` `@Setting` with value transforms preceding a single validator.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Ordered `String` transforms applied prior to validation.
///   - validate: Single `String` validator evaluated against the transformed value.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `@Setting` with typed value transforms preceding a single validator.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Ordered typed transforms applied prior to validation.
///   - validate: Single typed validator evaluated against the transformed value.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `String` `@Setting` with value transforms preceding multiple validators.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Ordered `String` transforms applied prior to validation.
///   - validate: Array of `String` validators evaluated against the transformed value.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a `@Setting` with typed value transforms preceding multiple validators.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Ordered typed transforms applied prior to validation.
///   - validate: Array of typed validators evaluated against the transformed value.
///   - envListStrategy: Collection decoding strategy override.
///   - resolveSecrets: Whether secret URI references are resolved on this field.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example values included in generated documentation.
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

/// Declares a leak-proof `Secret` configuration field (`Secret<T>` or `Secret<T>?`)
/// participating in two-phase batched secret resolution.
///
/// `@SecretSetting` fields accept secret provider URIs (`op://`, `keychain://`, `bws://`, `bw://`,
/// `pass://`, `sops://`, `file://`, `env://`), `@/path/to/key` file references, environment values,
/// or optional defaults. By default (`allowLiteralInProjectConfig: false`), literal plaintext values
/// committed in repository project configuration files fail with exit code `4` (`unsafeSecret`).
///
/// ```swift
/// @Settings(envPrefix: "ASC_", projectConfigFiles: [".asc.json"])
/// public struct SigningCredentials {
///     /// PKCS#8 `.p8` private key (`op://`, `keychain://`, or `@~/.asc/AuthKey.p8`).
///     @SecretSetting(
///         transforms: [
///             .expandFileReference(requirePermissions: 0o600),
///             .decodeBase64IfPrefixed,
///             .normalizePEM,
///         ]
///     )
///     public var privateKey: Secret<String>
///
///     /// Optional PKCS#12 signing certificate bytes.
///     @SecretSetting
///     public var certificate: Secret<Data>?
/// }
/// ```
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Post-resolution `SecretTransform` pipeline applied to resolved bytes.
///   - allowLiteralInProjectConfig: When `false` (default), rejects literal plaintext secrets inside repo-committed `projectConfigFiles`.
///   - help: Explicit documentation override (defaults to the property's `///` doc comment).
///   - deprecated: Optional deprecation message surfaced by `config doctor`.
///   - examples: Example secret reference URIs included in generated templates (never plaintext).
@attached(peer)
public macro SecretSetting(
    aliases: [SettingAlias] = [],
    transforms: [SecretTransform] = [],
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

/// Declares a `@SecretSetting` validated by a single `String` validator.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Post-resolution `SecretTransform` pipeline applied prior to validation.
///   - validate: Single `String` validator evaluated against the resolved secret (failure messages are scrubbed).
///   - allowLiteralInProjectConfig: Whether literal plaintext secrets are allowed in repository project config files.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example secret reference URIs.
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

/// Declares a `@SecretSetting` validated by a single typed `SettingValidator<T>`.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Post-resolution `SecretTransform` pipeline applied prior to validation.
///   - validate: Single typed validator evaluated against the unwrapped `T` secret payload.
///   - allowLiteralInProjectConfig: Whether literal plaintext secrets are allowed in repository project config files.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example secret reference URIs.
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

/// Declares a `@SecretSetting` validated by multiple `String` validators.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Post-resolution `SecretTransform` pipeline applied prior to validation.
///   - validate: Array of `String` validators evaluated against the resolved secret.
///   - allowLiteralInProjectConfig: Whether literal plaintext secrets are allowed in repository project config files.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example secret reference URIs.
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

/// Declares a `@SecretSetting` validated by multiple typed `SettingValidator<T>` rules.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - transforms: Post-resolution `SecretTransform` pipeline applied prior to validation.
///   - validate: Array of typed validators evaluated against the unwrapped `T` secret payload.
///   - allowLiteralInProjectConfig: Whether literal plaintext secrets are allowed in repository project config files.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example secret reference URIs.
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

/// Declares a `@SecretSetting` accepting a single `String` validator prior to `transforms`.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Single `String` validator evaluated against the resolved secret.
///   - transforms: Post-resolution `SecretTransform` pipeline applied prior to validation.
///   - allowLiteralInProjectConfig: Whether literal plaintext secrets are allowed in repository project config files.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example secret reference URIs.
@attached(peer)
public macro SecretSetting(
    aliases: [SettingAlias] = [],
    validate: SettingValidator<String>,
    transforms: [SecretTransform],
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

/// Declares a `@SecretSetting` accepting a single typed `SettingValidator<T>` prior to `transforms`.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Single typed validator evaluated against the unwrapped `T` secret payload.
///   - transforms: Post-resolution `SecretTransform` pipeline applied prior to validation.
///   - allowLiteralInProjectConfig: Whether literal plaintext secrets are allowed in repository project config files.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example secret reference URIs.
@attached(peer)
public macro SecretSetting<T: Sendable>(
    aliases: [SettingAlias] = [],
    validate: SettingValidator<T>,
    transforms: [SecretTransform],
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

/// Declares a `@SecretSetting` accepting multiple `String` validators prior to `transforms`.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Array of `String` validators evaluated against the resolved secret.
///   - transforms: Post-resolution `SecretTransform` pipeline applied prior to validation.
///   - allowLiteralInProjectConfig: Whether literal plaintext secrets are allowed in repository project config files.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example secret reference URIs.
@attached(peer)
public macro SecretSetting(
    aliases: [SettingAlias] = [],
    validate: [SettingValidator<String>],
    transforms: [SecretTransform],
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

/// Declares a `@SecretSetting` accepting multiple typed `SettingValidator<T>` rules prior to `transforms`.
///
/// - Parameters:
///   - aliases: Alternate environment variable, CLI flag, or configuration file key path aliases.
///   - validate: Array of typed validators evaluated against the unwrapped `T` secret payload.
///   - transforms: Post-resolution `SecretTransform` pipeline applied prior to validation.
///   - allowLiteralInProjectConfig: Whether literal plaintext secrets are allowed in repository project config files.
///   - help: Explicit documentation override.
///   - deprecated: Optional deprecation message.
///   - examples: Example secret reference URIs.
@attached(peer)
public macro SecretSetting<T: Sendable>(
    aliases: [SettingAlias] = [],
    validate: [SettingValidator<T>],
    transforms: [SecretTransform],
    allowLiteralInProjectConfig: Bool = false,
    help: String? = nil,
    deprecated: String? = nil,
    examples: [String] = []
) = #externalMacro(module: "RiggingMacros", type: "SecretSettingMacro")

// MARK: - `@NestedSettings` Macro

/// Embeds a nested `@Settings` or `@Rigged` struct inside a parent configuration model.
///
/// Nested groups participate seamlessly in hierarchical file decoding (`{"database": {"port": 5432}}`),
/// delimiter-separated environment variables (`APP_DATABASE__PORT=5432`), Phase 1 batched secret
/// collection across the entire object graph, `$field` provenance reporting, and JSON Schema `object` generation.
/// Both required/defaulted (`var database: DatabaseSettings = .init()`) and optional (`var webhook: WebhookSettings?`)
/// nested models are supported.
///
/// ```swift
/// @Settings
/// public struct TLSSettings: Sendable, Equatable {
///     @Setting public var enabled: Bool = false
///     @SecretSetting public var certificate: Secret<Data>?
/// }
///
/// @Settings(envPrefix: "SERVER_")
/// public struct ServerSettings: Sendable, Equatable {
///     @NestedSettings
///     public var tls: TLSSettings = .init()
/// }
/// ```
@attached(peer)
public macro NestedSettings() = #externalMacro(module: "RiggingMacros", type: "NestedSettingsMacro")

// MARK: - Synthesized Backing Storage & Support Helpers

/// Internal backing storage synthesized into `@Settings` and `@Rigged` structs.
///
/// `Equatable` and `Hashable` intentionally ignore transient provenance/redactor state so that
/// user-declared `Equatable` / `Hashable` conformances on `@Settings` structs compare field values cleanly.
@_documentation(visibility: internal)
public struct _RiggingStorage: Sendable, Equatable, Hashable, Codable {
    /// Recorded provenance state for a single decoded field.
    @_documentation(visibility: internal)
    public struct FieldRecord: Sendable, Equatable, Hashable, Codable {
        /// Canonical hierarchical key path of the field.
        public let keyPath: [String]
        /// Winning configuration source origin.
        public let origin: SettingOrigin
        /// Shadowed lower-priority configuration source origins.
        public let overriddenOrigins: [SettingOrigin]

        /// Creates a per-field provenance record.
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

    /// Map of property names to recorded field provenance.
    public var fields: [String: FieldRecord]
    /// Complete provenance report captured when loaded via `SettingsLoader`.
    public var provenanceReport: ProvenanceReport?
    /// Active diagnostic redactor associated with this settings instance.
    public var redactor: DiagnosticRedactor

    /// Creates backing storage for a synthesized settings model.
    public init(
        fields: [String: FieldRecord] = [:],
        provenanceReport: ProvenanceReport? = nil,
        redactor: DiagnosticRedactor = DiagnosticRedactor()
    ) {
        self.fields = fields
        self.provenanceReport = provenanceReport
        self.redactor = redactor
    }

    /// Records resolved provenance metadata for a property name.
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

    /// Reconstructs typed `SettingMetadata` for a projected `$property` accessor.
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

    /// Returns `true` so synthesized provenance storage never perturbs value equality on `@Settings` structs.
    public static func == (lhs: _RiggingStorage, rhs: _RiggingStorage) -> Bool {
        true
    }

    /// No-op hash implementation keeping synthesized provenance neutral in `Hashable` conformances.
    public func hash(into hasher: inout Hasher) {}

    /// Initializes empty transient provenance storage when decoding via `Codable`.
    public init(from decoder: any Decoder) throws {
        self.init()
    }

    /// Encodes no transient storage fields when serializing via `Codable`.
    public func encode(to encoder: any Encoder) throws {}
}

/// Compile-time and runtime helpers called by macro-synthesized `@Settings` members.
@_documentation(visibility: internal)
public enum _RiggingMacroSupport {
    /// Returns `fallback` JSON Schema type for arbitrary scalar or custom types.
    @_disfavoredOverload
    public static func schemaType<T>(
        for _: T.Type,
        fallback: JSONSchemaFieldType
    ) -> JSONSchemaFieldType {
        fallback
    }

    /// Infers a JSON Schema `enum` list from `String`-backed `CaseIterable` Swift enums.
    public static func schemaType<T: CaseIterable & RawRepresentable>(
        for _: T.Type,
        fallback: JSONSchemaFieldType
    ) -> JSONSchemaFieldType where T.RawValue == String {
        .enumValues(T.allCases.map(\.rawValue))
    }

    /// Normalizes a single `SettingValidator<T>` into a validator array.
    public static func validators<T: Sendable>(
        as _: T.Type,
        _ single: SettingValidator<T>
    ) -> [SettingValidator<T>] {
        [single]
    }

    /// Passes through an array of `SettingValidator<T>` rules with type inference anchored to `T`.
    public static func validators<T: Sendable>(
        as _: T.Type,
        _ list: [SettingValidator<T>]
    ) -> [SettingValidator<T>] {
        list
    }

    /// Binds a single `SettingTransform<T>` to `context` as a throwing transformation closure.
    public static func transforms<T: Sendable>(
        as _: T.Type,
        context: SettingsContext,
        _ single: SettingTransform<T>
    ) -> (@Sendable (T) throws -> T)? {
        { value in
            try single.apply(value, context: context)
        }
    }

    /// Composes an ordered list of `SettingTransform<T>` steps into a single throwing closure.
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

    /// Rebases relative `.configPath` aliases onto a nested key path `prefix`.
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

    /// Prepends `prefix` to validation issue key paths emitted by nested `validate(_:)` hooks.
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

    /// Determines whether an optional `@NestedSettings` group is present in the merged configuration tree.
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

    /// Decodes an optional `@NestedSettings` group that declares a non-`nil` inline default.
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

    /// Registers a directly initialized `Secret<Value>` in the instance's `DiagnosticRedactor`.
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

    /// Registers an optional directly initialized `Secret<Value>?` in the instance's `DiagnosticRedactor`.
    public static func registerDirectSecret<Value: Sendable>(
        _ secret: Secret<Value>?,
        into redactor: DiagnosticRedactor
    ) {
        guard let secret else { return }
        registerDirectSecret(secret, into: redactor)
    }

    /// Builds a fallback `ProvenanceEntry` for an optional field on a memberwise-initialized instance.
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

    /// Builds a fallback `ProvenanceEntry` for a non-optional field on a memberwise-initialized instance.
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

    /// Extracts and rebases fallback provenance entries from a nested `RiggedSettings` value.
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

    /// Fallback returning no provenance entries when a nested value does not conform to `RiggedSettings`.
    @_disfavoredOverload
    public static func nestedFallbackEntries<Nested>(
        from _: Nested,
        prefix _: [String]
    ) -> [ProvenanceEntry] {
        []
    }

    // MARK: - Default Display Formatting

    /// Formats an optional `String` default value for schema and `.env` export.
    public static func defaultDisplay(as _: String.Type, _ value: String?) -> String? {
        value
    }

    /// Formats an optional `Bool` default value for schema and `.env` export.
    public static func defaultDisplay(as _: Bool.Type, _ value: Bool?) -> String? {
        guard let value else { return nil }
        return value ? "true" : "false"
    }

    /// Formats an optional `BinaryInteger` default value for schema and `.env` export.
    public static func defaultDisplay<I: BinaryInteger>(as _: I.Type, _ value: I?) -> String? {
        guard let value else { return nil }
        return String(value)
    }

    /// Formats an optional `Double` default value for schema and `.env` export.
    public static func defaultDisplay(as _: Double.Type, _ value: Double?) -> String? {
        guard let value else { return nil }
        return String(value)
    }

    /// Formats an optional `Float` default value for schema and `.env` export.
    public static func defaultDisplay(as _: Float.Type, _ value: Float?) -> String? {
        guard let value else { return nil }
        return String(value)
    }

    /// Formats an optional `Decimal` default value for schema and `.env` export.
    public static func defaultDisplay(as _: Decimal.Type, _ value: Decimal?) -> String? {
        value?.description
    }

    /// Formats an optional `UUID` default value for schema and `.env` export.
    public static func defaultDisplay(as _: UUID.Type, _ value: UUID?) -> String? {
        value?.uuidString
    }

    /// Formats an optional `URL` default value for schema and `.env` export.
    public static func defaultDisplay(as _: URL.Type, _ value: URL?) -> String? {
        value?.absoluteString
    }

    /// Formats an optional `ByteCount` default value for schema and `.env` export.
    public static func defaultDisplay(as _: ByteCount.Type, _ value: ByteCount?) -> String? {
        guard let value else { return nil }
        return String(value.bytes)
    }

    /// Formats an optional `Duration` default value (`"30s"`, `"250ms"`) for schema and `.env` export.
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

    /// Formats an optional `RawRepresentable` default value using its `rawValue`.
    public static func defaultDisplay<E: RawRepresentable>(as _: E.Type, _ value: E?) -> String? {
        guard let value else { return nil }
        return String(describing: value.rawValue)
    }

    /// Formats an optional array default value for schema and `.env` export.
    public static func defaultDisplay<Element>(as _: [Element].Type, _ value: [Element]?) -> String? {
        guard let value else { return nil }
        if value.isEmpty { return "[]" }
        return value.map { String(describing: $0) }.joined(separator: ",")
    }

    /// Formats an optional dictionary default value for schema and `.env` export.
    public static func defaultDisplay<K, V>(as _: [K: V].Type, _ value: [K: V]?) -> String? {
        guard let value else { return nil }
        if value.isEmpty { return "{}" }
        return String(describing: value)
    }

    /// Fallback formatter converting an arbitrary default value via `String(describing:)`.
    @_disfavoredOverload
    public static func defaultDisplay<T>(as _: T.Type, _ value: T?) -> String? {
        guard let value else { return nil }
        return String(describing: value)
    }
}
