import RiggingMacros
import SwiftSyntax
import SwiftSyntaxMacroExpansion
import SwiftSyntaxMacros
import SwiftSyntaxMacrosGenericTestSupport
import SwiftSyntaxMacrosTestSupport
import Testing

private let riggingTestMacroSpecs: [String: MacroSpec] = [
    "Settings": MacroSpec(type: SettingsMacro.self),
    "Rigged": MacroSpec(type: SettingsMacro.self),
    "Setting": MacroSpec(type: SettingMacro.self),
    "SecretSetting": MacroSpec(type: SecretSettingMacro.self),
    "NestedSettings": MacroSpec(type: NestedSettingsMacro.self),
]

private func expectMacroExpansion(
    _ originalSource: String,
    expandedSource expectedExpandedSource: String,
    diagnostics: [DiagnosticSpec] = [],
    indentationWidth: Trivia = .spaces(4),
    fileID: StaticString = #fileID,
    filePath: StaticString = #filePath,
    line: UInt = #line,
    column: UInt = #column
) {
    SwiftSyntaxMacrosGenericTestSupport.assertMacroExpansion(
        originalSource,
        expandedSource: expectedExpandedSource,
        diagnostics: diagnostics,
        macroSpecs: riggingTestMacroSpecs,
        indentationWidth: indentationWidth,
        failureHandler: { failure in
            Issue.record(
                Comment(rawValue: failure.message),
                sourceLocation: SourceLocation(
                    fileID: failure.location.fileID,
                    filePath: failure.location.filePath,
                    line: failure.location.line,
                    column: failure.location.column
                )
            )
        },
        fileID: fileID,
        filePath: filePath,
        line: line,
        column: column
    )
}

@Suite("Macro Expansion & Diagnostics")
struct MacroExpansionTests {
    @Test("@Settings expands projected accessors, schema metadata, two-phase secret batching, and conformances")
    func settingsExpansion() {
        expectMacroExpansion(
            #"""
            @Settings(envPrefix: "APP_", extraKeys: .forbid)
            public struct ServiceSettings {
                /// Listening TCP port
                @Setting(validate: .range(1...65535))
                public var port: Int = 8080

                /// API Signing Secret
                @SecretSetting(transforms: [.trimWhitespace])
                public var apiSecret: Secret<String>

                @NestedSettings
                public var tls: TLSSettings = .init()
            }
            """#,
            expandedSource: #"""
            public struct ServiceSettings {
                /// Listening TCP port
                public var port: Int = 8080

                /// API Signing Secret
                public var apiSecret: Secret<String>
                public var tls: TLSSettings = .init()

                private var _riggingStorage = _RiggingStorage()

                public var $port: SettingMetadata<Int> {
                    _riggingStorage.metadata(
                        for: "port",
                        defaultKeyPath: ["port"],
                        value: self.port,
                        isSecret: false
                    )
                }

                public var $apiSecret: SettingMetadata<Secret<String>> {
                    _riggingStorage.metadata(
                        for: "apiSecret",
                        defaultKeyPath: ["apiSecret"],
                        value: self.apiSecret,
                        isSecret: true
                    )
                }

                public var provenance: ProvenanceReport {
                    if let report = _riggingStorage.provenanceReport {
                        return report
                    }
                    return ProvenanceReport(entries: Self._riggingFallbackProvenanceEntries(for: self, prefix: []))
                }

                public var redactor: DiagnosticRedactor {
                    _riggingStorage.redactor
                }

                public init(
                    port: Int = 8080,
                    apiSecret: Secret<String>,
                    tls: TLSSettings = .init()
                ) {
                    self.port = port
                    self.apiSecret = apiSecret
                    self.tls = tls
                    let _storage = _RiggingStorage()
                    _RiggingMacroSupport.registerDirectSecret(apiSecret, into: _storage.redactor)
                    self._riggingStorage = _storage
                }

                private init(
                    _riggingStorage: _RiggingStorage,
                    port: Int,
                    apiSecret: Secret<String>,
                    tls: TLSSettings
                ) {
                    self._riggingStorage = _riggingStorage
                    self.port = port
                    self.apiSecret = apiSecret
                    self.tls = tls
                }

                public static var configuration: SettingsConfiguration {
                    SettingsConfiguration(
                        envPrefix: "APP_",
                        extraKeys: .forbid
                    )
                }

                public static var fieldDescriptors: [SettingFieldDescriptor] {
                    fieldDescriptors(prefix: [], configuration: configuration)
                }

                public static func fieldDescriptors(
                    prefix: [String],
                    configuration: SettingsConfiguration
                ) -> [SettingFieldDescriptor] {
                    [
                        SettingFieldDescriptor(
                            name: "port",
                            keyPath: prefix + ["port"],
                            aliases: [],
                            typeName: "Int",
                            schemaType: .integer,
                            isOptional: false,
                            isSecret: false,
                            hasDefault: true,
                            defaultDisplay: _RiggingMacroSupport.defaultDisplay(as: Int.self, 8080),
                            help: "Listening TCP port",
                            deprecated: nil,
                            examples: [],
                            allowsArbitraryChildKeys: false
                        ),
                        SettingFieldDescriptor(
                            name: "apiSecret",
                            keyPath: prefix + ["apiSecret"],
                            aliases: [],
                            typeName: "Secret<String>",
                            schemaType: .string(),
                            isOptional: false,
                            isSecret: true,
                            hasDefault: false,
                            defaultDisplay: nil,
                            help: "API Signing Secret",
                            deprecated: nil,
                            examples: [],
                            allowsArbitraryChildKeys: false
                        ),
                        SettingFieldDescriptor(
                            name: "tls",
                            keyPath: prefix + ["tls"],
                            aliases: [],
                            typeName: "TLSSettings",
                            schemaType: .object(fields: TLSSettings.fieldDescriptors(prefix: prefix + ["tls"], configuration: configuration)),
                            isOptional: false,
                            isSecret: false,
                            hasDefault: true,
                            defaultDisplay: nil,
                            help: nil,
                            deprecated: nil,
                            examples: [],
                            allowsArbitraryChildKeys: false
                        )
                    ]
                }

                public static func enqueueSecrets(
                    into loader: inout SettingsLoader,
                    prefix: [String]
                ) {
                    loader.enqueueSecret(
                        keyPath: prefix + ["apiSecret"],
                        aliases: [],
                        transforms: [.trimWhitespace],
                        allowLiteralInProjectConfig: false,
                        expectedType: "Secret<String>",
                        isOptional: false,
                        hasDefault: false
                    )
                    TLSSettings.enqueueSecrets(into: &loader, prefix: prefix + ["tls"])
                }

                public static func decodeNested(
                    from loader: inout SettingsLoader,
                    prefix: [String]
                ) -> Self? {
                    let _decoded_port = loader.decodeDefaulted(
                        Int.self,
                        default: 8080,
                        keyPath: prefix + ["port"],
                        aliases: [],
                        envListStrategy: nil,
                        resolveSecrets: false,
                        transform: nil,
                        validators: _RiggingMacroSupport.validators(as: Int.self, .range(1 ... 65535))
                    )
                    let _decoded_apiSecret = loader.decodeRequiredSecret(
                        String.self,
                        keyPath: prefix + ["apiSecret"],
                        aliases: [],
                        validators: []
                    )
                    let _decoded_tls = loader.decodeNested(TLSSettings.self, keyPath: prefix + ["tls"])
                    guard let _val_port = _decoded_port,
                          let _val_apiSecret = _decoded_apiSecret,
                          let _val_tls = _decoded_tls else {
                        return nil
                    }
                    var _storage = _RiggingStorage(redactor: loader.context.redactor)
                    _storage.recordField("port", metadata: _val_port)
                    _storage.recordField("apiSecret", metadata: _val_apiSecret)
                    return Self(
                        _riggingStorage: _storage,
                        port: _val_port.value,
                        apiSecret: _val_apiSecret.value,
                        tls: _val_tls
                    )
                }

                public static func validate(_ settings: Self, prefix: [String]) -> [ValidationIssue] {
                    _RiggingMacroSupport.rebaseIssues(Self.validate(settings), prefix: prefix)
                }

                public static func load(
                    context: SettingsContext,
                    overrides: [SettingOverride]
                ) async throws -> Self {
                    var loader = try await SettingsLoader.prepare(
                        for: Self.self,
                        context: context,
                        overrides: overrides
                    )
                    Self.enqueueSecrets(into: &loader, prefix: [])
                    await loader.resolveEnqueuedSecrets()
                    guard let decoded = Self.decodeNested(from: &loader, prefix: []) else {
                        try loader.throwIfInvalid()
                        preconditionFailure("Expected validation error when settings decoding returned nil.")
                    }
                    var finalized = try loader.finalize(decoded)
                    finalized._riggingStorage.provenanceReport = loader.buildProvenanceReport()
                    finalized._riggingStorage.redactor = loader.context.redactor
                    return finalized
                }

                private static func _riggingFallbackProvenanceEntries(
                    for instance: Self,
                    prefix: [String]
                ) -> [ProvenanceEntry] {
                    var entries: [ProvenanceEntry] = []
                    entries.append(
                        _RiggingMacroSupport.fallbackProvenanceEntry(
                            metadata: instance.$port,
                            prefix: prefix,
                            typeName: "Int"
                        )
                    )
                    entries.append(
                        _RiggingMacroSupport.fallbackProvenanceEntry(
                            metadata: instance.$apiSecret,
                            prefix: prefix,
                            typeName: "Secret<String>"
                        )
                    )
                    entries.append(
                        contentsOf: _RiggingMacroSupport.nestedFallbackEntries(
                            from: instance.tls,
                            prefix: prefix + ["tls"]
                        )
                    )
                    return entries
                }
            }

            extension ServiceSettings: RiggedSettings, RiggedNestedSettings, Sendable {
            }
            """#
        )
    }

    @Test("@Rigged parameterless macro omits redundant Sendable when struct already declares Sendable, Equatable")
    func riggedParameterlessExpansion() {
        expectMacroExpansion(
            #"""
            @Rigged
            struct FeatureFlags: Sendable, Equatable {
                @Setting var enabled: Bool = false
            }
            """#,
            expandedSource: #"""
            struct FeatureFlags: Sendable, Equatable {
                var enabled: Bool = false

                private var _riggingStorage = _RiggingStorage()

                var $enabled: SettingMetadata<Bool> {
                    _riggingStorage.metadata(
                        for: "enabled",
                        defaultKeyPath: ["enabled"],
                        value: self.enabled,
                        isSecret: false
                    )
                }

                var provenance: ProvenanceReport {
                    if let report = _riggingStorage.provenanceReport {
                        return report
                    }
                    return ProvenanceReport(entries: Self._riggingFallbackProvenanceEntries(for: self, prefix: []))
                }

                var redactor: DiagnosticRedactor {
                    _riggingStorage.redactor
                }

                init(
                    enabled: Bool = false
                ) {
                    self.enabled = enabled
                    self._riggingStorage = _RiggingStorage()
                }

                private init(
                    _riggingStorage: _RiggingStorage,
                    enabled: Bool
                ) {
                    self._riggingStorage = _riggingStorage
                    self.enabled = enabled
                }

                static var configuration: SettingsConfiguration {
                    SettingsConfiguration()
                }

                static var fieldDescriptors: [SettingFieldDescriptor] {
                    fieldDescriptors(prefix: [], configuration: configuration)
                }

                static func fieldDescriptors(
                    prefix: [String],
                    configuration: SettingsConfiguration
                ) -> [SettingFieldDescriptor] {
                    [
                        SettingFieldDescriptor(
                            name: "enabled",
                            keyPath: prefix + ["enabled"],
                            aliases: [],
                            typeName: "Bool",
                            schemaType: .boolean,
                            isOptional: false,
                            isSecret: false,
                            hasDefault: true,
                            defaultDisplay: _RiggingMacroSupport.defaultDisplay(as: Bool.self, false),
                            help: nil,
                            deprecated: nil,
                            examples: [],
                            allowsArbitraryChildKeys: false
                        )
                    ]
                }

                static func enqueueSecrets(
                    into loader: inout SettingsLoader,
                    prefix: [String]
                ) {

                }

                static func decodeNested(
                    from loader: inout SettingsLoader,
                    prefix: [String]
                ) -> Self? {
                    let _decoded_enabled = loader.decodeDefaulted(
                        Bool.self,
                        default: false,
                        keyPath: prefix + ["enabled"],
                        aliases: [],
                        envListStrategy: nil,
                        resolveSecrets: false,
                        transform: nil,
                        validators: []
                    )
                    guard let _val_enabled = _decoded_enabled else {
                        return nil
                    }
                    var _storage = _RiggingStorage(redactor: loader.context.redactor)
                    _storage.recordField("enabled", metadata: _val_enabled)
                    return Self(
                        _riggingStorage: _storage,
                        enabled: _val_enabled.value
                    )
                }

                static func validate(_ settings: Self, prefix: [String]) -> [ValidationIssue] {
                    _RiggingMacroSupport.rebaseIssues(Self.validate(settings), prefix: prefix)
                }

                static func load(
                    context: SettingsContext,
                    overrides: [SettingOverride]
                ) async throws -> Self {
                    var loader = try await SettingsLoader.prepare(
                        for: Self.self,
                        context: context,
                        overrides: overrides
                    )
                    Self.enqueueSecrets(into: &loader, prefix: [])
                    await loader.resolveEnqueuedSecrets()
                    guard let decoded = Self.decodeNested(from: &loader, prefix: []) else {
                        try loader.throwIfInvalid()
                        preconditionFailure("Expected validation error when settings decoding returned nil.")
                    }
                    var finalized = try loader.finalize(decoded)
                    finalized._riggingStorage.provenanceReport = loader.buildProvenanceReport()
                    finalized._riggingStorage.redactor = loader.context.redactor
                    return finalized
                }

                private static func _riggingFallbackProvenanceEntries(
                    for instance: Self,
                    prefix: [String]
                ) -> [ProvenanceEntry] {
                    var entries: [ProvenanceEntry] = []
                    entries.append(
                        _RiggingMacroSupport.fallbackProvenanceEntry(
                            metadata: instance.$enabled,
                            prefix: prefix,
                            typeName: "Bool"
                        )
                    )
                    return entries
                }
            }

            extension FeatureFlags: RiggedSettings, RiggedNestedSettings {
            }
            """#
        )
    }

    @Test("Diagnostic: @Settings and @Rigged reject class, enum, and actor targets")
    func nonStructDiagnostics() {
        expectMacroExpansion(
            #"""
            @Settings
            final class ClassConfig {}
            """#,
            expandedSource: #"""
            final class ClassConfig {}
            """#,
            diagnostics: [
                DiagnosticSpec(
                    message: "@Settings can only be applied to a struct declaration.",
                    line: 1,
                    column: 1
                )
            ]
        )

        expectMacroExpansion(
            #"""
            @Rigged
            enum EnumConfig {
                case production
            }
            """#,
            expandedSource: #"""
            enum EnumConfig {
                case production
            }
            """#,
            diagnostics: [
                DiagnosticSpec(
                    message: "@Rigged can only be applied to a struct declaration.",
                    line: 1,
                    column: 1
                )
            ]
        )

        expectMacroExpansion(
            #"""
            @Settings
            actor ActorConfig {}
            """#,
            expandedSource: #"""
            actor ActorConfig {}
            """#,
            diagnostics: [
                DiagnosticSpec(
                    message: "@Settings can only be applied to a struct declaration.",
                    line: 1,
                    column: 1
                )
            ]
        )
    }

    @Test("Diagnostic: @SecretSetting requires Secret<T> or Secret<T>?")
    func invalidSecretSettingTypeDiagnostic() {
        expectMacroExpansion(
            #"""
            @Settings
            struct BadSecrets {
                @SecretSetting
                var plainToken: String
            }
            """#,
            expandedSource: #"""
            struct BadSecrets {
                var plainToken: String

                private var _riggingStorage = _RiggingStorage()

                var provenance: ProvenanceReport {
                    if let report = _riggingStorage.provenanceReport {
                        return report
                    }
                    return ProvenanceReport(entries: Self._riggingFallbackProvenanceEntries(for: self, prefix: []))
                }

                var redactor: DiagnosticRedactor {
                    _riggingStorage.redactor
                }

                init() {
                    self._riggingStorage = _RiggingStorage()
                }

                private init(
                    _riggingStorage: _RiggingStorage
                ) {
                    self._riggingStorage = _riggingStorage
                }

                static var configuration: SettingsConfiguration {
                    SettingsConfiguration()
                }

                static var fieldDescriptors: [SettingFieldDescriptor] {
                    fieldDescriptors(prefix: [], configuration: configuration)
                }

                static func fieldDescriptors(
                    prefix: [String],
                    configuration: SettingsConfiguration
                ) -> [SettingFieldDescriptor] {
                    []
                }

                static func enqueueSecrets(
                    into loader: inout SettingsLoader,
                    prefix: [String]
                ) {

                }

                static func decodeNested(
                    from loader: inout SettingsLoader,
                    prefix: [String]
                ) -> Self? {
                    Self(_riggingStorage: _RiggingStorage())
                }

                static func validate(_ settings: Self, prefix: [String]) -> [ValidationIssue] {
                    _RiggingMacroSupport.rebaseIssues(Self.validate(settings), prefix: prefix)
                }

                static func load(
                    context: SettingsContext,
                    overrides: [SettingOverride]
                ) async throws -> Self {
                    var loader = try await SettingsLoader.prepare(
                        for: Self.self,
                        context: context,
                        overrides: overrides
                    )
                    Self.enqueueSecrets(into: &loader, prefix: [])
                    await loader.resolveEnqueuedSecrets()
                    guard let decoded = Self.decodeNested(from: &loader, prefix: []) else {
                        try loader.throwIfInvalid()
                        preconditionFailure("Expected validation error when settings decoding returned nil.")
                    }
                    var finalized = try loader.finalize(decoded)
                    finalized._riggingStorage.provenanceReport = loader.buildProvenanceReport()
                    finalized._riggingStorage.redactor = loader.context.redactor
                    return finalized
                }

                private static func _riggingFallbackProvenanceEntries(
                    for instance: Self,
                    prefix: [String]
                ) -> [ProvenanceEntry] {
                    []
                }
            }

            extension BadSecrets: RiggedSettings, RiggedNestedSettings, Sendable {
            }
            """#,
            diagnostics: [
                DiagnosticSpec(
                    message: "@SecretSetting property 'plainToken' must have type 'Secret<Value>' or 'Secret<Value>?' (got 'String').",
                    line: 4,
                    column: 21
                )
            ]
        )
    }

    @Test("Diagnostic: immutable let with inline default and unannotated uninitialized let are rejected")
    func letPropertyDiagnostics() {
        expectMacroExpansion(
            #"""
            @Settings
            struct BadLetConfig {
                @Setting
                let readOnly: Bool = false

                let uninitializedKey: String
            }
            """#,
            expandedSource: #"""
            struct BadLetConfig {
                let readOnly: Bool = false

                let uninitializedKey: String

                private var _riggingStorage = _RiggingStorage()

                var provenance: ProvenanceReport {
                    if let report = _riggingStorage.provenanceReport {
                        return report
                    }
                    return ProvenanceReport(entries: Self._riggingFallbackProvenanceEntries(for: self, prefix: []))
                }

                var redactor: DiagnosticRedactor {
                    _riggingStorage.redactor
                }

                init() {
                    self._riggingStorage = _RiggingStorage()
                }

                private init(
                    _riggingStorage: _RiggingStorage
                ) {
                    self._riggingStorage = _riggingStorage
                }

                static var configuration: SettingsConfiguration {
                    SettingsConfiguration()
                }

                static var fieldDescriptors: [SettingFieldDescriptor] {
                    fieldDescriptors(prefix: [], configuration: configuration)
                }

                static func fieldDescriptors(
                    prefix: [String],
                    configuration: SettingsConfiguration
                ) -> [SettingFieldDescriptor] {
                    []
                }

                static func enqueueSecrets(
                    into loader: inout SettingsLoader,
                    prefix: [String]
                ) {

                }

                static func decodeNested(
                    from loader: inout SettingsLoader,
                    prefix: [String]
                ) -> Self? {
                    Self(_riggingStorage: _RiggingStorage())
                }

                static func validate(_ settings: Self, prefix: [String]) -> [ValidationIssue] {
                    _RiggingMacroSupport.rebaseIssues(Self.validate(settings), prefix: prefix)
                }

                static func load(
                    context: SettingsContext,
                    overrides: [SettingOverride]
                ) async throws -> Self {
                    var loader = try await SettingsLoader.prepare(
                        for: Self.self,
                        context: context,
                        overrides: overrides
                    )
                    Self.enqueueSecrets(into: &loader, prefix: [])
                    await loader.resolveEnqueuedSecrets()
                    guard let decoded = Self.decodeNested(from: &loader, prefix: []) else {
                        try loader.throwIfInvalid()
                        preconditionFailure("Expected validation error when settings decoding returned nil.")
                    }
                    var finalized = try loader.finalize(decoded)
                    finalized._riggingStorage.provenanceReport = loader.buildProvenanceReport()
                    finalized._riggingStorage.redactor = loader.context.redactor
                    return finalized
                }

                private static func _riggingFallbackProvenanceEntries(
                    for instance: Self,
                    prefix: [String]
                ) -> [ProvenanceEntry] {
                    []
                }
            }

            extension BadLetConfig: RiggedSettings, RiggedNestedSettings, Sendable {
            }
            """#,
            diagnostics: [
                DiagnosticSpec(
                    message: "@Setting property 'readOnly' with a default value must use 'var' instead of 'let' so loaded configuration values can override the default.",
                    line: 4,
                    column: 5
                ),
                DiagnosticSpec(
                    message: "Stored property 'uninitializedKey' must be annotated with @Setting, @SecretSetting, or @NestedSettings, or declare a default value.",
                    line: 6,
                    column: 5
                ),
            ]
        )
    }

    @Test("Diagnostic: @Setting outside a @Settings/@Rigged struct is rejected")
    func outsideSettingsStructDiagnostic() {
        expectMacroExpansion(
            #"""
            struct PlainStruct {
                @Setting
                var host: String = "localhost"
            }
            """#,
            expandedSource: #"""
            struct PlainStruct {
                var host: String = "localhost"
            }
            """#,
            diagnostics: [
                DiagnosticSpec(
                    message: "@Setting can only be applied to properties inside a @Settings or @Rigged struct.",
                    line: 2,
                    column: 5
                )
            ]
        )
    }
}
