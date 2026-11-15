import Foundation

/// Protocol implemented by `@NestedSettings` value types so nested groups participate in
/// schema generation, single-pass batched secret resolution, and exhaustive validation.
public protocol RiggedNestedSettings: Sendable {
    static func fieldDescriptors(
        prefix: [String],
        configuration: SettingsConfiguration
    ) -> [SettingFieldDescriptor]

    static func enqueueSecrets(
        into loader: inout SettingsLoader,
        prefix: [String]
    )

    static func decodeNested(
        from loader: inout SettingsLoader,
        prefix: [String]
    ) -> Self?

    static func validate(
        _ settings: Self,
        prefix: [String]
    ) -> [ValidationIssue]
}

extension RiggedNestedSettings {
    public static func validate(
        _ settings: Self,
        prefix: [String]
    ) -> [ValidationIssue] {
        []
    }
}

/// Runtime coordinator orchestrating source cascade merging, `extraKeys` inspection,
/// two-phase batched `SecretResolver` execution, typed `SettingValueDecodable` coercion,
/// field/model validation, and `ProvenanceReport` construction.
public struct SettingsLoader: Sendable {
    public let configuration: SettingsConfiguration
    public let context: SettingsContext
    public let mergedTree: RawConfigTree

    public private(set) var issues: [ValidationIssue] = []
    public private(set) var warnings: [ValidationIssue] = []
    public private(set) var provenanceEntries: [ProvenanceEntry] = []

    private var pendingSecretRequests: [SecretResolutionRequest] = []
    private var enqueuedSecretKeyPaths: Set<[String]> = []
    private var resolvedSecretsByKeyPath: [[String]: ResolvedSecret] = [:]
    private let decodingContext: ValueDecodingContext

    public init(
        configuration: SettingsConfiguration,
        context: SettingsContext,
        mergedTree: RawConfigTree,
        initialIssues: [ValidationIssue] = [],
        initialWarnings: [ValidationIssue] = []
    ) {
        self.configuration = configuration
        self.context = context
        self.mergedTree = mergedTree
        self.issues = initialIssues
        self.warnings = initialWarnings
        self.decodingContext = ValueDecodingContext(configuration: configuration)
    }

    // MARK: - Step 1: Source Cascade & Extra Keys Inspection

    /// Loads and merges all configured `SettingsSource` layers for `Settings`, then enforces
    /// `configuration.extraKeys` against `Settings.fieldDescriptors`.
    public static func prepare<Settings: RiggedSettings>(
        for settingsType: Settings.Type,
        context: SettingsContext = SettingsContext(),
        overrides: [SettingOverride] = []
    ) async throws -> SettingsLoader {
        var effectiveContext = context
        if !overrides.isEmpty {
            effectiveContext.cliOverrides = overrides + context.cliOverrides
        }

        let config = Settings.configuration
        let sources = Settings.customizeSources(DefaultSources())

        var accumulatedTree = RawConfigTree.empty
        var initialIssues: [ValidationIssue] = []
        var initialWarnings: [ValidationIssue] = []

        for source in sources {
            do {
                let sourceTree = try await source.load(configuration: config, context: effectiveContext)
                accumulatedTree = accumulatedTree.merging(
                    lowerPriority: sourceTree,
                    caseSensitive: config.caseSensitive
                )
            } catch let validationError as SettingsValidationError {
                initialIssues.append(contentsOf: validationError.issues)
                initialWarnings.append(contentsOf: validationError.warnings)
            } catch let issue as ValidationIssue {
                initialIssues.append(issue)
            }
        }

        if config.extraKeys != .ignore && config.extraKeys != .allow {
            let schemaInfo = collectDeclaredSchemaPaths(
                from: Settings.fieldDescriptors,
                configuration: config
            )
            let unknowns = accumulatedTree.unknownKeyPaths(
                declaredPaths: schemaInfo.declaredPaths,
                arbitraryChildPrefixes: schemaInfo.arbitraryPrefixes,
                caseSensitive: config.caseSensitive
            )

            for unknown in unknowns {
                if isMetaConfigKey(unknown.keyPath) {
                    continue
                }
                if config.envPrefix.isEmpty, case .environment = unknown.origin {
                    continue
                }
                let issue = ValidationIssue(
                    keyPath: unknown.keyPath,
                    kind: .unknownKey,
                    message: "Unknown configuration key '\(unknown.keyPath.joined(separator: "."))' is not declared in \(String(describing: Settings.self)).",
                    origin: unknown.origin
                )
                switch config.extraKeys {
                case .forbid:
                    initialIssues.append(issue)
                case .warn:
                    initialWarnings.append(issue)
                case .ignore, .allow:
                    break
                }
            }
        }

        return SettingsLoader(
            configuration: config,
            context: effectiveContext,
            mergedTree: accumulatedTree,
            initialIssues: initialIssues,
            initialWarnings: initialWarnings
        )
    }

    // MARK: - Step 2: Two-Phase Secret Batching

    /// Registers a `@SecretSetting` field for Phase 1 batched secret resolution.
    public mutating func enqueueSecret(
        keyPath: [String],
        aliases: [SettingAlias] = [],
        transforms: [SecretTransform] = [],
        allowLiteralInProjectConfig: Bool = false,
        expectedType: String = "Secret<String>",
        isOptional: Bool = false,
        hasDefault: Bool = false
    ) {
        let envHint = DotEnvExporter.resolvedEnvName(
            for: SettingFieldDescriptor(
                name: keyPath.last ?? "",
                keyPath: keyPath,
                aliases: aliases,
                typeName: expectedType,
                isOptional: isOptional,
                isSecret: true,
                hasDefault: hasDefault
            ),
            configuration: configuration
        )

        guard let node = lookupNode(keyPath: keyPath, aliases: aliases) else {
            if !isOptional && !hasDefault {
                issues.append(
                    ValidationIssue(
                        keyPath: keyPath,
                        kind: .missingRequired,
                        message: "Missing required secret setting '\(keyPath.joined(separator: "."))'.",
                        expectedType: expectedType,
                        envVariableHint: envHint
                    )
                )
            }
            return
        }

        if decodingContext.representsNull(node.value) {
            if !isOptional && !hasDefault {
                issues.append(
                    ValidationIssue(
                        keyPath: keyPath,
                        kind: .missingRequired,
                        message: "Required secret setting '\(keyPath.joined(separator: "."))' cannot be null.",
                        origin: node.origin,
                        expectedType: expectedType,
                        envVariableHint: envHint
                    )
                )
            }
            return
        }

        enqueuedSecretKeyPaths.insert(keyPath)
        pendingSecretRequests.append(
            SecretResolutionRequest(
                keyPath: keyPath,
                node: node,
                transforms: transforms,
                allowLiteralInProjectConfig: allowLiteralInProjectConfig,
                expectedType: expectedType,
                envVariableHint: envHint
            )
        )
    }

    /// Conditionally registers a non-secret `@Setting(resolveSecrets: true)` field for Phase 1
    /// batched secret resolution ONLY when its winning node parses as a non-literal `SecretReference`
    /// (e.g. `"op://..."`, `"keychain://..."`, `"file://..."`). Plain literal values are left untouched
    /// for normal Phase 2 decoding without registering non-secret strings in `DiagnosticRedactor`.
    public mutating func enqueuePotentialSecretReference(
        keyPath: [String],
        aliases: [SettingAlias] = [],
        transforms: [SecretTransform] = [],
        expectedType: String = "String",
        isOptional: Bool = false,
        hasDefault: Bool = false
    ) {
        guard let node = lookupNode(keyPath: keyPath, aliases: aliases),
              !decodingContext.representsNull(node.value),
              case .string(let rawString) = node.value else {
            return
        }

        let envHint = canonicalEnvHint(keyPath: keyPath, aliases: aliases, typeName: expectedType)
        let customSchemes = Set(context.secretProviders.flatMap(\.supportedSchemes))

        do {
            let parsedRef = try SecretReference.parse(rawString, additionalSchemes: customSchemes)
            if case .literal = parsedRef {
                return
            }
            enqueuedSecretKeyPaths.insert(keyPath)
            pendingSecretRequests.append(
                SecretResolutionRequest(
                    keyPath: keyPath,
                    node: node,
                    transforms: transforms,
                    allowLiteralInProjectConfig: true,
                    expectedType: expectedType,
                    envVariableHint: envHint
                )
            )
        } catch let refError as SecretReferenceError {
            enqueuedSecretKeyPaths.insert(keyPath)
            issues.append(
                ValidationIssue(
                    keyPath: keyPath,
                    kind: .invalidValue,
                    message: refError.description,
                    origin: node.origin,
                    expectedType: expectedType,
                    envVariableHint: envHint
                )
            )
        } catch {
            enqueuedSecretKeyPaths.insert(keyPath)
            issues.append(
                ValidationIssue(
                    keyPath: keyPath,
                    kind: .invalidValue,
                    message: String(describing: error),
                    origin: node.origin,
                    expectedType: expectedType,
                    envVariableHint: envHint
                )
            )
        }
    }

    /// Executes the single deduplicated batch pass across all queued `SecretResolutionRequest` items.
    public mutating func resolveEnqueuedSecrets(
        resolver: SecretResolver = SecretResolver()
    ) async {
        guard !pendingSecretRequests.isEmpty else { return }
        let requests = pendingSecretRequests
        pendingSecretRequests.removeAll()

        let batchResult = await resolver.resolveAll(requests, context: context)
        for (path, resolved) in batchResult.resolvedByKeyPath {
            resolvedSecretsByKeyPath[path] = resolved
        }
        issues.append(contentsOf: batchResult.issues)
    }

    // MARK: - Step 3: Non-Secret Field Decoding & Validation

    /// Decodes and validates a required non-optional setting field.
    public mutating func decodeRequired<Value: SettingValueDecodable>(
        _ type: Value.Type = Value.self,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        envListStrategy: EnvCollectionStrategy? = nil,
        resolveSecrets: Bool = false,
        transform: ((Value) throws -> Value)? = nil,
        validators: [SettingValidator<Value>] = []
    ) -> SettingMetadata<Value>? {
        let envHint = canonicalEnvHint(keyPath: keyPath, aliases: aliases, typeName: Value.settingTypeDisplayName)

        if resolveSecrets {
            if let resolved = resolvedSecretsByKeyPath[keyPath] {
                let node = Self.nodeFromResolvedSecret(resolved, as: Value.self)
                return decodeAndValidateNode(
                    node: node,
                    as: Value.self,
                    keyPath: keyPath,
                    envHint: envHint,
                    envListStrategy: envListStrategy,
                    transform: transform,
                    validators: validators
                )
            }
            if enqueuedSecretKeyPaths.contains(keyPath) {
                return nil
            }
        }

        guard let node = lookupNode(keyPath: keyPath, aliases: aliases) else {
            issues.append(
                ValidationIssue(
                    keyPath: keyPath,
                    kind: .missingRequired,
                    message: "Missing required setting '\(keyPath.joined(separator: "."))' (expected \(Value.settingTypeDisplayName)).",
                    expectedType: Value.settingTypeDisplayName,
                    envVariableHint: envHint
                )
            )
            return nil
        }

        if decodingContext.representsNull(node.value) {
            issues.append(
                ValidationIssue(
                    keyPath: keyPath,
                    kind: .missingRequired,
                    message: "Required setting '\(keyPath.joined(separator: "."))' cannot be null.",
                    origin: node.origin,
                    expectedType: Value.settingTypeDisplayName,
                    envVariableHint: envHint
                )
            )
            return nil
        }

        return decodeAndValidateNode(
            node: node,
            as: Value.self,
            keyPath: keyPath,
            envHint: envHint,
            envListStrategy: envListStrategy,
            transform: transform,
            validators: validators
        )
    }

    /// Decodes and validates a setting field with a declared default value.
    public mutating func decodeDefaulted<Value: SettingValueDecodable>(
        _ type: Value.Type = Value.self,
        default defaultValue: @autoclosure () -> Value,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        envListStrategy: EnvCollectionStrategy? = nil,
        resolveSecrets: Bool = false,
        transform: ((Value) throws -> Value)? = nil,
        validators: [SettingValidator<Value>] = []
    ) -> SettingMetadata<Value>? {
        let envHint = canonicalEnvHint(keyPath: keyPath, aliases: aliases, typeName: Value.settingTypeDisplayName)

        if resolveSecrets {
            if let resolved = resolvedSecretsByKeyPath[keyPath] {
                let node = Self.nodeFromResolvedSecret(resolved, as: Value.self)
                return decodeAndValidateNode(
                    node: node,
                    as: Value.self,
                    keyPath: keyPath,
                    envHint: envHint,
                    envListStrategy: envListStrategy,
                    transform: transform,
                    validators: validators
                )
            }
            if enqueuedSecretKeyPaths.contains(keyPath) {
                return nil
            }
        }

        guard let node = lookupNode(keyPath: keyPath, aliases: aliases),
              !decodingContext.representsNull(node.value) else {
            let fallback = defaultValue()
            return validateResolvedValue(
                fallback,
                typeName: Value.settingTypeDisplayName,
                keyPath: keyPath,
                origin: .defaultValue,
                overriddenOrigins: [],
                envHint: envHint,
                transform: transform,
                validators: validators
            )
        }

        return decodeAndValidateNode(
            node: node,
            as: Value.self,
            keyPath: keyPath,
            envHint: envHint,
            envListStrategy: envListStrategy,
            transform: transform,
            validators: validators
        )
    }

    /// Decodes and validates an optional setting field (`Value?`).
    public mutating func decodeOptional<Wrapped: SettingValueDecodable>(
        _ type: Wrapped.Type = Wrapped.self,
        default defaultValue: Wrapped? = nil,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        envListStrategy: EnvCollectionStrategy? = nil,
        resolveSecrets: Bool = false,
        transform: ((Wrapped) throws -> Wrapped)? = nil,
        validators: [SettingValidator<Wrapped>] = []
    ) -> SettingMetadata<Wrapped?>? {
        let typeName = "\(Wrapped.settingTypeDisplayName)?"
        let envHint = canonicalEnvHint(keyPath: keyPath, aliases: aliases, typeName: typeName)

        if resolveSecrets {
            if let resolved = resolvedSecretsByKeyPath[keyPath] {
                let resolvedNode = Self.nodeFromResolvedSecret(resolved, as: Wrapped.self)
                guard let unwrappedMeta = decodeAndValidateNode(
                    node: resolvedNode,
                    as: Wrapped.self,
                    keyPath: keyPath,
                    envHint: envHint,
                    envListStrategy: envListStrategy,
                    transform: transform,
                    validators: validators,
                    recordProvenance: false
                ) else {
                    return nil
                }
                let metadata = SettingMetadata<Wrapped?>(
                    keyPath: keyPath,
                    value: unwrappedMeta.value,
                    isSecret: false,
                    origin: unwrappedMeta.origin,
                    overriddenOrigins: unwrappedMeta.overriddenOrigins
                )
                recordProvenanceEntry(for: metadata, typeName: typeName, customDisplay: String(describing: unwrappedMeta.value))
                return metadata
            }
            if enqueuedSecretKeyPaths.contains(keyPath) {
                return nil
            }
        }

        guard let node = lookupNode(keyPath: keyPath, aliases: aliases) else {
            if let fallback = defaultValue {
                guard let validated = validateResolvedValue(
                    fallback,
                    typeName: typeName,
                    keyPath: keyPath,
                    origin: .defaultValue,
                    overriddenOrigins: [],
                    envHint: envHint,
                    transform: transform,
                    validators: validators,
                    recordProvenance: false
                ) else {
                    return nil
                }
                let metadata = SettingMetadata<Wrapped?>(
                    keyPath: keyPath,
                    value: validated.value,
                    isSecret: false,
                    origin: .defaultValue,
                    overriddenOrigins: []
                )
                recordProvenanceEntry(for: metadata, typeName: typeName)
                return metadata
            }

            let metadata = SettingMetadata<Wrapped?>(
                keyPath: keyPath,
                value: nil,
                isSecret: false,
                origin: .defaultValue,
                overriddenOrigins: []
            )
            recordProvenanceEntry(for: metadata, typeName: typeName, customDisplay: "nil")
            return metadata
        }

        if decodingContext.representsNull(node.value) {
            let metadata = SettingMetadata<Wrapped?>(
                keyPath: keyPath,
                value: nil,
                isSecret: false,
                origin: node.origin,
                overriddenOrigins: node.overriddenOrigins
            )
            recordProvenanceEntry(for: metadata, typeName: typeName, customDisplay: "nil")
            return metadata
        }

        guard let unwrappedMeta = decodeAndValidateNode(
            node: node,
            as: Wrapped.self,
            keyPath: keyPath,
            envHint: envHint,
            envListStrategy: envListStrategy,
            transform: transform,
            validators: validators,
            recordProvenance: false
        ) else {
            return nil
        }

        let metadata = SettingMetadata<Wrapped?>(
            keyPath: keyPath,
            value: unwrappedMeta.value,
            isSecret: false,
            origin: unwrappedMeta.origin,
            overriddenOrigins: unwrappedMeta.overriddenOrigins
        )
        recordProvenanceEntry(for: metadata, typeName: typeName, customDisplay: String(describing: unwrappedMeta.value))
        return metadata
    }

    // MARK: - Step 4: Secret Field Decoding & Validation

    /// Completes Phase 2 decoding and validation for a required `@SecretSetting` field.
    public mutating func decodeRequiredSecret<Value: SettingValueDecodable>(
        _ type: Value.Type = Value.self,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        validators: [SettingValidator<Value>] = []
    ) -> SettingMetadata<Secret<Value>>? {
        guard let resolved = resolvedSecretsByKeyPath[keyPath] else {
            return nil
        }
        return finalizeResolvedSecret(
            resolved,
            as: Value.self,
            keyPath: keyPath,
            aliases: aliases,
            validators: validators
        )
    }

    /// Completes Phase 2 decoding and validation for a defaulted `@SecretSetting` field.
    public mutating func decodeDefaultedSecret<Value: SettingValueDecodable>(
        _ type: Value.Type = Value.self,
        default defaultSecret: @autoclosure () -> Secret<Value>,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        validators: [SettingValidator<Value>] = []
    ) -> SettingMetadata<Secret<Value>>? {
        if let resolved = resolvedSecretsByKeyPath[keyPath] {
            return finalizeResolvedSecret(
                resolved,
                as: Value.self,
                keyPath: keyPath,
                aliases: aliases,
                validators: validators
            )
        }

        if let node = lookupNode(keyPath: keyPath, aliases: aliases),
           !decodingContext.representsNull(node.value) {
            // An error was already recorded for this node during Phase 1/batch resolution.
            return nil
        }

        let fallback = defaultSecret()
        registerSecretInRedactor(fallback.expose())
        let typeName = "Secret<\(Value.settingTypeDisplayName)>"
        let envHint = canonicalEnvHint(keyPath: keyPath, aliases: aliases, typeName: typeName)

        var fieldValid = true
        for validator in validators {
            if let issue = validator.forSecret().validate(
                fallback,
                keyPath: keyPath,
                origin: .defaultValue,
                envVariableHint: envHint,
                context: context
            ) {
                issues.append(issue)
                fieldValid = false
            }
        }
        guard fieldValid else { return nil }

        let metadata = SettingMetadata<Secret<Value>>(
            keyPath: keyPath,
            value: fallback,
            isSecret: true,
            origin: .defaultValue,
            overriddenOrigins: []
        )
        recordProvenanceEntry(for: metadata, typeName: typeName)
        return metadata
    }

    /// Completes Phase 2 decoding and validation for an optional `@SecretSetting` (`Secret<Value>?`).
    public mutating func decodeOptionalSecret<Value: SettingValueDecodable>(
        _ type: Value.Type = Value.self,
        default defaultSecret: Secret<Value>? = nil,
        keyPath: [String],
        aliases: [SettingAlias] = [],
        validators: [SettingValidator<Value>] = []
    ) -> SettingMetadata<Secret<Value>?>? {
        let typeName = "Secret<\(Value.settingTypeDisplayName)>?"

        if let resolved = resolvedSecretsByKeyPath[keyPath] {
            guard let unwrapped = finalizeResolvedSecret(
                resolved,
                as: Value.self,
                keyPath: keyPath,
                aliases: aliases,
                validators: validators,
                recordProvenance: false
            ) else {
                return nil
            }
            let metadata = SettingMetadata<Secret<Value>?>(
                keyPath: keyPath,
                value: unwrapped.value,
                isSecret: true,
                origin: unwrapped.origin,
                overriddenOrigins: unwrapped.overriddenOrigins
            )
            recordProvenanceEntry(for: metadata, typeName: typeName)
            return metadata
        }

        if let node = lookupNode(keyPath: keyPath, aliases: aliases) {
            if decodingContext.representsNull(node.value) {
                let metadata = SettingMetadata<Secret<Value>?>(
                    keyPath: keyPath,
                    value: nil,
                    isSecret: true,
                    origin: node.origin,
                    overriddenOrigins: node.overriddenOrigins
                )
                recordProvenanceEntry(for: metadata, typeName: typeName)
                return metadata
            }
            // Non-null node without resolved secret means Phase 1 / provider failed; error already queued.
            return nil
        }

        if let fallback = defaultSecret {
            registerSecretInRedactor(fallback.expose())
            let envHint = canonicalEnvHint(keyPath: keyPath, aliases: aliases, typeName: typeName)
            var fieldValid = true
            for validator in validators {
                if let issue = validator.forSecret().validate(
                    fallback,
                    keyPath: keyPath,
                    origin: .defaultValue,
                    envVariableHint: envHint,
                    context: context
                ) {
                    issues.append(issue)
                    fieldValid = false
                }
            }
            guard fieldValid else { return nil }
        }

        let metadata = SettingMetadata<Secret<Value>?>(
            keyPath: keyPath,
            value: defaultSecret,
            isSecret: true,
            origin: .defaultValue,
            overriddenOrigins: []
        )
        recordProvenanceEntry(for: metadata, typeName: typeName)
        return metadata
    }

    // MARK: - Step 5: Nested Settings Helpers

    /// Decodes a nested `@NestedSettings` group at `keyPath`.
    public mutating func decodeNested<Nested: RiggedNestedSettings>(
        _ type: Nested.Type = Nested.self,
        keyPath: [String]
    ) -> Nested? {
        guard let decoded = Nested.decodeNested(from: &self, prefix: keyPath) else {
            return nil
        }
        let nestedIssues = Nested.validate(decoded, prefix: keyPath)
        if !nestedIssues.isEmpty {
            issues.append(contentsOf: nestedIssues)
            return nil
        }
        return decoded
    }

    /// Decodes an optional nested `@NestedSettings` group (`Nested?`), returning `nil` when
    /// no child keys exist under `keyPath` in the merged tree.
    public mutating func decodeOptionalNested<Nested: RiggedNestedSettings>(
        _ type: Nested.Type = Nested.self,
        keyPath: [String]
    ) -> Nested?? {
        guard let existingNode = mergedTree.lookup(path: keyPath, caseSensitive: configuration.caseSensitive),
              !decodingContext.representsNull(existingNode.value) else {
            return .some(nil)
        }
        guard let decoded = decodeNested(Nested.self, keyPath: keyPath) else {
            return nil
        }
        return .some(decoded)
    }

    // MARK: - Step 6: Finalization & Cross-Field Validation

    /// Appends a custom `ValidationIssue`.
    public mutating func recordIssue(_ issue: ValidationIssue) {
        issues.append(issue)
    }

    /// Throws `SettingsValidationError` if any field or secret issues were accumulated.
    public func throwIfInvalid() throws {
        guard issues.isEmpty else {
            throw SettingsValidationError(
                issues: issues,
                warnings: warnings,
                redactor: context.redactor
            )
        }
    }

    /// Constructs the immutable `ProvenanceReport` for a successfully decoded settings model.
    public func buildProvenanceReport() -> ProvenanceReport {
        ProvenanceReport(entries: provenanceEntries, warnings: warnings)
    }

    /// Runs `Settings.validate(_:)` cross-field checks and throws `SettingsValidationError` if non-empty.
    public mutating func finalize<Settings: RiggedSettings>(_ settings: Settings) throws -> Settings {
        try throwIfInvalid()
        let crossFieldIssues = Settings.validate(settings)
        if !crossFieldIssues.isEmpty {
            issues.append(contentsOf: crossFieldIssues)
            throw SettingsValidationError(
                issues: issues,
                warnings: warnings,
                redactor: context.redactor
            )
        }
        return settings
    }

    // MARK: - Lookup & Precedence Helpers

    /// Resolves the highest-precedence `RawNode` for `keyPath` and its `aliases`, recording
    /// any lower-precedence alias/canonical matches into `overriddenOrigins`.
    public func lookupNode(
        keyPath: [String],
        aliases: [SettingAlias] = []
    ) -> RawNode? {
        var candidates: [RawNode] = []

        // Check explicit CLI flag aliases in context.cliOverrides first
        for alias in aliases {
            if case .cli(let flagName) = alias {
                if let match = context.cliOverrides.first(where: { $0.flag == flagName }) {
                    candidates.append(RawNode(value: match.value, origin: match.origin))
                }
            }
        }

        // Canonical path in merged tree
        if let canonical = mergedTree.lookup(path: keyPath, caseSensitive: configuration.caseSensitive) {
            candidates.append(canonical)
        }

        // Alias lookups (.env and .configPath)
        for alias in aliases {
            switch alias {
            case .env(let variableName):
                if let envNode = mergedTree.lookupEnvironmentEntry(
                    variableName,
                    caseSensitive: configuration.caseSensitive
                ) {
                    candidates.append(envNode)
                } else if let rawEnvVal = lookupContextEnvironment(variableName) {
                    if !(configuration.envIgnoreEmpty && rawEnvVal.isEmpty) {
                        let rawValue: RawValue = decodingContext.representsNull(.string(rawEnvVal))
                            ? .null
                            : .string(rawEnvVal)
                        candidates.append(
                            RawNode(value: rawValue, origin: .environment(variable: variableName))
                        )
                    }
                }
            case .configPath(let altPath):
                if let altNode = mergedTree.lookup(path: altPath, caseSensitive: configuration.caseSensitive) {
                    candidates.append(altNode)
                }
            case .cli(let cliKey):
                let stripped = cliKey.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
                if !stripped.isEmpty,
                   let cliNode = mergedTree.lookup(path: [stripped], caseSensitive: configuration.caseSensitive) {
                    candidates.append(cliNode)
                }
            }
        }

        guard !candidates.isEmpty else { return nil }

        let sorted = candidates.enumerated().sorted { lhs, rhs in
            let rankA = Self.originPrecedenceRank(lhs.element.origin)
            let rankB = Self.originPrecedenceRank(rhs.element.origin)
            if rankA != rankB {
                return rankA < rankB
            }
            return lhs.offset < rhs.offset
        }.map(\.element)

        var winner = sorted[0]
        for other in sorted.dropFirst() {
            for candidateOrigin in [other.origin] + other.overriddenOrigins {
                if candidateOrigin != winner.origin && !winner.overriddenOrigins.contains(candidateOrigin) {
                    winner.overriddenOrigins.append(candidateOrigin)
                }
            }
        }
        return winner
    }

    private func lookupContextEnvironment(_ variableName: String) -> String? {
        if let exact = context.environment[variableName] {
            return exact
        }
        guard !configuration.caseSensitive else { return nil }
        let lower = variableName.lowercased()
        for key in context.environment.keys.sorted() where key.lowercased() == lower {
            return context.environment[key]
        }
        return nil
    }

    private static func originPrecedenceRank(_ origin: SettingOrigin) -> Int {
        switch origin {
        case .cliArgument:
            return 0
        case .initOverride:
            return 1
        case .environment:
            return 2
        case .dotEnv:
            return 3
        case .secretsDirectory:
            return 4
        case .projectConfig:
            return 5
        case .userConfig:
            return 6
        case .managedPolicy:
            return 7
        case .customSource:
            return 8
        case .secretProvider(_, _, let via):
            return originPrecedenceRank(via)
        case .defaultValue:
            return 9
        }
    }

    // MARK: - Internal Decoding & Validation Helpers

    private static func nodeFromResolvedSecret<Value>(
        _ resolved: ResolvedSecret,
        as type: Value.Type
    ) -> RawNode {
        let rawValue: RawValue
        if Value.self == Data.self || Value.self == [UInt8].self {
            rawValue = .data(resolved.data)
        } else if let str = String(data: resolved.data, encoding: .utf8) {
            rawValue = .string(str)
        } else {
            rawValue = .data(resolved.data)
        }
        return RawNode(
            value: rawValue,
            origin: resolved.origin,
            overriddenOrigins: resolved.overriddenOrigins
        )
    }

    private mutating func decodeAndValidateNode<Value: SettingValueDecodable>(
        node: RawNode,
        as type: Value.Type,
        keyPath: [String],
        envHint: String,
        envListStrategy: EnvCollectionStrategy? = nil,
        transform: ((Value) throws -> Value)?,
        validators: [SettingValidator<Value>],
        recordProvenance: Bool = true
    ) -> SettingMetadata<Value>? {
        var effectiveDecodingContext = decodingContext
        if let envListStrategy {
            effectiveDecodingContext.envListStrategy = envListStrategy
        }

        let decoded: Value
        do {
            decoded = try Value.decodeSettingValue(from: node.value, context: effectiveDecodingContext)
        } catch let decodeError as ValueDecodingError {
            issues.append(
                ValidationIssue(
                    keyPath: keyPath,
                    kind: .invalidValue,
                    message: decodeError.description,
                    origin: node.origin,
                    expectedType: Value.settingTypeDisplayName,
                    envVariableHint: envHint
                )
            )
            return nil
        } catch {
            issues.append(
                ValidationIssue(
                    keyPath: keyPath,
                    kind: .invalidValue,
                    message: String(describing: error),
                    origin: node.origin,
                    expectedType: Value.settingTypeDisplayName,
                    envVariableHint: envHint
                )
            )
            return nil
        }

        return validateResolvedValue(
            decoded,
            typeName: Value.settingTypeDisplayName,
            keyPath: keyPath,
            origin: node.origin,
            overriddenOrigins: node.overriddenOrigins,
            envHint: envHint,
            transform: transform,
            validators: validators,
            recordProvenance: recordProvenance
        )
    }

    private mutating func validateResolvedValue<Value: Sendable>(
        _ rawDecoded: Value,
        typeName: String,
        keyPath: [String],
        origin: SettingOrigin,
        overriddenOrigins: [SettingOrigin],
        envHint: String,
        transform: ((Value) throws -> Value)?,
        validators: [SettingValidator<Value>],
        recordProvenance: Bool = true
    ) -> SettingMetadata<Value>? {
        let transformed: Value
        if let transform {
            do {
                transformed = try transform(rawDecoded)
            } catch {
                issues.append(
                    ValidationIssue(
                        keyPath: keyPath,
                        kind: .invalidValue,
                        message: "Value transform failed: \(error)",
                        origin: origin,
                        expectedType: typeName,
                        envVariableHint: envHint
                    )
                )
                return nil
            }
        } else {
            transformed = rawDecoded
        }

        var allValid = true
        for validator in validators {
            if let issue = validator.validate(
                transformed,
                keyPath: keyPath,
                origin: origin,
                envVariableHint: envHint,
                context: context
            ) {
                issues.append(issue)
                allValid = false
            }
        }
        guard allValid else { return nil }

        let metadata = SettingMetadata<Value>(
            keyPath: keyPath,
            value: transformed,
            isSecret: false,
            origin: origin,
            overriddenOrigins: overriddenOrigins
        )
        if recordProvenance {
            recordProvenanceEntry(for: metadata, typeName: typeName)
        }
        return metadata
    }

    private mutating func finalizeResolvedSecret<Value: SettingValueDecodable>(
        _ resolved: ResolvedSecret,
        as type: Value.Type,
        keyPath: [String],
        aliases: [SettingAlias],
        validators: [SettingValidator<Value>],
        recordProvenance: Bool = true
    ) -> SettingMetadata<Secret<Value>>? {
        let typeName = "Secret<\(Value.settingTypeDisplayName)>"
        let envHint = canonicalEnvHint(keyPath: keyPath, aliases: aliases, typeName: typeName)

        let secretValue: Secret<Value>
        do {
            secretValue = try resolved.decode(as: Value.self, context: decodingContext)
        } catch let decodeError as ValueDecodingError {
            issues.append(
                ValidationIssue(
                    keyPath: keyPath,
                    kind: .invalidValue,
                    message: context.redactor.scrub(decodeError.description),
                    origin: resolved.origin,
                    expectedType: typeName,
                    envVariableHint: envHint
                )
            )
            return nil
        } catch {
            issues.append(
                ValidationIssue(
                    keyPath: keyPath,
                    kind: .invalidValue,
                    message: context.redactor.scrub(String(describing: error)),
                    origin: resolved.origin,
                    expectedType: typeName,
                    envVariableHint: envHint
                )
            )
            return nil
        }

        var allValid = true
        for validator in validators {
            if let issue = validator.forSecret().validate(
                secretValue,
                keyPath: keyPath,
                origin: resolved.origin,
                envVariableHint: envHint,
                context: context
            ) {
                issues.append(issue)
                allValid = false
            }
        }
        guard allValid else { return nil }

        let metadata = SettingMetadata<Secret<Value>>(
            keyPath: keyPath,
            value: secretValue,
            isSecret: true,
            origin: resolved.origin,
            overriddenOrigins: resolved.overriddenOrigins
        )
        if recordProvenance {
            recordProvenanceEntry(for: metadata, typeName: typeName)
        }
        return metadata
    }

    private func registerSecretInRedactor<Value>(_ value: Value) {
        if let str = value as? String {
            context.redactor.register(str)
        } else if let data = value as? Data {
            context.redactor.register(data)
        } else if let bytes = value as? [UInt8] {
            context.redactor.register(Data(bytes))
        }
    }

    private mutating func recordProvenanceEntry<Value: Sendable>(
        for metadata: SettingMetadata<Value>,
        typeName: String,
        customDisplay: String? = nil
    ) {
        let display = metadata.isSecret ? "**********" : (customDisplay ?? metadata.displayValue)
        provenanceEntries.append(
            ProvenanceEntry(
                keyPath: metadata.keyPath,
                typeName: typeName,
                isSecret: metadata.isSecret,
                displayValue: display,
                origin: metadata.origin,
                overriddenOrigins: metadata.overriddenOrigins
            )
        )
    }

    private func canonicalEnvHint(
        keyPath: [String],
        aliases: [SettingAlias],
        typeName: String
    ) -> String {
        DotEnvExporter.resolvedEnvName(
            for: SettingFieldDescriptor(
                name: keyPath.last ?? "",
                keyPath: keyPath,
                aliases: aliases,
                typeName: typeName
            ),
            configuration: configuration
        )
    }

    private static func collectDeclaredSchemaPaths(
        from descriptors: [SettingFieldDescriptor],
        configuration: SettingsConfiguration,
        parentPath: [String] = []
    ) -> (declaredPaths: [[String]], arbitraryPrefixes: [[String]]) {
        var declared: [[String]] = []
        var prefixes: [[String]] = []

        let registerEnvKeyAsPath: (String, Bool) -> Void = { envKey, allowsDynamic in
            guard let stripped = EnvironmentKeyMapper.stripPrefix(
                from: envKey.trimmingCharacters(in: .whitespaces),
                prefix: configuration.envPrefix,
                caseSensitive: configuration.caseSensitive
            ), !stripped.isEmpty else {
                return
            }
            let segments = EnvironmentKeyMapper.splitKeyPath(
                stripped,
                delimiter: configuration.envNestedDelimiter,
                maxSplits: configuration.envNestedMaxSplit,
                caseSensitive: configuration.caseSensitive
            )
            guard !segments.isEmpty else { return }
            declared.append(segments)
            if allowsDynamic {
                prefixes.append(segments)
            }
        }

        for field in descriptors {
            let fullPath = field.keyPath.isEmpty ? (parentPath + [field.name]) : field.keyPath
            if case .object(let children) = field.schemaType, !children.isEmpty {
                declared.append(fullPath)
                let rebased = children.map { child -> SettingFieldDescriptor in
                    let childPath = child.keyPath.starts(with: fullPath)
                        ? child.keyPath
                        : (fullPath + child.keyPath)
                    return SettingFieldDescriptor(
                        name: child.name,
                        keyPath: childPath,
                        envVariable: child.envVariable,
                        aliases: child.aliases,
                        typeName: child.typeName,
                        schemaType: child.schemaType,
                        isOptional: child.isOptional,
                        isSecret: child.isSecret,
                        hasDefault: child.hasDefault,
                        defaultDisplay: child.defaultDisplay,
                        help: child.help,
                        deprecated: child.deprecated,
                        examples: child.examples,
                        allowsArbitraryChildKeys: child.allowsArbitraryChildKeys
                    )
                }
                let nested = collectDeclaredSchemaPaths(
                    from: rebased,
                    configuration: configuration,
                    parentPath: fullPath
                )
                declared.append(contentsOf: nested.declaredPaths)
                prefixes.append(contentsOf: nested.arbitraryPrefixes)
            } else {
                declared.append(fullPath)
                if field.allowsArbitraryChildKeys {
                    prefixes.append(fullPath)
                }
            }

            if let explicitEnv = field.envVariable, !explicitEnv.isEmpty {
                registerEnvKeyAsPath(explicitEnv, field.allowsArbitraryChildKeys)
            }

            for alias in field.aliases {
                switch alias {
                case .configPath(let altPath):
                    declared.append(altPath)
                    if field.allowsArbitraryChildKeys {
                        prefixes.append(altPath)
                    }
                case .env(let envAlias):
                    registerEnvKeyAsPath(envAlias, field.allowsArbitraryChildKeys)
                case .cli(let cliAlias):
                    let strippedCLI = cliAlias.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
                    if !strippedCLI.isEmpty {
                        declared.append([strippedCLI])
                        if field.allowsArbitraryChildKeys {
                            prefixes.append([strippedCLI])
                        }
                    }
                }
            }
        }

        return (declared, prefixes)
    }

    private static func isMetaConfigKey(_ path: [String]) -> Bool {
        guard let first = path.first else { return false }
        if first == "$schema" || first == "profiles" {
            return true
        }
        if path.count == 1 && first.lowercased() == "profile" {
            return true
        }
        return false
    }
}
