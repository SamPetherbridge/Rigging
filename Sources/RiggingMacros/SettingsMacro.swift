import SwiftDiagnostics
import SwiftSyntax
import SwiftSyntaxMacros

/// Implementation of both `@Settings` and `@Rigged` attached member + extension macros.
public struct SettingsMacro: MemberMacro, ExtensionMacro {
    private static let canonicalConfigParamOrder: [String] = [
        "envPrefix",
        "envNestedDelimiter",
        "envNestedMaxSplit",
        "caseSensitive",
        "envIgnoreEmpty",
        "envNullStrings",
        "extraKeys",
        "dotEnvFiles",
        "projectConfigFiles",
        "xdgAppName",
        "profile",
        "secretsDirectory",
        "secretsNestedSubdir",
        "trimSecretTrailingNewline",
        "envListStrategy",
        "managedPreferencesDomain",
    ]

    // MARK: - MemberMacro

    public static func expansion(
        of node: AttributeSyntax,
        providingMembersOf declaration: some DeclGroupSyntax,
        conformingTo protocols: [TypeSyntax],
        in context: some MacroExpansionContext
    ) throws -> [DeclSyntax] {
        let macroName = FieldInspector.attributeSimpleName(node) ?? "Settings"

        guard let structDecl = declaration.as(StructDeclSyntax.self) else {
            context.diagnose(
                Diagnostic(
                    node: Syntax(node),
                    message: RiggingMacroDiagnostic.notAStruct(macroName: macroName)
                )
            )
            return []
        }

        let apiAccess = synthesizedAPIAccessPrefix(for: structDecl)
        let parsedFields = collectFields(from: structDecl, in: context)
        let hasUserInit = structDecl.memberBlock.members.contains {
            $0.decl.is(InitializerDeclSyntax.self)
        }

        var members: [DeclSyntax] = []

        // 1. Backing provenance & redactor storage (Equatable-neutral so user `Equatable` compares field values)
        members.append("private var _riggingStorage = _RiggingStorage()")

        // 2. Projected `$property` metadata accessors for `@Setting` and `@SecretSetting` fields
        for field in parsedFields where field.kind == .setting || field.kind == .secretSetting {
            let escapedName = FieldInspector.escapeSwiftStringLiteral(field.cleanName)
            let isSecretLiteral = field.kind == .secretSetting ? "true" : "false"
            let projected: DeclSyntax = """
                \(raw: field.accessPrefix)var $\(raw: field.cleanName): SettingMetadata<\(raw: field.fullTypeText)> {
                    _riggingStorage.metadata(
                        for: "\(raw: escapedName)",
                        defaultKeyPath: ["\(raw: escapedName)"],
                        value: self.\(raw: field.rawIdentifier),
                        isSecret: \(raw: isSecretLiteral)
                    )
                }
                """
            members.append(projected)
        }

        // 3. `provenance` and `redactor` instance properties
        members.append(
            """
            \(raw: apiAccess)var provenance: ProvenanceReport {
                if let report = _riggingStorage.provenanceReport {
                    return report
                }
                return ProvenanceReport(entries: Self._riggingFallbackProvenanceEntries(for: self, prefix: []))
            }
            """
        )

        members.append(
            """
            \(raw: apiAccess)var redactor: DiagnosticRedactor {
                _riggingStorage.redactor
            }
            """
        )

        // 4. Memberwise initializer (when user has not declared a custom `init`) + private loader initializer
        if !hasUserInit {
            members.append(buildMemberwiseInit(fields: parsedFields, apiAccess: apiAccess))
        }
        members.append(buildLoaderInit(fields: parsedFields))

        // 5. `configuration` static property
        members.append(buildConfigurationProperty(from: node, apiAccess: apiAccess))

        // 6. `fieldDescriptors` static property & `RiggedNestedSettings.fieldDescriptors(prefix:configuration:)`
        members.append(
            """
            \(raw: apiAccess)static var fieldDescriptors: [SettingFieldDescriptor] {
                fieldDescriptors(prefix: [], configuration: configuration)
            }
            """
        )
        members.append(buildFieldDescriptorsMethod(fields: parsedFields, apiAccess: apiAccess))

        // 7. `RiggedNestedSettings.enqueueSecrets(into:prefix:)`
        members.append(buildEnqueueSecretsMethod(fields: parsedFields, apiAccess: apiAccess))

        // 8. `RiggedNestedSettings.decodeNested(from:prefix:)`
        members.append(buildDecodeNestedMethod(fields: parsedFields, apiAccess: apiAccess))

        // 9. `RiggedNestedSettings.validate(_:prefix:)` bridging user `validate(_:)` with prefix rebasing
        members.append(
            """
            \(raw: apiAccess)static func validate(_ settings: Self, prefix: [String]) -> [ValidationIssue] {
                _RiggingMacroSupport.rebaseIssues(Self.validate(settings), prefix: prefix)
            }
            """
        )

        // 10. `RiggedSettings.load(context:overrides:)`
        members.append(
            """
            \(raw: apiAccess)static func load(
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
            """
        )

        // 11. Fallback provenance builder for direct `init(...)` instances
        members.append(buildFallbackProvenanceMethod(fields: parsedFields))

        return members
    }

    // MARK: - ExtensionMacro

    public static func expansion(
        of node: AttributeSyntax,
        attachedTo declaration: some DeclGroupSyntax,
        providingExtensionsOf type: some TypeSyntaxProtocol,
        conformingTo protocols: [TypeSyntax],
        in context: some MacroExpansionContext
    ) throws -> [ExtensionDeclSyntax] {
        guard let structDecl = declaration.as(StructDeclSyntax.self) else {
            return []
        }

        let existingInherited = inheritedProtocolNames(from: structDecl)
        let targetProtocols = ["RiggedSettings", "RiggedNestedSettings", "Sendable"].filter {
            !existingInherited.contains($0)
        }

        guard !targetProtocols.isEmpty else {
            return []
        }

        let conformanceList = targetProtocols.joined(separator: ", ")
        let extDecl: DeclSyntax = "extension \(type.trimmed): \(raw: conformanceList) {}"
        guard let extensionSyntax = extDecl.as(ExtensionDeclSyntax.self) else {
            return []
        }
        return [extensionSyntax]
    }

    // MARK: - Helpers

    private static func synthesizedAPIAccessPrefix(for structDecl: StructDeclSyntax) -> String {
        for modifier in structDecl.modifiers where modifier.detail == nil {
            switch modifier.name.tokenKind {
            case .keyword(.public), .keyword(.open):
                return "public "
            case .keyword(.package):
                return "package "
            default:
                continue
            }
        }
        return ""
    }

    private static func inheritedProtocolNames(from structDecl: StructDeclSyntax) -> Set<String> {
        guard let clause = structDecl.inheritanceClause else { return [] }
        var names: Set<String> = []
        for inherited in clause.inheritedTypes {
            let text = inherited.type.trimmedDescription
            if let lastComponent = text.split(separator: ".").last {
                names.insert(String(lastComponent))
            }
            names.insert(text)
        }
        return names
    }

    private static func collectFields(
        from structDecl: StructDeclSyntax,
        in context: some MacroExpansionContext
    ) -> [ParsedSettingField] {
        var fields: [ParsedSettingField] = []

        for member in structDecl.memberBlock.members {
            guard let varDecl = member.decl.as(VariableDeclSyntax.self) else {
                continue
            }
            if FieldInspector.isStaticOrClass(varDecl.modifiers) {
                continue
            }

            let settingAttrs = FieldInspector.findSettingAttributes(on: varDecl.attributes)
            if settingAttrs.isEmpty {
                // Check for unannotated stored properties without an inline initializer
                for binding in varDecl.bindings where FieldInspector.isStoredBinding(binding) {
                    if binding.initializer == nil {
                        let isOptionalType: Bool
                        if let typeSyntax = binding.typeAnnotation?.type {
                            isOptionalType = FieldInspector.inspectType(typeSyntax).isOptional
                        } else {
                            isOptionalType = false
                        }
                        if !isOptionalType {
                            let propName = binding.pattern.trimmedDescription
                            context.diagnose(
                                Diagnostic(
                                    node: Syntax(varDecl),
                                    message: RiggingMacroDiagnostic.unannotatedUninitializedProperty(
                                        propertyName: propName
                                    )
                                )
                            )
                        }
                    }
                }
                continue
            }

            guard settingAttrs.count == 1, let firstAttr = settingAttrs.first else {
                // Conflicting attribute diagnostic is emitted by SettingMacro
                continue
            }

            // Diagnostics on invalid annotated properties are emitted once by SettingMacro / SecretSettingMacro
            if let parsed = FieldInspector.parseField(
                from: varDecl,
                attribute: firstAttr.attribute,
                kind: firstAttr.kind,
                in: context,
                emitDiagnostics: false
            ) {
                fields.append(parsed)
            }
        }

        return fields
    }

    // MARK: - Initializer Builders

    private static func buildMemberwiseInit(
        fields: [ParsedSettingField],
        apiAccess: String
    ) -> DeclSyntax {
        let paramStrings = fields.map { field -> String in
            if let defaultExpr = field.defaultExprText {
                return "\(field.rawIdentifier): \(field.fullTypeText) = \(defaultExpr)"
            } else if field.isOptional {
                return "\(field.rawIdentifier): \(field.fullTypeText) = nil"
            } else {
                return "\(field.rawIdentifier): \(field.fullTypeText)"
            }
        }

        var bodyLines: [String] = []
        for field in fields {
            bodyLines.append("self.\(field.rawIdentifier) = \(field.rawIdentifier)")
        }

        let secretFields = fields.filter { $0.kind == .secretSetting }
        if !secretFields.isEmpty {
            bodyLines.append("let _storage = _RiggingStorage()")
            for secretField in secretFields {
                bodyLines.append("_RiggingMacroSupport.registerDirectSecret(\(secretField.rawIdentifier), into: _storage.redactor)")
            }
            bodyLines.append("self._riggingStorage = _storage")
        } else {
            bodyLines.append("self._riggingStorage = _RiggingStorage()")
        }

        let paramsJoined = paramStrings.joined(separator: ",\n    ")
        let bodyJoined = bodyLines.joined(separator: "\n    ")

        if paramStrings.isEmpty {
            return """
                \(raw: apiAccess)init() {
                    \(raw: bodyJoined)
                }
                """
        }

        return """
            \(raw: apiAccess)init(
                \(raw: paramsJoined)
            ) {
                \(raw: bodyJoined)
            }
            """
    }

    private static func buildLoaderInit(fields: [ParsedSettingField]) -> DeclSyntax {
        var paramStrings = ["_riggingStorage: _RiggingStorage"]
        for field in fields {
            paramStrings.append("\(field.rawIdentifier): \(field.fullTypeText)")
        }

        var bodyLines = ["self._riggingStorage = _riggingStorage"]
        for field in fields {
            bodyLines.append("self.\(field.rawIdentifier) = \(field.rawIdentifier)")
        }

        let paramsJoined = paramStrings.joined(separator: ",\n    ")
        let bodyJoined = bodyLines.joined(separator: "\n    ")

        return """
            private init(
                \(raw: paramsJoined)
            ) {
                \(raw: bodyJoined)
            }
            """
    }

    // MARK: - Configuration Builder

    private static func buildConfigurationProperty(
        from node: AttributeSyntax,
        apiAccess: String
    ) -> DeclSyntax {
        let argMap = FieldInspector.argumentDictionary(from: node)
        var orderedArgs: [String] = []
        for key in canonicalConfigParamOrder {
            if let expr = argMap[key] {
                orderedArgs.append("\(key): \(expr.trimmedDescription)")
            }
        }

        if orderedArgs.isEmpty {
            return """
                \(raw: apiAccess)static var configuration: SettingsConfiguration {
                    SettingsConfiguration()
                }
                """
        }

        let argsJoined = orderedArgs.joined(separator: ",\n        ")
        return """
            \(raw: apiAccess)static var configuration: SettingsConfiguration {
                SettingsConfiguration(
                    \(raw: argsJoined)
                )
            }
            """
    }

    // MARK: - Schema Descriptors Builder

    private static func buildFieldDescriptorsMethod(
        fields: [ParsedSettingField],
        apiAccess: String
    ) -> DeclSyntax {
        guard !fields.isEmpty else {
            return """
                \(raw: apiAccess)static func fieldDescriptors(
                    prefix: [String],
                    configuration: SettingsConfiguration
                ) -> [SettingFieldDescriptor] {
                    []
                }
                """
        }

        let descriptorItems = fields.map { field -> String in
            let escapedName = FieldInspector.escapeSwiftStringLiteral(field.cleanName)
            let aliasesExpr = rebasedAliasesExpr(field.aliasesExpr)
            let isSecretLiteral = field.kind == .secretSetting ? "true" : "false"
            let hasNonNilDefault = field.hasExplicitDefault && !field.isNilLiteralDefault
            let hasDefaultLiteral = hasNonNilDefault ? "true" : "false"

            let defaultDisplayExpr: String
            if field.kind == .setting && hasNonNilDefault, let defaultExpr = field.defaultExprText {
                defaultDisplayExpr = "_RiggingMacroSupport.defaultDisplay(as: \(field.unwrappedTypeText).self, \(defaultExpr))"
            } else {
                defaultDisplayExpr = "nil"
            }

            let helpExpr: String
            if let explicitHelp = field.helpExpr {
                helpExpr = explicitHelp
            } else if let doc = field.documentation {
                helpExpr = "\"\(FieldInspector.escapeSwiftStringLiteral(doc))\""
            } else {
                helpExpr = "nil"
            }

            let deprecatedExpr = field.deprecatedExpr ?? "nil"
            let examplesExpr = field.examplesExpr ?? "[]"
            let arbitraryChildLiteral = field.allowsArbitraryChildKeys ? "true" : "false"

            return """
                SettingFieldDescriptor(
                    name: "\(escapedName)",
                    keyPath: prefix + ["\(escapedName)"],
                    aliases: \(aliasesExpr),
                    typeName: "\(FieldInspector.escapeSwiftStringLiteral(field.fullTypeText))",
                    schemaType: \(field.schemaTypeExpr),
                    isOptional: \(field.isOptional ? "true" : "false"),
                    isSecret: \(isSecretLiteral),
                    hasDefault: \(hasDefaultLiteral),
                    defaultDisplay: \(defaultDisplayExpr),
                    help: \(helpExpr),
                    deprecated: \(deprecatedExpr),
                    examples: \(examplesExpr),
                    allowsArbitraryChildKeys: \(arbitraryChildLiteral)
                )
                """
        }

        let joined = indentSubsequentLines(descriptorItems.joined(separator: ",\n"), by: 8)
        return """
            \(raw: apiAccess)static func fieldDescriptors(
                prefix: [String],
                configuration: SettingsConfiguration
            ) -> [SettingFieldDescriptor] {
                [
                    \(raw: joined)
                ]
            }
            """
    }

    // MARK: - Phase 1 Secret Enqueue Builder

    private static func buildEnqueueSecretsMethod(
        fields: [ParsedSettingField],
        apiAccess: String
    ) -> DeclSyntax {
        var statements: [String] = []

        for field in fields {
            let escapedName = FieldInspector.escapeSwiftStringLiteral(field.cleanName)
            let keyPathExpr = "prefix + [\"\(escapedName)\"]"
            let aliasesExpr = rebasedAliasesExpr(field.aliasesExpr)
            let hasNonNilDefault = field.hasExplicitDefault && !field.isNilLiteralDefault

            switch field.kind {
            case .secretSetting:
                let transformsExpr = field.transformsExpr ?? "[]"
                let allowLiteralExpr = field.allowLiteralInProjectConfigExpr ?? "false"
                let expectedType = FieldInspector.escapeSwiftStringLiteral(field.fullTypeText)
                statements.append(
                    """
                    loader.enqueueSecret(
                        keyPath: \(keyPathExpr),
                        aliases: \(aliasesExpr),
                        transforms: \(transformsExpr),
                        allowLiteralInProjectConfig: \(allowLiteralExpr),
                        expectedType: "\(expectedType)",
                        isOptional: \(field.isOptional ? "true" : "false"),
                        hasDefault: \(hasNonNilDefault ? "true" : "false")
                    )
                    """
                )

            case .setting:
                if let resolveExpr = field.resolveSecretsExpr, resolveExpr != "false" {
                    let expectedType = FieldInspector.escapeSwiftStringLiteral(field.fullTypeText)
                    let call = """
                        loader.enqueuePotentialSecretReference(
                            keyPath: \(keyPathExpr),
                            aliases: \(aliasesExpr),
                            expectedType: "\(expectedType)",
                            isOptional: \(field.isOptional ? "true" : "false"),
                            hasDefault: \(hasNonNilDefault ? "true" : "false")
                        )
                        """
                    if resolveExpr == "true" {
                        statements.append(call)
                    } else {
                        statements.append("if \(resolveExpr) {\n        \(call)\n    }")
                    }
                }

            case .nestedSettings:
                let nestedType = field.unwrappedTypeText
                if field.isOptional {
                    statements.append(
                        """
                        if _RiggingMacroSupport.shouldEnqueueOptionalNested(in: loader, at: \(keyPathExpr)) {
                            \(nestedType).enqueueSecrets(into: &loader, prefix: \(keyPathExpr))
                        }
                        """
                    )
                } else {
                    statements.append("\(nestedType).enqueueSecrets(into: &loader, prefix: \(keyPathExpr))")
                }
            }
        }

        let body = indentSubsequentLines(statements.joined(separator: "\n"), by: 4)
        return """
            \(raw: apiAccess)static func enqueueSecrets(
                into loader: inout SettingsLoader,
                prefix: [String]
            ) {
                \(raw: body)
            }
            """
    }

    // MARK: - Phase 2 Nested / Model Decoding Builder

    private static func buildDecodeNestedMethod(
        fields: [ParsedSettingField],
        apiAccess: String
    ) -> DeclSyntax {
        guard !fields.isEmpty else {
            return """
                \(raw: apiAccess)static func decodeNested(
                    from loader: inout SettingsLoader,
                    prefix: [String]
                ) -> Self? {
                    Self(_riggingStorage: _RiggingStorage())
                }
                """
        }

        var decodeLines: [String] = []
        var guardBindings: [String] = []
        var storageLines: [String] = []
        var initArgs: [String] = ["_riggingStorage: _storage"]

        let hasDirectMetadataFields = fields.contains { $0.kind == .setting || $0.kind == .secretSetting }

        for field in fields {
            let escapedName = FieldInspector.escapeSwiftStringLiteral(field.cleanName)
            let localVar = "_decoded_\(field.cleanName)"
            let unwrappedVar = "_val_\(field.cleanName)"
            let keyPathExpr = "prefix + [\"\(escapedName)\"]"
            let aliasesExpr = rebasedAliasesExpr(field.aliasesExpr)
            let hasNonNilDefault = field.hasExplicitDefault && !field.isNilLiteralDefault

            switch field.kind {
            case .setting:
                let targetType = field.unwrappedTypeText
                let envListExpr = field.envListStrategyExpr ?? "nil"
                let resolveSecretsExpr = field.resolveSecretsExpr ?? "false"
                let transformExpr: String
                if let rawTransform = field.transformsExpr {
                    transformExpr = "_RiggingMacroSupport.transforms(as: \(targetType).self, context: loader.context, \(rawTransform))"
                } else {
                    transformExpr = "nil"
                }
                let validatorsExpr: String
                if let rawValidate = field.validateExpr {
                    validatorsExpr = "_RiggingMacroSupport.validators(as: \(targetType).self, \(rawValidate))"
                } else {
                    validatorsExpr = "[]"
                }

                if field.isOptional {
                    let defaultArg = hasNonNilDefault ? (field.defaultExprText ?? "nil") : "nil"
                    decodeLines.append(
                        """
                        let \(localVar) = loader.decodeOptional(
                            \(targetType).self,
                            default: \(defaultArg),
                            keyPath: \(keyPathExpr),
                            aliases: \(aliasesExpr),
                            envListStrategy: \(envListExpr),
                            resolveSecrets: \(resolveSecretsExpr),
                            transform: \(transformExpr),
                            validators: \(validatorsExpr)
                        )
                        """
                    )
                } else if hasNonNilDefault, let defaultExpr = field.defaultExprText {
                    decodeLines.append(
                        """
                        let \(localVar) = loader.decodeDefaulted(
                            \(targetType).self,
                            default: \(defaultExpr),
                            keyPath: \(keyPathExpr),
                            aliases: \(aliasesExpr),
                            envListStrategy: \(envListExpr),
                            resolveSecrets: \(resolveSecretsExpr),
                            transform: \(transformExpr),
                            validators: \(validatorsExpr)
                        )
                        """
                    )
                } else {
                    decodeLines.append(
                        """
                        let \(localVar) = loader.decodeRequired(
                            \(targetType).self,
                            keyPath: \(keyPathExpr),
                            aliases: \(aliasesExpr),
                            envListStrategy: \(envListExpr),
                            resolveSecrets: \(resolveSecretsExpr),
                            transform: \(transformExpr),
                            validators: \(validatorsExpr)
                        )
                        """
                    )
                }

                guardBindings.append("let \(unwrappedVar) = \(localVar)")
                storageLines.append("_storage.recordField(\"\(escapedName)\", metadata: \(unwrappedVar))")
                initArgs.append("\(field.rawIdentifier): \(unwrappedVar).value")

            case .secretSetting:
                let innerType = field.secretInnerTypeText ?? "String"
                let validatorsExpr: String
                if let rawValidate = field.validateExpr {
                    validatorsExpr = "_RiggingMacroSupport.validators(as: \(innerType).self, \(rawValidate))"
                } else {
                    validatorsExpr = "[]"
                }

                if field.isOptional {
                    let defaultArg = hasNonNilDefault ? (field.defaultExprText ?? "nil") : "nil"
                    decodeLines.append(
                        """
                        let \(localVar) = loader.decodeOptionalSecret(
                            \(innerType).self,
                            default: \(defaultArg),
                            keyPath: \(keyPathExpr),
                            aliases: \(aliasesExpr),
                            validators: \(validatorsExpr)
                        )
                        """
                    )
                } else if hasNonNilDefault, let defaultExpr = field.defaultExprText {
                    decodeLines.append(
                        """
                        let \(localVar) = loader.decodeDefaultedSecret(
                            \(innerType).self,
                            default: \(defaultExpr),
                            keyPath: \(keyPathExpr),
                            aliases: \(aliasesExpr),
                            validators: \(validatorsExpr)
                        )
                        """
                    )
                } else {
                    decodeLines.append(
                        """
                        let \(localVar) = loader.decodeRequiredSecret(
                            \(innerType).self,
                            keyPath: \(keyPathExpr),
                            aliases: \(aliasesExpr),
                            validators: \(validatorsExpr)
                        )
                        """
                    )
                }

                guardBindings.append("let \(unwrappedVar) = \(localVar)")
                storageLines.append("_storage.recordField(\"\(escapedName)\", metadata: \(unwrappedVar))")
                initArgs.append("\(field.rawIdentifier): \(unwrappedVar).value")

            case .nestedSettings:
                let nestedType = field.unwrappedTypeText
                if field.isOptional {
                    if hasNonNilDefault, let defaultExpr = field.defaultExprText {
                        decodeLines.append(
                            """
                            let \(localVar) = _RiggingMacroSupport.decodeOptionalNestedWithDefault(
                                \(nestedType).self,
                                from: &loader,
                                keyPath: \(keyPathExpr),
                                default: \(defaultExpr)
                            )
                            """
                        )
                    } else {
                        decodeLines.append(
                            "let \(localVar) = loader.decodeOptionalNested(\(nestedType).self, keyPath: \(keyPathExpr))"
                        )
                    }
                } else {
                    decodeLines.append(
                        "let \(localVar) = loader.decodeNested(\(nestedType).self, keyPath: \(keyPathExpr))"
                    )
                }

                guardBindings.append("let \(unwrappedVar) = \(localVar)")
                initArgs.append("\(field.rawIdentifier): \(unwrappedVar)")
            }
        }

        let decodeJoined = indentSubsequentLines(decodeLines.joined(separator: "\n"), by: 4)
        let guardJoined = guardBindings.joined(separator: ",\n          ")
        let storageDecl = hasDirectMetadataFields
            ? "var _storage = _RiggingStorage(redactor: loader.context.redactor)"
            : "let _storage = _RiggingStorage(redactor: loader.context.redactor)"
        let storageJoined = storageLines.isEmpty ? "" : ("\n    " + storageLines.joined(separator: "\n    "))
        let initJoined = initArgs.joined(separator: ",\n        ")

        return """
            \(raw: apiAccess)static func decodeNested(
                from loader: inout SettingsLoader,
                prefix: [String]
            ) -> Self? {
                \(raw: decodeJoined)
                guard \(raw: guardJoined) else {
                    return nil
                }
                \(raw: storageDecl)\(raw: storageJoined)
                return Self(
                    \(raw: initJoined)
                )
            }
            """
    }

    // MARK: - Fallback Provenance Builder

    private static func buildFallbackProvenanceMethod(fields: [ParsedSettingField]) -> DeclSyntax {
        guard !fields.isEmpty else {
            return """
                private static func _riggingFallbackProvenanceEntries(
                    for instance: Self,
                    prefix: [String]
                ) -> [ProvenanceEntry] {
                    []
                }
                """
        }

        var lines: [String] = ["var entries: [ProvenanceEntry] = []"]
        for field in fields {
            let escapedName = FieldInspector.escapeSwiftStringLiteral(field.cleanName)
            let escapedType = FieldInspector.escapeSwiftStringLiteral(field.fullTypeText)
            switch field.kind {
            case .setting:
                lines.append(
                    """
                    entries.append(
                        _RiggingMacroSupport.fallbackProvenanceEntry(
                            metadata: instance.$\(field.cleanName),
                            prefix: prefix,
                            typeName: "\(escapedType)"
                        )
                    )
                    """
                )
            case .secretSetting:
                lines.append(
                    """
                    entries.append(
                        _RiggingMacroSupport.fallbackProvenanceEntry(
                            metadata: instance.$\(field.cleanName),
                            prefix: prefix,
                            typeName: "\(escapedType)"
                        )
                    )
                    """
                )
            case .nestedSettings:
                if field.isOptional {
                    lines.append(
                        """
                        if let nestedVal = instance.\(field.rawIdentifier) {
                            entries.append(
                                contentsOf: _RiggingMacroSupport.nestedFallbackEntries(
                                    from: nestedVal,
                                    prefix: prefix + ["\(escapedName)"]
                                )
                            )
                        }
                        """
                    )
                } else {
                    lines.append(
                        """
                        entries.append(
                            contentsOf: _RiggingMacroSupport.nestedFallbackEntries(
                                from: instance.\(field.rawIdentifier),
                                prefix: prefix + ["\(escapedName)"]
                            )
                        )
                        """
                    )
                }
            }
        }
        lines.append("return entries")

        let bodyJoined = indentSubsequentLines(lines.joined(separator: "\n"), by: 4)
        return """
            private static func _riggingFallbackProvenanceEntries(
                for instance: Self,
                prefix: [String]
            ) -> [ProvenanceEntry] {
                \(raw: bodyJoined)
            }
            """
    }

    private static func indentSubsequentLines(_ text: String, by spaces: Int) -> String {
        guard !text.isEmpty, spaces > 0 else { return text }
        let pad = String(repeating: " ", count: spaces)
        let splitLines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard let first = splitLines.first else { return text }
        var out = String(first)
        for line in splitLines.dropFirst() {
            if line.isEmpty {
                out += "\n"
            } else {
                out += "\n" + pad + line
            }
        }
        return out
    }

    private static func rebasedAliasesExpr(_ rawAliases: String?) -> String {
        guard let rawAliases, rawAliases != "[]" else {
            return "[]"
        }
        return "_RiggingMacroSupport.rebaseAliases(\(rawAliases), prefix: prefix)"
    }
}
