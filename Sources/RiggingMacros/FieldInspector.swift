import Foundation
import SwiftDiagnostics
import SwiftSyntax
import SwiftSyntaxMacros

enum SettingAttributeKind: Equatable {
    case setting
    case secretSetting
    case nestedSettings

    var attributeDisplayName: String {
        switch self {
        case .setting: return "Setting"
        case .secretSetting: return "SecretSetting"
        case .nestedSettings: return "NestedSettings"
        }
    }
}

struct ParsedSettingField {
    let rawIdentifier: String
    let cleanName: String
    let accessPrefix: String
    let isLet: Bool
    let kind: SettingAttributeKind
    let fullTypeText: String
    let unwrappedTypeText: String
    let secretInnerTypeText: String?
    let isOptional: Bool
    let defaultExprText: String?
    let hasExplicitDefault: Bool
    let isNilLiteralDefault: Bool
    let documentation: String?
    let aliasesExpr: String?
    let validateExpr: String?
    let transformsExpr: String?
    let envListStrategyExpr: String?
    let resolveSecretsExpr: String?
    let allowLiteralInProjectConfigExpr: String?
    let helpExpr: String?
    let deprecatedExpr: String?
    let examplesExpr: String?
    let schemaTypeExpr: String
    let allowsArbitraryChildKeys: Bool
}

enum FieldInspector {
    // MARK: - Access Level

    static func accessPrefix(from modifiers: DeclModifierListSyntax) -> String {
        for modifier in modifiers where modifier.detail == nil {
            switch modifier.name.tokenKind {
            case .keyword(.public), .keyword(.open):
                return "public "
            case .keyword(.package):
                return "package "
            case .keyword(.fileprivate):
                return "fileprivate "
            case .keyword(.private):
                return "private "
            default:
                continue
            }
        }
        return ""
    }

    static func isStaticOrClass(_ modifiers: DeclModifierListSyntax) -> Bool {
        modifiers.contains { modifier in
            modifier.name.tokenKind == .keyword(.static) || modifier.name.tokenKind == .keyword(.class)
        }
    }

    static func isStoredBinding(_ binding: PatternBindingSyntax) -> Bool {
        guard let accessorBlock = binding.accessorBlock else {
            return true
        }
        switch accessorBlock.accessors {
        case .getter:
            return false
        case .accessors(let list):
            if list.isEmpty {
                return true
            }
            return list.allSatisfy { accessor in
                let kind = accessor.accessorSpecifier.tokenKind
                return kind == .keyword(.willSet) || kind == .keyword(.didSet)
            }
        }
    }

    // MARK: - Attribute Classification

    static func attributeSimpleName(_ attr: AttributeSyntax) -> String? {
        if let ident = attr.attributeName.as(IdentifierTypeSyntax.self) {
            return ident.name.text
        }
        if let member = attr.attributeName.as(MemberTypeSyntax.self) {
            return member.name.text
        }
        return nil
    }

    static func isSettingsStructAttribute(_ attr: AttributeSyntax) -> Bool {
        guard let name = attributeSimpleName(attr) else { return false }
        return name == "Settings" || name == "Rigged"
    }

    static func settingAttributeKind(for attr: AttributeSyntax) -> SettingAttributeKind? {
        guard let name = attributeSimpleName(attr) else { return nil }
        switch name {
        case "Setting":
            return .setting
        case "SecretSetting":
            return .secretSetting
        case "NestedSettings":
            return .nestedSettings
        default:
            return nil
        }
    }

    static func findSettingAttributes(
        on attributes: AttributeListSyntax
    ) -> [(attribute: AttributeSyntax, kind: SettingAttributeKind)] {
        var matches: [(AttributeSyntax, SettingAttributeKind)] = []
        for element in attributes {
            guard let attr = element.as(AttributeSyntax.self),
                  let kind = settingAttributeKind(for: attr) else {
                continue
            }
            matches.append((attr, kind))
        }
        return matches
    }

    static func isEnclosedInSettingsStruct(_ lexicalContext: [Syntax]) -> Bool {
        guard let nearestType = lexicalContext.first(where: {
            $0.is(StructDeclSyntax.self)
                || $0.is(ClassDeclSyntax.self)
                || $0.is(EnumDeclSyntax.self)
                || $0.is(ActorDeclSyntax.self)
                || $0.is(ExtensionDeclSyntax.self)
        }) else {
            // Top-level standalone expansion without enclosing type context
            return true
        }
        guard let structDecl = nearestType.as(StructDeclSyntax.self) else {
            return false
        }
        return structDecl.attributes.contains { elem in
            guard let attr = elem.as(AttributeSyntax.self) else { return false }
            return isSettingsStructAttribute(attr)
        }
    }

    // MARK: - Type Inspection

    struct UnwrappedTypeInfo {
        let fullType: TypeSyntax
        let unwrappedType: TypeSyntax
        let isOptional: Bool
        let secretInnerType: TypeSyntax?
    }

    static func inspectType(_ typeSyntax: TypeSyntax) -> UnwrappedTypeInfo {
        let (unwrapped, isOptional) = unwrapOptional(typeSyntax)
        let secretInner = unwrapSecret(unwrapped)
        return UnwrappedTypeInfo(
            fullType: typeSyntax.trimmed,
            unwrappedType: unwrapped.trimmed,
            isOptional: isOptional,
            secretInnerType: secretInner?.trimmed
        )
    }

    static func inferLiteralType(from initializer: InitializerClauseSyntax?) -> TypeSyntax? {
        guard let expr = initializer?.value else { return nil }
        if expr.is(BooleanLiteralExprSyntax.self) {
            return TypeSyntax("Bool")
        }
        if expr.is(IntegerLiteralExprSyntax.self) {
            return TypeSyntax("Int")
        }
        if expr.is(FloatLiteralExprSyntax.self) {
            return TypeSyntax("Double")
        }
        if expr.is(StringLiteralExprSyntax.self) {
            return TypeSyntax("String")
        }
        return nil
    }

    private static func unwrapOptional(_ typeSyntax: TypeSyntax) -> (TypeSyntax, Bool) {
        if let opt = typeSyntax.as(OptionalTypeSyntax.self) {
            return (opt.wrappedType, true)
        }
        if let ident = typeSyntax.as(IdentifierTypeSyntax.self),
           ident.name.text == "Optional",
           let genericArgs = ident.genericArgumentClause?.arguments,
           genericArgs.count == 1,
           let firstType = genericArgType(genericArgs.first) {
            return (firstType, true)
        }
        if let member = typeSyntax.as(MemberTypeSyntax.self),
           member.name.text == "Optional",
           let genericArgs = member.genericArgumentClause?.arguments,
           genericArgs.count == 1,
           let firstType = genericArgType(genericArgs.first) {
            return (firstType, true)
        }
        return (typeSyntax, false)
    }

    private static func unwrapSecret(_ typeSyntax: TypeSyntax) -> TypeSyntax? {
        if let ident = typeSyntax.as(IdentifierTypeSyntax.self),
           ident.name.text == "Secret",
           let genericArgs = ident.genericArgumentClause?.arguments,
           genericArgs.count == 1,
           let inner = genericArgType(genericArgs.first) {
            return inner
        }
        if let member = typeSyntax.as(MemberTypeSyntax.self),
           member.name.text == "Secret",
           let genericArgs = member.genericArgumentClause?.arguments,
           genericArgs.count == 1,
           let inner = genericArgType(genericArgs.first) {
            return inner
        }
        return nil
    }

    private static func genericArgType(_ arg: GenericArgumentSyntax?) -> TypeSyntax? {
        guard let arg else { return nil }
        switch arg.argument {
        case .type(let t):
            return t
        default:
            return nil
        }
    }

    static func isDictionaryType(_ unwrappedType: TypeSyntax) -> Bool {
        if unwrappedType.is(DictionaryTypeSyntax.self) {
            return true
        }
        if let ident = unwrappedType.as(IdentifierTypeSyntax.self),
           ident.name.text == "Dictionary" {
            return true
        }
        if let member = unwrappedType.as(MemberTypeSyntax.self),
           member.name.text == "Dictionary" {
            return true
        }
        return false
    }

    static func schemaTypeExpression(
        for unwrappedType: TypeSyntax,
        kind: SettingAttributeKind,
        secretInner: TypeSyntax?,
        nestedPrefixExpr: String
    ) -> String {
        switch kind {
        case .nestedSettings:
            let nestedType = unwrappedType.trimmedDescription
            return ".object(fields: \(nestedType).fieldDescriptors(prefix: \(nestedPrefixExpr), configuration: configuration))"
        case .secretSetting:
            if let secretInner {
                return scalarOrCollectionSchemaExpr(for: secretInner.trimmed)
            }
            return ".string()"
        case .setting:
            return scalarOrCollectionSchemaExpr(for: unwrappedType.trimmed)
        }
    }

    private static func scalarOrCollectionSchemaExpr(for typeSyntax: TypeSyntax) -> String {
        if let arrayType = typeSyntax.as(ArrayTypeSyntax.self) {
            let elem = arrayType.element.trimmed
            if simpleTypeName(elem) == "UInt8" {
                return ".string(format: \"byte\")"
            }
            return ".array(items: \(scalarOrCollectionSchemaExpr(for: elem)))"
        }

        if let dictType = typeSyntax.as(DictionaryTypeSyntax.self) {
            let val = dictType.value.trimmed
            return ".dictionary(values: \(scalarOrCollectionSchemaExpr(for: val)))"
        }

        if let ident = typeSyntax.as(IdentifierTypeSyntax.self),
           let genericArgs = ident.genericArgumentClause?.arguments {
            let name = ident.name.text
            if (name == "Array" || name == "Set"),
               genericArgs.count == 1,
               let elem = genericArgType(genericArgs.first)?.trimmed {
                if name == "Array" && simpleTypeName(elem) == "UInt8" {
                    return ".string(format: \"byte\")"
                }
                return ".array(items: \(scalarOrCollectionSchemaExpr(for: elem)))"
            }
            if name == "Dictionary",
               genericArgs.count == 2,
               let second = genericArgType(genericArgs.dropFirst().first)?.trimmed {
                return ".dictionary(values: \(scalarOrCollectionSchemaExpr(for: second)))"
            }
        }

        let name = simpleTypeName(typeSyntax)
        switch name {
        case "String", "Substring", "Character", "ByteCount":
            return ".string()"
        case "UUID":
            return ".string(format: \"uuid\")"
        case "URL":
            return ".string(format: \"uri\")"
        case "Date":
            return ".string(format: \"date-time\")"
        case "Data":
            return ".string(format: \"byte\")"
        case "Duration":
            return ".string(format: \"duration\")"
        case "Bool":
            return ".boolean"
        case "Int", "Int8", "Int16", "Int32", "Int64",
             "UInt", "UInt8", "UInt16", "UInt32", "UInt64":
            return ".integer"
        case "Double", "Float", "Decimal", "CGFloat":
            return ".number"
        default:
            let rawType = typeSyntax.trimmedDescription
            return "_RiggingMacroSupport.schemaType(for: \(rawType).self, fallback: .string())"
        }
    }

    private static func simpleTypeName(_ typeSyntax: TypeSyntax) -> String {
        if let ident = typeSyntax.as(IdentifierTypeSyntax.self),
           ident.genericArgumentClause == nil {
            return ident.name.text
        }
        if let member = typeSyntax.as(MemberTypeSyntax.self),
           member.genericArgumentClause == nil {
            return member.name.text
        }
        return typeSyntax.trimmedDescription
    }

    // MARK: - Attribute Argument Extraction

    static func argumentDictionary(from attr: AttributeSyntax) -> [String: ExprSyntax] {
        guard let args = attr.arguments?.as(LabeledExprListSyntax.self) else {
            return [:]
        }
        var dict: [String: ExprSyntax] = [:]
        for item in args {
            if let label = item.label?.text {
                dict[label] = item.expression.trimmed
            }
        }
        return dict
    }

    // MARK: - Documentation Comment Extraction

    static func extractDocumentation(from varDecl: VariableDeclSyntax) -> String? {
        if let fromLeading = extractDocFromTrivia(varDecl.leadingTrivia) {
            return fromLeading
        }
        if let firstMod = varDecl.modifiers.first,
           let fromMod = extractDocFromTrivia(firstMod.leadingTrivia) {
            return fromMod
        }
        return extractDocFromTrivia(varDecl.bindingSpecifier.leadingTrivia)
    }

    static func extractDocFromTrivia(_ trivia: Trivia) -> String? {
        var currentLines: [String] = []

        for piece in trivia.pieces {
            switch piece {
            case .docLineComment(let raw):
                var line = raw
                if line.hasPrefix("///") {
                    line.removeFirst(3)
                }
                if line.hasPrefix(" ") {
                    line.removeFirst(1)
                }
                currentLines.append(line.trimmingCharacters(in: CharacterSet(charactersIn: "\r")))

            case .docBlockComment(let raw):
                let parsed = parseDocBlockComment(raw)
                currentLines.append(contentsOf: parsed)

            case .newlines(let count), .carriageReturns(let count), .carriageReturnLineFeeds(let count):
                if count > 1 {
                    currentLines.removeAll()
                }

            case .lineComment, .blockComment:
                currentLines.removeAll()

            default:
                break
            }
        }

        while let first = currentLines.first, first.trimmingCharacters(in: .whitespaces).isEmpty {
            currentLines.removeFirst()
        }
        while let last = currentLines.last, last.trimmingCharacters(in: .whitespaces).isEmpty {
            currentLines.removeLast()
        }

        guard !currentLines.isEmpty else { return nil }
        return currentLines.joined(separator: "\n")
    }

    private static func parseDocBlockComment(_ raw: String) -> [String] {
        var body = raw
        if body.hasPrefix("/**") {
            body.removeFirst(3)
        }
        if body.hasSuffix("*/") {
            body.removeLast(2)
        }
        let rawLines = body.split(separator: "\n", omittingEmptySubsequences: false)
        return rawLines.map { slice in
            var trimmed = slice.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("*") {
                trimmed.removeFirst()
                if trimmed.hasPrefix(" ") {
                    trimmed.removeFirst()
                }
            }
            return trimmed
        }
    }

    // MARK: - Field Parsing

    static func parseField(
        from varDecl: VariableDeclSyntax,
        attribute: AttributeSyntax,
        kind: SettingAttributeKind,
        in context: some MacroExpansionContext,
        emitDiagnostics: Bool
    ) -> ParsedSettingField? {
        let macroName = kind.attributeDisplayName

        if isStaticOrClass(varDecl.modifiers) {
            if emitDiagnostics {
                context.diagnose(
                    Diagnostic(
                        node: Syntax(varDecl),
                        message: RiggingMacroDiagnostic.staticPropertyNotAllowed(macroName: macroName)
                    )
                )
            }
            return nil
        }

        if varDecl.bindings.count != 1 {
            if emitDiagnostics {
                context.diagnose(
                    Diagnostic(
                        node: Syntax(varDecl),
                        message: RiggingMacroDiagnostic.multipleBindings(macroName: macroName)
                    )
                )
            }
            return nil
        }

        guard let binding = varDecl.bindings.first,
              isStoredBinding(binding),
              let identPattern = binding.pattern.as(IdentifierPatternSyntax.self) else {
            if emitDiagnostics {
                context.diagnose(
                    Diagnostic(
                        node: Syntax(varDecl),
                        message: RiggingMacroDiagnostic.notAStoredProperty(macroName: macroName)
                    )
                )
            }
            return nil
        }

        let rawIdentifier = identPattern.identifier.trimmedDescription
        let cleanName = rawIdentifier.replacingOccurrences(of: "`", with: "")
        let isLet = varDecl.bindingSpecifier.tokenKind == .keyword(.let)
        let hasExplicitDefault = binding.initializer != nil

        if isLet && hasExplicitDefault {
            if emitDiagnostics {
                context.diagnose(
                    Diagnostic(
                        node: Syntax(varDecl.bindingSpecifier),
                        message: RiggingMacroDiagnostic.immutablePropertyWithDefault(
                            propertyName: cleanName,
                            macroName: macroName
                        )
                    )
                )
            }
            return nil
        }

        guard let resolvedTypeSyntax = binding.typeAnnotation?.type ?? inferLiteralType(from: binding.initializer) else {
            if emitDiagnostics {
                context.diagnose(
                    Diagnostic(
                        node: Syntax(varDecl),
                        message: RiggingMacroDiagnostic.missingTypeAnnotation(
                            propertyName: cleanName,
                            macroName: macroName
                        )
                    )
                )
            }
            return nil
        }

        let typeInfo = inspectType(resolvedTypeSyntax)

        if kind == .secretSetting && typeInfo.secretInnerType == nil {
            if emitDiagnostics {
                context.diagnose(
                    Diagnostic(
                        node: Syntax(resolvedTypeSyntax),
                        message: RiggingMacroDiagnostic.invalidSecretSettingType(
                            propertyName: cleanName,
                            actualType: typeInfo.fullType.trimmedDescription
                        )
                    )
                )
            }
            return nil
        }

        let args = argumentDictionary(from: attribute)
        let defaultExpr = binding.initializer?.value.trimmed
        let defaultExprText = defaultExpr?.trimmedDescription
        let isNilLiteralDefault = defaultExpr?.is(NilLiteralExprSyntax.self) ?? false
        let escapedName = escapeSwiftStringLiteral(cleanName)
        let nestedPrefixExpr = "prefix + [\"\(escapedName)\"]"

        return ParsedSettingField(
            rawIdentifier: rawIdentifier,
            cleanName: cleanName,
            accessPrefix: accessPrefix(from: varDecl.modifiers),
            isLet: isLet,
            kind: kind,
            fullTypeText: typeInfo.fullType.trimmedDescription,
            unwrappedTypeText: typeInfo.unwrappedType.trimmedDescription,
            secretInnerTypeText: typeInfo.secretInnerType?.trimmedDescription,
            isOptional: typeInfo.isOptional,
            defaultExprText: defaultExprText,
            hasExplicitDefault: hasExplicitDefault,
            isNilLiteralDefault: isNilLiteralDefault,
            documentation: extractDocumentation(from: varDecl),
            aliasesExpr: args["aliases"]?.trimmedDescription,
            validateExpr: args["validate"]?.trimmedDescription,
            transformsExpr: args["transforms"]?.trimmedDescription,
            envListStrategyExpr: args["envListStrategy"]?.trimmedDescription,
            resolveSecretsExpr: args["resolveSecrets"]?.trimmedDescription,
            allowLiteralInProjectConfigExpr: args["allowLiteralInProjectConfig"]?.trimmedDescription,
            helpExpr: args["help"]?.trimmedDescription,
            deprecatedExpr: args["deprecated"]?.trimmedDescription,
            examplesExpr: args["examples"]?.trimmedDescription,
            schemaTypeExpr: schemaTypeExpression(
                for: typeInfo.unwrappedType,
                kind: kind,
                secretInner: typeInfo.secretInnerType,
                nestedPrefixExpr: nestedPrefixExpr
            ),
            allowsArbitraryChildKeys: isDictionaryType(typeInfo.unwrappedType)
        )
    }

    static func escapeSwiftStringLiteral(_ text: String) -> String {
        var escaped = ""
        escaped.reserveCapacity(text.count)
        for ch in text {
            switch ch {
            case "\\":
                escaped.append("\\\\")
            case "\"":
                escaped.append("\\\"")
            case "\n":
                escaped.append("\\n")
            case "\r":
                escaped.append("\\r")
            case "\t":
                escaped.append("\\t")
            default:
                escaped.append(ch)
            }
        }
        return escaped
    }
}
