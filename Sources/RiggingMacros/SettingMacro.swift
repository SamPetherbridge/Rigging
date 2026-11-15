import SwiftDiagnostics
import SwiftSyntax
import SwiftSyntaxMacros

/// Peer macro implementation for `@Setting`.
///
/// Validates property placement, storage semantics, and attribute conflicts while `SettingsMacro`
/// synthesizes the `$property` metadata projection alongside the backing `_RiggingStorage`.
public struct SettingMacro: PeerMacro {
    /// Validates the `@Setting` attribute against its target property declaration.
    ///
    /// - Parameters:
    ///   - node: The `@Setting` attribute syntax node.
    ///   - declaration: The declaration to which `@Setting` is attached.
    ///   - context: The macro expansion context used for emitting diagnostics.
    /// - Returns: An empty peer declaration list (`SettingsMacro` emits the `$property` projection).
    public static func expansion(
        of node: AttributeSyntax,
        providingPeersOf declaration: some DeclSyntaxProtocol,
        in context: some MacroExpansionContext
    ) throws -> [DeclSyntax] {
        validateFieldPeer(node: node, declaration: declaration, kind: .setting, in: context)
        return []
    }
}

/// Peer macro implementation for `@SecretSetting`.
public struct SecretSettingMacro: PeerMacro {
    /// Validates that `@SecretSetting` is attached to a `Secret<Value>` or `Secret<Value>?` stored property inside a `@Settings` or `@Rigged` struct.
    ///
    /// - Parameters:
    ///   - node: The `@SecretSetting` attribute syntax node.
    ///   - declaration: The declaration to which `@SecretSetting` is attached.
    ///   - context: The macro expansion context used for emitting diagnostics.
    /// - Returns: An empty peer declaration list (`SettingsMacro` emits the `$property` projection).
    public static func expansion(
        of node: AttributeSyntax,
        providingPeersOf declaration: some DeclSyntaxProtocol,
        in context: some MacroExpansionContext
    ) throws -> [DeclSyntax] {
        validateFieldPeer(node: node, declaration: declaration, kind: .secretSetting, in: context)
        return []
    }
}

/// Peer macro implementation for `@NestedSettings`.
public struct NestedSettingsMacro: PeerMacro {
    /// Validates that `@NestedSettings` is attached to a stored property inside a `@Settings` or `@Rigged` struct.
    ///
    /// - Parameters:
    ///   - node: The `@NestedSettings` attribute syntax node.
    ///   - declaration: The declaration to which `@NestedSettings` is attached.
    ///   - context: The macro expansion context used for emitting diagnostics.
    /// - Returns: An empty peer declaration list.
    public static func expansion(
        of node: AttributeSyntax,
        providingPeersOf declaration: some DeclSyntaxProtocol,
        in context: some MacroExpansionContext
    ) throws -> [DeclSyntax] {
        validateFieldPeer(node: node, declaration: declaration, kind: .nestedSettings, in: context)
        return []
    }
}

private func validateFieldPeer(
    node: AttributeSyntax,
    declaration: some DeclSyntaxProtocol,
    kind: SettingAttributeKind,
    in context: some MacroExpansionContext
) {
    let macroName = FieldInspector.attributeSimpleName(node) ?? kind.attributeDisplayName

    guard FieldInspector.isEnclosedInSettingsStruct(context.lexicalContext) else {
        context.diagnose(
            Diagnostic(
                node: Syntax(node),
                message: RiggingMacroDiagnostic.outsideSettingsStruct(macroName: macroName)
            )
        )
        return
    }

    guard let varDecl = declaration.as(VariableDeclSyntax.self) else {
        context.diagnose(
            Diagnostic(
                node: Syntax(declaration),
                message: RiggingMacroDiagnostic.notAStoredProperty(macroName: macroName)
            )
        )
        return
    }

    let allAttrs = FieldInspector.findSettingAttributes(on: varDecl.attributes)
    if allAttrs.count > 1 {
        if allAttrs.first?.attribute.id == node.id {
            let propName = varDecl.bindings.first?.pattern.trimmedDescription ?? "<property>"
            context.diagnose(
                Diagnostic(
                    node: Syntax(node),
                    message: RiggingMacroDiagnostic.conflictingSettingAttributes(propertyName: propName)
                )
            )
        }
        return
    }

    _ = FieldInspector.parseField(
        from: varDecl,
        attribute: node,
        kind: kind,
        in: context,
        emitDiagnostics: true
    )
}
