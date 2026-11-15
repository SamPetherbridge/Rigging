import SwiftCompilerPlugin
import SwiftSyntaxMacros

@main
struct RiggingCompilerPlugin: CompilerPlugin {
    let providingMacros: [Macro.Type] = [
        SettingsMacro.self,
        SettingMacro.self,
        SecretSettingMacro.self,
        NestedSettingsMacro.self,
    ]
}
