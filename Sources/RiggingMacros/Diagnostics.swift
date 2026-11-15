import SwiftDiagnostics
import SwiftSyntax

/// Compile-time diagnostic messages emitted by `RiggingMacros`.
public enum RiggingMacroDiagnostic: DiagnosticMessage, Error, Equatable {
    case notAStruct(macroName: String)
    case notAStoredProperty(macroName: String)
    case staticPropertyNotAllowed(macroName: String)
    case multipleBindings(macroName: String)
    case missingTypeAnnotation(propertyName: String, macroName: String)
    case immutablePropertyWithDefault(propertyName: String, macroName: String)
    case unannotatedUninitializedProperty(propertyName: String)
    case invalidSecretSettingType(propertyName: String, actualType: String)
    case outsideSettingsStruct(macroName: String)
    case conflictingSettingAttributes(propertyName: String)

    public var message: String {
        switch self {
        case .notAStruct(let macroName):
            return "@\(macroName) can only be applied to a struct declaration."
        case .notAStoredProperty(let macroName):
            return "@\(macroName) can only be applied to a stored property."
        case .staticPropertyNotAllowed(let macroName):
            return "@\(macroName) cannot be applied to a static or class property."
        case .multipleBindings(let macroName):
            return "@\(macroName) requires a single property declaration per binding."
        case .missingTypeAnnotation(let propertyName, let macroName):
            return "@\(macroName) property '\(propertyName)' requires an explicit type annotation."
        case .immutablePropertyWithDefault(let propertyName, let macroName):
            return "@\(macroName) property '\(propertyName)' with a default value must use 'var' instead of 'let' so loaded configuration values can override the default."
        case .unannotatedUninitializedProperty(let propertyName):
            return "Stored property '\(propertyName)' must be annotated with @Setting, @SecretSetting, or @NestedSettings, or declare a default value."
        case .invalidSecretSettingType(let propertyName, let actualType):
            return "@SecretSetting property '\(propertyName)' must have type 'Secret<Value>' or 'Secret<Value>?' (got '\(actualType)')."
        case .outsideSettingsStruct(let macroName):
            return "@\(macroName) can only be applied to properties inside a @Settings or @Rigged struct."
        case .conflictingSettingAttributes(let propertyName):
            return "Property '\(propertyName)' cannot combine multiple @Setting, @SecretSetting, or @NestedSettings attributes."
        }
    }

    public var diagnosticID: MessageID {
        let id: String
        switch self {
        case .notAStruct:
            id = "not_a_struct"
        case .notAStoredProperty:
            id = "not_a_stored_property"
        case .staticPropertyNotAllowed:
            id = "static_property_not_allowed"
        case .multipleBindings:
            id = "multiple_bindings"
        case .missingTypeAnnotation:
            id = "missing_type_annotation"
        case .immutablePropertyWithDefault:
            id = "immutable_property_with_default"
        case .unannotatedUninitializedProperty:
            id = "unannotated_uninitialized_property"
        case .invalidSecretSettingType:
            id = "invalid_secret_setting_type"
        case .outsideSettingsStruct:
            id = "outside_settings_struct"
        case .conflictingSettingAttributes:
            id = "conflicting_setting_attributes"
        }
        return MessageID(domain: "RiggingMacros", id: id)
    }

    public var severity: DiagnosticSeverity {
        .error
    }
}
