import Foundation

/// Exports Draft 2020-12 JSON Schema documents from `RiggedSettings` field metadata.
public enum JSONSchemaExporter {
    public static let draft202012URI = "https://json-schema.org/draft/2020-12/schema"

    public static func export<S: RiggedSettings>(
        for settingsType: S.Type,
        title: String? = nil,
        prettyPrinted: Bool = true
    ) -> String {
        export(
            fields: S.fieldDescriptors,
            configuration: S.configuration,
            title: title ?? String(describing: S.self),
            prettyPrinted: prettyPrinted
        )
    }

    public static func export(
        fields: [SettingFieldDescriptor],
        configuration: SettingsConfiguration = SettingsConfiguration(),
        title: String = "Settings",
        prettyPrinted: Bool = true
    ) -> String {
        var rootObject = buildObjectSchema(
            fields: fields,
            additionalProperties: configuration.extraKeys != .forbid
        )
        rootObject["$schema"] = draft202012URI
        rootObject["title"] = title

        // Allow "$schema" and "profiles" in config files even when extraKeys == .forbid
        if var properties = rootObject["properties"] as? [String: Any] {
            if properties["$schema"] == nil {
                properties["$schema"] = [
                    "type": "string",
                    "description": "JSON Schema URI for editor validation.",
                ] as [String: Any]
            }
            if !configuration.projectConfigFiles.isEmpty || configuration.xdgAppName != nil {
                if properties["profiles"] == nil {
                    let profileItemSchema = buildObjectSchema(
                        fields: fields,
                        additionalProperties: configuration.extraKeys != .forbid,
                        allOptional: true
                    )
                    properties["profiles"] = [
                        "type": "object",
                        "description": "Named environment profile overrides.",
                        "additionalProperties": profileItemSchema,
                    ] as [String: Any]
                }
            }
            rootObject["properties"] = properties
        }

        var options: JSONSerialization.WritingOptions = [.sortedKeys, .withoutEscapingSlashes]
        if prettyPrinted {
            options.insert(.prettyPrinted)
        }
        guard let data = try? JSONSerialization.data(withJSONObject: rootObject, options: options),
              let string = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return string
    }

    // MARK: - Internal Builders

    private static func buildObjectSchema(
        fields: [SettingFieldDescriptor],
        additionalProperties: Bool,
        allOptional: Bool = false
    ) -> [String: Any] {
        var properties: [String: Any] = [:]
        var required: [String] = []

        for field in fields {
            let key = field.keyPath.last ?? field.name
            properties[key] = buildFieldSchema(field)
            if !allOptional && !field.isOptional && !field.hasDefault {
                required.append(key)
            }
        }

        var schema: [String: Any] = [
            "type": "object",
            "properties": properties,
            "additionalProperties": additionalProperties,
        ]
        if !required.isEmpty {
            schema["required"] = required.sorted()
        }
        return schema
    }

    private static func buildFieldSchema(_ field: SettingFieldDescriptor) -> [String: Any] {
        var schema = buildTypeSchema(field.schemaType)

        if field.isOptional {
            if let existingType = schema["type"] as? String {
                schema["type"] = [existingType, "null"]
            } else {
                schema = ["anyOf": [schema, ["type": "null"]]]
            }
        }

        if let help = field.help, !help.isEmpty {
            schema["description"] = help
        }

        if let deprecated = field.deprecated {
            schema["deprecated"] = true
            if !deprecated.isEmpty {
                schema["x-deprecationMessage"] = deprecated
            }
        }

        if field.isSecret {
            schema["writeOnly"] = true
            schema["x-secret"] = true
        } else if let defaultDisplay = field.defaultDisplay {
            schema["default"] = coerceDefaultJSONValue(defaultDisplay, schemaType: field.schemaType)
        }

        if !field.examples.isEmpty && !field.isSecret {
            schema["examples"] = field.examples
        }

        if let envVariable = field.envVariable {
            schema["x-envVariable"] = envVariable
        }

        return schema
    }

    private static func buildTypeSchema(_ schemaType: JSONSchemaFieldType) -> [String: Any] {
        switch schemaType {
        case .string(let format):
            var dict: [String: Any] = ["type": "string"]
            if let format {
                dict["format"] = format
            }
            return dict
        case .integer:
            return ["type": "integer"]
        case .number:
            return ["type": "number"]
        case .boolean:
            return ["type": "boolean"]
        case .array(let items):
            return [
                "type": "array",
                "items": buildTypeSchema(items),
            ]
        case .dictionary(let values):
            return [
                "type": "object",
                "additionalProperties": buildTypeSchema(values),
            ]
        case .enumValues(let cases):
            return [
                "type": "string",
                "enum": cases,
            ]
        case .object(let nestedFields):
            return buildObjectSchema(fields: nestedFields, additionalProperties: true)
        }
    }

    private static func coerceDefaultJSONValue(
        _ display: String,
        schemaType: JSONSchemaFieldType
    ) -> Any {
        switch schemaType {
        case .integer:
            if let intVal = Int64(display) { return NSNumber(value: intVal) }
            return display
        case .number:
            if let doubleVal = Double(display), doubleVal.isFinite { return NSNumber(value: doubleVal) }
            return display
        case .boolean:
            if display.lowercased() == "true" { return NSNumber(value: true) }
            if display.lowercased() == "false" { return NSNumber(value: false) }
            return display
        default:
            return display
        }
    }
}
