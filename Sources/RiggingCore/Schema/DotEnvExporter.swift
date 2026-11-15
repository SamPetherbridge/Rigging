import Foundation

/// Generates `.env.example` templates and GitHub-Flavored Markdown documentation tables
/// from `RiggedSettings` field descriptors, redacting all secret defaults by construction.
public enum DotEnvExporter {
    public static func exportDotEnvTemplate<S: RiggedSettings>(
        for settingsType: S.Type,
        includeDefaults: Bool = true
    ) -> String {
        exportDotEnvTemplate(
            fields: S.fieldDescriptors,
            configuration: S.configuration,
            includeDefaults: includeDefaults
        )
    }

    public static func exportDotEnvTemplate(
        fields: [SettingFieldDescriptor],
        configuration: SettingsConfiguration = SettingsConfiguration(),
        includeDefaults: Bool = true
    ) -> String {
        let flattened = flattenFields(fields, configuration: configuration)
        var blocks: [String] = []

        for field in flattened {
            var lines: [String] = []
            if let help = field.help, !help.isEmpty {
                for helpLine in help.split(separator: "\n", omittingEmptySubsequences: false) {
                    lines.append("# \(helpLine)")
                }
            }
            if let deprecated = field.deprecated {
                let note = deprecated.isEmpty ? "Deprecated." : deprecated
                lines.append("# DEPRECATED: \(note)")
            }

            let requirementLabel = (!field.isOptional && !field.hasDefault) ? "Required" : "Optional"
            if field.isSecret {
                lines.append("# Type: \(field.typeName) (\(requirementLabel), Secret — supports op://, keychain://, bws://, file://)")
            } else {
                lines.append("# Type: \(field.typeName) (\(requirementLabel))")
            }

            let envKey = resolvedEnvName(for: field, configuration: configuration)
            if field.isSecret {
                if !field.isOptional && !field.hasDefault {
                    lines.append("\(envKey)=")
                } else {
                    lines.append("# \(envKey)=")
                }
            } else if includeDefaults, let defaultVal = field.defaultDisplay {
                let formatted = formatDotEnvScalar(defaultVal)
                lines.append("\(envKey)=\(formatted)")
            } else if !field.isOptional && !field.hasDefault {
                lines.append("\(envKey)=")
            } else {
                lines.append("# \(envKey)=")
            }

            blocks.append(lines.joined(separator: "\n"))
        }

        return blocks.joined(separator: "\n\n") + (blocks.isEmpty ? "" : "\n")
    }

    public static func exportMarkdownDocs<S: RiggedSettings>(
        for settingsType: S.Type,
        title: String? = nil
    ) -> String {
        exportMarkdownDocs(
            fields: S.fieldDescriptors,
            configuration: S.configuration,
            title: title ?? String(describing: S.self)
        )
    }

    public static func exportMarkdownDocs(
        fields: [SettingFieldDescriptor],
        configuration: SettingsConfiguration = SettingsConfiguration(),
        title: String = "Configuration Reference"
    ) -> String {
        let flattened = flattenFields(fields, configuration: configuration)
        var lines: [String] = [
            "# \(title)",
            "",
            "| Key | Environment Variable | Type | Required | Default | Description |",
            "|---|---|---|---|---|---|",
        ]

        for field in flattened {
            let key = escapeMarkdownCell("`\(field.keyPath.joined(separator: "."))`")
            let envVar = escapeMarkdownCell("`\(resolvedEnvName(for: field, configuration: configuration))`")
            let typeText = escapeMarkdownCell("`\(field.typeName)`")
            let requiredText = (!field.isOptional && !field.hasDefault) ? "Yes" : "No"

            let defaultText: String
            if field.isSecret {
                defaultText = field.hasDefault ? "`**********`" : "—"
            } else if let defaultDisplay = field.defaultDisplay {
                defaultText = escapeMarkdownCell("`\(defaultDisplay)`")
            } else {
                defaultText = "—"
            }

            var descriptionParts: [String] = []
            if let help = field.help, !help.isEmpty {
                descriptionParts.append(help)
            }
            if field.isSecret {
                descriptionParts.append("*(Secret)*")
            }
            if let deprecated = field.deprecated {
                let msg = deprecated.isEmpty ? "Deprecated" : "Deprecated: \(deprecated)"
                descriptionParts.append("**\(msg)**")
            }

            let descCell = escapeMarkdownCell(
                descriptionParts.isEmpty ? "—" : descriptionParts.joined(separator: " ")
            )

            lines.append("| \(key) | \(envVar) | \(typeText) | \(requiredText) | \(defaultText) | \(descCell) |")
        }

        return lines.joined(separator: "\n") + "\n"
    }

    // MARK: - Helpers

    private static func flattenFields(
        _ fields: [SettingFieldDescriptor],
        configuration: SettingsConfiguration,
        parentPath: [String] = []
    ) -> [SettingFieldDescriptor] {
        var result: [SettingFieldDescriptor] = []
        for field in fields {
            let fullPath = field.keyPath.isEmpty ? (parentPath + [field.name]) : field.keyPath
            if case .object(let children) = field.schemaType, !children.isEmpty {
                let rebasedChildren = children.map { child -> SettingFieldDescriptor in
                    let childRelative = child.keyPath.starts(with: fullPath)
                        ? child.keyPath
                        : (fullPath + child.keyPath)
                    return SettingFieldDescriptor(
                        name: child.name,
                        keyPath: childRelative,
                        envVariable: child.envVariable,
                        aliases: child.aliases,
                        typeName: child.typeName,
                        schemaType: child.schemaType,
                        isOptional: child.isOptional || field.isOptional,
                        isSecret: child.isSecret,
                        hasDefault: child.hasDefault || field.hasDefault,
                        defaultDisplay: child.defaultDisplay,
                        help: child.help,
                        deprecated: child.deprecated ?? field.deprecated,
                        examples: child.examples,
                        allowsArbitraryChildKeys: child.allowsArbitraryChildKeys
                    )
                }
                result.append(contentsOf: flattenFields(rebasedChildren, configuration: configuration, parentPath: fullPath))
            } else {
                result.append(field)
            }
        }
        return result
    }

    public static func resolvedEnvName(
        for field: SettingFieldDescriptor,
        configuration: SettingsConfiguration
    ) -> String {
        if let explicit = field.envVariable, !explicit.isEmpty {
            return explicit
        }
        for alias in field.aliases {
            if case .env(let envAlias) = alias {
                return envAlias
            }
        }
        let delimiter = configuration.envNestedDelimiter.isEmpty ? "_" : configuration.envNestedDelimiter
        let joined = field.keyPath
            .map { RawConfigTree.normalizeIdentifier($0).uppercased() }
            .joined(separator: delimiter)
        return "\(configuration.envPrefix)\(joined)"
    }

    private static func formatDotEnvScalar(_ value: String) -> String {
        if value.isEmpty { return "\"\"" }
        let needsQuotes = value.contains(where: { $0.isWhitespace || $0 == "#" || $0 == "\"" || $0 == "'" })
        if needsQuotes {
            let escaped = value
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\n", with: "\\n")
            return "\"\(escaped)\""
        }
        return value
    }

    private static func escapeMarkdownCell(_ text: String) -> String {
        text
            .replacingOccurrences(of: "|", with: "\\|")
            .replacingOccurrences(of: "\n", with: "<br>")
    }
}
