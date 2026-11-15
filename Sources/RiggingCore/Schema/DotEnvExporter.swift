import Foundation

/// Exports annotated `.env.example` templates and GitHub-Flavored Markdown reference tables
/// from ``RiggedSettings`` field metadata.
///
/// Secret fields never emit literal default values in generated `.env` templates or Markdown tables;
/// instead, `DotEnvExporter` documents supported secret URI schemes (`op://`, `keychain://`,
/// `bws://`, `file://`) and masks defaulted secrets with `"**********"`.
///
/// ```swift
/// let dotEnvExample = DotEnvExporter.exportDotEnvTemplate(for: AppSettings.self)
/// let referenceDocs = DotEnvExporter.exportMarkdownDocs(for: AppSettings.self)
/// ```
public enum DotEnvExporter: Sendable {
    /// Generates an annotated `.env.example` template for a ``RiggedSettings`` model type.
    ///
    /// - Parameters:
    ///   - settingsType: The settings model type to document.
    ///   - includeDefaults: Whether non-secret default values are pre-populated in assignments.
    /// - Returns: A formatted `.env` template string with comment headers per field.
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

    /// Generates an annotated `.env.example` template from explicit field descriptors and configuration.
    ///
    /// - Parameters:
    ///   - fields: Field descriptors to render.
    ///   - configuration: Settings configuration controlling environment variable prefixes and delimiters.
    ///   - includeDefaults: Whether non-secret default values are pre-populated in assignments.
    /// - Returns: A formatted `.env` template string.
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

    /// Generates a GitHub-Flavored Markdown configuration reference table for a ``RiggedSettings`` model type.
    ///
    /// - Parameters:
    ///   - settingsType: The settings model type to document.
    ///   - title: Optional Markdown H1 heading (defaults to the Swift type name of `S`).
    /// - Returns: A Markdown document containing a table of keys, environment variables, types, defaults, and descriptions.
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

    /// Generates a GitHub-Flavored Markdown configuration reference table from explicit field descriptors.
    ///
    /// - Parameters:
    ///   - fields: Field descriptors to document.
    ///   - configuration: Settings configuration controlling environment variable naming.
    ///   - title: Markdown H1 heading title.
    /// - Returns: A Markdown document string.
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

    /// Computes the canonical environment variable name for `field` under `configuration`.
    ///
    /// Explicit `envVariable` and `.env(...)` aliases take precedence; otherwise the normalized
    /// uppercase `keyPath` segments are joined by ``SettingsConfiguration/envNestedDelimiter`` and
    /// prefixed with ``SettingsConfiguration/envPrefix``.
    ///
    /// - Parameters:
    ///   - field: Field descriptor to inspect.
    ///   - configuration: Settings configuration providing `envPrefix` and `envNestedDelimiter`.
    /// - Returns: Resolved environment variable identifier.
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
