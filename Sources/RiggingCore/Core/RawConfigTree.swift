import Foundation

/// An untyped configuration value extracted from a ``SettingsSource`` prior to typed Swift decoding.
public enum RawValue: Sendable, Equatable, Hashable, Codable {
    /// A textual scalar value.
    case string(String)

    /// A boolean scalar value.
    case bool(Bool)

    /// A signed 64-bit integer scalar value.
    case int(Int64)

    /// A double-precision floating-point scalar value.
    case double(Double)

    /// Raw binary bytes (for example, non-UTF8 secret file contents or `<data>` plist nodes).
    case data(Data)

    /// An explicit null value (`null` in JSON or a configured null sentinel in `.env` / environment variables).
    case null

    /// An ordered array of child ``RawNode`` elements.
    case array([RawNode])

    /// A keyed dictionary of child ``RawNode`` entries.
    case object([String: RawNode])

    /// Indicates whether this value is ``null``.
    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }
}

/// A node in a ``RawConfigTree`` pairing an untyped ``RawValue`` with its winning ``SettingOrigin``
/// and any lower-priority origins displaced during source merging.
public struct RawNode: Sendable, Equatable, Hashable, Codable {
    /// Untyped value held at this node.
    public var value: RawValue

    /// Highest-priority provenance source that supplied ``value``.
    public var origin: SettingOrigin

    /// Ordered lower-priority origins shadowed by ``origin`` from highest to lowest displaced priority.
    public var overriddenOrigins: [SettingOrigin]

    /// Creates a configuration node with provenance metadata.
    ///
    /// - Parameters:
    ///   - value: Untyped configuration value.
    ///   - origin: Winning ``SettingOrigin`` for `value`.
    ///   - overriddenOrigins: Lower-priority origins shadowed by `origin`.
    public init(
        value: RawValue,
        origin: SettingOrigin,
        overriddenOrigins: [SettingOrigin] = []
    ) {
        self.value = value
        self.origin = origin
        self.overriddenOrigins = overriddenOrigins
    }
}

/// Hierarchical intermediate representation produced by each ``SettingsSource`` and merged across
/// the configuration precedence cascade.
///
/// `RawConfigTree` preserves exact ``SettingOrigin`` provenance at every leaf and container node,
/// deep-merges nested `.object` dictionaries across sources, normalizes camelCase / `snake_case` /
/// `kebab-case` identifiers when `caseSensitive` is `false`, and detects undeclared keys via
/// ``unknownKeyPaths(declaredPaths:arbitraryChildPrefixes:caseSensitive:)``.
///
/// ```swift
/// var tree = RawConfigTree()
/// tree.set(path: ["database", "port"], value: .int(5432), origin: .environment(variable: "DB_PORT"))
/// let node = tree.lookup(path: ["database", "port"])
/// ```
public struct RawConfigTree: Sendable, Equatable, Hashable, Codable {
    /// Hierarchical configuration nodes keyed by top-level path segment.
    public var root: [String: RawNode]

    /// Flat map of raw environment and `.env` variable assignments used to resolve explicit
    /// ``SettingAlias/env(_:)`` bindings that bypass ``SettingsConfiguration/envPrefix``.
    public var directEnvironment: [String: RawNode]

    /// An empty configuration tree containing zero hierarchical or direct-environment entries.
    public static let empty = RawConfigTree()

    /// Creates a configuration tree from root and direct-environment node dictionaries.
    ///
    /// - Parameters:
    ///   - root: Hierarchical configuration nodes.
    ///   - directEnvironment: Raw variable-name map for direct `.env(...)` alias lookups.
    public init(
        root: [String: RawNode] = [:],
        directEnvironment: [String: RawNode] = [:]
    ) {
        self.root = root
        self.directEnvironment = directEnvironment
    }

    /// Indicates whether both ``root`` and ``directEnvironment`` contain zero entries.
    public var isEmpty: Bool {
        root.isEmpty && directEnvironment.isEmpty
    }

    // MARK: - Mutation

    /// Inserts or overwrites a value at `path`, recording any displaced origin in ``RawNode/overriddenOrigins``.
    ///
    /// - Parameters:
    ///   - path: Non-empty hierarchical path segments.
    ///   - value: Untyped ``RawValue`` to store.
    ///   - origin: Provenance of `value`.
    ///   - caseSensitive: Whether segment matching is case-sensitive.
    public mutating func set(
        path: [String],
        value: RawValue,
        origin: SettingOrigin,
        caseSensitive: Bool = false
    ) {
        set(
            path: path,
            node: RawNode(value: value, origin: origin),
            caseSensitive: caseSensitive
        )
    }

    /// Inserts or overwrites `node` at `path`, preserving displaced origins when an existing entry is shadowed.
    ///
    /// - Parameters:
    ///   - path: Non-empty hierarchical path segments.
    ///   - node: Configuration node with value and provenance.
    ///   - caseSensitive: Whether segment matching is case-sensitive.
    public mutating func set(
        path: [String],
        node: RawNode,
        caseSensitive: Bool = false
    ) {
        let filtered = path.filter { !$0.isEmpty }
        guard !filtered.isEmpty else { return }
        Self.insertNode(
            into: &root,
            path: filtered[...],
            newNode: node,
            caseSensitive: caseSensitive
        )
    }

    /// Records a raw environment or `.env` entry by exact variable name for ``SettingAlias/env(_:)`` lookups.
    ///
    /// - Parameters:
    ///   - variable: Environment or `.env` variable name.
    ///   - value: Untyped ``RawValue`` to store.
    ///   - origin: Provenance of `value`.
    ///   - caseSensitive: Whether variable-name matching is case-sensitive.
    public mutating func setEnvironmentEntry(
        _ variable: String,
        value: RawValue,
        origin: SettingOrigin,
        caseSensitive: Bool = true
    ) {
        setEnvironmentEntry(
            variable,
            node: RawNode(value: value, origin: origin),
            caseSensitive: caseSensitive
        )
    }

    /// Records a raw environment or `.env` node by variable name, preserving displaced origins.
    ///
    /// - Parameters:
    ///   - variable: Environment or `.env` variable name.
    ///   - node: Configuration node with value and provenance.
    ///   - caseSensitive: Whether variable-name matching is case-sensitive.
    public mutating func setEnvironmentEntry(
        _ variable: String,
        node: RawNode,
        caseSensitive: Bool = true
    ) {
        if let existingKey = Self.findMatchingKey(
            in: directEnvironment,
            target: variable,
            caseSensitive: caseSensitive,
            allowIdentifierNormalization: false
        ), let existing = directEnvironment[existingKey] {
            var updated = node
            Self.appendUniqueOrigins(
                [existing.origin] + existing.overriddenOrigins,
                into: &updated.overriddenOrigins,
                excluding: updated.origin
            )
            directEnvironment.removeValue(forKey: existingKey)
            directEnvironment[variable] = updated
        } else {
            directEnvironment[variable] = node
        }
    }

    // MARK: - Lookup

    /// Looks up a node at `path`, matching normalized identifiers (`apiTimeout` / `api_timeout` / `API_TIMEOUT`)
    /// when `caseSensitive` is `false`.
    ///
    /// - Parameters:
    ///   - path: Hierarchical path segments to query.
    ///   - caseSensitive: Whether key matching requires exact case equality.
    /// - Returns: Matching ``RawNode`` if present, or `nil` otherwise.
    public func lookup(path: [String], caseSensitive: Bool = false) -> RawNode? {
        let filtered = path.filter { !$0.isEmpty }
        guard !filtered.isEmpty else { return nil }

        var currentDict = root
        for (index, segment) in filtered.enumerated() {
            guard let matchedKey = Self.findMatchingKey(
                in: currentDict,
                target: segment,
                caseSensitive: caseSensitive,
                allowIdentifierNormalization: !caseSensitive
            ), let node = currentDict[matchedKey] else {
                return nil
            }

            if index == filtered.count - 1 {
                return node
            }

            guard case .object(let children) = node.value else {
                return nil
            }
            currentDict = children
        }
        return nil
    }

    /// Looks up a raw environment or `.env` entry recorded in ``directEnvironment``.
    ///
    /// - Parameters:
    ///   - variable: Environment variable identifier to query.
    ///   - caseSensitive: Whether variable-name matching is case-sensitive.
    /// - Returns: Matching ``RawNode`` if present, or `nil` otherwise.
    public func lookupEnvironmentEntry(
        _ variable: String,
        caseSensitive: Bool = true
    ) -> RawNode? {
        guard let key = Self.findMatchingKey(
            in: directEnvironment,
            target: variable,
            caseSensitive: caseSensitive,
            allowIdentifierNormalization: false
        ) else {
            return nil
        }
        return directEnvironment[key]
    }

    // MARK: - Merging

    /// Merges `self` (higher priority) over `lowerPriority`, deep-merging `.object` dictionaries
    /// and recording displaced origins in ``RawNode/overriddenOrigins``.
    ///
    /// - Parameters:
    ///   - lowerPriority: Lower-precedence configuration tree.
    ///   - caseSensitive: Whether key matching during merging is case-sensitive.
    /// - Returns: Combined ``RawConfigTree`` preserving full provenance history.
    public func merging(
        lowerPriority: RawConfigTree,
        caseSensitive: Bool = false
    ) -> RawConfigTree {
        let mergedRoot = Self.mergeDictionaries(
            higher: root,
            lower: lowerPriority.root,
            caseSensitive: caseSensitive
        )
        let mergedEnv = Self.mergeEnvironmentDictionaries(
            higher: directEnvironment,
            lower: lowerPriority.directEnvironment,
            caseSensitive: caseSensitive
        )
        return RawConfigTree(root: mergedRoot, directEnvironment: mergedEnv)
    }

    // MARK: - Inspection & Unknown Key Detection

    /// Returns all leaf (non-object or empty-object) key paths and nodes in deterministic sorted order.
    ///
    /// - Returns: Sorted array of `(keyPath, node)` pairs.
    public func allLeafNodes() -> [(keyPath: [String], node: RawNode)] {
        var results: [(keyPath: [String], node: RawNode)] = []
        Self.collectLeafNodes(from: root, prefix: [], into: &results)
        return results
    }

    /// Returns leaf key paths in ``root`` that do not match any declared schema path or dynamic dictionary prefix.
    ///
    /// - Parameters:
    ///   - declaredPaths: Canonical key paths declared by the settings schema and its aliases.
    ///   - arbitraryChildPrefixes: Key paths of `[String: V]` dictionary fields whose child keys are user-defined.
    ///   - caseSensitive: Whether path comparison is case-sensitive.
    /// - Returns: Ordered `(keyPath, origin)` pairs for undeclared keys.
    public func unknownKeyPaths(
        declaredPaths: [[String]],
        arbitraryChildPrefixes: [[String]] = [],
        caseSensitive: Bool = false
    ) -> [(keyPath: [String], origin: SettingOrigin)] {
        let leaves = allLeafNodes()
        var unknowns: [(keyPath: [String], origin: SettingOrigin)] = []

        for (leafPath, node) in leaves {
            let matchesDeclared = declaredPaths.contains { declared in
                Self.pathsMatch(leafPath, declared, caseSensitive: caseSensitive)
            }
            if matchesDeclared {
                continue
            }

            if case .object(let children) = node.value, children.isEmpty {
                let isDeclaredContainerPrefix = declaredPaths.contains { declared in
                    guard declared.count > leafPath.count else { return false }
                    return Self.pathsMatch(
                        leafPath,
                        Array(declared.prefix(leafPath.count)),
                        caseSensitive: caseSensitive
                    )
                }
                if isDeclaredContainerPrefix {
                    continue
                }
            }

            let matchesDynamicPrefix = arbitraryChildPrefixes.contains { prefix in
                guard !prefix.isEmpty, leafPath.count >= prefix.count else { return false }
                return Self.pathsMatch(
                    Array(leafPath.prefix(prefix.count)),
                    prefix,
                    caseSensitive: caseSensitive
                )
            }
            if matchesDynamicPrefix {
                continue
            }

            unknowns.append((keyPath: leafPath, origin: node.origin))
        }

        return unknowns
    }

    // MARK: - Internal Helpers

    private static func insertNode(
        into dict: inout [String: RawNode],
        path: ArraySlice<String>,
        newNode: RawNode,
        caseSensitive: Bool
    ) {
        guard let head = path.first else { return }
        let tail = path.dropFirst()

        let existingKey = findMatchingKey(
            in: dict,
            target: head,
            caseSensitive: caseSensitive,
            allowIdentifierNormalization: !caseSensitive
        )
        let targetKey = existingKey ?? head

        if tail.isEmpty {
            if let existing = dict[targetKey] {
                dict[targetKey] = mergeNodes(
                    higher: newNode,
                    lower: existing,
                    caseSensitive: caseSensitive
                )
            } else {
                dict[targetKey] = newNode
            }
        } else {
            if var existing = dict[targetKey] {
                if case .object(var children) = existing.value {
                    insertNode(
                        into: &children,
                        path: tail,
                        newNode: newNode,
                        caseSensitive: caseSensitive
                    )
                    existing.value = .object(children)
                    dict[targetKey] = existing
                } else {
                    var children: [String: RawNode] = [:]
                    insertNode(
                        into: &children,
                        path: tail,
                        newNode: newNode,
                        caseSensitive: caseSensitive
                    )
                    var overridden = newNode.overriddenOrigins
                    appendUniqueOrigins(
                        [existing.origin] + existing.overriddenOrigins,
                        into: &overridden,
                        excluding: newNode.origin
                    )
                    dict[targetKey] = RawNode(
                        value: .object(children),
                        origin: newNode.origin,
                        overriddenOrigins: overridden
                    )
                }
            } else {
                var children: [String: RawNode] = [:]
                insertNode(
                    into: &children,
                    path: tail,
                    newNode: newNode,
                    caseSensitive: caseSensitive
                )
                dict[targetKey] = RawNode(
                    value: .object(children),
                    origin: newNode.origin
                )
            }
        }
    }

    private static func mergeDictionaries(
        higher: [String: RawNode],
        lower: [String: RawNode],
        caseSensitive: Bool
    ) -> [String: RawNode] {
        var result = higher
        for (lowerKey, lowerNode) in lower {
            if let matchingHigherKey = findMatchingKey(
                in: result,
                target: lowerKey,
                caseSensitive: caseSensitive,
                allowIdentifierNormalization: !caseSensitive
            ), let higherNode = result[matchingHigherKey] {
                result[matchingHigherKey] = mergeNodes(
                    higher: higherNode,
                    lower: lowerNode,
                    caseSensitive: caseSensitive
                )
            } else {
                result[lowerKey] = lowerNode
            }
        }
        return result
    }

    private static func mergeEnvironmentDictionaries(
        higher: [String: RawNode],
        lower: [String: RawNode],
        caseSensitive: Bool
    ) -> [String: RawNode] {
        var result = higher
        for (lowerKey, lowerNode) in lower {
            if let matchingHigherKey = findMatchingKey(
                in: result,
                target: lowerKey,
                caseSensitive: caseSensitive,
                allowIdentifierNormalization: false
            ), var higherNode = result[matchingHigherKey] {
                appendUniqueOrigins(
                    [lowerNode.origin] + lowerNode.overriddenOrigins,
                    into: &higherNode.overriddenOrigins,
                    excluding: higherNode.origin
                )
                result[matchingHigherKey] = higherNode
            } else {
                result[lowerKey] = lowerNode
            }
        }
        return result
    }

    private static func mergeNodes(
        higher: RawNode,
        lower: RawNode,
        caseSensitive: Bool
    ) -> RawNode {
        if case .object(let higherChildren) = higher.value,
           case .object(let lowerChildren) = lower.value {
            let mergedChildren = mergeDictionaries(
                higher: higherChildren,
                lower: lowerChildren,
                caseSensitive: caseSensitive
            )
            var overridden = higher.overriddenOrigins
            appendUniqueOrigins(
                [lower.origin] + lower.overriddenOrigins,
                into: &overridden,
                excluding: higher.origin
            )
            return RawNode(
                value: .object(mergedChildren),
                origin: higher.origin,
                overriddenOrigins: overridden
            )
        }

        var updated = higher
        appendUniqueOrigins(
            [lower.origin] + lower.overriddenOrigins,
            into: &updated.overriddenOrigins,
            excluding: updated.origin
        )
        return updated
    }

    private static func appendUniqueOrigins(
        _ candidates: [SettingOrigin],
        into destination: inout [SettingOrigin],
        excluding primary: SettingOrigin
    ) {
        for origin in candidates where origin != primary && !destination.contains(origin) {
            destination.append(origin)
        }
    }

    private static func collectLeafNodes(
        from dict: [String: RawNode],
        prefix: [String],
        into results: inout [(keyPath: [String], node: RawNode)]
    ) {
        for key in dict.keys.sorted() {
            guard let node = dict[key] else { continue }
            let path = prefix + [key]
            if case .object(let children) = node.value, !children.isEmpty {
                collectLeafNodes(from: children, prefix: path, into: &results)
            } else {
                results.append((keyPath: path, node: node))
            }
        }
    }

    /// Returns `true` when two key-path arrays have equal length and matching segments.
    ///
    /// - Parameters:
    ///   - lhs: First key path.
    ///   - rhs: Second key path.
    ///   - caseSensitive: Whether segment comparison is case-sensitive.
    /// - Returns: `true` if every corresponding segment matches.
    public static func pathsMatch(
        _ lhs: [String],
        _ rhs: [String],
        caseSensitive: Bool
    ) -> Bool {
        guard lhs.count == rhs.count else { return false }
        for (a, b) in zip(lhs, rhs) {
            if !keysMatch(
                a,
                b,
                caseSensitive: caseSensitive,
                allowIdentifierNormalization: !caseSensitive
            ) {
                return false
            }
        }
        return true
    }

    /// Returns `true` when two single-segment keys match under the requested case and normalization rules.
    ///
    /// - Parameters:
    ///   - lhs: First key segment.
    ///   - rhs: Second key segment.
    ///   - caseSensitive: Whether comparison requires exact case equality.
    ///   - allowIdentifierNormalization: Whether `camelCase`, `snake_case`, and `kebab-case` normalize together when `caseSensitive` is `false`.
    /// - Returns: `true` if the two keys refer to the same logical identifier.
    public static func keysMatch(
        _ lhs: String,
        _ rhs: String,
        caseSensitive: Bool,
        allowIdentifierNormalization: Bool = true
    ) -> Bool {
        if lhs == rhs { return true }
        guard !caseSensitive else { return false }
        if lhs.lowercased() == rhs.lowercased() { return true }
        if allowIdentifierNormalization {
            return normalizeIdentifier(lhs) == normalizeIdentifier(rhs)
        }
        return false
    }

    private static func findMatchingKey(
        in dict: [String: RawNode],
        target: String,
        caseSensitive: Bool,
        allowIdentifierNormalization: Bool
    ) -> String? {
        if dict[target] != nil {
            return target
        }
        guard !caseSensitive else {
            return nil
        }

        let targetLower = target.lowercased()
        for key in dict.keys.sorted() where key.lowercased() == targetLower {
            return key
        }

        if allowIdentifierNormalization {
            let normalizedTarget = normalizeIdentifier(target)
            for key in dict.keys.sorted() where normalizeIdentifier(key) == normalizedTarget {
                return key
            }
        }
        return nil
    }

    /// Normalizes `camelCase`, `PascalCase`, `snake_case`, `SCREAMING_SNAKE_CASE`, and `kebab-case`
    /// identifiers into canonical lowercase `snake_case`.
    ///
    /// - Parameter key: Raw identifier string (for example, `"apiTimeout"` or `"HTTPSPort"`).
    /// - Returns: Canonical lowercase `snake_case` identifier (for example, `"api_timeout"` or `"https_port"`).
    public static func normalizeIdentifier(_ key: String) -> String {
        guard !key.isEmpty else { return key }
        var scalars: [Character] = []
        let chars = Array(key)

        for i in chars.indices {
            let ch = chars[i]
            if ch == "-" || ch == "_" {
                if scalars.last != "_" && !scalars.isEmpty {
                    scalars.append("_")
                }
                continue
            }

            if ch.isUppercase {
                if i > 0 {
                    let prev = chars[i - 1]
                    let nextIsLower = (i + 1 < chars.count) && chars[i + 1].isLowercase
                    if prev != "_" && prev != "-" && (prev.isLowercase || prev.isNumber || nextIsLower) {
                        if scalars.last != "_" {
                            scalars.append("_")
                        }
                    }
                }
                for lower in ch.lowercased() {
                    scalars.append(lower)
                }
            } else {
                scalars.append(ch)
            }
        }

        while scalars.last == "_" {
            scalars.removeLast()
        }
        return String(scalars)
    }
}
