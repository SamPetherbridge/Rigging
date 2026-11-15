import Foundation

/// Untyped configuration value extracted from a configuration source before typed decoding.
public enum RawValue: Sendable, Equatable, Hashable, Codable {
    case string(String)
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case data(Data)
    case null
    case array([RawNode])
    case object([String: RawNode])

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }
}

/// A single node in a `RawConfigTree`, pairing a `RawValue` with its winning `SettingOrigin`
/// and any lower-priority origins it shadowed during source merging.
public struct RawNode: Sendable, Equatable, Hashable, Codable {
    public var value: RawValue
    public var origin: SettingOrigin
    public var overriddenOrigins: [SettingOrigin]

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

/// Hierarchical intermediate representation produced by each `SettingsSource` and merged across
/// the source precedence cascade.
public struct RawConfigTree: Sendable, Equatable, Hashable, Codable {
    /// Structured hierarchical configuration nodes keyed by path segments.
    public var root: [String: RawNode]

    /// Optional raw environment/dotenv variable map keyed by exact variable name, used to resolve
    /// explicit `@Setting(aliases: [.env("...")])` bindings that bypass `envPrefix`.
    public var directEnvironment: [String: RawNode]

    public static let empty = RawConfigTree()

    public init(
        root: [String: RawNode] = [:],
        directEnvironment: [String: RawNode] = [:]
    ) {
        self.root = root
        self.directEnvironment = directEnvironment
    }

    public var isEmpty: Bool {
        root.isEmpty && directEnvironment.isEmpty
    }

    // MARK: - Mutation

    /// Sets a value at `path`, recording any displaced origin in `overriddenOrigins`.
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

    /// Inserts or overwrites `node` at `path`. When overwriting an existing node (e.g. a later
    /// `.env` file overriding an earlier `.env` file), the displaced node's origin and its own
    /// `overriddenOrigins` are preserved.
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

    /// Records a raw environment or `.env` entry by variable name for direct alias lookups.
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

    /// Records a raw environment or `.env` node by variable name, preserving overridden origins.
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

    /// Looks up a node at `path`. When `caseSensitive` is `false`, matches keys case-insensitively
    /// first and then by normalized identifier (`apiTimeout` <-> `api_timeout` <-> `API_TIMEOUT`).
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

    /// Looks up a raw environment or `.env` entry by variable name.
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
    /// and appending shadowed origins into `overriddenOrigins`.
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

    /// Returns all leaf (non-object, or empty-object) key paths in deterministic sorted order.
    public func allLeafNodes() -> [(keyPath: [String], node: RawNode)] {
        var results: [(keyPath: [String], node: RawNode)] = []
        Self.collectLeafNodes(from: root, prefix: [], into: &results)
        return results
    }

    /// Finds unknown configuration key paths not matching any declared schema path.
    ///
    /// - Parameters:
    ///   - declaredPaths: Canonical key paths declared by the settings schema (plus any `.configPath` aliases).
    ///   - arbitraryChildPrefixes: Key paths corresponding to `[String: T]` dictionary fields whose child keys are dynamic.
    ///   - caseSensitive: Whether key comparison is case-sensitive.
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

    /// Converts camelCase, PascalCase, snake_case, SCREAMING_SNAKE_CASE, and kebab-case
    /// into a canonical lowercase snake_case representation for flexible key matching.
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
