import Foundation
#if canImport(CoreFoundation) && os(macOS)
import CoreFoundation
#endif

/// Loads enterprise MDM and managed preference policies on macOS via `CFPreferences`, while
/// compiling cleanly as a deterministic mockable or no-op source on Linux and non-macOS Apple platforms.
///
/// When ``keys`` is `nil` on macOS, `ManagedPreferencesSource` discovers preference keys for the
/// configured domain and restricts results by default to MDM-forced keys (`CFPreferencesAppValueIsForced`)
/// so ordinary `UserDefaults` values do not masquerade as managed policy.
///
/// ```swift
/// let source = ManagedPreferencesSource(domain: "com.example.asc")
/// ```
public struct ManagedPreferencesSource: SettingsSource, Sendable {
    /// Optional preference domain overriding ``SettingsConfiguration/managedPreferencesDomain`` (for example, `"com.example.asc"`).
    public let domain: String?

    /// Optional explicit preference keys to query instead of discovering all keys in `domain`.
    public let keys: [String]?

    /// Whether only MDM-forced keys (`CFPreferencesAppValueIsForced`) are loaded.
    public let requireForced: Bool?

    /// Optional injectable mock dictionary for deterministic unit tests across all platforms.
    public let mockValues: [String: RawValue]?

    /// Human-readable name identifying this source in diagnostics (`"ManagedPreferencesSource"`).
    public var sourceName: String { "ManagedPreferencesSource" }

    /// Creates a managed preferences configuration source.
    ///
    /// - Parameters:
    ///   - domain: Optional reverse-DNS preference domain overriding ``SettingsConfiguration/managedPreferencesDomain``.
    ///   - keys: Optional explicit preference keys to query.
    ///   - requireForced: When `true`, loads only MDM-forced keys; defaults to `true` when `keys` is `nil` and `false` otherwise.
    ///   - mockValues: Optional mock policy dictionary used in tests on any platform.
    public init(
        domain: String? = nil,
        keys: [String]? = nil,
        requireForced: Bool? = nil,
        mockValues: [String: RawValue]? = nil
    ) {
        self.domain = domain
        self.keys = keys
        self.requireForced = requireForced
        self.mockValues = mockValues
    }

    /// Reads managed preference entries into a ``RawConfigTree``.
    ///
    /// - Parameters:
    ///   - configuration: Settings configuration providing `managedPreferencesDomain` and key-splitting rules.
    ///   - context: Execution context for the load pass.
    /// - Returns: A ``RawConfigTree`` tagged with ``SettingOrigin/managedPolicy(domain:key:)`` provenance,
    ///   or ``RawConfigTree/empty`` on platforms without macOS `CFPreferences`.
    public func load(
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) async throws -> RawConfigTree {
        let resolvedDomain = (domain ?? configuration.managedPreferencesDomain)?
            .trimmingCharacters(in: .whitespacesAndNewlines)

        // Injectable mock values work identically on every platform for unit testing.
        if let mockValues {
            let effectiveDomain = (resolvedDomain?.isEmpty == false)
                ? resolvedDomain!
                : "mock.managed.preferences"
            return buildTreeFromMockValues(
                mockValues,
                domain: effectiveDomain,
                configuration: configuration
            )
        }

        guard let effectiveDomain = resolvedDomain, !effectiveDomain.isEmpty else {
            return .empty
        }

        #if canImport(CoreFoundation) && os(macOS)
        return loadMacOSManagedPreferences(
            domain: effectiveDomain,
            configuration: configuration
        )
        #else
        _ = context
        return .empty
        #endif
    }

    private func buildTreeFromMockValues(
        _ values: [String: RawValue],
        domain: String,
        configuration: SettingsConfiguration
    ) -> RawConfigTree {
        var tree = RawConfigTree()
        for key in values.keys.sorted() {
            if let allowedKeys = keys, !allowedKeys.contains(key) {
                continue
            }
            guard let rawValue = values[key] else { continue }
            let origin = SettingOrigin.managedPolicy(domain: domain, key: key)
            let segments = splitManagedKey(key, configuration: configuration)
            guard !segments.isEmpty else { continue }

            let stampedValue = Self.recursivelyStampOrigin(rawValue, origin: origin)
            tree.set(
                path: segments,
                value: stampedValue,
                origin: origin,
                caseSensitive: configuration.caseSensitive
            )
        }
        return tree
    }

    #if canImport(CoreFoundation) && os(macOS)
    private func loadMacOSManagedPreferences(
        domain: String,
        configuration: SettingsConfiguration
    ) -> RawConfigTree {
        let cfDomain = domain as CFString
        let candidateKeys: [String]
        let enforceForced: Bool

        if let explicitKeys = keys {
            candidateKeys = explicitKeys
            enforceForced = requireForced ?? false
        } else {
            candidateKeys = Self.discoverPreferenceKeys(forDomain: cfDomain)
            enforceForced = requireForced ?? true
        }

        guard !candidateKeys.isEmpty else { return .empty }

        var tree = RawConfigTree()
        for key in candidateKeys.sorted() {
            let trimmedKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedKey.isEmpty else { continue }
            let cfKey = trimmedKey as CFString

            if enforceForced && !CFPreferencesAppValueIsForced(cfKey, cfDomain) {
                continue
            }

            guard let cfValue = CFPreferencesCopyAppValue(cfKey, cfDomain) else {
                continue
            }

            let origin = SettingOrigin.managedPolicy(domain: domain, key: trimmedKey)
            let segments = splitManagedKey(trimmedKey, configuration: configuration)
            guard !segments.isEmpty else { continue }

            let convertedValue = FoundationObjectConverter.convertValue(
                cfValue as Any,
                keyPath: segments
            ) { _ in origin }

            tree.set(
                path: segments,
                value: convertedValue,
                origin: origin,
                caseSensitive: configuration.caseSensitive
            )
        }

        return tree
    }

    private static func discoverPreferenceKeys(forDomain cfDomain: CFString) -> [String] {
        var discovered = Set<String>()
        if let userKeys = CFPreferencesCopyKeyList(
            cfDomain,
            kCFPreferencesCurrentUser,
            kCFPreferencesAnyHost
        ) as? [String] {
            discovered.formUnion(userKeys)
        }
        if let hostKeys = CFPreferencesCopyKeyList(
            cfDomain,
            kCFPreferencesCurrentUser,
            kCFPreferencesCurrentHost
        ) as? [String] {
            discovered.formUnion(hostKeys)
        }
        if let anyUserKeys = CFPreferencesCopyKeyList(
            cfDomain,
            kCFPreferencesAnyUser,
            kCFPreferencesCurrentHost
        ) as? [String] {
            discovered.formUnion(anyUserKeys)
        }
        return Array(discovered)
    }
    #endif

    private func splitManagedKey(
        _ key: String,
        configuration: SettingsConfiguration
    ) -> [String] {
        if key.contains(".") {
            return key.split(separator: ".", omittingEmptySubsequences: true).map(String.init)
        }
        return EnvironmentKeyMapper.splitKeyPath(
            key,
            delimiter: configuration.envNestedDelimiter,
            maxSplits: configuration.envNestedMaxSplit,
            caseSensitive: configuration.caseSensitive
        )
    }

    private static func recursivelyStampOrigin(
        _ value: RawValue,
        origin: SettingOrigin
    ) -> RawValue {
        switch value {
        case .object(let children):
            var updated: [String: RawNode] = [:]
            for (k, node) in children {
                updated[k] = RawNode(
                    value: recursivelyStampOrigin(node.value, origin: origin),
                    origin: origin,
                    overriddenOrigins: node.overriddenOrigins
                )
            }
            return .object(updated)
        case .array(let elements):
            return .array(
                elements.map { node in
                    RawNode(
                        value: recursivelyStampOrigin(node.value, origin: origin),
                        origin: origin,
                        overriddenOrigins: node.overriddenOrigins
                    )
                }
            )
        default:
            return value
        }
    }
}
