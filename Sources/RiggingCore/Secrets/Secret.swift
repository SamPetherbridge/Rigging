import Foundation

/// Controls whether ``Secret`` serializes a redacted mask or its underlying plaintext during `Encodable` encoding.
public enum SecretEncodingPolicy: Sendable, Equatable, Hashable {
    /// Encodes `"**********"` instead of the underlying value (the default behavior).
    case redact

    /// Explicitly opts in to encoding the underlying plaintext value.
    case exposePlaintext
}

extension CodingUserInfoKey {
    /// Encoder `userInfo` key controlling ``Secret`` serialization behavior via ``SecretEncodingPolicy``.
    ///
    /// Assign `encoder.userInfo[.secretEncodingPolicy] = SecretEncodingPolicy.exposePlaintext`
    /// only when intentionally writing secrets to an encrypted store.
    public static let secretEncodingPolicy = CodingUserInfoKey(rawValue: "rigging.secretEncodingPolicy")!
}

/// A leak-proof container wrapping a sensitive configuration value.
///
/// `Secret` redacts its payload across `String(describing:)`, `debugDescription`, string interpolation,
/// `Mirror` reflection (`dump`), and default `Encodable` serialization, always emitting `"**********"`.
/// Callers must explicitly invoke ``expose()``, ``withExposedUTF8(_:)``, `withExposedBytes(_:)`,
/// or `withEphemeralFile(prefix:suffix:permissions:_:)` at the boundary where the secret is consumed.
///
/// ```swift
/// let apiKey = Secret("sk_live_example_token")
/// print("Loaded key: \(apiKey)") // Prints: Loaded key: **********
/// request.setValue("Bearer \(apiKey.expose())", forHTTPHeaderField: "Authorization")
/// ```
public struct Secret<Value: Sendable>: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Canonical redaction mask emitted by ``Secret`` and ``DiagnosticRedactor`` (`"**********"`).
    public static var redactedPlaceholder: String { "**********" }

    private let storage: Value

    /// Creates a secret wrapper around a sensitive value.
    ///
    /// - Parameter value: Sensitive plaintext or binary payload to protect from accidental logging.
    public init(_ value: Value) {
        self.storage = value
    }

    /// Explicitly unwraps and returns the underlying sensitive value.
    ///
    /// - Returns: The wrapped plaintext or binary value.
    public func expose() -> Value {
        storage
    }

    /// Transforms the wrapped value while keeping the result wrapped in ``Secret``.
    ///
    /// - Parameter transform: Closure mapping the exposed value to a derived sensitive value.
    /// - Returns: A new ``Secret`` wrapping the transformed result.
    /// - Throws: Rethrows any error thrown by `transform`.
    public func map<NewValue: Sendable>(
        _ transform: (Value) throws -> NewValue
    ) rethrows -> Secret<NewValue> {
        Secret<NewValue>(try transform(storage))
    }

    // MARK: - Redacted String & Reflection Conformances

    /// Always returns `"**********"` so string interpolation never leaks plaintext.
    public var description: String {
        Self.redactedPlaceholder
    }

    /// Always returns `"**********"` so debug logging never leaks plaintext.
    public var debugDescription: String {
        Self.redactedPlaceholder
    }

    /// Empty mirror preventing `Mirror(reflecting:)` and `dump(_:)` from traversing `storage`.
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection())
    }
}

// MARK: - Scoped Buffer Accessors

extension Secret where Value == String {
    /// Provides scoped access to the contiguous UTF-8 bytes of the secret string.
    ///
    /// - Parameter body: Closure receiving an `UnsafeBufferPointer<UInt8>` valid only during execution.
    /// - Returns: Value returned by `body`.
    /// - Throws: Rethrows any error thrown by `body`.
    public func withExposedUTF8<R>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        var copy = storage
        return try copy.withUTF8(body)
    }

    /// Indicates whether the underlying secret string is empty.
    public var isEmpty: Bool {
        storage.isEmpty
    }
}

extension Secret where Value == Data {
    /// Provides scoped access to the typed `UInt8` buffer of the secret `Data`.
    ///
    /// - Parameter body: Closure receiving an `UnsafeBufferPointer<UInt8>` valid only during execution.
    /// - Returns: Value returned by `body`.
    /// - Throws: Rethrows any error thrown by `body`.
    public func withExposedBytes<R>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        try storage.withUnsafeBytes { rawBuffer in
            try body(rawBuffer.bindMemory(to: UInt8.self))
        }
    }

    /// Provides scoped access to the raw untyped byte buffer of the secret `Data`.
    ///
    /// - Parameter body: Closure receiving an `UnsafeRawBufferPointer` valid only during execution.
    /// - Returns: Value returned by `body`.
    /// - Throws: Rethrows any error thrown by `body`.
    public func withExposedRawBytes<R>(
        _ body: (UnsafeRawBufferPointer) throws -> R
    ) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }

    /// Indicates whether the underlying secret data buffer is empty.
    public var isEmpty: Bool {
        storage.isEmpty
    }
}

extension Secret where Value == [UInt8] {
    /// Provides scoped access to the contiguous byte buffer of the secret `[UInt8]` array.
    ///
    /// - Parameter body: Closure receiving an `UnsafeBufferPointer<UInt8>` valid only during execution.
    /// - Returns: Value returned by `body`.
    /// - Throws: Rethrows any error thrown by `body`.
    public func withExposedBytes<R>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        try storage.withUnsafeBufferPointer(body)
    }

    /// Indicates whether the underlying secret byte array is empty.
    public var isEmpty: Bool {
        storage.isEmpty
    }
}

// MARK: - Equatable, Hashable, Codable

extension Secret: Equatable where Value: Equatable {
    /// Compares two secrets for equality using their underlying values.
    public static func == (lhs: Secret<Value>, rhs: Secret<Value>) -> Bool {
        lhs.storage == rhs.storage
    }
}

extension Secret: Hashable where Value: Hashable {
    /// Hashes the underlying value into `hasher`.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(storage)
    }
}

extension Secret: Encodable where Value: Encodable {
    /// Encodes `"**********"` by default, or encodes the plaintext value only when
    /// `encoder.userInfo[.secretEncodingPolicy]` is set to ``SecretEncodingPolicy/exposePlaintext``.
    ///
    /// - Parameter encoder: Encoder receiving the serialized representation.
    /// - Throws: Any encoding error thrown by `encoder`.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        if let policy = encoder.userInfo[.secretEncodingPolicy] as? SecretEncodingPolicy,
           policy == .exposePlaintext {
            try container.encode(storage)
        } else {
            try container.encode(Self.redactedPlaceholder)
        }
    }
}

extension Secret: Decodable where Value: Decodable {
    /// Decodes a ``Secret`` from a single-value container.
    ///
    /// - Parameter decoder: Decoder providing the wrapped `Value`.
    /// - Throws: Any decoding error thrown by `decoder`.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.storage = try container.decode(Value.self)
    }
}

extension Secret: SettingValueDecodable where Value: SettingValueDecodable {
    /// Human-readable display name (`"Secret<Value>"`) used in schema exports and validation diagnostics.
    public static var settingTypeDisplayName: String {
        "Secret<\(Value.settingTypeDisplayName)>"
    }

    /// Decodes a ``RawValue`` into the wrapped `Value` type and packages it inside ``Secret``.
    ///
    /// - Parameters:
    ///   - rawValue: Untyped configuration value to coerce.
    ///   - context: Decoding context controlling case sensitivity and list splitting.
    /// - Returns: A ``Secret`` wrapping the decoded value.
    /// - Throws: ``ValueDecodingError`` if `rawValue` cannot be coerced to `Value`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Secret<Value> {
        if Value.self == [UInt8].self, case .data(let rawData) = rawValue {
            return Secret(Array(rawData) as! Value)
        }
        return Secret(try Value.decodeSettingValue(from: rawValue, context: context))
    }
}
