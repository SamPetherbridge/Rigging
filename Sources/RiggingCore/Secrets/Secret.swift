import Foundation

/// Controls whether `Secret<Value>` encodes a redacted mask or its underlying plaintext value.
public enum SecretEncodingPolicy: Sendable, Equatable, Hashable {
    /// Encode `"**********"` instead of the underlying value (the default).
    case redact
    /// Explicitly opt in to encoding the underlying plaintext value.
    case exposePlaintext
}

extension CodingUserInfoKey {
    /// Set `encoder.userInfo[.secretEncodingPolicy] = SecretEncodingPolicy.exposePlaintext`
    /// to explicitly opt in to serializing plaintext secret values.
    public static let secretEncodingPolicy = CodingUserInfoKey(rawValue: "rigging.secretEncodingPolicy")!
}

/// Leak-proof wrapper around a sensitive configuration value.
///
/// `Secret` redacts its contents across `String(describing:)`, `debugDescription`,
/// string interpolation, `Mirror` / `dump()`, and default `Encodable` serialization.
/// Plaintext is accessible only via explicit opt-in APIs (`expose()`, `withExposedUTF8`,
/// `withExposedBytes`, or `withEphemeralFile`).
public struct Secret<Value: Sendable>: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Canonical redaction mask emitted by `Secret` and `DiagnosticRedactor`.
    public static var redactedPlaceholder: String { "**********" }

    private let storage: Value

    /// Wraps a sensitive value inside a leak-proof container.
    public init(_ value: Value) {
        self.storage = value
    }

    /// Explicitly unwraps and returns the underlying plaintext value.
    public func expose() -> Value {
        storage
    }

    /// Transforms the wrapped secret value while keeping the result wrapped in `Secret`.
    public func map<NewValue: Sendable>(
        _ transform: (Value) throws -> NewValue
    ) rethrows -> Secret<NewValue> {
        Secret<NewValue>(try transform(storage))
    }

    // MARK: - Redacted String & Reflection Conformances

    public var description: String {
        Self.redactedPlaceholder
    }

    public var debugDescription: String {
        Self.redactedPlaceholder
    }

    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection())
    }
}

// MARK: - Scoped Buffer Accessors

extension Secret where Value == String {
    /// Provides scoped access to the contiguous UTF-8 bytes of the secret string.
    public func withExposedUTF8<R>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        var copy = storage
        return try copy.withUTF8(body)
    }

    /// Whether the underlying string is empty.
    public var isEmpty: Bool {
        storage.isEmpty
    }
}

extension Secret where Value == Data {
    /// Provides scoped access to the underlying secret bytes.
    public func withExposedBytes<R>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        try storage.withUnsafeBytes { rawBuffer in
            try body(rawBuffer.bindMemory(to: UInt8.self))
        }
    }

    /// Provides scoped access to the raw untyped byte buffer of the underlying `Data`.
    public func withExposedRawBytes<R>(
        _ body: (UnsafeRawBufferPointer) throws -> R
    ) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }

    /// Whether the underlying data buffer is empty.
    public var isEmpty: Bool {
        storage.isEmpty
    }
}

extension Secret where Value == [UInt8] {
    /// Provides scoped access to the underlying secret byte array buffer.
    public func withExposedBytes<R>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        try storage.withUnsafeBufferPointer(body)
    }

    /// Whether the underlying byte array is empty.
    public var isEmpty: Bool {
        storage.isEmpty
    }
}

// MARK: - Equatable, Hashable, Codable

extension Secret: Equatable where Value: Equatable {
    public static func == (lhs: Secret<Value>, rhs: Secret<Value>) -> Bool {
        lhs.storage == rhs.storage
    }
}

extension Secret: Hashable where Value: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(storage)
    }
}

extension Secret: Encodable where Value: Encodable {
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
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.storage = try container.decode(Value.self)
    }
}

extension Secret: SettingValueDecodable where Value: SettingValueDecodable {
    public static var settingTypeDisplayName: String {
        "Secret<\(Value.settingTypeDisplayName)>"
    }

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

