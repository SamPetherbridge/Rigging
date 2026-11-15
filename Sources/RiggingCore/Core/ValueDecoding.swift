import Foundation
#if canImport(ObjectiveC)
import CoreFoundation
#endif

/// Contextual rules governing scalar coercion, null-sentinel detection, and string collection parsing.
public struct ValueDecodingContext: Sendable, Equatable, Hashable {
    /// Whether enum raw-value and null-sentinel matching is case-sensitive.
    public var caseSensitive: Bool

    /// Strings interpreted as explicit null values when decoding optional or nullable fields.
    public var envNullStrings: Set<String>

    /// Strategy used when decoding `[T]`, `Set<T>`, or `[String: V]` from flat string sources.
    public var envListStrategy: EnvCollectionStrategy

    /// Creates a value-decoding context with explicit rules.
    ///
    /// - Parameters:
    ///   - caseSensitive: Whether string comparisons require exact case equality.
    ///   - envNullStrings: Sentinel strings treated as null (defaults to `["null", "none", "~"]`).
    ///   - envListStrategy: Strategy for decoding collections from environment strings.
    public init(
        caseSensitive: Bool = false,
        envNullStrings: Set<String> = ["null", "none", "~"],
        envListStrategy: EnvCollectionStrategy = .jsonOrCommaSeparated
    ) {
        self.caseSensitive = caseSensitive
        self.envNullStrings = envNullStrings
        self.envListStrategy = envListStrategy
    }

    /// Creates a value-decoding context derived from a ``SettingsConfiguration``.
    ///
    /// - Parameter configuration: Settings configuration supplying `caseSensitive`, `envNullStrings`, and `envListStrategy`.
    public init(configuration: SettingsConfiguration) {
        self.caseSensitive = configuration.caseSensitive
        self.envNullStrings = configuration.envNullStrings
        self.envListStrategy = configuration.envListStrategy
    }

    /// Returns `true` if `rawValue` is ``RawValue/null`` or a string matching ``envNullStrings``.
    ///
    /// - Parameter rawValue: Candidate configuration value to inspect.
    /// - Returns: `true` when `rawValue` represents a null value.
    public func representsNull(_ rawValue: RawValue) -> Bool {
        switch rawValue {
        case .null:
            return true
        case .string(let s):
            let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if caseSensitive {
                return envNullStrings.contains(trimmed)
            }
            let lower = trimmed.lowercased()
            return envNullStrings.contains { $0.lowercased() == lower }
        default:
            return false
        }
    }
}

/// An error thrown when an untyped ``RawValue`` cannot be coerced into the requested Swift type.
public struct ValueDecodingError: Error, Sendable, Equatable, Hashable, CustomStringConvertible, LocalizedError {
    /// Human-readable name of the target Swift type (for example, `"Int"` or `"Duration"`).
    public let expectedType: String

    /// Explanation of why coercion failed without echoing unredacted secret inputs.
    public let reason: String

    /// Creates a typed value-decoding error.
    ///
    /// - Parameters:
    ///   - expectedType: Display name of the target Swift type.
    ///   - reason: Explanation of why the input value was rejected.
    public init(expectedType: String, reason: String) {
        self.expectedType = expectedType
        self.reason = reason
    }

    /// Formatted diagnostic string (`"Invalid <expectedType> value: <reason>"`).
    public var description: String {
        "Invalid \(expectedType) value: \(reason)"
    }

    /// Localized error description matching ``description`` for CLI error reporters.
    public var errorDescription: String? {
        description
    }
}

/// A type that can be decoded from an untyped ``RawValue`` within a ``SettingsLoader`` pass.
///
/// Out-of-the-box conformances cover `String`, `Bool`, all fixed-width signed and unsigned integers,
/// `Double`, `Float`, `Decimal`, `UUID`, `URL`, `Date`, `Data`, `Duration`, ``ByteCount``,
/// `RawRepresentable` enums (including case-insensitive `CaseIterable` string enums), `Optional`,
/// `Array`, `Set`, `Dictionary<String, Value>`, and ``Secret``.
public protocol SettingValueDecodable: Sendable {
    /// Human-readable type name displayed in schema exports and validation errors.
    static var settingTypeDisplayName: String { get }

    /// Coerces an untyped ``RawValue`` into an instance of `Self`.
    ///
    /// - Parameters:
    ///   - rawValue: Untyped value from the merged configuration tree.
    ///   - context: Contextual rules governing case sensitivity, null sentinels, and list parsing.
    /// - Returns: Decoded value of type `Self`.
    /// - Throws: ``ValueDecodingError`` when `rawValue` is incompatible with `Self`.
    static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Self
}

extension SettingValueDecodable {
    /// Default display name derived from `String(describing: Self.self)`.
    public static var settingTypeDisplayName: String {
        String(describing: Self.self)
    }

    /// Coerces an untyped ``RawValue`` into `Self` using default ``ValueDecodingContext`` settings.
    ///
    /// - Parameter rawValue: Untyped configuration value.
    /// - Returns: Decoded value of type `Self`.
    /// - Throws: ``ValueDecodingError`` when `rawValue` cannot be coerced to `Self`.
    public static func decodeSettingValue(from rawValue: RawValue) throws -> Self {
        try decodeSettingValue(from: rawValue, context: ValueDecodingContext())
    }
}

// MARK: - String

extension String: SettingValueDecodable {
    /// Display name for `String` settings (`"String"`).
    public static var settingTypeDisplayName: String { "String" }

    /// Decodes a scalar or UTF-8 byte ``RawValue`` into a `String`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> String {
        switch rawValue {
        case .string(let value):
            return value
        case .bool(let value):
            return value ? "true" : "false"
        case .int(let value):
            return String(value)
        case .double(let value):
            return String(value)
        case .data(let data):
            guard let string = String(data: data, encoding: .utf8) else {
                throw ValueDecodingError(expectedType: "String", reason: "Data is not valid UTF-8.")
            }
            return string
        case .null, .array, .object:
            throw ValueDecodingError(
                expectedType: "String",
                reason: "Expected string scalar, got \(rawKindName(rawValue))."
            )
        }
    }
}

// MARK: - Bool

extension Bool: SettingValueDecodable {
    /// Display name for `Bool` settings (`"Bool"`).
    public static var settingTypeDisplayName: String { "Bool" }

    private static let truthyLiterals: Set<String> = ["true", "1", "yes", "on"]
    private static let falsyLiterals: Set<String> = ["false", "0", "no", "off"]

    /// Decodes booleans, `0`/`1` integers, and `true`/`false`/`yes`/`no`/`on`/`off` strings into a `Bool`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Bool {
        switch rawValue {
        case .bool(let value):
            return value
        case .int(let value):
            if value == 1 { return true }
            if value == 0 { return false }
            throw ValueDecodingError(
                expectedType: "Bool",
                reason: "Expected 0 or 1, got integer \(value)."
            )
        case .string(let raw):
            let normalized = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if truthyLiterals.contains(normalized) { return true }
            if falsyLiterals.contains(normalized) { return false }
            throw ValueDecodingError(
                expectedType: "Bool",
                reason: "Expected one of true/false/1/0/yes/no/on/off."
            )
        default:
            throw ValueDecodingError(
                expectedType: "Bool",
                reason: "Expected boolean scalar, got \(rawKindName(rawValue))."
            )
        }
    }
}

// MARK: - Fixed-Width Integers

private func decodeFixedWidthInteger<T: FixedWidthInteger & Sendable>(
    _ type: T.Type,
    from rawValue: RawValue
) throws -> T {
    let typeName = String(describing: T.self)
    switch rawValue {
    case .int(let value):
        guard let converted = T(exactly: value) else {
            throw ValueDecodingError(
                expectedType: typeName,
                reason: "Integer \(value) is out of range for \(typeName) (\(T.min)...\(T.max))."
            )
        }
        return converted
    case .double(let value):
        guard value.isFinite, value.rounded(.towardZero) == value, let converted = T(exactly: value) else {
            throw ValueDecodingError(
                expectedType: typeName,
                reason: "Expected exact integer within \(typeName) range, got \(value)."
            )
        }
        return converted
    case .string(let raw):
        let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "_", with: "")
        guard !cleaned.isEmpty, let converted = T(cleaned) else {
            throw ValueDecodingError(
                expectedType: typeName,
                reason: "Expected valid \(typeName) integer."
            )
        }
        return converted
    default:
        throw ValueDecodingError(
            expectedType: typeName,
            reason: "Expected integer scalar, got \(rawKindName(rawValue))."
        )
    }
}

extension Int: SettingValueDecodable {
    /// Decodes a range-checked `Int` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> Int {
        try decodeFixedWidthInteger(Int.self, from: rawValue)
    }
}

extension Int8: SettingValueDecodable {
    /// Decodes a range-checked `Int8` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> Int8 {
        try decodeFixedWidthInteger(Int8.self, from: rawValue)
    }
}

extension Int16: SettingValueDecodable {
    /// Decodes a range-checked `Int16` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> Int16 {
        try decodeFixedWidthInteger(Int16.self, from: rawValue)
    }
}

extension Int32: SettingValueDecodable {
    /// Decodes a range-checked `Int32` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> Int32 {
        try decodeFixedWidthInteger(Int32.self, from: rawValue)
    }
}

extension Int64: SettingValueDecodable {
    /// Decodes a range-checked `Int64` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> Int64 {
        try decodeFixedWidthInteger(Int64.self, from: rawValue)
    }
}

extension UInt: SettingValueDecodable {
    /// Decodes a range-checked `UInt` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> UInt {
        try decodeFixedWidthInteger(UInt.self, from: rawValue)
    }
}

extension UInt8: SettingValueDecodable {
    /// Decodes a range-checked `UInt8` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> UInt8 {
        try decodeFixedWidthInteger(UInt8.self, from: rawValue)
    }
}

extension UInt16: SettingValueDecodable {
    /// Decodes a range-checked `UInt16` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> UInt16 {
        try decodeFixedWidthInteger(UInt16.self, from: rawValue)
    }
}

extension UInt32: SettingValueDecodable {
    /// Decodes a range-checked `UInt32` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> UInt32 {
        try decodeFixedWidthInteger(UInt32.self, from: rawValue)
    }
}

extension UInt64: SettingValueDecodable {
    /// Decodes a range-checked `UInt64` from integer, exact-float, or numeric string configuration values.
    public static func decodeSettingValue(from rawValue: RawValue, context: ValueDecodingContext) throws -> UInt64 {
        try decodeFixedWidthInteger(UInt64.self, from: rawValue)
    }
}

// MARK: - Floating Point & Decimal

extension Double: SettingValueDecodable {
    /// Display name for `Double` settings (`"Double"`).
    public static var settingTypeDisplayName: String { "Double" }

    /// Decodes a finite `Double` from numeric or string configuration values.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Double {
        switch rawValue {
        case .double(let value):
            guard value.isFinite else {
                throw ValueDecodingError(expectedType: "Double", reason: "Non-finite float is not allowed.")
            }
            return value
        case .int(let value):
            return Double(value)
        case .string(let raw):
            let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "_", with: "")
            guard !cleaned.isEmpty, let value = Double(cleaned), value.isFinite else {
                throw ValueDecodingError(expectedType: "Double", reason: "Expected finite floating-point number.")
            }
            return value
        default:
            throw ValueDecodingError(
                expectedType: "Double",
                reason: "Expected numeric scalar, got \(rawKindName(rawValue))."
            )
        }
    }
}

extension Float: SettingValueDecodable {
    /// Display name for `Float` settings (`"Float"`).
    public static var settingTypeDisplayName: String { "Float" }

    /// Decodes a finite `Float` from numeric or string configuration values.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Float {
        let doubleValue = try Double.decodeSettingValue(from: rawValue, context: context)
        let floatValue = Float(doubleValue)
        guard floatValue.isFinite else {
            throw ValueDecodingError(expectedType: "Float", reason: "Value overflows Float range.")
        }
        return floatValue
    }
}

extension Decimal: SettingValueDecodable {
    /// Display name for `Decimal` settings (`"Decimal"`).
    public static var settingTypeDisplayName: String { "Decimal" }

    /// Decodes an exact base-10 `Decimal` using the `en_US_POSIX` locale.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Decimal {
        switch rawValue {
        case .int(let value):
            return Decimal(value)
        case .double(let value):
            guard value.isFinite else {
                throw ValueDecodingError(expectedType: "Decimal", reason: "Non-finite number is not allowed.")
            }
            return Decimal(string: String(value), locale: Locale(identifier: "en_US_POSIX")) ?? Decimal(value)
        case .string(let raw):
            let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "_", with: "")
            guard !cleaned.isEmpty,
                  let decimal = Decimal(string: cleaned, locale: Locale(identifier: "en_US_POSIX")),
                  !decimal.isNaN else {
                throw ValueDecodingError(expectedType: "Decimal", reason: "Expected valid decimal number.")
            }
            return decimal
        default:
            throw ValueDecodingError(
                expectedType: "Decimal",
                reason: "Expected decimal scalar, got \(rawKindName(rawValue))."
            )
        }
    }
}

// MARK: - Foundation Types (UUID, URL, Date, Data)

extension UUID: SettingValueDecodable {
    /// Display name for `UUID` settings (`"UUID"`).
    public static var settingTypeDisplayName: String { "UUID" }

    /// Decodes a 36-character RFC 4122 `UUID` string.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> UUID {
        guard case .string(let raw) = rawValue else {
            throw ValueDecodingError(
                expectedType: "UUID",
                reason: "Expected UUID string, got \(rawKindName(rawValue))."
            )
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let uuid = UUID(uuidString: trimmed) else {
            throw ValueDecodingError(
                expectedType: "UUID",
                reason: "Expected 36-character RFC 4122 UUID string."
            )
        }
        return uuid
    }
}

extension URL: SettingValueDecodable {
    /// Display name for `URL` settings (`"URL"`).
    public static var settingTypeDisplayName: String { "URL" }

    /// Decodes a non-empty `URL` string.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> URL {
        guard case .string(let raw) = rawValue else {
            throw ValueDecodingError(
                expectedType: "URL",
                reason: "Expected URL string, got \(rawKindName(rawValue))."
            )
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let url = URL(string: trimmed) else {
            throw ValueDecodingError(
                expectedType: "URL",
                reason: "Expected valid non-empty URL string."
            )
        }
        return url
    }
}

extension Date: SettingValueDecodable {
    /// Display name for `Date` settings (`"Date"`).
    public static var settingTypeDisplayName: String { "Date" }

    /// Decodes an ISO-8601 timestamp string (internet date-time with or without fractional seconds, or full date)
    /// or Unix epoch seconds number into a `Date`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Date {
        switch rawValue {
        case .int(let epochSeconds):
            return Date(timeIntervalSince1970: TimeInterval(epochSeconds))
        case .double(let epochSeconds):
            guard epochSeconds.isFinite else {
                throw ValueDecodingError(expectedType: "Date", reason: "Epoch timestamp must be finite.")
            }
            return Date(timeIntervalSince1970: epochSeconds)
        case .string(let raw):
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw ValueDecodingError(expectedType: "Date", reason: "Expected ISO-8601 timestamp string.")
            }

            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = fractional.date(from: trimmed) {
                return date
            }

            let standard = ISO8601DateFormatter()
            standard.formatOptions = [.withInternetDateTime]
            if let date = standard.date(from: trimmed) {
                return date
            }

            let dateOnly = ISO8601DateFormatter()
            dateOnly.formatOptions = [.withFullDate]
            if let date = dateOnly.date(from: trimmed) {
                return date
            }

            throw ValueDecodingError(
                expectedType: "Date",
                reason: "Expected ISO-8601 timestamp (e.g. '2026-11-15T09:30:00Z')."
            )
        default:
            throw ValueDecodingError(
                expectedType: "Date",
                reason: "Expected ISO-8601 string or epoch timestamp, got \(rawKindName(rawValue))."
            )
        }
    }
}

extension Data: SettingValueDecodable {
    /// Display name for `Data` settings (`"Data"`).
    public static var settingTypeDisplayName: String { "Data" }

    /// Decodes raw bytes, `"base64:..."` payloads, UTF-8 strings, or `[UInt8]` arrays into `Data`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Data {
        switch rawValue {
        case .data(let data):
            return data
        case .string(let raw):
            if raw.hasPrefix("base64:") {
                let encoded = String(raw.dropFirst("base64:".count)).trimmingCharacters(in: .whitespacesAndNewlines)
                guard let decoded = Data(base64Encoded: encoded) else {
                    throw ValueDecodingError(expectedType: "Data", reason: "Invalid base64 payload after 'base64:'.")
                }
                return decoded
            }
            return Data(raw.utf8)
        case .array(let nodes):
            var bytes: [UInt8] = []
            bytes.reserveCapacity(nodes.count)
            for node in nodes {
                bytes.append(try UInt8.decodeSettingValue(from: node.value, context: context))
            }
            return Data(bytes)
        default:
            throw ValueDecodingError(
                expectedType: "Data",
                reason: "Expected bytes or string, got \(rawKindName(rawValue))."
            )
        }
    }
}

// MARK: - Duration

extension Duration: SettingValueDecodable {
    /// Display name for `Duration` settings (`"Duration"`).
    public static var settingTypeDisplayName: String { "Duration" }

    /// Decodes human-readable duration strings (such as `"500ms"`, `"30s"`, `"5m"`, `"1h30m"`)
    /// or non-negative numeric seconds into a Swift `Duration`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Duration {
        switch rawValue {
        case .int(let seconds):
            guard seconds >= 0 else {
                throw ValueDecodingError(expectedType: "Duration", reason: "Duration must be non-negative.")
            }
            return .seconds(seconds)
        case .double(let seconds):
            guard seconds.isFinite, seconds >= 0 else {
                throw ValueDecodingError(expectedType: "Duration", reason: "Duration must be finite and non-negative.")
            }
            return durationFromSeconds(seconds)
        case .string(let raw):
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw ValueDecodingError(expectedType: "Duration", reason: "Expected duration (e.g. '30s', '500ms', '5m', '1h').")
            }
            if let numericSeconds = Double(trimmed) {
                guard numericSeconds.isFinite, numericSeconds >= 0 else {
                    throw ValueDecodingError(expectedType: "Duration", reason: "Duration must be finite and non-negative.")
                }
                return durationFromSeconds(numericSeconds)
            }
            return try parseDurationString(trimmed)
        default:
            throw ValueDecodingError(
                expectedType: "Duration",
                reason: "Expected duration string or numeric seconds, got \(rawKindName(rawValue))."
            )
        }
    }

    private static func durationFromSeconds(_ seconds: Double) -> Duration {
        let wholeSeconds = Int64(seconds.rounded(.towardZero))
        let fractionalSeconds = seconds - Double(wholeSeconds)
        let attoseconds = Int64((fractionalSeconds * 1e18).rounded())
        return Duration(secondsComponent: wholeSeconds, attosecondsComponent: attoseconds)
    }

    private static func parseDurationString(_ text: String) throws -> Duration {
        var index = text.startIndex
        var totalNanoseconds: Double = 0
        var parsedAnySegment = false

        while index < text.endIndex {
            while index < text.endIndex && text[index].isWhitespace {
                index = text.index(after: index)
            }
            if index == text.endIndex { break }

            let numStart = index
            var sawDot = false
            while index < text.endIndex {
                let ch = text[index]
                if ch.isNumber {
                    index = text.index(after: index)
                } else if ch == "." && !sawDot {
                    sawDot = true
                    index = text.index(after: index)
                } else {
                    break
                }
            }

            guard numStart < index, let amount = Double(text[numStart..<index]), amount.isFinite, amount >= 0 else {
                throw ValueDecodingError(
                    expectedType: "Duration",
                    reason: "Invalid duration '\(text)'; expected format like '30s', '500ms', '5m', '1h'."
                )
            }

            let unitStart = index
            while index < text.endIndex && (text[index].isLetter || text[index] == "µ") {
                index = text.index(after: index)
            }

            let unit = String(text[unitStart..<index]).lowercased()
            let multiplierNanoseconds: Double
            switch unit {
            case "ns":
                multiplierNanoseconds = 1
            case "us", "µs", "μs":
                multiplierNanoseconds = 1_000
            case "ms":
                multiplierNanoseconds = 1_000_000
            case "s", "sec", "secs":
                multiplierNanoseconds = 1_000_000_000
            case "m", "min", "mins":
                multiplierNanoseconds = 60 * 1_000_000_000
            case "h", "hr", "hrs":
                multiplierNanoseconds = 3_600 * 1_000_000_000
            case "d", "day", "days":
                multiplierNanoseconds = 86_400 * 1_000_000_000
            default:
                throw ValueDecodingError(
                    expectedType: "Duration",
                    reason: "Unknown duration unit '\(unit)'; supported units: ns, us, ms, s, m, h, d."
                )
            }

            totalNanoseconds += amount * multiplierNanoseconds
            parsedAnySegment = true
        }

        guard parsedAnySegment else {
            throw ValueDecodingError(
                expectedType: "Duration",
                reason: "Expected duration (e.g. '30s', '500ms', '5m', '1h')."
            )
        }

        let wholeSeconds = Int64((totalNanoseconds / 1_000_000_000).rounded(.towardZero))
        let remNanoseconds = totalNanoseconds - (Double(wholeSeconds) * 1_000_000_000)
        let attoseconds = Int64((remNanoseconds * 1_000_000_000).rounded())
        return Duration(secondsComponent: wholeSeconds, attosecondsComponent: attoseconds)
    }
}

// MARK: - ByteCount

/// A byte-size quantity supporting decimal SI (`KB`, `MB`, `GB`, `TB`, `PB`) and binary IEC
/// (`KiB`, `MiB`, `GiB`, `TiB`, `PiB`) configuration literals as well as integer byte counts.
///
/// ```swift
/// let maxUpload = try ByteCount.decodeSettingValue(from: .string("25MiB"))
/// // maxUpload.bytes == 26_214_400
/// ```
public struct ByteCount:
    Sendable,
    Equatable,
    Hashable,
    Comparable,
    Codable,
    ExpressibleByIntegerLiteral,
    CustomStringConvertible,
    SettingValueDecodable
{
    /// Display name for ``ByteCount`` settings (`"ByteCount"`).
    public static var settingTypeDisplayName: String { "ByteCount" }

    /// Exact number of bytes represented by this value.
    public let bytes: Int64

    /// Creates a byte-size quantity from an exact byte count.
    ///
    /// - Parameter bytes: Number of bytes.
    public init(bytes: Int64) {
        self.bytes = bytes
    }

    /// Creates a byte-size quantity from an integer literal representing exact bytes.
    ///
    /// - Parameter value: Integer byte count literal.
    public init(integerLiteral value: Int64) {
        self.bytes = value
    }

    /// Compares two ``ByteCount`` values by their underlying ``bytes``.
    public static func < (lhs: ByteCount, rhs: ByteCount) -> Bool {
        lhs.bytes < rhs.bytes
    }

    /// Formatted string representation (`"<bytes> B"`).
    public var description: String {
        "\(bytes) B"
    }

    /// Creates a ``ByteCount`` equal to `count * 1_000` bytes (decimal SI kilobytes).
    public static func kilobytes(_ count: Int64) -> ByteCount { ByteCount(bytes: count * 1_000) }

    /// Creates a ``ByteCount`` equal to `count * 1_000_000` bytes (decimal SI megabytes).
    public static func megabytes(_ count: Int64) -> ByteCount { ByteCount(bytes: count * 1_000_000) }

    /// Creates a ``ByteCount`` equal to `count * 1_000_000_000` bytes (decimal SI gigabytes).
    public static func gigabytes(_ count: Int64) -> ByteCount { ByteCount(bytes: count * 1_000_000_000) }

    /// Creates a ``ByteCount`` equal to `count * 1_000_000_000_000` bytes (decimal SI terabytes).
    public static func terabytes(_ count: Int64) -> ByteCount { ByteCount(bytes: count * 1_000_000_000_000) }

    /// Creates a ``ByteCount`` equal to `count * 1_024` bytes (binary IEC kibibytes).
    public static func kibibytes(_ count: Int64) -> ByteCount { ByteCount(bytes: count * 1_024) }

    /// Creates a ``ByteCount`` equal to `count * 1_048_576` bytes (binary IEC mebibytes).
    public static func mebibytes(_ count: Int64) -> ByteCount { ByteCount(bytes: count * 1_048_576) }

    /// Creates a ``ByteCount`` equal to `count * 1_073_741_824` bytes (binary IEC gibibytes).
    public static func gibibytes(_ count: Int64) -> ByteCount { ByteCount(bytes: count * 1_073_741_824) }

    /// Creates a ``ByteCount`` equal to `count * 1_099_511_627_776` bytes (binary IEC tebibytes).
    public static func tebibytes(_ count: Int64) -> ByteCount { ByteCount(bytes: count * 1_099_511_627_776) }

    /// Decodes a non-negative ``ByteCount`` from numeric byte counts or SI/IEC unit strings.
    ///
    /// - Parameters:
    ///   - rawValue: Untyped configuration value.
    ///   - context: Value-decoding context.
    /// - Returns: Parsed ``ByteCount``.
    /// - Throws: ``ValueDecodingError`` if negative, malformed, or overflowing `Int64`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> ByteCount {
        switch rawValue {
        case .int(let value):
            guard value >= 0 else {
                throw ValueDecodingError(expectedType: "ByteCount", reason: "ByteCount must be non-negative.")
            }
            return ByteCount(bytes: value)
        case .double(let value):
            guard value.isFinite, value >= 0, let exact = Int64(exactly: value.rounded()) else {
                throw ValueDecodingError(expectedType: "ByteCount", reason: "Expected non-negative byte count.")
            }
            return ByteCount(bytes: exact)
        case .string(let raw):
            return try parseByteCount(raw)
        default:
            throw ValueDecodingError(
                expectedType: "ByteCount",
                reason: "Expected byte size string (e.g. '512KB', '10MB', '2GiB') or integer, got \(rawKindName(rawValue))."
            )
        }
    }

    private static func parseByteCount(_ raw: String) throws -> ByteCount {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "_", with: "")
        guard !trimmed.isEmpty else {
            throw ValueDecodingError(
                expectedType: "ByteCount",
                reason: "Expected byte size (e.g. '512KB', '10MB', '2GiB')."
            )
        }

        if let plainInt = Int64(trimmed) {
            guard plainInt >= 0 else {
                throw ValueDecodingError(expectedType: "ByteCount", reason: "ByteCount must be non-negative.")
            }
            return ByteCount(bytes: plainInt)
        }

        var index = trimmed.startIndex
        var sawDot = false
        while index < trimmed.endIndex {
            let ch = trimmed[index]
            if ch.isNumber {
                index = trimmed.index(after: index)
            } else if ch == "." && !sawDot {
                sawDot = true
                index = trimmed.index(after: index)
            } else {
                break
            }
        }

        let numberPart = String(trimmed[..<index])
        let unitPart = trimmed[index...].trimmingCharacters(in: .whitespaces).lowercased()

        guard !numberPart.isEmpty, let magnitude = Double(numberPart), magnitude.isFinite, magnitude >= 0 else {
            throw ValueDecodingError(
                expectedType: "ByteCount",
                reason: "Invalid byte size '\(raw)'; expected e.g. '512KB', '10MB', '2GiB'."
            )
        }

        let multiplier: Double
        switch unitPart {
        case "", "b", "byte", "bytes":
            multiplier = 1
        case "kb", "k":
            multiplier = 1_000
        case "mb", "m":
            multiplier = 1_000_000
        case "gb", "g":
            multiplier = 1_000_000_000
        case "tb", "t":
            multiplier = 1_000_000_000_000
        case "pb", "p":
            multiplier = 1_000_000_000_000_000
        case "kib", "ki":
            multiplier = 1_024
        case "mib", "mi":
            multiplier = 1_048_576
        case "gib", "gi":
            multiplier = 1_073_741_824
        case "tib", "ti":
            multiplier = 1_099_511_627_776
        case "pib", "pi":
            multiplier = 1_125_899_906_842_624
        default:
            throw ValueDecodingError(
                expectedType: "ByteCount",
                reason: "Unknown byte unit '\(unitPart)'; supported units: B, KB, MB, GB, TB, KiB, MiB, GiB, TiB."
            )
        }

        let product = (magnitude * multiplier).rounded()
        guard product >= 0, product <= Double(Int64.max) else {
            throw ValueDecodingError(expectedType: "ByteCount", reason: "Byte size overflows Int64.")
        }
        return ByteCount(bytes: Int64(product))
    }
}

// MARK: - RawRepresentable Enums

extension SettingValueDecodable where Self: RawRepresentable, Self.RawValue: SettingValueDecodable {
    /// Decodes a `RawRepresentable` setting by first decoding its underlying `RawValue`.
    public static func decodeSettingValue(
        from rawValue: RiggingCore.RawValue,
        context: ValueDecodingContext
    ) throws -> Self {
        let decodedRaw = try Self.RawValue.decodeSettingValue(from: rawValue, context: context)
        if let exact = Self(rawValue: decodedRaw) {
            return exact
        }
        throw ValueDecodingError(
            expectedType: settingTypeDisplayName,
            reason: "Unsupported \(settingTypeDisplayName) value '\(decodedRaw)'."
        )
    }
}

extension SettingValueDecodable where Self: RawRepresentable & CaseIterable, Self.RawValue == String {
    /// Decodes a `CaseIterable` string enum, matching case-insensitively when ``ValueDecodingContext/caseSensitive``
    /// is `false` and listing all valid cases on failure.
    public static func decodeSettingValue(
        from rawValue: RiggingCore.RawValue,
        context: ValueDecodingContext
    ) throws -> Self {
        let decodedRaw = try String.decodeSettingValue(from: rawValue, context: context)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        if let exact = Self(rawValue: decodedRaw) {
            return exact
        }

        if !context.caseSensitive {
            let lower = decodedRaw.lowercased()
            if let matched = Self.allCases.first(where: { $0.rawValue.lowercased() == lower }) {
                return matched
            }
        }

        let validOptions = Self.allCases.map(\.rawValue).joined(separator: ", ")
        throw ValueDecodingError(
            expectedType: settingTypeDisplayName,
            reason: "Expected one of [\(validOptions)], got '\(decodedRaw)'."
        )
    }
}

// MARK: - Optional

extension Optional: SettingValueDecodable where Wrapped: SettingValueDecodable {
    /// Display name for optional settings (`"<Wrapped>?"`).
    public static var settingTypeDisplayName: String {
        "\(Wrapped.settingTypeDisplayName)?"
    }

    /// Decodes `nil` when `rawValue` matches ``ValueDecodingContext/representsNull(_:)``, otherwise decodes `Wrapped`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Wrapped? {
        if context.representsNull(rawValue) {
            return nil
        }
        return try Wrapped.decodeSettingValue(from: rawValue, context: context)
    }
}

// MARK: - Collections ([T], Set<T>, [String: V])

extension Array: SettingValueDecodable where Element: SettingValueDecodable {
    /// Display name for array settings (`"[<Element>]"`).
    public static var settingTypeDisplayName: String {
        "[\(Element.settingTypeDisplayName)]"
    }

    /// Decodes structured `.array` nodes or formatted list strings according to ``ValueDecodingContext/envListStrategy``.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> [Element] {
        switch rawValue {
        case .array(let nodes):
            return try nodes.map { try Element.decodeSettingValue(from: $0.value, context: context) }
        case .string(let raw):
            let itemValues = try parseListRawValues(
                from: raw,
                strategy: context.envListStrategy,
                expectedType: settingTypeDisplayName
            )
            return try itemValues.map { try Element.decodeSettingValue(from: $0, context: context) }
        default:
            throw ValueDecodingError(
                expectedType: settingTypeDisplayName,
                reason: "Expected array or formatted list string, got \(rawKindName(rawValue))."
            )
        }
    }
}

extension Set: SettingValueDecodable where Element: SettingValueDecodable & Hashable {
    /// Display name for set settings (`"Set<<Element>>"`).
    public static var settingTypeDisplayName: String {
        "Set<\(Element.settingTypeDisplayName)>"
    }

    /// Decodes structured `.array` nodes or formatted list strings into a deduplicated `Set`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> Set<Element> {
        let array = try [Element].decodeSettingValue(from: rawValue, context: context)
        return Set(array)
    }
}

extension Dictionary: SettingValueDecodable where Key == String, Value: SettingValueDecodable {
    /// Display name for string-keyed dictionary settings (`"[String: <Value>]"`).
    public static var settingTypeDisplayName: String {
        "[String: \(Value.settingTypeDisplayName)]"
    }

    /// Decodes structured `.object` nodes or formatted `k=v` / JSON object strings into `[String: Value]`.
    public static func decodeSettingValue(
        from rawValue: RawValue,
        context: ValueDecodingContext
    ) throws -> [String: Value] {
        switch rawValue {
        case .object(let dict):
            var result: [String: Value] = [:]
            result.reserveCapacity(dict.count)
            for (k, node) in dict {
                result[k] = try Value.decodeSettingValue(from: node.value, context: context)
            }
            return result
        case .string(let raw):
            let mapValues = try parseDictionaryRawValues(
                from: raw,
                strategy: context.envListStrategy,
                expectedType: settingTypeDisplayName
            )
            var result: [String: Value] = [:]
            result.reserveCapacity(mapValues.count)
            for (k, val) in mapValues {
                result[k] = try Value.decodeSettingValue(from: val, context: context)
            }
            return result
        default:
            throw ValueDecodingError(
                expectedType: settingTypeDisplayName,
                reason: "Expected dictionary/object or formatted map string, got \(rawKindName(rawValue))."
            )
        }
    }
}

// MARK: - Collection String Helpers

private func parseListRawValues(
    from string: String,
    strategy: EnvCollectionStrategy,
    expectedType: String
) throws -> [RawValue] {
    let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)

    switch strategy {
    case .noDecode:
        throw ValueDecodingError(
            expectedType: expectedType,
            reason: "Collection decoding from environment strings is disabled (.noDecode)."
        )

    case .jsonOnly:
        return try decodeJSONArray(from: trimmed, expectedType: expectedType)

    case .jsonOrCommaSeparated:
        if trimmed.isEmpty {
            return []
        }
        if trimmed.hasPrefix("[") {
            return try decodeJSONArray(from: trimmed, expectedType: expectedType)
        }
        return splitSeparatedItems(trimmed, separator: ",")

    case .separator(let separator):
        if trimmed.isEmpty {
            return []
        }
        return splitSeparatedItems(trimmed, separator: separator)
    }
}

private func parseDictionaryRawValues(
    from string: String,
    strategy: EnvCollectionStrategy,
    expectedType: String
) throws -> [String: RawValue] {
    let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)

    switch strategy {
    case .noDecode:
        throw ValueDecodingError(
            expectedType: expectedType,
            reason: "Dictionary decoding from environment strings is disabled (.noDecode)."
        )

    case .jsonOnly:
        return try decodeJSONObject(from: trimmed, expectedType: expectedType)

    case .jsonOrCommaSeparated:
        if trimmed.isEmpty {
            return [:]
        }
        if trimmed.hasPrefix("{") {
            return try decodeJSONObject(from: trimmed, expectedType: expectedType)
        }
        return try parseKeyValuePairs(trimmed, separator: ",", expectedType: expectedType)

    case .separator(let separator):
        if trimmed.isEmpty {
            return [:]
        }
        return try parseKeyValuePairs(trimmed, separator: separator, expectedType: expectedType)
    }
}

private func splitSeparatedItems(_ text: String, separator: Character) -> [RawValue] {
    text
        .split(separator: separator, omittingEmptySubsequences: false)
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
        .map { .string($0) }
}

private func parseKeyValuePairs(
    _ text: String,
    separator: Character,
    expectedType: String
) throws -> [String: RawValue] {
    var result: [String: RawValue] = [:]
    let pairs = text.split(separator: separator, omittingEmptySubsequences: true)
    for pair in pairs {
        let trimmedPair = pair.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedPair.isEmpty else { continue }
        guard let eqIndex = trimmedPair.firstIndex(of: "=") else {
            throw ValueDecodingError(
                expectedType: expectedType,
                reason: "Expected 'key=value' entry in dictionary string, got '\(trimmedPair)'."
            )
        }
        let key = trimmedPair[..<eqIndex].trimmingCharacters(in: .whitespacesAndNewlines)
        let val = trimmedPair[trimmedPair.index(after: eqIndex)...].trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else {
            throw ValueDecodingError(expectedType: expectedType, reason: "Dictionary entry has an empty key.")
        }
        result[key] = .string(val)
    }
    return result
}

private func decodeJSONArray(from text: String, expectedType: String) throws -> [RawValue] {
    guard let data = text.data(using: .utf8),
          let json = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]),
          let array = json as? [Any] else {
        throw ValueDecodingError(expectedType: expectedType, reason: "Expected valid JSON array.")
    }
    return try array.map { try convertJSONObjectToRawValue($0, expectedType: expectedType) }
}

private func decodeJSONObject(from text: String, expectedType: String) throws -> [String: RawValue] {
    guard let data = text.data(using: .utf8),
          let json = try? JSONSerialization.jsonObject(with: data, options: []),
          let dict = json as? [String: Any] else {
        throw ValueDecodingError(expectedType: expectedType, reason: "Expected valid JSON object.")
    }
    var mapped: [String: RawValue] = [:]
    mapped.reserveCapacity(dict.count)
    for (key, value) in dict {
        mapped[key] = try convertJSONObjectToRawValue(value, expectedType: expectedType)
    }
    return mapped
}

private func convertJSONObjectToRawValue(_ object: Any, expectedType: String) throws -> RawValue {
    if object is NSNull {
        return .null
    }
    if let string = object as? String {
        return .string(string)
    }
    #if canImport(ObjectiveC)
    if let number = object as? NSNumber {
        if CFGetTypeID(number) == CFBooleanGetTypeID() {
            return .bool(number.boolValue)
        }
        let objCType = String(cString: number.objCType)
        if ["c", "i", "s", "l", "q", "C", "I", "S", "L", "Q"].contains(objCType) {
            if objCType == "Q" && number.uint64Value > UInt64(Int64.max) {
                return .double(number.doubleValue)
            }
            return .int(number.int64Value)
        }
        return .double(number.doubleValue)
    }
    #else
    if let boolValue = object as? Bool {
        return .bool(boolValue)
    }
    if let int64Value = object as? Int64 {
        return .int(int64Value)
    }
    if let intValue = object as? Int {
        return .int(Int64(intValue))
    }
    if let uint64Value = object as? UInt64 {
        if uint64Value <= UInt64(Int64.max) {
            return .int(Int64(uint64Value))
        }
        return .double(Double(uint64Value))
    }
    if let doubleValue = object as? Double {
        return .double(doubleValue)
    }
    if let number = object as? NSNumber {
        let objCType = String(cString: number.objCType)
        if objCType == "B" {
            return .bool(number.boolValue)
        }
        if objCType == "d" || objCType == "f" {
            return .double(number.doubleValue)
        }
        if objCType == "Q" && number.uint64Value > UInt64(Int64.max) {
            return .double(number.doubleValue)
        }
        return .int(number.int64Value)
    }
    #endif
    if let array = object as? [Any] {
        let items = try array.map {
            RawNode(
                value: try convertJSONObjectToRawValue($0, expectedType: expectedType),
                origin: .defaultValue
            )
        }
        return .array(items)
    }
    if let dict = object as? [String: Any] {
        var mapped: [String: RawNode] = [:]
        for (k, v) in dict {
            mapped[k] = RawNode(
                value: try convertJSONObjectToRawValue(v, expectedType: expectedType),
                origin: .defaultValue
            )
        }
        return .object(mapped)
    }
    throw ValueDecodingError(expectedType: expectedType, reason: "Unsupported JSON value.")
}

private func rawKindName(_ rawValue: RawValue) -> String {
    switch rawValue {
    case .string: return "string"
    case .bool: return "boolean"
    case .int: return "integer"
    case .double: return "number"
    case .data: return "bytes"
    case .null: return "null"
    case .array: return "array"
    case .object: return "object"
    }
}
