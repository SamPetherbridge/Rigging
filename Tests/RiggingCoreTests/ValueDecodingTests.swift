import Foundation
import RiggingCore
import RiggingTesting
import Testing

private enum SampleLogLevel: String, CaseIterable, Sendable, SettingValueDecodable {
    case debug
    case info
    case warning
    case error
}

private enum SampleHTTPVersion: Int, Sendable, SettingValueDecodable {
    case v1 = 1
    case v2 = 2
    case v3 = 3
}

@Suite("ValueDecoding, Collections, Null Strings & Empty Env Handling")
struct ValueDecodingTests {

    @Test(
        "Bool decodes truthy and falsy string & integer literals",
        arguments: [
            ("true", true),
            ("TRUE", true),
            ("1", true),
            ("yes", true),
            ("YES", true),
            ("on", true),
            ("ON", true),
            ("false", false),
            ("FALSE", false),
            ("0", false),
            ("no", false),
            ("NO", false),
            ("off", false),
            ("OFF", false),
        ]
    )
    func boolLiterals(input: String, expected: Bool) throws {
        let decoded = try Bool.decodeSettingValue(from: .string(input))
        #expect(decoded == expected)
    }

    @Test("Bool integer coercion and invalid rejection")
    func boolIntegersAndErrors() throws {
        #expect(try Bool.decodeSettingValue(from: .int(1)) == true)
        #expect(try Bool.decodeSettingValue(from: .int(0)) == false)
        #expect(throws: ValueDecodingError.self) {
            try Bool.decodeSettingValue(from: .int(2))
        }
        #expect(throws: ValueDecodingError.self) {
            try Bool.decodeSettingValue(from: .string("maybe"))
        }
    }

    @Test("Fixed-width integers, floating-point numbers, and Decimal")
    func numericScalars() throws {
        #expect(try Int.decodeSettingValue(from: .string("1_000_000")) == 1_000_000)
        #expect(try Int8.decodeSettingValue(from: .int(-128)) == -128)
        #expect(throws: ValueDecodingError.self) {
            try UInt8.decodeSettingValue(from: .int(300))
        }
        #expect(throws: ValueDecodingError.self) {
            try Int.decodeSettingValue(from: .double(3.14))
        }

        #expect(try Double.decodeSettingValue(from: .string("3.14159")) == 3.14159)
        #expect(try Float.decodeSettingValue(from: .int(42)) == Float(42))
        #expect(throws: ValueDecodingError.self) {
            try Double.decodeSettingValue(from: .double(.infinity))
        }

        let dec = try Decimal.decodeSettingValue(from: .string("12345.67"))
        #expect(dec == Decimal(string: "12345.67"))
    }

    @Test("UUID, URL, ISO-8601 Date, and Data decoding")
    func foundationTypes() throws {
        let uuid = try UUID.decodeSettingValue(from: .string("11111111-2222-3333-4444-555555555555"))
        #expect(uuid.uuidString == "11111111-2222-3333-4444-555555555555")
        #expect(throws: ValueDecodingError.self) {
            try UUID.decodeSettingValue(from: .string("not-a-uuid"))
        }

        let url = try URL.decodeSettingValue(from: .string("https://api.appstoreconnect.apple.com/v1"))
        #expect(url.host == "api.appstoreconnect.apple.com")

        let isoStandard = try Date.decodeSettingValue(from: .string("2026-11-15T10:00:00Z"))
        let isoFractional = try Date.decodeSettingValue(from: .string("2026-11-15T10:00:00.500Z"))
        let isoDateOnly = try Date.decodeSettingValue(from: .string("2026-11-15"))
        let epochDate = try Date.decodeSettingValue(from: .int(1_700_000_000))
        #expect(isoFractional.timeIntervalSince(isoStandard) == 0.5)
        #expect(isoDateOnly < isoStandard)
        #expect(epochDate.timeIntervalSince1970 == 1_700_000_000)

        let b64Data = try Data.decodeSettingValue(from: .string("base64:SGVsbG8="))
        #expect(String(data: b64Data, encoding: .utf8) == "Hello")
        let rawData = try Data.decodeSettingValue(from: .string("plain-text"))
        #expect(String(data: rawData, encoding: .utf8) == "plain-text")
    }

    @Test("Duration parses human units ('30s', '500ms', '2m', '1h', compound) and numeric seconds")
    func durationParsing() throws {
        #expect(try Duration.decodeSettingValue(from: .string("30s")) == .seconds(30))
        #expect(try Duration.decodeSettingValue(from: .string("500ms")) == .milliseconds(500))
        #expect(try Duration.decodeSettingValue(from: .string("2m")) == .seconds(120))
        #expect(try Duration.decodeSettingValue(from: .string("1h")) == .seconds(3_600))
        #expect(try Duration.decodeSettingValue(from: .string("1m30s")) == .seconds(90))
        #expect(try Duration.decodeSettingValue(from: .string("45")) == .seconds(45))
        #expect(try Duration.decodeSettingValue(from: .int(15)) == .seconds(15))
        #expect(try Duration.decodeSettingValue(from: .double(0.5)) == .milliseconds(500))

        #expect(throws: ValueDecodingError.self) {
            try Duration.decodeSettingValue(from: .int(-5))
        }
        #expect(throws: ValueDecodingError.self) {
            try Duration.decodeSettingValue(from: .string("10weeks"))
        }
    }

    @Test("ByteCount parses SI ('512KB', '10MB') and IEC ('2GiB', '4KiB') units and integers")
    func byteCountParsing() throws {
        #expect(try ByteCount.decodeSettingValue(from: .string("512KB")) == .kilobytes(512))
        #expect(try ByteCount.decodeSettingValue(from: .string("10MB")) == .megabytes(10))
        #expect(try ByteCount.decodeSettingValue(from: .string("2GiB")) == .gibibytes(2))
        #expect(try ByteCount.decodeSettingValue(from: .string("4KiB")) == .kibibytes(4))
        #expect(try ByteCount.decodeSettingValue(from: .int(1_024)).bytes == 1_024)
        #expect(ByteCount.kilobytes(1) < ByteCount.kibibytes(1))

        #expect(throws: ValueDecodingError.self) {
            try ByteCount.decodeSettingValue(from: .int(-1))
        }
        #expect(throws: ValueDecodingError.self) {
            try ByteCount.decodeSettingValue(from: .string("12ZB"))
        }
    }

    @Test("RawRepresentable String (case-insensitive vs case-sensitive) and Int enums")
    func rawRepresentableEnums() throws {
        let insensitive = ValueDecodingContext(caseSensitive: false)
        #expect(try SampleLogLevel.decodeSettingValue(from: .string("INFO"), context: insensitive) == .info)
        #expect(try SampleLogLevel.decodeSettingValue(from: .string("Warning"), context: insensitive) == .warning)

        let sensitive = ValueDecodingContext(caseSensitive: true)
        #expect(try SampleLogLevel.decodeSettingValue(from: .string("info"), context: sensitive) == .info)
        #expect(throws: ValueDecodingError.self) {
            try SampleLogLevel.decodeSettingValue(from: .string("INFO"), context: sensitive)
        }

        #expect(try SampleHTTPVersion.decodeSettingValue(from: .int(2)) == .v2)
        #expect(try SampleHTTPVersion.decodeSettingValue(from: .string("3")) == .v3)
        #expect(throws: ValueDecodingError.self) {
            try SampleHTTPVersion.decodeSettingValue(from: .int(9))
        }
    }

    @Test("Collection strategies: CSV vs JSON array, Set<T>, [String: V], separator, and .noDecode")
    func collectionDecodingStrategies() throws {
        let csvOrJSON = ValueDecodingContext(envListStrategy: .jsonOrCommaSeparated)
        #expect(try [String].decodeSettingValue(from: .string("alpha, beta, gamma"), context: csvOrJSON) == ["alpha", "beta", "gamma"])
        #expect(try [String].decodeSettingValue(from: .string(#"["one", "two"]"#), context: csvOrJSON) == ["one", "two"])
        #expect(try Set<Int>.decodeSettingValue(from: .string("1, 2, 2, 3"), context: csvOrJSON) == [1, 2, 3])
        #expect(try [String: Int].decodeSettingValue(from: .string("a=1, b=2"), context: csvOrJSON) == ["a": 1, "b": 2])
        #expect(try [String: Int].decodeSettingValue(from: .string(#"{"a": 10, "b": 20}"#), context: csvOrJSON) == ["a": 10, "b": 20])

        let jsonOnly = ValueDecodingContext(envListStrategy: .jsonOnly)
        #expect(try [String].decodeSettingValue(from: .string(#"["x","y"]"#), context: jsonOnly) == ["x", "y"])
        #expect(throws: ValueDecodingError.self) {
            try [String].decodeSettingValue(from: .string("x,y"), context: jsonOnly)
        }

        let colonSeparated = ValueDecodingContext(envListStrategy: .separator(":"))
        #expect(try [String].decodeSettingValue(from: .string("/usr/local/bin:/usr/bin:/bin"), context: colonSeparated) == ["/usr/local/bin", "/usr/bin", "/bin"])

        let noDecode = ValueDecodingContext(envListStrategy: .noDecode)
        #expect(throws: ValueDecodingError.self) {
            try [String].decodeSettingValue(from: .string("a,b"), context: noDecode)
        }
    }

    @Test("envIgnoreEmpty skips empty env vars while envNullStrings ('null', 'none', '~') reset optionals to nil")
    func envIgnoreEmptyAndNullStrings() async throws {
        let config = SettingsConfiguration(
            envPrefix: "TEST_",
            envIgnoreEmpty: true,
            envNullStrings: ["null", "none", "~"],
            projectConfigFiles: [".test.json"]
        )

        let envTree = try await EnvironmentSource().load(
            configuration: config,
            context: .inMemory(
                environment: [
                    "TEST_EMPTY": "",
                    "TEST_NULL_WORD": "NULL",
                    "TEST_NONE_WORD": "none",
                    "TEST_TILDE": "~",
                ]
            )
        )
        let projectTree = try await ProjectConfigSource().load(
            configuration: config,
            context: .inMemory(
                files: [
                    "/repo/.test.json": #"""
                    {
                      "empty": "fallback-from-json",
                      "nullWord": "overridden-by-null",
                      "noneWord": "overridden-by-none",
                      "tilde": "overridden-by-tilde"
                    }
                    """#
                ],
                directories: ["/repo/.git"]
            )
        )

        let merged = envTree.merging(lowerPriority: projectTree, caseSensitive: false)
        var loader = SettingsLoader(
            configuration: config,
            context: .inMemory(),
            mergedTree: merged
        )

        // Empty env var was ignored -> falls through to project config!
        let decodedEmpty = loader.decodeRequired(String.self, keyPath: ["empty"])
        let emptyMeta = try #require(decodedEmpty)
        #expect(emptyMeta.value == "fallback-from-json")
        #expect(emptyMeta.origin == .projectConfig(path: "/repo/.test.json", keyPath: ["empty"], profile: nil))

        // Null strings override project config back to nil!
        for key in ["nullWord", "noneWord", "tilde"] {
            let decodedOpt = loader.decodeOptional(String.self, keyPath: [key])
            let optMeta = try #require(decodedOpt)
            #expect(optMeta.value == nil)
        }
    }
}
