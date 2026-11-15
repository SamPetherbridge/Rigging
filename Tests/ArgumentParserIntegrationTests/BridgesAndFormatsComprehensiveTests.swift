import ArgumentParser
import Foundation
import Rigging
import RiggingArgumentParser
import RiggingCore
import RiggingTesting
import RiggingTOML
import RiggingYAML
import Testing

// MARK: - Helper Types & Models for ArgumentParser / ConfigSubcommand / TOML / YAML Coverage

enum SampleCLIMode: String, ExpressibleByArgument, CLIRawValueRepresentable, CaseIterable, Sendable, Equatable {
    case fast
    case safe
}

enum SampleCLICode: Int, ExpressibleByArgument, CLIRawValueRepresentable, Sendable, Equatable {
    case low = 1
    case high = 2
}

struct NonRepresentableArg: ExpressibleByArgument, Sendable, Equatable {
    let raw: String
    init?(argument: String) { self.raw = argument }
    var defaultValueDescription: String { "desc:\(raw)" }
}

struct PlainNestedOptionGroup: ParsableArguments, Sendable {
    @Option(name: .long)
    var nestedHost: String?
}

struct BuilderDrivenGroup: CLIOverridesConvertible, Sendable {
    var flag: Bool?
    var extraTags: [String] = []

    func cliSettingOverrides() -> [SettingOverride] {
        var b = CLIOverridesBuilder()
        b.add(flag, key: "groupFlag", flag: "--group-flag")
        b.addNonEmpty(extraTags, key: "extraTags", flag: "--extra-tags")
        return b.overrides
    }
}

struct ComprehensiveCLIOptions: RiggingCLIOptions, Sendable {
    static var cliKeyMap: [String: CLIFieldTarget] {
        [
            "mappedVal": .key("nested", "mappedVal", flag: "--mapped-val"),
            "autoFlagTarget": CLIFieldTarget(keyPath: ["nested", "autoFlag"], flag: nil),
        ]
    }

    @Flag(inversion: .prefixedEnableDisable)
    var featureToggle: Bool?

    @Flag
    var plainDebug: Bool = false

    @Flag(name: .shortAndLong)
    var verbose: Int

    @Argument
    var positionalName: String?

    @Option(name: .long)
    var tags: [String] = []

    @Option(name: .long)
    var mode: SampleCLIMode?

    @Option(name: .long)
    var code: SampleCLICode?

    @Option(name: .long)
    var customArg: NonRepresentableArg?

    @Option(name: .customLong("mapped-val"))
    var mappedVal: String?

    @Option(name: .long)
    var autoFlagTarget: Int?

    @OptionGroup
    var plainGroup: PlainNestedOptionGroup
}

@Settings(
    envPrefix: "STARTER_",
    projectConfigFiles: [".starter.json"],
    xdgAppName: "starterapp",
    extraKeys: .warn
)
struct StarterRichSettings: Sendable {
    @Setting(examples: ["example-host"])
    var requiredHost: String

    @Setting(examples: ["8080"])
    var requiredPort: Int

    @Setting(examples: ["0.75"])
    var requiredRatio: Double

    @Setting(examples: ["true"])
    var requiredFlag: Bool

    @Setting
    var noExampleStr: String

    @Setting
    var noExampleInt: Int

    @Setting
    var noExampleDouble: Double

    @Setting
    var noExampleBool: Bool

    @Setting
    var optionalStr: String? = nil

    @Setting
    var optionalInt: Int?

    @Setting
    var optionalDouble: Double?

    @Setting
    var optionalBool: Bool?

    @Setting
    var logLevel: SampleCLIMode = .safe

    @Setting
    var requiredLevel: SampleCLIMode

    @Setting
    var tags: [String] = ["alpha", "beta"]

    @Setting
    var emptyArr: [Int] = []

    @Setting
    var labels: [String: Int] = ["k": 1]

    @Setting
    var emptyDict: [String: String] = [:]

    @SecretSetting(examples: ["not-a-uri-literal"])
    var fallbackSecret: Secret<String>

    @SecretSetting(examples: ["keychain://com.example.starter/token"])
    var keychainSecret: Secret<String>

    @NestedSettings
    var signing: SigningOptions = SigningOptions()
}

@Suite("ArgumentParser, InitSource, ConfigSubcommand, TOML & YAML Comprehensive Coverage")
struct BridgesAndFormatsComprehensiveTests {

    @Test("InitSource covers values, keyPathValues, optionalCLI/optionalInit, and empty-segment filtering")
    func initSourceComprehensive() async throws {
        let fromValues = InitSource(values: [
            "host": .string("api.example"),
            "ignoredNil": nil,
        ])
        #expect(fromValues.sourceName == "InitSource")
        #expect(fromValues.overrides.count == 1)

        let fromPaths = InitSource(keyPathValues: [
            ["db", "port"]: .int(5432),
            ["a", "flag"]: .bool(true),
            ["db", "unset"]: nil,
            [""]: .string("ignored-empty-path"),
        ])
        #expect(fromPaths.overrides.count == 3)

        #expect(InitSource.optionalCLI(flag: "--port", keyPath: ["port"], value: nil) == nil)
        #expect(InitSource.optionalCLI(flag: "--port", keyPath: ["port"], value: .int(90))?.origin == .cliArgument(flag: "--port"))
        #expect(InitSource.optionalInit(keyPath: ["port"], value: nil) == nil)
        #expect(InitSource.optionalInit(keyPath: ["port"], value: .int(90))?.origin == .initOverride(keyPath: ["port"]))

        let ctx = SettingsContext.inMemory(
            cli: [
                .cli(flag: "--port", keyPath: ["db", "port"], value: .int(6432)),
                SettingOverride(keyPath: [""], value: .string("skip"), flag: "--skip"),
            ]
        )
        let tree = try await fromPaths.load(configuration: SettingsConfiguration(), context: ctx)
        let dbPort = tree.lookup(path: ["db", "port"])
        #expect(dbPort?.value == RawValue.int(6432))
        #expect(dbPort?.overriddenOrigins == [SettingOrigin.initOverride(keyPath: ["db", "port"])])
    }

    @Test("CLIRawValueRepresentable, CLIOverridesBuilder, ArgumentParserSource, and reflection edge cases")
    func argumentParserComprehensive() async throws {
        let orig = SettingOrigin.cliArgument(flag: "--test")

        // Exercise every CLIRawValueRepresentable conformance
        #expect("abc".cliRawValue == .string("abc"))
        #expect(Substring("sub").cliRawValue == .string("sub"))
        #expect(true.cliRawValue == .bool(true))
        #expect(Int(-5).cliRawValue == .int(-5))
        #expect(Int8(-8).cliRawValue == .int(-8))
        #expect(Int16(-16).cliRawValue == .int(-16))
        #expect(Int32(-32).cliRawValue == .int(-32))
        #expect(Int64(-64).cliRawValue == .int(-64))
        #expect(UInt(42).cliRawValue == .int(42))
        #expect(UInt.max.cliRawValue == .string(String(UInt.max)))
        #expect(UInt8(8).cliRawValue == .int(8))
        #expect(UInt16(16).cliRawValue == .int(16))
        #expect(UInt32(32).cliRawValue == .int(32))
        #expect(UInt64(64).cliRawValue == .int(64))
        #expect(UInt64.max.cliRawValue == .string(String(UInt64.max)))
        #expect(Float(1.5).cliRawValue == .double(1.5))
        #expect(Double(2.5).cliRawValue == .double(2.5))
        #expect(Decimal(string: "19.95")!.cliRawValue == .string("19.95"))
        #expect(URL(string: "https://example.com")!.cliRawValue == .string("https://example.com"))
        let id = UUID()
        #expect(id.cliRawValue == .string(id.uuidString))
        #expect(SampleCLIMode.fast.cliRawValue == .string("fast"))
        #expect(SampleCLICode.high.cliRawValue == .int(2))
        let arrRaw = [10, 20].cliRawValue(origin: orig)
        #expect(arrRaw == .array([RawNode(value: .int(10), origin: orig), RawNode(value: .int(20), origin: orig)]))

        // CLIOverridesBuilder all methods
        #expect(CLIOverridesBuilder.defaultFlagName(forProperty: "_maxHTTPConnections") == "--max-http-connections")
        #expect(CLIOverridesBuilder.defaultFlagName(forProperty: "___") == "--option")

        var builder = CLIOverridesBuilder()
        builder.add(Optional("val"), keyPath: ["a", "b"], flag: "--k1")
        builder.add(String?.none, keyPath: ["a", "c"], flag: "--k2")
        builder.add(Optional(99), key: "num", flag: "--num")
        builder.addNonEmpty([String](), keyPath: ["empty"], flag: "--empty")
        builder.addNonEmpty(["x"], keyPath: ["nonEmpty"], flag: "--non-empty")
        builder.addNonEmpty(["y"], key: "topArr", flag: "--top-arr")
        builder.append(.cli(flag: "--manual", keyPath: ["manual"], value: .bool(true)))
        builder.include(BuilderDrivenGroup(flag: true, extraTags: ["t1"]), prefix: ["grp"])
        let built = builder.overrides
        #expect(built.count == 7)

        // Unparsed definition-state struct safely yields empty overrides
        let unparsed = ComprehensiveCLIOptions()
        #expect(unparsed.cliSettingOverrides().isEmpty)

        // Default parsed flags (featureToggle=false without --disable, verbose=0, tags=[]) are NOT emitted!
        let emptyParsed = try ComprehensiveCLIOptions.parse([])
        #expect(emptyParsed.cliSettingOverrides().isEmpty)

        // Explicit --enable-feature-toggle, -vv, positional, --tags, enums, ExpressibleByArgument, mapped keys, plain @OptionGroup
        let richParsed = try ComprehensiveCLIOptions.parse([
            "--enable-feature-toggle",
            "-vv",
            "prod-target",
            "--tags", "one",
            "--tags", "two",
            "--mode", "safe",
            "--code", "2",
            "--custom-arg", "hello",
            "--mapped-val", "mv",
            "--auto-flag-target", "7",
            "--nested-host", "nested.example.com",
        ])
        let overrides = richParsed.cliSettingOverrides()
        #expect(overrides.contains(where: { $0.flag == "--enable-feature-toggle" && $0.value == .bool(true) }))
        #expect(overrides.contains(where: { $0.keyPath == ["verbose"] && $0.value == .int(2) }))
        #expect(overrides.contains(where: { $0.keyPath == ["positionalName"] && $0.value == .string("prod-target") }))
        #expect(overrides.contains(where: { $0.keyPath == ["mode"] && $0.value == .string("safe") }))
        #expect(overrides.contains(where: { $0.keyPath == ["code"] && $0.value == .int(2) }))
        #expect(overrides.contains(where: { $0.keyPath == ["customArg"] && $0.value == .string("desc:hello") }))
        #expect(overrides.contains(where: { $0.keyPath == ["nested", "mappedVal"] && $0.flag == "--mapped-val" }))
        #expect(overrides.contains(where: { $0.keyPath == ["nested", "autoFlag"] && $0.flag == "--auto-flag-target" }))
        #expect(overrides.contains(where: { $0.keyPath == ["nestedHost"] && $0.value == .string("nested.example.com") }))

        // Also test --disable-feature-toggle
        let disabledParsed = try ComprehensiveCLIOptions.parse(["--disable-feature-toggle"])
        #expect(disabledParsed.cliSettingOverrides().contains(where: { $0.flag == "--disable-feature-toggle" && $0.value == .bool(false) }))

        // ArgumentParserSource all initializers & includeContextCLIOverrides true/false
        let src1 = ArgumentParserSource(richParsed, includeContextCLIOverrides: false)
        #expect(src1.sourceName == "ArgumentParserSource")
        let ctxWithCLI = SettingsContext.inMemory(cli: [.cli(flag: "--ctx", keyPath: ["ctxKey"], value: .string("fromCtx"))])
        let treeNoCtx = try await src1.load(configuration: SettingsConfiguration(), context: ctxWithCLI)
        #expect(treeNoCtx.lookup(path: ["ctxKey"]) == nil)
        #expect(treeNoCtx.lookup(path: ["verbose"])?.value == .int(2))

        let src2 = ArgumentParserSource(includeContextCLIOverrides: true) { b in
            b.include(BuilderDrivenGroup(flag: false, extraTags: ["z"]))
        }
        let treeWithCtx = try await src2.load(configuration: SettingsConfiguration(), context: ctxWithCLI)
        #expect(treeWithCtx.lookup(path: ["ctxKey"])?.value == .string("fromCtx"))
        #expect(treeWithCtx.lookup(path: ["groupFlag"])?.value == .bool(false))

        let plainParsed = try PlainNestedOptionGroup.parse(["--nested-host", "custom-mapped"])
        let srcKeyMap = ArgumentParserSource(
            plainParsed,
            keyMap: [:],
            prefix: ["svc"],
            includeContextCLIOverrides: false
        )
        let treeKeyMap = try await srcKeyMap.load(configuration: SettingsConfiguration(), context: ctxWithCLI)
        #expect(treeKeyMap.lookup(path: ["svc", "nestedHost"])?.value == .string("custom-mapped"))

        let src3 = ArgumentParserSource(overrides: [.cli(flag: "--ov", keyPath: ["ov"], value: .int(1))], includeContextCLIOverrides: false)
        let tree3 = try await src3.load(configuration: SettingsConfiguration(), context: ctxWithCLI)
        #expect(tree3.lookup(path: ["ov"])?.value == .int(1))

        // RiggedSettings.load(cliArguments:keyMap:context:additionalOverrides:)
        let mockOP = MockOnePasswordProvider(secrets: ["op://Personal/ASC/private_key": TestFixtures.sampleP8PEM])
        let loadedViaKeyMap = try await ASCIntegrationSettings.load(
            cliArguments: plainParsed,
            keyMap: ["nestedHost": .key("keyId", flag: "--nested-host")],
            context: .inMemory(
                environment: ["ASC_PRIVATE_KEY": "op://Personal/ASC/private_key"],
                secretProviders: [mockOP]
            ),
            additionalOverrides: [.cli(flag: "--read-only", keyPath: ["readOnly"], value: .bool(true))]
        )
        #expect(loadedViaKeyMap.keyId == "custom-mapped")
        #expect(loadedViaKeyMap.readOnly == true)
    }

    @Test("ConfigSubcommand covers show errors/warnings, doctor preflight file-permission checks, compact schema, and rich starter JSON")
    func configSubcommandComprehensive() async throws {
        // 1. `show` failure in human & --json modes
        let missingCtx = SettingsContext.inMemory()
        let showFailHuman = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["show"],
            context: missingCtx
        )
        #expect(showFailHuman.exitCode == 2)
        #expect(showFailHuman.stderr.contains("keyId"))

        let showFailJSON = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["show", "--json"],
            context: missingCtx
        )
        #expect(showFailJSON.exitCode == 2)
        #expect(showFailJSON.stdout.contains("\"errorCount\" : 2"))

        // 2. `show` with warnings (human & --json) and `--profile`
        let mockOP = MockOnePasswordProvider(secrets: ["op://Personal/ASC/private_key": TestFixtures.sampleP8PEM])
        let fs = InMemoryFileSystem(
            files: [
                "/repo/.env": "ASC_LEGACY_TEAM=OLD_ONE\n",
                "/repo/.asc.json": """
                {
                    "keyId": "BASE",
                    "privateKey": "op://Personal/ASC/private_key",
                    "unknownExtra": 1,
                    "profiles": {
                        "staging": { "keyId": "STAGING_ID" }
                    }
                }
                """,
                "/Users/jane/.config/asc/config.json": "{\"readOnly\": true}",
            ],
            directories: ["/repo/.git"],
            permissions: [
                "/repo/.env": 0o666, // world-writable -> doctor preflight warning!
                "/Users/jane/.config/asc/config.json": 0o644, // world-readable -> doctor preflight warning!
            ]
        )
        let warnCtx = SettingsContext.inMemory(
            workingDirectory: "/repo",
            homeDirectory: "/Users/jane",
            fileSystem: fs,
            secretProviders: [mockOP]
        )
        let showWarnHuman = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["show", "--profile", "staging"],
            context: warnCtx
        )
        #expect(showWarnHuman.exitCode == 0)
        #expect(showWarnHuman.stdout.contains("STAGING_ID"))

        let showWarnJSON = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["show", "--json", "--profile", "staging"],
            context: warnCtx
        )
        #expect(showWarnJSON.exitCode == 0)
        #expect(showWarnJSON.stdout.contains("\"values\""))

        // 3. `doctor` human mode with world-writable `.env` & `0644` XDG `config.json` preflight warnings
        let docWarnHuman = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["doctor", "--profile", "staging"],
            context: warnCtx
        )
        #expect(docWarnHuman.exitCode == 0)
        #expect(docWarnHuman.stdout.contains("chmod 600"))
        #expect(docWarnHuman.stdout.contains("Warnings ("))

        // Clean `doctor` human mode (0 warnings)
        let cleanCtx = SettingsContext.inMemory(
            environment: [
                "ASC_KEY_ID": "CLEAN_KEY",
                "ASC_PRIVATE_KEY": "op://Personal/ASC/private_key",
            ],
            secretProviders: [mockOP]
        )
        let docCleanHuman = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["doctor"],
            context: cleanCtx
        )
        #expect(docCleanHuman.exitCode == 0)
        #expect(docCleanHuman.stdout.contains("Configuration healthy"))

        // 4. `show` and `doctor` coerce `ConfigFileParseError` and `DotEnvParseError`
        let malformedJSONCtx = SettingsContext.inMemory(
            files: ["/repo/.asc.json": "{ broken json"],
            directories: ["/repo/.git"]
        )
        let malformedShow = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["show"],
            context: malformedJSONCtx
        )
        #expect(malformedShow.exitCode == 2)
        #expect(malformedShow.stderr.contains(".asc.json"))

        let malformedDotEnvCtx = SettingsContext.inMemory(
            files: ["/repo/.env": "UNTERMINATED=\"hello\n"],
            directories: ["/repo/.git"]
        )
        let malformedDoc = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["doctor", "--json"],
            context: malformedDotEnvCtx
        )
        #expect(malformedDoc.exitCode == 2)
        #expect(malformedDoc.stdout.contains(".env"))

        // 5. `schema --compact --title CustomTitle`
        let compactSchema = try await ConfigSubcommand<ASCIntegrationSettings>.execute(
            arguments: ["schema", "--compact", "--title", "CustomTitle"]
        )
        #expect(compactSchema.exitCode == 0)
        #expect(!compactSchema.stdout.contains("\n  "))
        #expect(compactSchema.stdout.contains("CustomTitle"))

        // 6. `init` default (no flags -> dotenv) and `init --json` on StarterRichSettings
        let defaultInit = try await ConfigSubcommand<StarterRichSettings>.execute(arguments: ["init"])
        #expect(defaultInit.exitCode == 0)
        #expect(defaultInit.stdout.contains("STARTER_REQUIRED_HOST="))

        let richInitJSON = try await ConfigSubcommand<StarterRichSettings>.execute(arguments: ["init", "--json"])
        #expect(richInitJSON.exitCode == 0)
        let richObj = try JSONSerialization.jsonObject(with: Data(richInitJSON.stdout.utf8)) as? [String: Any]
        #expect(richObj?["requiredHost"] as? String == "example-host")
        #expect(richObj?["requiredPort"] as? Int == 8080)
        #expect(richObj?["requiredRatio"] as? Double == 0.75)
        #expect(richObj?["requiredFlag"] as? Bool == true)
        #expect(richObj?["noExampleStr"] as? String == "")
        #expect(richObj?["noExampleInt"] as? Int == 0)
        #expect(richObj?["fallbackSecret"] as? String == "op://Personal/starterapp/fallbackSecret")
        #expect(richObj?["keychainSecret"] as? String == "keychain://com.example.starter/token")
        #expect(richObj?["optionalStr"] is NSNull)

        // Also cover MockSecretProvider + loadInMemory + ByteCount.terabytes/tebibytes + SettingsWatcher(reloadOnSIGHUP:)
        let customVault = MockSecretProvider(schemes: ["bws"], secrets: [
            "bws://00000000-0000-0000-0000-000000000099": "bws-resolved-key",
        ])
        await customVault.setSecret("updated-bws-key", for: "bws://00000000-0000-0000-0000-000000000099")
        await customVault.setBinarySecret(Data([0x01, 0x02]), for: "bws://00000000-0000-0000-0000-000000000088")
        await customVault.setFailure(nil)
        let binVault = MockSecretProvider(schemes: ["pass"], binarySecrets: ["pass://infra/bin": Data([0xAA])])
        #expect(await binVault.batchHistory.isEmpty)
        let failVault = MockSecretProvider(schemes: ["vault"], failingWith: POSIXError(.EACCES))
        let vaultRef = try SecretReference.parse("vault://kv/item")
        await #expect(throws: POSIXError.self) {
            _ = try await failVault.resolveBatch([vaultRef], context: .inMemory())
        }
        let bwsGood = try SecretReference.parse("bws://00000000-0000-0000-0000-000000000088")
        let bwsMissing = try SecretReference.parse("bws://00000000-0000-0000-0000-000000000077")
        await #expect(throws: SecretBatchPartialFailureError.self) {
            _ = try await customVault.resolveBatch([bwsGood, bwsMissing], context: .inMemory())
        }
        await customVault.resetHistory()
        let inMemLoaded = try await ASCIntegrationSettings.loadInMemory(
            environment: [
                "ASC_KEY_ID": "INMEM_KEY",
                "ASC_PRIVATE_KEY": "bws://00000000-0000-0000-0000-000000000099",
            ],
            secretProviders: [customVault]
        )
        #expect(inMemLoaded.keyId == "INMEM_KEY")
        #expect(inMemLoaded.privateKey.expose() == "updated-bws-key")
        #expect(await customVault.invocationCount == 1)
        #expect(ByteCount.terabytes(1).bytes == 1_000_000_000_000)
        #expect(ByteCount.tebibytes(1).bytes == 1_099_511_627_776)
        let sighupWatcher = try await SettingsWatcher<ASCIntegrationSettings>.start(
            context: .inMemory(
                environment: [
                    "ASC_KEY_ID": "WATCH_KEY",
                    "ASC_PRIVATE_KEY": "bws://00000000-0000-0000-0000-000000000099",
                ],
                secretProviders: [customVault]
            ),
            pollInterval: .milliseconds(50),
            reloadOnSIGHUP: true
        )
        await sighupWatcher.stop()
    }

    @Test("TOMLParser, TOMLValue, TOMLParseError, and TOML sources cover all syntax, edge cases, and error diagnostics")
    func tomlComprehensiveCoverage() async throws {
        // TOMLParseError & TOMLValue accessors + Hashable/Equatable
        let errWithPath = TOMLParseError(path: "/etc/app.toml", line: 3, column: 7, reason: "bad token")
        let errNoPath = TOMLParseError(line: 1, column: 2, reason: "oops")
        #expect(errWithPath.description.contains("/etc/app.toml"))
        #expect(errWithPath.errorDescription == errWithPath.description)
        #expect(!errNoPath.description.contains("in '"))
        #expect(Set([errWithPath, errNoPath]).count == 2)

        let vStr = TOMLValue.string("hi")
        let vInt = TOMLValue.int(7)
        let vFlt = TOMLValue.float(1.5)
        let vNan1 = TOMLValue.float(.nan)
        let vNan2 = TOMLValue.float(-.nan)
        let vPosZero = TOMLValue.float(0.0)
        let vNegZero = TOMLValue.float(-0.0)
        let vBool = TOMLValue.bool(true)
        let vDT = TOMLValue.datetime("2026-11-15")
        let vArr = TOMLValue.array([vInt])
        let vTbl = TOMLValue.table(["k": vStr])

        #expect(vStr.stringValue == "hi" && vInt.stringValue == nil)
        #expect(vInt.intValue == 7 && vStr.intValue == nil)
        #expect(vFlt.floatValue == 1.5 && vStr.floatValue == nil)
        #expect(vBool.boolValue == true && vStr.boolValue == nil)
        #expect(vDT.datetimeValue == "2026-11-15" && vStr.datetimeValue == nil)
        #expect(vArr.arrayValue == [vInt] && vStr.arrayValue == nil)
        #expect(vTbl.tableValue == ["k": vStr] && vStr.tableValue == nil)
        #expect(vTbl["k"] == vStr)
        #expect(vStr["k"] == nil)
        #expect(vNan1 == vNan2)
        #expect(vPosZero == vNegZero)
        #expect(vStr != vInt)
        let valueSet: Set<TOMLValue> = [vStr, vInt, vFlt, vNan1, vNan2, vPosZero, vNegZero, vBool, vDT, vArr, vTbl]
        #expect(valueSet.count == 9)

        // Invalid UTF-8 data throws TOMLParseError
        #expect(throws: TOMLParseError.self) {
            _ = try TOMLParser.parse(data: Data([0xFF, 0xFE]), path: "bad.toml")
        }

        // UTF-8 BOM + CRLF + all escapes + trailing quotes in """ and ''' + dates/times + reopened implicit table + nested [[array]]
        let bomDoc = "\u{FEFF}" + [
            #"escapes = "\b\t\n\f\r\"\\\u0041\U0001F680""#,
            "mlQuotes = \"\"\"\r\nHello \"\"world\"\"\"\"\"",
            "mlLitQuotes = '''\r\nRaw ''single'''''",
            "negInf = -inf",
            "plainInf = inf",
            "plusNan = +nan",
            "minusNan = -nan",
            "negSci = -1_2.3_4e-2",
            "leapDate = 2024-02-29",
            "localDT = 2026-04-30t23:59:59.999",
            "offsetDT = 2026-04-30T12:00:00+10:00",
            "lowerZ = 2026-04-30T12:00:00z",
            "localTime = 08:05:09.25",
            "emptyInline = {}",
            "nestedInline = { a.b = 1, 'q.k' = true }",
            "\"quoted.key\" = 99",
            "",
            "[implicitParent.child]",
            "x = 1",
            "[implicitParent]",
            "y = 2",
            "[[implicitParent.items]]",
            "name = 'first'",
        ].joined(separator: "\r\n")

        let bomParsed = try TOMLParser.parse(data: Data(bomDoc.utf8), path: "bom.toml")
        #expect(bomParsed["escapes"]?.stringValue == "\u{0008}\t\n\u{000C}\r\"\\A🚀")
        #expect(bomParsed["mlQuotes"]?.stringValue == "Hello \"\"world\"\"")
        #expect(bomParsed["mlLitQuotes"]?.stringValue == "Raw ''single''")
        #expect(bomParsed["negInf"] == .float(-.infinity))
        #expect(bomParsed["plainInf"] == .float(.infinity))
        #expect(bomParsed["leapDate"] == .datetime("2024-02-29"))
        #expect(bomParsed["lowerZ"] == .datetime("2026-04-30T12:00:00Z"))
        #expect(bomParsed["localTime"] == .datetime("08:05:09.25"))
        #expect(bomParsed["emptyInline"] == .table([:]))
        #expect(bomParsed["implicitParent"]?["y"] == .int(2))
        #expect(bomParsed["implicitParent"]?["child"]?["x"] == .int(1))

        // Invalid TOML corpus: every case must throw TOMLParseError
        let invalidSnippets: [String] = [
            "[]",
            "[unclosed",
            "[[]]",
            "[[unclosed]",
            "a.b = 1\n[a.b]\nc = 2",
            "a.b.c = 1\n[a.b.d]\ne = 2",
            "inl = { x = 1 }\n[inl.sub]\ny = 2",
            "inl = { x = 1 }\n[[inl.sub]]\ny = 2",
            "s = 1\n[s.sub]\ny = 2",
            "s = 1\n[[s.sub]]\ny = 2",
            "a.b = 1\n[[a.c]]\ny = 2",
            "arr = [1]\n[[arr]]\ny = 2",
            "inl = { x = 1 }\ninl.y = 2",
            "s = 1\ns.b = 2",
            "\"\"\"ml\"\"\" = 1",
            "'''ml''' = 1",
            "= 1",
            "noEquals\n",
            "k = \"unterminated",
            "k = \"line\nbreak\"",
            "k = \"\u{0001}\"",
            "k = \"\"\"unterminated",
            "k = \"\"\"\"\"\"\"\"\"\"",
            "k = \"\\q\"",
            "k = \"\\u12G4\"",
            "k = \"\\UD8000000\"",
            "k = 'unterminated",
            "k = 'line\nbreak'",
            "k = '''unterminated",
            "k = ''''''''''",
            "k = [1, 2",
            "k = [1 2]",
            "k = { a = 1\n}",
            "k = { a = 1, }",
            "k = { a = 1",
            "k = tru",
            "k = 0X1A",
            "k = +0x1",
            "k = 0x_1",
            "k = 0b102",
            "k = 007",
            "k = 1__000",
            "k = 01.5",
            "k = 1..5",
            "k = 1.e2",
            "k = 1e2.3",
            "k = 1e+",
            "k = 2025-02-29",
            "k = 25:00:00",
            "k = 12:30:00.",
            "k = 2026-01-01X00:00:00",
            "k = 2026-01-01T25:00:00Z",
            "k = 2026-01-01T12:00:00+25:00",
            "a = 1 b = 2",
        ]
        for snippet in invalidSnippets {
            #expect(throws: TOMLParseError.self) {
                _ = try TOMLParser.parse(snippet, path: "invalid.toml")
            }
        }

        // TOMLFileSource, TOMLProjectConfigSource, TOMLUserConfigSource edge cases
        let emptySrc = TOMLFileSource(paths: [])
        #expect(emptySrc.sourceName == "TOMLFileSource")
        #expect(TOMLFileSource(path: "a.toml", originStyle: .projectConfig).sourceName == "TOMLProjectConfigSource")
        #expect(TOMLFileSource(path: "a.toml", originStyle: .userConfig).sourceName == "TOMLUserConfigSource")

        let emptyLoaded = try await emptySrc.load(configuration: SettingsConfiguration(), context: .inMemory())
        #expect(emptyLoaded.isEmpty)

        // Non-optional missing file throws CocoaError
        await #expect(throws: CocoaError.self) {
            _ = try await TOMLFileSource(path: "/missing.toml", optional: false).load(
                configuration: SettingsConfiguration(),
                context: .inMemory()
            )
        }

        // Malformed TOML in file throws ConfigFileParseError
        await #expect(throws: ConfigFileParseError.self) {
            _ = try await TOMLFileSource(path: "~/bad.toml").load(
                configuration: SettingsConfiguration(),
                context: .inMemory(files: ["/Users/jane/bad.toml": "port = 007"], homeDirectory: "/Users/jane")
            )
        }

        // Multi-file merge + custom origin + explicit profile + case-insensitive PROFILES + App Support fallback
        let tomlCtx = SettingsContext.inMemory(
            environment: ["XDG_CONFIG_HOME": "~/custom-xdg"],
            files: [
                "/repo/base.toml": """
                host = "base"
                port = 80
                [PROFILES.Prod]
                port = 443
                """,
                "/Users/jane/override.toml": """
                host = "override"
                when = 2026-11-15T10:00:00Z
                ratio = 2.5
                """,
                "/Users/jane/Library/Application Support/myapp/config.toml": """
                fromAppSupport = true
                shared = "app-support"
                """,
                "/Users/jane/custom-xdg/myapp/config.toml": """
                shared = "xdg-wins"
                """,
                "/repo/config.toml": "projKey = 'root'\n",
                "/repo/sub/config.toml": "projKey = 'nearest'\n",
            ],
            directories: ["/repo/.git", "/repo/sub"],
            workingDirectory: "/repo/sub",
            homeDirectory: "/Users/jane"
        )
        let multiFile = TOMLFileSource(
            paths: ["../base.toml", "~/override.toml", "   ", "nonexistent.toml"],
            optional: true,
            profile: "prod",
            originStyle: .custom(sourceName: "CustomTOML")
        )
        let multiTree = try await multiFile.load(configuration: SettingsConfiguration(caseSensitive: false), context: tomlCtx)
        #expect(multiTree.lookup(path: ["host"])?.value == .string("override"))
        #expect(multiTree.lookup(path: ["port"])?.value == .int(443))
        #expect(multiTree.lookup(path: ["ratio"])?.value == .double(2.5))

        let userSrc = TOMLUserConfigSource(appName: "myapp")
        let userTree = try await userSrc.load(configuration: SettingsConfiguration(), context: tomlCtx)
        #expect(userTree.lookup(path: ["fromAppSupport"])?.value == .bool(true))
        #expect(userTree.lookup(path: ["shared"])?.value == .string("xdg-wins"))
        #expect(try await TOMLUserConfigSource(appName: "  ").load(configuration: SettingsConfiguration(), context: tomlCtx).isEmpty)

        let projStopFirst = TOMLProjectConfigSource(fileName: "config.toml", stopAtFirstFound: true)
        let projTree = try await projStopFirst.load(configuration: SettingsConfiguration(), context: tomlCtx)
        #expect(projTree.lookup(path: ["projKey"])?.value == .string("nearest"))
    }

    @Test("YAMLFileSource, YAMLProjectConfigSource, and YAMLUserConfigSource cover merge keys, scalar tags, profiles, and errors")
    func yamlComprehensiveCoverage() async throws {
        #expect(YAMLFileSource(path: "a.yml", originStyle: .projectConfig).sourceName == "YAMLProjectConfigSource")
        #expect(YAMLFileSource(path: "a.yml", originStyle: .userConfig).sourceName == "YAMLUserConfigSource")
        #expect(YAMLFileSource(paths: []).sourceName == "YAMLFileSource")
        #expect(try await YAMLFileSource(paths: []).load(configuration: SettingsConfiguration(), context: .inMemory()).isEmpty)

        // Missing non-optional YAML throws CocoaError
        await #expect(throws: CocoaError.self) {
            _ = try await YAMLFileSource(path: "/missing.yaml", optional: false).load(
                configuration: SettingsConfiguration(),
                context: .inMemory()
            )
        }

        // Invalid UTF-8, invalid YAML syntax, non-mapping root, invalid `<<` merge scalar & sequence errors
        let badFS = InMemoryFileSystem(
            files: [
                "/repo/empty.yaml": "# comment only\n",
                "/repo/null.yaml": "~\n",
                "/repo/seq.yaml": "- item1\n- item2\n",
                "/repo/syntax.yaml": "a: [unclosed\n",
                "/repo/badmerge1.yaml": "<<: 123\n",
                "/repo/badmerge2.yaml": "<<: [123]\n",
            ]
        )
        badFS.writeFile(Data([0xFF, 0xFE]), atPath: "/repo/nonutf8.yaml")
        let badCtx = SettingsContext.inMemory(fileSystem: badFS)

        #expect(try await YAMLFileSource(path: "/repo/empty.yaml").load(configuration: SettingsConfiguration(), context: badCtx).isEmpty)
        #expect(try await YAMLFileSource(path: "/repo/null.yaml").load(configuration: SettingsConfiguration(), context: badCtx).isEmpty)

        for errPath in ["/repo/seq.yaml", "/repo/syntax.yaml", "/repo/badmerge1.yaml", "/repo/badmerge2.yaml", "/repo/nonutf8.yaml"] {
            await #expect(throws: ConfigFileParseError.self) {
                _ = try await YAMLFileSource(path: errPath).load(configuration: SettingsConfiguration(), context: badCtx)
            }
        }

        // Rich YAML features: anchors, `<<` single & sequence merge, null/bool/int/float/binary/timestamp scalars, custom origin, App Support + XDG
        let yamlCtx = SettingsContext.inMemory(
            environment: [
                "XDG_CONFIG_HOME": "~/custom-xdg",
                "RIGGING_PROFILE": "canary",
            ],
            files: [
                "/repo/rich.yaml": """
                base_high: &high
                  timeout: 10
                  shared: from-high
                base_low: &low
                  timeout: 99
                  retries: 3
                  shared: from-low
                service:
                  <<: [*high, *low]
                  explicit: true
                single_merge:
                  <<: *low
                  retries: 5
                emptyVal: ~
                ratio: 3.25
                bigInt: 1_000_000
                rawBin: !!binary SGVsbG8=
                createdAt: 2026-11-15 09:30:00Z
                PROFILES:
                  Canary:
                    ratio: 9.5
                """,
                "/Users/jane/Library/Application Support/yamlsvc/config.yml": """
                fromSupport: yes_str
                winner: support
                """,
                "/Users/jane/custom-xdg/yamlsvc/config.yaml": """
                winner: xdg-yaml
                """,
                "/repo/config.yml": "level: root\n",
                "/repo/sub/config.yaml": "level: sub\n",
            ],
            directories: ["/repo/.git", "/repo/sub"],
            workingDirectory: "/repo/sub",
            homeDirectory: "/Users/jane"
        )

        let richTree = try await YAMLFileSource(
            paths: ["../rich.yaml", "  "],
            originStyle: .custom(sourceName: "CustomYAML")
        ).load(configuration: SettingsConfiguration(caseSensitive: false), context: yamlCtx)

        #expect(richTree.lookup(path: ["service", "timeout"])?.value == .int(10))
        #expect(richTree.lookup(path: ["service", "retries"])?.value == .int(3))
        #expect(richTree.lookup(path: ["service", "shared"])?.value == .string("from-high"))
        #expect(richTree.lookup(path: ["single_merge", "retries"])?.value == .int(5))
        #expect(richTree.lookup(path: ["emptyVal"])?.value == .null)
        #expect(richTree.lookup(path: ["ratio"])?.value == .double(9.5))
        #expect(richTree.lookup(path: ["bigInt"])?.value == .int(1_000_000))
        #expect(richTree.lookup(path: ["rawBin"])?.value == .data(Data("Hello".utf8)))
        #expect(richTree.lookup(path: ["createdAt"])?.value == .string("2026-11-15T09:30:00Z"))

        let yamlUser = YAMLUserConfigSource(appName: "yamlsvc")
        let yamlUserTree = try await yamlUser.load(configuration: SettingsConfiguration(), context: yamlCtx)
        #expect(yamlUserTree.lookup(path: ["winner"])?.value == .string("xdg-yaml"))
        #expect(yamlUserTree.lookup(path: ["fromSupport"])?.value == .string("yes_str"))
        #expect(try await YAMLUserConfigSource(appName: nil).load(configuration: SettingsConfiguration(), context: yamlCtx).isEmpty)

        let yamlUserSingle = YAMLUserConfigSource(appName: "yamlsvc", fileName: "config.yml", includeApplicationSupportFallback: true)
        let yamlSingleTree = try await yamlUserSingle.load(configuration: SettingsConfiguration(), context: yamlCtx)
        #expect(yamlSingleTree.lookup(path: ["winner"])?.value == .string("support"))

        let yamlProj = YAMLProjectConfigSource(stopAtFirstFound: true)
        let yamlProjTree = try await yamlProj.load(
            configuration: SettingsConfiguration(projectConfigFiles: [".nonexistent.json"]),
            context: yamlCtx
        )
        #expect(yamlProjTree.lookup(path: ["level"])?.value == .string("sub"))
    }
}
