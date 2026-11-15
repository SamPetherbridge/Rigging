import Foundation
import RiggingCore
import RiggingTesting
import Testing

// MARK: - Fixture Settings Model with extraKeys: .forbid & .configPath Aliases

private struct StrictASCProjectSettings: RiggedSettings, Equatable, Sendable {
    static let configuration = SettingsConfiguration(
        envPrefix: "ASC_",
        extraKeys: .forbid,
        projectConfigFiles: [".asc.json"],
        xdgAppName: "asc"
    )

    static let fieldDescriptors: [SettingFieldDescriptor] = [
        SettingFieldDescriptor(
            name: "keyId",
            keyPath: ["keyId"],
            aliases: [.env("ASC_KEY_ID"), .env("ASC_LEGACY_AUTH_KEY"), .configPath(["auth", "keyId"])],
            typeName: "String",
            schemaType: .string()
        ),
        SettingFieldDescriptor(
            name: "appId",
            keyPath: ["appId"],
            typeName: "String?",
            schemaType: .string(),
            isOptional: true
        ),
        SettingFieldDescriptor(
            name: "readOnly",
            keyPath: ["readOnly"],
            typeName: "Bool",
            schemaType: .boolean,
            hasDefault: true,
            defaultDisplay: "false"
        ),
    ]

    let keyId: String
    let appId: String?
    let readOnly: Bool
    let provenance: ProvenanceReport

    static func load(context: SettingsContext, overrides: [SettingOverride]) async throws -> StrictASCProjectSettings {
        var loader = try await SettingsLoader.prepare(for: Self.self, context: context, overrides: overrides)
        let keyIdMeta = loader.decodeRequired(
            String.self,
            keyPath: ["keyId"],
            aliases: [.env("ASC_KEY_ID"), .env("ASC_LEGACY_AUTH_KEY"), .configPath(["auth", "keyId"])]
        )
        let appIdMeta = loader.decodeOptional(String.self, keyPath: ["appId"])
        let readOnlyMeta = loader.decodeDefaulted(Bool.self, default: false, keyPath: ["readOnly"])

        try loader.throwIfInvalid()
        return try loader.finalize(
            StrictASCProjectSettings(
                keyId: keyIdMeta!.value,
                appId: appIdMeta!.value,
                readOnly: readOnlyMeta!.value,
                provenance: loader.buildProvenanceReport()
            )
        )
    }
}

@Suite("ProjectConfig, UserConfig, Profiles, ExtraKeys, SecretsDir, Plist & ManagedPreferences")
struct ConfigSourcesTests {

    @Test("ProjectConfigSource walks upward from nested cwd to repo root and stops at .git boundary")
    func projectConfigUpwardDiscoveryStopsAtGitRoot() async throws {
        let config = SettingsConfiguration(projectConfigFiles: [".asc.json"])
        let context = SettingsContext.inMemory(
            files: [
                // Above .git boundary — MUST NOT be read!
                "/.asc.json": #"{"leakedAboveGit": "forbidden", "appId": "wrong"}"#,
                "/parent/.asc.json": #"{"leakedAboveGit": "forbidden", "appId": "wrong"}"#,
                // At repo root containing .git — MUST be discovered!
                "/parent/repo/.asc.json": #"{"appId": "6500000001", "timeout": 45}"#,
            ],
            directories: ["/parent/repo/.git", "/parent/repo/apps/ios-app"],
            workingDirectory: "/parent/repo/apps/ios-app",
            homeDirectory: "/Users/test"
        )

        let tree = try await ProjectConfigSource().load(configuration: config, context: context)
        #expect(tree.lookup(path: ["appId"])?.value == .string("6500000001"))
        #expect(tree.lookup(path: ["timeout"])?.value == .int(45))
        #expect(tree.lookup(path: ["leakedAboveGit"]) == nil)
        #expect(
            tree.lookup(path: ["appId"])?.origin
                == .projectConfig(path: "/parent/repo/.asc.json", keyPath: ["appId"], profile: nil)
        )
    }

    @Test("ProjectConfigSource stops upward walk at homeDirectory when outside a git repo")
    func projectConfigStopsAtHomeDirectoryBoundary() async throws {
        let config = SettingsConfiguration(projectConfigFiles: [".asc.json"])
        let context = SettingsContext.inMemory(
            files: [
                "/Users/.asc.json": #"{"outsideHome": true}"#,
                "/Users/test/.asc.json": #"{"insideHome": true}"#,
            ],
            directories: ["/Users/test/scratch/subproject"],
            workingDirectory: "/Users/test/scratch/subproject",
            homeDirectory: "/Users/test"
        )

        let tree = try await ProjectConfigSource().load(configuration: config, context: context)
        #expect(tree.lookup(path: ["insideHome"])?.value == .bool(true))
        #expect(tree.lookup(path: ["outsideHome"]) == nil)
    }

    @Test("UserConfigSource resolves $XDG_CONFIG_HOME, ~/.config/<app>/config.json, and Application Support fallback")
    func userConfigXDGAndFallbackPrecedence() async throws {
        let config = SettingsConfiguration(xdgAppName: "asc")

        // 1. Default ~/.config/asc/config.json beats ~/Library/Application Support/asc/config.json
        let defaultXDGTree = try await UserConfigSource().load(
            configuration: config,
            context: .inMemory(
                files: [
                    "/Users/test/Library/Application Support/asc/config.json": #"{"region": "app-support", "fallbackOnly": "yes"}"#,
                    "/Users/test/.config/asc/config.json": #"{"region": "dot-config"}"#,
                ],
                homeDirectory: "/Users/test"
            )
        )
        #expect(defaultXDGTree.lookup(path: ["region"])?.value == .string("dot-config"))
        #expect(defaultXDGTree.lookup(path: ["fallbackOnly"])?.value == .string("yes"))

        // 2. Explicit $XDG_CONFIG_HOME overrides ~/.config
        let customXDGTree = try await UserConfigSource().load(
            configuration: config,
            context: .inMemory(
                environment: ["XDG_CONFIG_HOME": "/custom/xdg"],
                files: [
                    "/Users/test/.config/asc/config.json": #"{"region": "dot-config"}"#,
                    "/custom/xdg/asc/config.json": #"{"region": "custom-xdg"}"#,
                ],
                homeDirectory: "/Users/test"
            )
        )
        #expect(customXDGTree.lookup(path: ["region"])?.value == .string("custom-xdg"))
        #expect(
            customXDGTree.lookup(path: ["region"])?.origin
                == .userConfig(path: "/custom/xdg/asc/config.json", keyPath: ["region"], profile: nil)
        )
    }

    @Test("Named profiles overlay via ASC_PROFILE and extraKeys: .forbid with .configPath aliases")
    func namedProfilesAndExtraKeysForbidWithAliases() async throws {
        // Valid .asc.json using "$schema", "profiles", .configPath(["auth", "keyId"]), and ASC_PROFILE=staging
        let validSettings = try await StrictASCProjectSettings.load(
            context: .inMemory(
                environment: ["ASC_PROFILE": "staging"],
                files: [
                    "/repo/.asc.json": #"""
                    {
                      "$schema": "https://schemas.example.com/asc.json",
                      "auth": {
                        "keyId": "ABC1234567"
                      },
                      "appId": "6500000001",
                      "readOnly": false,
                      "profiles": {
                        "staging": {
                          "appId": "6500000099",
                          "readOnly": true
                        }
                      }
                    }
                    """#
                ],
                directories: ["/repo/.git", "/repo/ios-app"],
                workingDirectory: "/repo/ios-app"
            )
        )

        #expect(validSettings.keyId == "ABC1234567")
        #expect(validSettings.appId == "6500000099")
        #expect(validSettings.readOnly == true)
        #expect(
            validSettings.provenance["appId"]?.origin
                == .projectConfig(path: "/repo/.asc.json", keyPath: ["appId"], profile: "staging")
        )
        #expect(
            validSettings.provenance["appId"]?.overriddenOrigins
                == [.projectConfig(path: "/repo/.asc.json", keyPath: ["appId"], profile: nil)]
        )

        // Custom .env("ASC_LEGACY_AUTH_KEY") alias is also permitted under extraKeys: .forbid
        let envAliasSettings = try await StrictASCProjectSettings.load(
            context: .inMemory(
                environment: ["ASC_LEGACY_AUTH_KEY": "LEGACY9999"],
                directories: ["/repo/.git"]
            )
        )
        #expect(envAliasSettings.keyId == "LEGACY9999")

        // Misspelled key in .asc.json triggers .unknownKey (exitCode 2) under extraKeys: .forbid
        let error = await #expect(throws: SettingsValidationError.self) {
            try await StrictASCProjectSettings.load(
                context: .inMemory(
                    files: [
                        "/repo/.asc.json": #"""
                        {
                          "auth": { "keyId": "ABC1234567" },
                          "read0nlyTypo": true
                        }
                        """#
                    ],
                    directories: ["/repo/.git"]
                )
            )
        }
        let unwrapped = try #require(error)
        #expect(unwrapped.exitCode == 2)
        #expect(unwrapped.issues.contains { $0.kind == .unknownKey && $0.keyPath == ["read0nlyTypo"] })
    }

    @Test("SecretsDirSource skips dotfiles, trims single trailing newline, and supports secretsNestedSubdir")
    func secretsDirSourceBehavior() async throws {
        let config = SettingsConfiguration(
            envPrefix: "APP_",
            secretsDirectory: "/run/secrets",
            secretsNestedSubdir: true,
            trimSecretTrailingNewline: true
        )
        let context = SettingsContext.inMemory(
            files: [
                "/run/secrets/.DS_Store": "ignored",
                "/run/secrets/..data": "ignored-k8s-symlink",
                "/run/secrets/db_password": "s3cr3t-value\n",
                "/run/secrets/two_newlines": "keep-one\n\n",
                "/run/secrets/crlf_secret": "windows-line\r\n",
                "/run/secrets/signing/cert_password": "nested-subdir-pass\n",
            ]
        )

        let tree = try await SecretsDirSource().load(configuration: config, context: context)
        #expect(tree.lookup(path: [".DS_Store"]) == nil)
        #expect(tree.lookup(path: ["..data"]) == nil)
        #expect(tree.lookup(path: ["dbPassword"])?.value == .string("s3cr3t-value"))
        #expect(tree.lookup(path: ["dbPassword"])?.origin == .secretsDirectory(path: "/run/secrets/db_password"))
        #expect(tree.lookup(path: ["twoNewlines"])?.value == .string("keep-one\n"))
        #expect(tree.lookup(path: ["crlfSecret"])?.value == .string("windows-line"))
        #expect(tree.lookup(path: ["signing", "certPassword"])?.value == .string("nested-subdir-pass"))
    }

    @Test("PlistFileSource loads XML and binary Property Lists with profile overlays")
    func plistFileSourceXMLAndBinary() async throws {
        let dict: [String: Any] = [
            "host": "prod.example.com",
            "port": 443,
            "tls": true,
            "profiles": [
                "dev": [
                    "host": "localhost",
                    "port": 8080,
                ]
            ],
        ]
        let xmlData = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        let binaryData = try PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0)

        let config = SettingsConfiguration(profile: "dev")
        let context = SettingsContext.inMemory(
            binaryFiles: [
                "/etc/app/xml.plist": xmlData,
                "/etc/app/bin.plist": binaryData,
            ]
        )

        let xmlTree = try await PlistFileSource(path: "/etc/app/xml.plist").load(configuration: config, context: context)
        #expect(xmlTree.lookup(path: ["host"])?.value == .string("localhost"))
        #expect(xmlTree.lookup(path: ["port"])?.value == .int(8080))
        #expect(xmlTree.lookup(path: ["tls"])?.value == .bool(true))

        let binTree = try await PlistFileSource(path: "/etc/app/bin.plist").load(configuration: config, context: context)
        #expect(binTree.lookup(path: ["host"])?.value == .string("localhost"))
        #expect(binTree.lookup(path: ["port"])?.value == .int(8080))
    }

    @Test("ManagedPreferencesSource loads mock MDM values and splits nested keys")
    func managedPreferencesSourceMockValues() async throws {
        let source = ManagedPreferencesSource(
            domain: "com.example.enterprise",
            mockValues: [
                "readOnly": .bool(true),
                "network.maxRetries": .int(5),
                "signing__teamId": .string("TEAM123456"),
            ]
        )
        let tree = try await source.load(
            configuration: SettingsConfiguration(envNestedDelimiter: "__"),
            context: .inMemory()
        )

        let readOnly = try #require(tree.lookup(path: ["readOnly"]))
        #expect(readOnly.value == .bool(true))
        #expect(readOnly.origin == .managedPolicy(domain: "com.example.enterprise", key: "readOnly"))

        #expect(tree.lookup(path: ["network", "maxRetries"])?.value == .int(5))
        #expect(tree.lookup(path: ["signing", "teamId"])?.value == .string("TEAM123456"))
    }
}
