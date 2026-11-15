import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Synchronization
import Testing
import RiggingCore
import RiggingOnePassword
import RiggingKeychain
import RiggingBitwarden
import RiggingUnixPass
import RiggingTesting

@Suite("OnePasswordProvider Tests")
struct OnePasswordProviderTests {

    @Test("Static SecretProvider factory extensions support ergonomic array literal syntax")
    func staticProviderFactorySyntax() {
        let providers: [any SecretProvider] = [
            .onePassword(account: "team.1password.com"),
            .keychain(),
            .bitwarden(),
            .unixPass(),
            .sops(),
            .file(),
            .env(),
        ]
        #expect(providers.count == 7)
        #expect(providers[0].supportedSchemes == ["op"])
        #expect(providers[1].supportedSchemes == ["keychain"])
        #expect(providers[2].supportedSchemes == ["bws", "bw"])
        #expect(providers[3].supportedSchemes == ["pass"])
        #expect(providers[4].supportedSchemes == ["sops"])
        #expect(providers[5].supportedSchemes == ["file"])
        #expect(providers[6].supportedSchemes == ["env"])
    }

    @Test("Batches 4 distinct op:// references (including multiline PEM + special chars + duplicate) in 1 single op inject stdin/stdout call with zero temp files")
    func singlePassBatchedOpInject() async throws {
        let multilineSpecialPEM = """
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg$pecial"Chars'{{not_a_template}}
        Line2+With/Slashes=And\\Backslashes==Unicode🔑
        -----END PRIVATE KEY-----
        """

        let expectedSecrets: [String: String] = [
            "op://Eng/ASC/key_id": "ABC1234567",
            "op://Eng/ASC/private_key": multilineSpecialPEM,
            "op://Eng/Signing/Credentials/p12_password": "p@ssw0rd!#%&*()[]{}",
            "op://Engineering/ASC%20API%20Key/issuer_id": "11111111-2222-3333-4444-555555555555",
        ]

        let runner = MockSubprocessRunner { invocation in
            #expect(invocation.executablePath == "/opt/homebrew/bin/op")
            #expect(invocation.arguments == ["inject", "--account", "eng.1password.com"])
            #expect(invocation.environment?["OP_SERVICE_ACCOUNT_TOKEN"] == "ops_live_token_abcdef123456")

            guard let template = invocation.stdinString else {
                Issue.record("Expected in-memory stdin template for op inject")
                return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("missing stdin".utf8))
            }

            // Simulate `op inject` replacing every `{{ op://... }}` placeholder in-memory.
            var rendered = template
            for (uri, secretValue) in expectedSecrets {
                rendered = rendered.replacingOccurrences(of: "{{ \(uri) }}", with: secretValue)
            }
            return SubprocessResult(exitCode: 0, stdout: Data(rendered.utf8), stderr: Data())
        }

        let fs = InMemoryFileSystem(
            files: ["/opt/homebrew/bin/op": ""],
            permissions: ["/opt/homebrew/bin/op": 0o755],
            executables: ["/opt/homebrew/bin/op"]
        )

        let context = SettingsContext.inMemory(
            environment: ["OP_SERVICE_ACCOUNT_TOKEN": "ops_live_token_abcdef123456"],
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [.onePassword(account: "eng.1password.com")]
        )

        // Enqueue 5 fields referencing 4 distinct `op://` URIs (1 duplicate URI to verify deduplication).
        let requests = [
            SecretResolutionRequest(
                keyPath: ["keyId"],
                rawString: "op://Eng/ASC/key_id",
                origin: .projectConfig(path: "/repo/.asc.json", keyPath: ["auth", "keyId"], profile: nil)
            ),
            SecretResolutionRequest(
                keyPath: ["privateKey"],
                rawString: "op://Eng/ASC/private_key",
                origin: .projectConfig(path: "/repo/.asc.json", keyPath: ["auth", "privateKey"], profile: nil)
            ),
            SecretResolutionRequest(
                keyPath: ["signing", "password"],
                rawString: "op://Eng/Signing/Credentials/p12_password",
                origin: .environment(variable: "ASC_SIGNING__PASSWORD")
            ),
            SecretResolutionRequest(
                keyPath: ["issuerId"],
                rawString: "op://Engineering/ASC API Key/issuer_id",
                origin: .projectConfig(path: "/repo/.asc.json", keyPath: ["auth", "issuerId"], profile: nil)
            ),
            SecretResolutionRequest(
                keyPath: ["backupKeyId"],
                rawString: "op://Eng/ASC/key_id",
                origin: .environment(variable: "ASC_BACKUP_KEY_ID")
            ),
        ]

        let batch = await SecretResolver().resolveAll(requests, context: context)
        #expect(batch.issues.isEmpty)
        #expect(batch.resolved.count == 5)

        // Must execute in EXACTLY ONE `op inject` subprocess invocation!
        let invocations = await runner.invocations
        #expect(invocations.count == 1)

        // Verify boundary markers used a 128-bit hex nonce and included only 4 deduplicated slots (0..3).
        let stdinText = try #require(invocations.first?.stdinString)
        #expect(stdinText.contains("<<<RIGGING_START_"))
        #expect(stdinText.contains("_0>>>"))
        #expect(stdinText.contains("_3>>>"))
        #expect(!stdinText.contains("_4>>>"))

        // Verify exact secret values (including multiline PEM with {{not_a_template}} intact).
        #expect(try batch.resolvedByKeyPath[["keyId"]]?.utf8Secret().expose() == "ABC1234567")
        #expect(try batch.resolvedByKeyPath[["backupKeyId"]]?.utf8Secret().expose() == "ABC1234567")
        #expect(try batch.resolvedByKeyPath[["privateKey"]]?.utf8Secret().expose() == multilineSpecialPEM)
        #expect(try batch.resolvedByKeyPath[["signing", "password"]]?.utf8Secret().expose() == "p@ssw0rd!#%&*()[]{}")
        #expect(try batch.resolvedByKeyPath[["issuerId"]]?.utf8Secret().expose() == "11111111-2222-3333-4444-555555555555")

        // Verify zero temp files were written to the in-memory filesystem.
        #expect(!fs.fileExists(atPath: "/tmp"))
        #expect((try? fs.contentsOfDirectory(atPath: "/opt/homebrew/bin")) == ["op"])

        // Verify resolved secrets & service account token are registered in DiagnosticRedactor.
        let leakedLog = "Failed auth with ops_live_token_abcdef123456 and key Line2+With/Slashes=And\\Backslashes==Unicode🔑"
        let scrubbed = context.redactor.scrub(leakedLog)
        #expect(!scrubbed.contains("ops_live_token_abcdef123456"))
        #expect(!scrubbed.contains("Line2+With/Slashes=And\\Backslashes==Unicode🔑"))
    }

    @Test("Handles ?attribute=otp and ?document=true alongside standard op:// batch")
    func otpAndDocumentReferences() async throws {
        let binaryP12 = Data([0x30, 0x82, 0x00, 0xFF, 0xFE, 0x01, 0x02, 0x7F])

        let runner = MockSubprocessRunner { invocation in
            if invocation.arguments.first == "inject" {
                let tpl = invocation.stdinString ?? ""
                let out = tpl.replacingOccurrences(of: "{{ op://Eng/ASC/key_id }}", with: "KEY9999999")
                return SubprocessResult(exitCode: 0, stdout: Data(out.utf8))
            }
            if invocation.arguments == ["item", "get", "GitHub", "--vault", "Eng", "--otp", "--account", "work"] {
                return SubprocessResult(exitCode: 0, stdout: Data("654321\n".utf8))
            }
            if invocation.arguments == ["document", "get", "DistCert.p12", "--vault", "Eng", "--account", "work"] {
                return SubprocessResult(exitCode: 0, stdout: binaryP12)
            }
            return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("unexpected args: \(invocation.arguments)".utf8))
        }

        let fs = InMemoryFileSystem(
            files: ["/usr/local/bin/op": ""],
            permissions: ["/usr/local/bin/op": 0o755],
            executables: ["/usr/local/bin/op"]
        )

        let context = SettingsContext.inMemory(
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [.onePassword()]
        )

        let requests = [
            SecretResolutionRequest(
                keyPath: ["keyId"],
                rawString: "op://Eng/ASC/key_id?account=work",
                origin: .environment(variable: "KEY_ID")
            ),
            SecretResolutionRequest(
                keyPath: ["totp"],
                rawString: "op://Eng/GitHub/one-time-password?attribute=otp&account=work",
                origin: .environment(variable: "TOTP")
            ),
            SecretResolutionRequest(
                keyPath: ["cert"],
                rawString: "op://Eng/DistCert.p12/file?document=true&account=work",
                origin: .environment(variable: "CERT")
            ),
        ]

        let batch = await SecretResolver().resolveAll(requests, context: context)
        #expect(batch.issues.isEmpty)
        #expect(try batch.resolvedByKeyPath[["keyId"]]?.utf8Secret().expose() == "KEY9999999")
        #expect(try batch.resolvedByKeyPath[["totp"]]?.utf8Secret().expose() == "654321")
        #expect(batch.resolvedByKeyPath[["cert"]]?.data == binaryP12)
    }

    @Test("Resolves op:// references in 1Password Connect Server REST mode without needing op CLI binary")
    func connectServerRESTMode() async throws {
        let recordedPaths = Mutex<[String]>([])
        let recordedAuthHeaders = Mutex<[String]>([])

        let transport = ClosureOnePasswordHTTPTransport { request in
            let url = try #require(request.url)
            recordedPaths.withLock { $0.append(url.path) }
            if let auth = request.value(forHTTPHeaderField: "Authorization") {
                recordedAuthHeaders.withLock { $0.append(auth) }
            }

            let makeOK: (Data) -> (Data, HTTPURLResponse) = { body in
                let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (body, resp)
            }

            switch url.path {
            case "/v1/vaults":
                let json = #"[{"id":"vlt_eng_01","name":"Engineering"}]"#
                return makeOK(Data(json.utf8))

            case "/v1/vaults/vlt_eng_01/items":
                let json = #"[{"id":"itm_asc_01","title":"ASC API Key"}]"#
                return makeOK(Data(json.utf8))

            case "/v1/vaults/vlt_eng_01/items/itm_asc_01":
                let json = #"""
                {
                  "id": "itm_asc_01",
                  "title": "ASC API Key",
                  "sections": [
                    { "id": "sec_auth", "label": "Auth" }
                  ],
                  "fields": [
                    { "id": "f1", "label": "key_id", "value": "CONNECTKEY1" },
                    { "id": "f2", "label": "private_key", "value": "-----BEGIN PRIVATE KEY-----\nCONNECT_PEM_BODY\n-----END PRIVATE KEY-----", "section": { "id": "sec_auth" } },
                    { "id": "f3", "label": "totp", "type": "OTP", "otp": "908172" }
                  ]
                }
                """#
                return makeOK(Data(json.utf8))

            default:
                let resp = HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (Data(), resp)
            }
        }

        // Empty filesystem: NO `op` binary exists anywhere!
        let emptyFS = InMemoryFileSystem()
        let runner = MockSubprocessRunner()

        let provider = OnePasswordProvider(
            httpTransport: transport
        )

        let context = SettingsContext.inMemory(
            environment: [
                "OP_CONNECT_HOST": "https://connect.internal.example",
                "OP_CONNECT_TOKEN": "connect_jwt_secret_token_xyz",
            ],
            fileSystem: emptyFS,
            subprocessRunner: runner,
            secretProviders: [provider]
        )

        let requests = [
            SecretResolutionRequest(
                keyPath: ["keyId"],
                rawString: "op://Engineering/ASC API Key/key_id",
                origin: .environment(variable: "ASC_KEY_ID")
            ),
            SecretResolutionRequest(
                keyPath: ["privateKey"],
                rawString: "op://Engineering/ASC API Key/Auth/private_key",
                origin: .environment(variable: "ASC_PRIVATE_KEY")
            ),
            SecretResolutionRequest(
                keyPath: ["otp"],
                rawString: "op://Engineering/ASC API Key/totp?attribute=otp",
                origin: .environment(variable: "ASC_OTP")
            ),
        ]

        let batch = await SecretResolver().resolveAll(requests, context: context)
        #expect(batch.issues.isEmpty)
        #expect(await runner.invocationCount == 0)

        #expect(try batch.resolvedByKeyPath[["keyId"]]?.utf8Secret().expose() == "CONNECTKEY1")
        #expect(try batch.resolvedByKeyPath[["privateKey"]]?.utf8Secret().expose().contains("CONNECT_PEM_BODY") == true)
        #expect(try batch.resolvedByKeyPath[["otp"]]?.utf8Secret().expose() == "908172")

        // Verify item detail was cached so 3 fields on the same item made only 3 HTTP calls total (vaults, items, item detail).
        let paths = recordedPaths.withLock { $0 }
        #expect(paths == [
            "/v1/vaults",
            "/v1/vaults/vlt_eng_01/items",
            "/v1/vaults/vlt_eng_01/items/itm_asc_01",
        ])
        let auths = recordedAuthHeaders.withLock { $0 }
        #expect(auths.allSatisfy { $0 == "Bearer connect_jwt_secret_token_xyz" })
        #expect(!context.redactor.scrub("token=connect_jwt_secret_token_xyz").contains("connect_jwt_secret_token_xyz"))
    }

    @Test("Maps non-zero op exit codes (not signed in / missing item) to exit code 6 without leaking stderr secrets")
    func nonZeroExitMapsToExitCode6WithoutLeakingStderr() async throws {
        let leakedStderrSecret = "ops_leaked_stderr_secret_value_99999"
        let runner = MockSubprocessRunner(
            results: [
                SubprocessResult(
                    exitCode: 1,
                    stdout: Data(),
                    stderr: Data("[ERROR] 2026/11/15 You are not currently signed in. Raw debug token: \(leakedStderrSecret)\n".utf8)
                )
            ]
        )

        let fs = InMemoryFileSystem(
            files: ["/opt/homebrew/bin/op": ""],
            permissions: ["/opt/homebrew/bin/op": 0o755],
            executables: ["/opt/homebrew/bin/op"]
        )

        let context = SettingsContext.inMemory(
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [.onePassword()]
        )

        let req = SecretResolutionRequest(
            keyPath: ["privateKey"],
            rawString: "op://Eng/ASC/private_key",
            origin: .environment(variable: "ASC_PRIVATE_KEY")
        )

        do {
            _ = try await SecretResolver().resolve(req, context: context)
            Issue.record("Expected SettingsValidationError with exitCode 6")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 6)
            #expect(error.issues.first?.kind == .providerFailure)
            let jsonText = String(decoding: error.jsonPayload(), as: UTF8.self)
            #expect(!error.description.contains(leakedStderrSecret))
            #expect(!jsonText.contains(leakedStderrSecret))
        }
    }

    @Test("Executable trust check rejects relative path './op' and world-writable 0777 '/usr/local/bin/op' with exit code 4")
    func executableTrustRejectsRelativeAndWorldWritableWithExitCode4() async throws {
        let runner = MockSubprocessRunner()
        let fs = InMemoryFileSystem(
            files: [
                "/repo/op": "",
                "/usr/local/bin/op": "",
            ],
            permissions: [
                "/repo/op": 0o755,
                "/usr/local/bin/op": 0o777,
            ],
            executables: [
                "/repo/op",
                "/usr/local/bin/op",
            ]
        )

        let ref = try SecretReference.parse("op://Eng/ASC/key_id")

        // 1. Relative path `./op` -> exit code 4 (`unsafeExecutable`)
        let relativeProvider = OnePasswordProvider(executablePath: "./op")
        let relativeContext = SettingsContext.inMemory(
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [relativeProvider]
        )

        await #expect(throws: SecretResolutionError.self) {
            try await relativeProvider.resolveBatch([ref], context: relativeContext)
        }
        do {
            _ = try await SecretResolver().resolve(
                SecretResolutionRequest(
                    keyPath: ["keyId"],
                    rawString: "op://Eng/ASC/key_id",
                    origin: .environment(variable: "ASC_KEY_ID")
                ),
                context: relativeContext
            )
            Issue.record("Expected exitCode 4 for relative ./op")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 4)
            #expect(error.issues.first?.kind == .unsafeSecret)
        }

        // 2. World-writable `0777` `/usr/local/bin/op` -> exit code 4 (`unsafeExecutable`)
        let worldWritableProvider = OnePasswordProvider(
            searchDirectories: ["/usr/local/bin"]
        )
        let worldWritableContext = SettingsContext.inMemory(
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [worldWritableProvider]
        )

        do {
            _ = try await worldWritableProvider.resolveBatch([ref], context: worldWritableContext)
            Issue.record("Expected SecretResolutionError.unsafeExecutable for 0777 /usr/local/bin/op")
        } catch let error as SecretResolutionError {
            #expect(error.exitCode == 4)
            #expect(error.issueKind == .unsafeSecret)
        }

        do {
            _ = try await SecretResolver().resolve(
                SecretResolutionRequest(
                    keyPath: ["keyId"],
                    rawString: "op://Eng/ASC/key_id",
                    origin: .environment(variable: "ASC_KEY_ID")
                ),
                context: worldWritableContext
            )
            Issue.record("Expected exitCode 4 for 0777 /usr/local/bin/op")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 4)
            #expect(error.issues.first?.kind == .unsafeSecret)
        }

        // Subprocess runner must NEVER have been invoked!
        #expect(await runner.invocationCount == 0)
    }
}
