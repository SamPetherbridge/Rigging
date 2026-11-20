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
            "op://Engineering/ASC API Key/issuer_id": "11111111-2222-3333-4444-555555555555",
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
        #expect(stdinText.contains("{{ op://Engineering/ASC API Key/issuer_id }}"))
        #expect(!stdinText.contains("%20"))

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

    @Test("Preserves spaces across vault, item, section, and field names in exact op inject templates while keeping Connect HTTP URL encoding separate")
    func preservesSpacesInCLITemplateAndSeparatesConnectHTTPEncoding() async throws {
        let capturedStdin = Mutex<String?>(nil)
        let capturedArgs = Mutex<[[String]]>([])

        let runner = MockSubprocessRunner { invocation in
            capturedArgs.withLock { $0.append(invocation.arguments) }
            if invocation.arguments.first == "inject" {
                let tpl = try #require(invocation.stdinString)
                capturedStdin.withLock { $0 = tpl }
                let rendered = tpl
                    .replacingOccurrences(
                        of: "{{ op://Example Vault/item-id/credential }}",
                        with: "space-vault-secret-1"
                    )
                    .replacingOccurrences(
                        of: "{{ op://Example Vault/Example Item/Example Section/credential field?ssh-format=openssh }}",
                        with: "space-all-segments-secret-2"
                    )
                return SubprocessResult(exitCode: 0, stdout: Data(rendered.utf8))
            }
            if invocation.arguments == [
                "item", "get", "Example Item", "--vault", "Example Vault", "--otp", "--account", "team.1password.com"
            ] {
                return SubprocessResult(exitCode: 0, stdout: Data("135790\n".utf8))
            }
            return SubprocessResult(
                exitCode: 1,
                stdout: Data(),
                stderr: Data("unexpected subprocess args: \(invocation.arguments)".utf8)
            )
        }

        let fs = InMemoryFileSystem(
            files: ["/opt/homebrew/bin/op": ""],
            permissions: ["/opt/homebrew/bin/op": 0o755],
            executables: ["/opt/homebrew/bin/op"]
        )
        let cliContext = SettingsContext.inMemory(
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [.onePassword()]
        )

        let requests = [
            SecretResolutionRequest(
                keyPath: ["mailToken"],
                rawString: "op://Example Vault/item-id/credential?account=team.1password.com",
                origin: .environment(variable: "MAIL_TOKEN")
            ),
            SecretResolutionRequest(
                keyPath: ["sshKey"],
                rawString: "op://Example Vault/Example Item/Example Section/credential field?account=team.1password.com&ssh-format=openssh",
                origin: .environment(variable: "SSH_KEY")
            ),
            // Percent-encoded %20 in raw input deduplicates and normalizes to the same space-preserving CLI reference.
            SecretResolutionRequest(
                keyPath: ["duplicateMailToken"],
                rawString: "op://Example%20Vault/item-id/credential?account=team.1password.com",
                origin: .environment(variable: "DUP_MAIL_TOKEN")
            ),
            SecretResolutionRequest(
                keyPath: ["otp"],
                rawString: "op://Example Vault/Example Item/one-time password?attribute=otp&account=team.1password.com",
                origin: .environment(variable: "OTP")
            ),
        ]

        let batch = await SecretResolver().resolveAll(requests, context: cliContext)
        #expect(batch.issues.isEmpty)
        #expect(try batch.resolvedByKeyPath[["mailToken"]]?.utf8Secret().expose() == "space-vault-secret-1")
        #expect(try batch.resolvedByKeyPath[["duplicateMailToken"]]?.utf8Secret().expose() == "space-vault-secret-1")
        #expect(try batch.resolvedByKeyPath[["sshKey"]]?.utf8Secret().expose() == "space-all-segments-secret-2")
        #expect(try batch.resolvedByKeyPath[["otp"]]?.utf8Secret().expose() == "135790")

        // Assert exact `op inject` stdin template structure and absence of percent-encoding.
        let exactStdin = try #require(capturedStdin.withLock { $0 })
        #expect(!exactStdin.contains("%"))
        let lines = exactStdin.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.count == 2)

        let prefix = "<<<RIGGING_START_"
        #expect(lines[0].hasPrefix(prefix))
        let afterPrefix = lines[0].dropFirst(prefix.count)
        let nonce = String(afterPrefix.prefix(32))
        #expect(nonce.count == 32)
        #expect(nonce.unicodeScalars.allSatisfy { ($0.value >= 0x30 && $0.value <= 0x39) || ($0.value >= 0x61 && $0.value <= 0x66) })

        #expect(
            lines[0] == "<<<RIGGING_START_\(nonce)_0>>>{{ op://Example Vault/item-id/credential }}<<<RIGGING_END_\(nonce)_0>>>"
        )
        #expect(
            lines[1] == "<<<RIGGING_START_\(nonce)_1>>>{{ op://Example Vault/Example Item/Example Section/credential field?ssh-format=openssh }}<<<RIGGING_END_\(nonce)_1>>>"
        )

        let recordedArgs = capturedArgs.withLock { $0 }
        #expect(recordedArgs.contains(["inject", "--account", "team.1password.com"]))

        // Verify Connect REST mode still percent-encodes HTTP URL path segments separately from CLI formatting.
        let connectRequestURIs = Mutex<[String]>([])
        let connectTransport = ClosureOnePasswordHTTPTransport { request in
            let url = try #require(request.url)
            connectRequestURIs.withLock { $0.append(url.absoluteString) }
            let ok: (String) -> (Data, HTTPURLResponse) = { body in
                (Data(body.utf8), HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!)
            }
            switch url.path {
            case "/v1/vaults":
                return ok(#"[{"id":"vault id","name":"Example Vault"}]"#)
            case "/v1/vaults/vault id/items":
                return ok(
                    #"""
                    [{
                      "id": "item id",
                      "title": "Example Item",
                      "sections": [{"id": "sec_1", "label": "Example Section"}],
                      "fields": [{"id": "f_1", "label": "credential field", "value": "connect-space-secret", "section": {"id": "sec_1"}}]
                    }]
                    """#
                )
            default:
                return (Data(), HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!)
            }
        }

        let connectProvider: OnePasswordProvider = .onePasswordConnect(
            host: URL(string: "https://connect.internal.example")!,
            token: Secret("connect_tok_abc123"),
            httpTransport: connectTransport
        )
        let connectResolved = try await SecretResolver().resolve(
            SecretResolutionRequest(
                keyPath: ["cred"],
                rawString: "op://Example Vault/Example Item/Example Section/credential field",
                origin: .environment(variable: "CRED")
            ),
            context: .inMemory(secretProviders: [connectProvider])
        )
        #expect(try connectResolved.utf8Secret().expose() == "connect-space-secret")
        let urls = connectRequestURIs.withLock { $0 }
        #expect(urls == [
            "https://connect.internal.example/v1/vaults",
            "https://connect.internal.example/v1/vaults/vault%20id/items",
        ])

        // Programmatically constructed references with template/delimiter characters are rejected before CLI invocation.
        let unsafeProgrammaticRefs: [OnePasswordSecretReference] = [
            OnePasswordSecretReference(vault: "Vault/Slash", item: "Item", field: "field"),
            OnePasswordSecretReference(vault: "Vault", item: "Item%Percent", field: "field"),
            OnePasswordSecretReference(vault: "Vault", item: "Item", field: "field}}"),
            OnePasswordSecretReference(
                vault: "Vault",
                item: "Item",
                field: "field",
                queryItems: [SecretQueryItem(name: "ssh-format", value: "open ssh")]
            ),
        ]
        for badOpRef in unsafeProgrammaticRefs {
            do {
                _ = try await OnePasswordProvider().resolveBatch([.onePassword(badOpRef)], context: cliContext)
                Issue.record("Expected invalidReference for \(badOpRef)")
            } catch let error as SecretResolutionError {
                #expect(error.exitCode == 2)
            }
        }
    }

    @Test("Classifies CLI op inject rate limits with optional retryAfter without leaking stderr secrets, preserving auth and itemNotFound cases")
    func cliRateLimitClassificationAndStructuredValidationIssue() async throws {
        let fs = InMemoryFileSystem(
            files: ["/opt/homebrew/bin/op": ""],
            permissions: ["/opt/homebrew/bin/op": 0o755],
            executables: ["/opt/homebrew/bin/op"]
        )
        let ref = try SecretReference.parse("op://Eng/ASC/private_key")
        let plantedSecret = "ops_planted_stderr_secret_401_not_found_987654"

        let cases: [(stderr: String, expectedRetry: Duration?)] = [
            (
                "Too many requests. Your client has been rate-limited. Try again in 30 seconds (token=\(plantedSecret))",
                .seconds(30)
            ),
            (
                "Too many requests. Your client has been rate-limited. Try again in 1 second",
                .seconds(1)
            ),
            (
                "Too many requests: service account rate limit exceeded. Try again in 60 seconds",
                .seconds(60)
            ),
            (
                "Too many requests. Your client has been rate-limited. Try again in  seconds",
                nil
            ),
            (
                "Too many requests. Your client has been rate-limited. Try again in soon seconds",
                nil
            ),
            (
                "Too many requests. Your client has been rate-limited. Try again in -5 seconds",
                nil
            ),
            (
                "Too many requests. Your client has been rate-limited. Try again in 0 seconds",
                nil
            ),
            (
                "Too many requests. Your client has been rate-limited. Try again in 99999999 seconds",
                nil
            ),
            (
                "Too many requests. Your client has been rate-limited. Try again in 999999999999999999999 seconds",
                nil
            ),
            (
                "Your client has been rate-limited. Raw secret: \(plantedSecret)",
                nil
            ),
        ]

        for (stderrText, expectedRetry) in cases {
            let runner = MockSubprocessRunner(results: [
                SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data(stderrText.utf8)),
                SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data(stderrText.utf8)),
            ])
            let provider = OnePasswordProvider()
            let context = SettingsContext.inMemory(
                fileSystem: fs,
                subprocessRunner: runner,
                secretProviders: [provider]
            )

            // 1. Direct provider switch on SecretResolutionError.rateLimited
            do {
                _ = try await provider.resolveBatch([ref], context: context)
                Issue.record("Expected SecretResolutionError.rateLimited for stderr: \(stderrText)")
            } catch let error as SecretResolutionError {
                #expect(error.exitCode == 6)
                #expect(error.issueKind == .providerFailure)
                if case .rateLimited(let scheme, let message, let retryAfter, let remediation) = error {
                    #expect(scheme == "op")
                    #expect(retryAfter == expectedRetry)
                    #expect(!message.contains(plantedSecret))
                    #expect(!message.contains("Too many requests"))
                    #expect(!(remediation ?? "").contains(plantedSecret))
                } else {
                    Issue.record("Expected .rateLimited, got \(error)")
                }
                #expect(!error.description.contains(plantedSecret))
            }

            // 2. SecretResolver -> ValidationIssue & SettingsValidationError.jsonPayload()
            do {
                _ = try await SecretResolver().resolve(
                    SecretResolutionRequest(
                        keyPath: ["privateKey"],
                        rawString: "op://Eng/ASC/private_key",
                        origin: .environment(variable: "ASC_PRIVATE_KEY")
                    ),
                    context: context
                )
                Issue.record("Expected SettingsValidationError")
            } catch let validationError as SettingsValidationError {
                #expect(validationError.exitCode == 6)
                let issue = try #require(validationError.issues.first)
                #expect(issue.kind == .providerFailure)
                #expect(issue.isRateLimited == true)
                #expect(issue.retryAfter == expectedRetry)
                #expect(!issue.message.contains(plantedSecret))
                #expect(!validationError.description.contains(plantedSecret))

                let jsonData = validationError.jsonPayload()
                let jsonText = String(decoding: jsonData, as: UTF8.self)
                #expect(!jsonText.contains(plantedSecret))

                let parsed = try #require(try JSONSerialization.jsonObject(with: jsonData) as? [String: Any])
                let jsonIssues = try #require(parsed["issues"] as? [[String: Any]])
                let firstJSON = try #require(jsonIssues.first)
                #expect(firstJSON["isRateLimited"] as? Bool == true)
                if let expectedRetry {
                    #expect(firstJSON["retryAfterSeconds"] as? Double == Double(expectedRetry.components.seconds))
                } else {
                    #expect(firstJSON["retryAfterSeconds"] == nil)
                }
            }
        }

        // Existing "not signed in" and "not found" (even for an item named "rate limit") retain their classifications.
        let preservedRunner = MockSubprocessRunner(results: [
            SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("[ERROR] You are not signed in.".utf8)),
            SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("[ERROR] \"rate limit\" isn't an item in the \"Eng\" vault.".utf8)),
        ])
        let preservedCtx = SettingsContext.inMemory(fileSystem: fs, subprocessRunner: preservedRunner)
        do {
            _ = try await OnePasswordProvider().resolveBatch([ref], context: preservedCtx)
            Issue.record("Expected authenticationFailed")
        } catch let error as SecretResolutionError {
            if case .authenticationFailed = error {} else {
                Issue.record("Expected .authenticationFailed, got \(error)")
            }
        }
        do {
            _ = try await OnePasswordProvider().resolveBatch([ref], context: preservedCtx)
            Issue.record("Expected itemNotFound")
        } catch let error as SecretResolutionError {
            if case .itemNotFound = error {} else {
                Issue.record("Expected .itemNotFound, got \(error)")
            }
        }
    }

    @Test("Classifies Connect HTTP 429 as rateLimited with Retry-After delta-seconds parsing and no response-body leakage")
    func connectHTTP429RateLimitClassification() async throws {
        let ref = try SecretReference.parse("op://Eng/ASC/key_id")
        let leakedBodySecret = "connect_429_body_secret_payload_abcdef12345"

        let headerCases: [(headers: [String: String]?, expectedRetry: Duration?)] = [
            (["Retry-After": "45"], .seconds(45)),
            (["retry-after": " 12 "], .seconds(12)),
            (nil, nil),
            (["Retry-After": ""], nil),
            (["Retry-After": "invalid"], nil),
            (["Retry-After": "-30"], nil),
            (["Retry-After": "0"], nil),
            (["Retry-After": "99999999"], nil),
            (["Retry-After": "Fri, 20 Nov 2026 01:30:00 GMT"], nil),
        ]

        for (headers, expectedRetry) in headerCases {
            let transport = ClosureOnePasswordHTTPTransport { request in
                let url = try #require(request.url)
                let response = HTTPURLResponse(
                    url: url,
                    statusCode: 429,
                    httpVersion: "HTTP/1.1",
                    headerFields: headers
                )!
                let body = Data(#"{"status":429,"message":"Too Many Requests","debug":"\#(leakedBodySecret)"}"#.utf8)
                return (body, response)
            }
            let provider: OnePasswordProvider = .onePasswordConnect(
                host: URL(string: "https://connect.internal.example")!,
                token: Secret("connect_bearer_tok"),
                httpTransport: transport
            )
            let context = SettingsContext.inMemory(secretProviders: [provider])

            do {
                _ = try await provider.resolveBatch([ref], context: context)
                Issue.record("Expected .rateLimited for HTTP 429 with headers \(String(describing: headers))")
            } catch let error as SecretResolutionError {
                #expect(error.exitCode == 6)
                if case .rateLimited(let scheme, let message, let retryAfter, let remediation) = error {
                    #expect(scheme == "op")
                    #expect(retryAfter == expectedRetry)
                    #expect(!message.contains(leakedBodySecret))
                    #expect(!(remediation ?? "").contains(leakedBodySecret))
                } else {
                    Issue.record("Expected .rateLimited, got \(error)")
                }
                #expect(!error.description.contains(leakedBodySecret))
            }

            let batch = await SecretResolver().resolveAll(
                [SecretResolutionRequest(keyPath: ["keyId"], rawString: "op://Eng/ASC/key_id", origin: .environment(variable: "KEY_ID"))],
                context: context
            )
            let issue = try #require(batch.issues.first)
            #expect(issue.exitCode == 6)
            #expect(issue.isRateLimited == true)
            #expect(issue.retryAfter == expectedRetry)
            #expect(!issue.message.contains(leakedBodySecret))
            let valErr = SettingsValidationError(issues: batch.issues, redactor: context.redactor)
            #expect(!String(decoding: valErr.jsonPayload(), as: UTF8.self).contains(leakedBodySecret))
        }

        // HTTP 403 remains authenticationFailed and HTTP 404 remains itemNotFound.
        for (statusCode, isAuth) in [(403, true), (404, false)] {
            let transport = ClosureOnePasswordHTTPTransport { request in
                (Data(), HTTPURLResponse(url: request.url!, statusCode: statusCode, httpVersion: "HTTP/1.1", headerFields: nil)!)
            }
            let provider: OnePasswordProvider = .onePasswordConnect(
                host: URL(string: "https://connect.internal.example")!,
                token: Secret("connect_bearer_tok"),
                httpTransport: transport
            )
            do {
                _ = try await provider.resolveBatch([ref], context: .inMemory())
                Issue.record("Expected error for HTTP \(statusCode)")
            } catch let error as SecretResolutionError {
                if isAuth {
                    if case .authenticationFailed = error {} else { Issue.record("Expected authenticationFailed for 403") }
                } else {
                    if case .itemNotFound = error {} else { Issue.record("Expected itemNotFound for 404") }
                }
            }
        }
    }
}
