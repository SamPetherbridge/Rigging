import Foundation
import Testing
import RiggingCore
import RiggingBitwarden
import RiggingUnixPass
import RiggingTesting

@Suite("Bitwarden, UnixPass, and SOPS Provider Tests")
struct BitwardenAndUnixPassTests {

    // MARK: - BitwardenProvider (`bws://` & `bw://`)

    @Test("BitwardenProvider resolves bws:// secrets and bw:// vault items (deduplicating bw get item calls)")
    func bitwardenBwsAndBwResolution() async throws {
        let bwsJSON = #"""
        {
          "id": "550e8400-e29b-41d4-a716-446655440000",
          "key": "PROD_API_KEY",
          "value": "bws-secret-value-xyz789"
        }
        """#

        let bwItemJSON = #"""
        {
          "id": "item-uuid-42",
          "name": "Production Database",
          "notes": "Primary RDS cluster credentials",
          "login": {
            "username": "rds_admin",
            "password": "bw-vault-password-123!"
          },
          "fields": [
            { "name": "connection_pool_key", "value": "pool-secret-key-999", "type": 1 }
          ]
        }
        """#

        let runner = MockSubprocessRunner { invocation in
            if invocation.executablePath == "/opt/homebrew/bin/bws" {
                #expect(invocation.arguments == ["secret", "get", "550e8400-e29b-41d4-a716-446655440000", "--output", "json"])
                #expect(invocation.environment?["BWS_ACCESS_TOKEN"] == "0.bws-machine-token-secret")
                return SubprocessResult(exitCode: 0, stdout: Data(bwsJSON.utf8))
            }
            if invocation.executablePath == "/opt/homebrew/bin/bw" {
                #expect(invocation.arguments == ["get", "item", "item-uuid-42"])
                #expect(invocation.environment?["BW_SESSION"] == "bw_session_secret_key_abc")
                return SubprocessResult(exitCode: 0, stdout: Data(bwItemJSON.utf8))
            }
            return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("unexpected binary".utf8))
        }

        let fs = InMemoryFileSystem(
            files: [
                "/opt/homebrew/bin/bws": "",
                "/opt/homebrew/bin/bw": "",
            ],
            permissions: [
                "/opt/homebrew/bin/bws": 0o755,
                "/opt/homebrew/bin/bw": 0o755,
            ],
            executables: [
                "/opt/homebrew/bin/bws",
                "/opt/homebrew/bin/bw",
            ]
        )

        let context = SettingsContext.inMemory(
            environment: [
                "BWS_ACCESS_TOKEN": "0.bws-machine-token-secret",
                "BW_SESSION": "bw_session_secret_key_abc",
            ],
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [.bitwarden()]
        )

        let requests = [
            SecretResolutionRequest(
                keyPath: ["apiKey"],
                rawString: "bws://550e8400-e29b-41d4-a716-446655440000",
                origin: .environment(variable: "API_KEY")
            ),
            SecretResolutionRequest(
                keyPath: ["dbPassword"],
                rawString: "bw://item-uuid-42/password",
                origin: .environment(variable: "DB_PASSWORD")
            ),
            SecretResolutionRequest(
                keyPath: ["dbUser"],
                rawString: "bw://item-uuid-42/username",
                origin: .environment(variable: "DB_USER")
            ),
            SecretResolutionRequest(
                keyPath: ["dbNotes"],
                rawString: "bw://item-uuid-42/notes",
                origin: .environment(variable: "DB_NOTES")
            ),
            SecretResolutionRequest(
                keyPath: ["poolKey"],
                rawString: "bw://item-uuid-42/connection_pool_key",
                origin: .environment(variable: "POOL_KEY")
            ),
        ]

        let batch = await SecretResolver().resolveAll(requests, context: context)
        #expect(batch.issues.isEmpty)

        // 1 `bws secret get` call + 1 deduplicated `bw get item` call across all 4 fields!
        #expect(await runner.invocationCount == 2)

        #expect(try batch.resolvedByKeyPath[["apiKey"]]?.utf8Secret().expose() == "bws-secret-value-xyz789")
        #expect(try batch.resolvedByKeyPath[["dbPassword"]]?.utf8Secret().expose() == "bw-vault-password-123!")
        #expect(try batch.resolvedByKeyPath[["dbUser"]]?.utf8Secret().expose() == "rds_admin")
        #expect(try batch.resolvedByKeyPath[["dbNotes"]]?.utf8Secret().expose() == "Primary RDS cluster credentials")
        #expect(try batch.resolvedByKeyPath[["poolKey"]]?.utf8Secret().expose() == "pool-secret-key-999")
    }

    // MARK: - UnixPassProvider (`pass://`)

    @Test("UnixPassProvider extracts line 1, #line:2, #username metadata, and ?full=true in 1 pass show call per entry")
    func unixPassExtractionModes() async throws {
        let passEntryOutput = """
        super-secret-first-line-password
        second-line-recovery-code
        username: pg_service_user
        url: https://db.internal.example:5432
        """

        let runner = MockSubprocessRunner { invocation in
            #expect(invocation.executablePath == "/opt/homebrew/bin/pass")
            #expect(invocation.arguments == ["show", "infra/prod/postgres"])
            #expect(invocation.environment?["PASSWORD_STORE_DIR"] == "/Users/test/.custom-pass")
            return SubprocessResult(exitCode: 0, stdout: Data((passEntryOutput + "\n").utf8))
        }

        let fs = InMemoryFileSystem(
            files: ["/opt/homebrew/bin/pass": ""],
            permissions: ["/opt/homebrew/bin/pass": 0o755],
            executables: ["/opt/homebrew/bin/pass"]
        )

        let context = SettingsContext.inMemory(
            environment: ["PASSWORD_STORE_DIR": "/Users/test/.custom-pass"],
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [.unixPass()]
        )

        let requests = [
            SecretResolutionRequest(
                keyPath: ["password"],
                rawString: "pass://infra/prod/postgres",
                origin: .environment(variable: "DB_PASS")
            ),
            SecretResolutionRequest(
                keyPath: ["recoveryCode"],
                rawString: "pass://infra/prod/postgres#line:2",
                origin: .environment(variable: "DB_RECOVERY")
            ),
            SecretResolutionRequest(
                keyPath: ["username"],
                rawString: "pass://infra/prod/postgres#username",
                origin: .environment(variable: "DB_USER")
            ),
            SecretResolutionRequest(
                keyPath: ["fullEntry"],
                rawString: "pass://infra/prod/postgres?full=true",
                origin: .environment(variable: "DB_FULL")
            ),
        ]

        let batch = await SecretResolver().resolveAll(requests, context: context)
        #expect(batch.issues.isEmpty)

        // All 4 references share `infra/prod/postgres` and default store, so `pass show` ran only ONCE!
        #expect(await runner.invocationCount == 1)

        #expect(try batch.resolvedByKeyPath[["password"]]?.utf8Secret().expose() == "super-secret-first-line-password")
        #expect(try batch.resolvedByKeyPath[["recoveryCode"]]?.utf8Secret().expose() == "second-line-recovery-code")
        #expect(try batch.resolvedByKeyPath[["username"]]?.utf8Secret().expose() == "pg_service_user")
        #expect(try batch.resolvedByKeyPath[["fullEntry"]]?.utf8Secret().expose() == passEntryOutput)
    }

    // MARK: - SOPSProvider (`sops://`)

    @Test("SOPSProvider decrypts once per file and extracts RFC 6901 JSON pointers and keys safely in memory")
    func sopsJSONPointerExtraction() async throws {
        let decryptedJSON = #"""
        {
          "database": {
            "password": "sops-db-password-456",
            "replicas": [
              { "token": "replica-0-token" },
              { "token": "replica-1-token" }
            ]
          },
          "a/b": {
            "c~d": "escaped-rfc6901-secret"
          },
          "slice[0::-1]": "safe-against-python-slice-injection",
          "top_api_key": "sops-top-level-key"
        }
        """#

        let runner = MockSubprocessRunner { invocation in
            #expect(invocation.executablePath == "/opt/homebrew/bin/sops")
            #expect(invocation.arguments == ["--decrypt", "--output-type", "json", "/repo/secrets/prod.enc.yaml"])
            // Verify `--extract` is NEVER passed to sops CLI!
            #expect(!invocation.arguments.contains("--extract"))
            return SubprocessResult(exitCode: 0, stdout: Data(decryptedJSON.utf8))
        }

        let fs = InMemoryFileSystem(
            files: ["/opt/homebrew/bin/sops": ""],
            permissions: ["/opt/homebrew/bin/sops": 0o755],
            executables: ["/opt/homebrew/bin/sops"]
        )

        let context = SettingsContext.inMemory(
            workingDirectory: "/repo",
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [.sops()]
        )

        let requests = [
            SecretResolutionRequest(
                keyPath: ["dbPassword"],
                rawString: "sops://secrets/prod.enc.yaml#/database/password",
                origin: .projectConfig(path: "/repo/.app.json", keyPath: ["dbPassword"], profile: nil)
            ),
            SecretResolutionRequest(
                keyPath: ["replicaToken"],
                rawString: "sops://secrets/prod.enc.yaml#/database/replicas/1/token",
                origin: .projectConfig(path: "/repo/.app.json", keyPath: ["replicaToken"], profile: nil)
            ),
            SecretResolutionRequest(
                keyPath: ["escapedKey"],
                rawString: "sops://secrets/prod.enc.yaml#/a~1b/c~0d",
                origin: .projectConfig(path: "/repo/.app.json", keyPath: ["escapedKey"], profile: nil)
            ),
            SecretResolutionRequest(
                keyPath: ["sliceSafe"],
                rawString: "sops://secrets/prod.enc.yaml#/slice%5B0::-1%5D",
                origin: .projectConfig(path: "/repo/.app.json", keyPath: ["sliceSafe"], profile: nil)
            ),
            SecretResolutionRequest(
                keyPath: ["topKey"],
                rawString: "sops://secrets/prod.enc.yaml#top_api_key",
                origin: .projectConfig(path: "/repo/.app.json", keyPath: ["topKey"], profile: nil)
            ),
        ]

        let batch = await SecretResolver().resolveAll(requests, context: context)
        #expect(batch.issues.isEmpty)
        #expect(await runner.invocationCount == 1)

        #expect(try batch.resolvedByKeyPath[["dbPassword"]]?.utf8Secret().expose() == "sops-db-password-456")
        #expect(try batch.resolvedByKeyPath[["replicaToken"]]?.utf8Secret().expose() == "replica-1-token")
        #expect(try batch.resolvedByKeyPath[["escapedKey"]]?.utf8Secret().expose() == "escaped-rfc6901-secret")
        #expect(try batch.resolvedByKeyPath[["sliceSafe"]]?.utf8Secret().expose() == "safe-against-python-slice-injection")
        #expect(try batch.resolvedByKeyPath[["topKey"]]?.utf8Secret().expose() == "sops-top-level-key")
    }

    // MARK: - Option-Injection & Executable Trust Checks Across Providers

    @Test("Bitwarden, UnixPass, and SOPS reject option-injection ('-' prefixes) and untrusted binaries (exit 2 / exit 4)")
    func rejectsOptionInjectionAndUntrustedBinaries() async throws {
        let runner = MockSubprocessRunner()
        let fs = InMemoryFileSystem(
            files: [
                "/usr/local/bin/bws": "",
                "/usr/local/bin/pass": "",
                "/usr/local/bin/sops": "",
            ],
            permissions: [
                "/usr/local/bin/bws": 0o777,
                "/usr/local/bin/pass": 0o777,
                "/usr/local/bin/sops": 0o777,
            ],
            executables: [
                "/usr/local/bin/bws",
                "/usr/local/bin/pass",
                "/usr/local/bin/sops",
            ]
        )

        let context = SettingsContext.inMemory(
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [
                BitwardenProvider(searchDirectories: ["/usr/local/bin"]),
                UnixPassProvider(searchDirectories: ["/usr/local/bin"]),
                SOPSProvider(searchDirectories: ["/usr/local/bin"]),
            ]
        )

        // 1. Option-injection URIs must be rejected with exit code 2 before touching any provider binary.
        let injectionPayloads = [
            "bws://--help",
            "bw://-evil-flag/password",
            "bw://item-1/--raw",
            "pass://--clip/prod/db",
            "pass://prod/-evil",
            "pass://prod/db#--option",
            "sops://--config/prod.yaml#/key",
            "sops://secrets/-flag.yaml#/key",
            "sops://secrets/prod.yaml#--extract",
            "op://-vault/item/field",
            "op://vault/item/field?account=--evil",
        ]

        for payload in injectionPayloads {
            let batch = await SecretResolver().resolveAll(
                [
                    SecretResolutionRequest(
                        keyPath: ["secret"],
                        rawString: payload,
                        origin: .environment(variable: "SECRET")
                    )
                ],
                context: context
            )
            #expect(batch.issues.count == 1, "Expected option-injection error for \(payload)")
            #expect(batch.issues.first?.exitCode == 2)
        }

        // Also verify defense-in-depth option-injection checks when structs are constructed directly in Swift.
        let directBitwarden = BitwardenProvider(searchDirectories: ["/usr/local/bin"])
        await #expect(throws: SecretResolutionError.self) {
            try await directBitwarden.resolveBatch(
                [.bitwardenSecretsManager(BitwardenSecretsManagerReference(secretID: "--injected"))],
                context: context
            )
        }
        let directPass = UnixPassProvider(searchDirectories: ["/usr/local/bin"])
        await #expect(throws: SecretResolutionError.self) {
            try await directPass.resolveBatch(
                [.pass(PassSecretReference(entryPath: "--injected"))],
                context: context
            )
        }
        let directSops = SOPSProvider(searchDirectories: ["/usr/local/bin"])
        await #expect(throws: SecretResolutionError.self) {
            try await directSops.resolveBatch(
                [.sops(SopsSecretReference(filePath: "--injected.yaml", jsonPointer: "/a"))],
                context: context
            )
        }

        // 2. World-writable 0777 binaries for bws, pass, and sops must fail with exit code 4 (`unsafeExecutable`).
        for validURI in ["bws://550e8400-e29b-41d4-a716-446655440000", "pass://prod/db", "sops://secrets/prod.yaml#/a"] {
            let batch = await SecretResolver().resolveAll(
                [
                    SecretResolutionRequest(
                        keyPath: ["secret"],
                        rawString: validURI,
                        origin: .environment(variable: "SECRET")
                    )
                ],
                context: context
            )
            #expect(batch.issues.first?.exitCode == 4, "Expected exitCode 4 on 0777 binary for \(validURI)")
            #expect(batch.issues.first?.kind == .unsafeSecret)
        }

        // 3. Relative executable paths (`./bws`, `./pass`, `./sops`) must also fail with exit code 4.
        let relativeProviders: [(any SecretProvider, SecretReference)] = [
            (BitwardenProvider(bwsExecutablePath: "./bws"), try SecretReference.parse("bws://550e8400-e29b-41d4-a716-446655440000")),
            (UnixPassProvider(executablePath: "./pass"), try SecretReference.parse("pass://prod/db")),
            (SOPSProvider(executablePath: "./sops"), try SecretReference.parse("sops://secrets/prod.yaml#/a")),
        ]

        for (provider, ref) in relativeProviders {
            do {
                _ = try await provider.resolveBatch([ref], context: context)
                Issue.record("Expected exitCode 4 for relative binary on \(ref.scheme)")
            } catch let error as SecretResolutionError {
                #expect(error.exitCode == 4)
            }
        }

        #expect(await runner.invocationCount == 0)
    }
}
