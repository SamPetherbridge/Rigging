import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Security)
import Security
#endif
import Testing
import RiggingCore
import RiggingOnePassword
import RiggingKeychain
import RiggingBitwarden
import RiggingUnixPass
import RiggingTesting

@Suite("Provider Edge Cases & Partial Failure Isolation")
struct ProviderEdgeCaseAndSecurityTests {

    @Test("OnePasswordProvider partitions mixed accountHints and forwards explicit serviceAccountToken")
    func onePasswordMixedAccountsAndExplicitServiceToken() async throws {
        let runner = MockSubprocessRunner { invocation in
            #expect(invocation.environment?["OP_SERVICE_ACCOUNT_TOKEN"] == "ops_explicit_constructor_token")
            let tpl = invocation.stdinString ?? ""
            if invocation.arguments == ["inject", "--account", "personal"] {
                return SubprocessResult(
                    exitCode: 0,
                    stdout: Data(tpl.replacingOccurrences(of: "{{ op://Personal/App/token }}", with: "personal-val").utf8)
                )
            }
            if invocation.arguments == ["inject", "--account", "work"] {
                return SubprocessResult(
                    exitCode: 0,
                    stdout: Data(tpl.replacingOccurrences(of: "{{ op://Work/App/token }}", with: "work-val").utf8)
                )
            }
            return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("unexpected".utf8))
        }

        let fs = InMemoryFileSystem(
            files: ["/opt/homebrew/bin/op": ""],
            permissions: ["/opt/homebrew/bin/op": 0o755],
            executables: ["/opt/homebrew/bin/op"]
        )

        let provider: OnePasswordProvider = .onePassword(
            serviceAccountToken: Secret("ops_explicit_constructor_token")
        )
        let context = SettingsContext.inMemory(
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [provider]
        )

        let refPersonal = try SecretReference.parse("op://Personal/App/token?account=personal")
        let refWork = try SecretReference.parse("op://Work/App/token?account=work")

        let directResult = try await provider.resolveBatch([refPersonal, refWork], context: context)
        #expect(String(decoding: directResult[refPersonal] ?? Data(), as: UTF8.self) == "personal-val")
        #expect(String(decoding: directResult[refWork] ?? Data(), as: UTF8.self) == "work-val")
        #expect(await runner.invocationCount == 2)
    }

    @Test("OnePasswordProvider Connect mode supports binary document downloads and HTTP 401 / incomplete env errors")
    func onePasswordConnectDocumentAndAuthErrors() async throws {
        let certBytes = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42])

        let docTransport = ClosureOnePasswordHTTPTransport { request in
            let url = try #require(request.url)
            let ok: (Data) -> (Data, HTTPURLResponse) = { body in
                (body, HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!)
            }
            switch url.path {
            case "/v1/vaults":
                return ok(Data(#"[{"id":"v1","name":"Signing"}]"#.utf8))
            case "/v1/vaults/v1/items":
                return ok(Data(#"[{"id":"i1","title":"DistCert","files":[{"id":"file99","name":"dist.p12","content_path":"/v1/vaults/v1/items/i1/files/file99/content"}]}]"#.utf8))
            case "/v1/vaults/v1/items/i1/files/file99/content":
                return ok(certBytes)
            default:
                return (Data(), HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!)
            }
        }

        let connectProvider: OnePasswordProvider = .onePasswordConnect(
            host: URL(string: "https://connect.example.internal/")!,
            token: Secret("connect_doc_token_secret"),
            httpTransport: docTransport
        )
        let docContext = SettingsContext.inMemory(secretProviders: [connectProvider])
        let resolvedDoc = try await SecretResolver().resolve(
            SecretResolutionRequest(
                keyPath: ["cert"],
                rawString: "op://Signing/DistCert/dist.p12?document=true",
                origin: .environment(variable: "CERT")
            ),
            context: docContext
        )
        #expect(resolvedDoc.data == certBytes)

        // HTTP 401 -> exitCode 6
        let unauthorizedTransport = ClosureOnePasswordHTTPTransport { request in
            let url = request.url!
            return (Data(), HTTPURLResponse(url: url, statusCode: 401, httpVersion: "HTTP/1.1", headerFields: nil)!)
        }
        let unauthorizedProvider: OnePasswordProvider = .onePasswordConnect(
            host: URL(string: "https://connect.example.internal")!,
            token: Secret("expired_connect_token"),
            httpTransport: unauthorizedTransport
        )
        let unauthorizedContext = SettingsContext.inMemory(secretProviders: [unauthorizedProvider])
        let authBatch = await SecretResolver().resolveAll(
            [SecretResolutionRequest(keyPath: ["k"], rawString: "op://Signing/DistCert/key", origin: .environment(variable: "K"))],
            context: unauthorizedContext
        )
        #expect(authBatch.issues.first?.exitCode == 6)

        // Incomplete OP_CONNECT_HOST without OP_CONNECT_TOKEN -> exitCode 6
        let incompleteEnvContext = SettingsContext.inMemory(
            environment: ["OP_CONNECT_HOST": "https://connect.example.internal"],
            secretProviders: [.onePassword()]
        )
        let incompleteBatch = await SecretResolver().resolveAll(
            [SecretResolutionRequest(keyPath: ["k"], rawString: "op://Signing/DistCert/key", origin: .environment(variable: "K"))],
            context: incompleteEnvContext
        )
        #expect(incompleteBatch.issues.first?.exitCode == 6)
    }

    #if canImport(Security)
    @Test("KeychainProvider supports binary Data secrets and isolates partial batch failures")
    func keychainBinaryAndPartialFailureIsolation() async throws {
        let rawBinary = Data([0xFF, 0x00, 0xFE, 0x80, 0x13, 0x37])

        let provider = KeychainProvider { query in
            let account = query[kSecAttrAccount as String] as? String
            if account == "p12-cert" {
                return KeychainBackendResponse(status: errSecSuccess, data: rawBinary)
            }
            return KeychainBackendResponse(status: errSecItemNotFound, data: nil)
        }

        let context = SettingsContext.inMemory(secretProviders: [provider])
        let batch = await SecretResolver().resolveAll(
            [
                SecretResolutionRequest(
                    keyPath: ["cert"],
                    rawString: "keychain://signing/p12-cert",
                    origin: .environment(variable: "CERT")
                ),
                SecretResolutionRequest(
                    keyPath: ["missing"],
                    rawString: "keychain://signing/does-not-exist",
                    origin: .environment(variable: "MISSING")
                ),
            ],
            context: context
        )

        // Valid sibling secret still resolves, and only the missing item records exitCode 6!
        #expect(batch.resolvedByKeyPath[["cert"]]?.dataSecret.expose() == rawBinary)
        #expect(batch.issues.count == 1)
        #expect(batch.issues.first?.keyPath == ["missing"])
        #expect(batch.issues.first?.exitCode == 6)
    }
    #endif

    @Test("UnixPassProvider and SOPSProvider handle scalar types, RFC 6901 validation errors, and decryption errors")
    func unixPassAndSopsEdgeCases() async throws {
        let sopsPayload = #"""
        {
          "enabled": true,
          "port": 8443,
          "nullable": null,
          "nestedObj": { "b": 2, "a": 1 }
        }
        """#

        let runner = MockSubprocessRunner { invocation in
            if invocation.executablePath.hasSuffix("/sops") {
                #expect(invocation.environment?["SOPS_AGE_KEY_FILE"] == "/Users/test/.config/sops/age/keys.txt")
                if invocation.arguments.last?.hasSuffix("bad-kms.yaml") == true {
                    return SubprocessResult(
                        exitCode: 128,
                        stdout: Data(),
                        stderr: Data("Failed to get the data key required to decrypt the SOPS file. AGE-SECRET-KEY-1SUPERSECRET\n".utf8)
                    )
                }
                return SubprocessResult(exitCode: 0, stdout: Data(sopsPayload.utf8))
            }
            if invocation.executablePath.hasSuffix("/pass") {
                return SubprocessResult(exitCode: 0, stdout: Data("only-one-line\n".utf8))
            }
            return SubprocessResult(exitCode: 1, stdout: Data())
        }

        let fs = InMemoryFileSystem(
            files: [
                "/opt/homebrew/bin/sops": "",
                "/opt/homebrew/bin/pass": "",
            ],
            permissions: [
                "/opt/homebrew/bin/sops": 0o755,
                "/opt/homebrew/bin/pass": 0o755,
            ],
            executables: [
                "/opt/homebrew/bin/sops",
                "/opt/homebrew/bin/pass",
            ]
        )

        let context = SettingsContext.inMemory(
            environment: ["SOPS_AGE_KEY": "AGE-SECRET-KEY-1SUPERSECRET"],
            fileSystem: fs,
            subprocessRunner: runner,
            secretProviders: [
                .unixPass(),
                .sops(ageKeyFile: "/Users/test/.config/sops/age/keys.txt"),
            ]
        )

        // Valid boolean, integer, and nested object JSON pointers in SOPS
        let validBatch = await SecretResolver().resolveAll(
            [
                SecretResolutionRequest(keyPath: ["enabled"], rawString: "sops://secrets.yaml#/enabled", origin: .environment(variable: "E")),
                SecretResolutionRequest(keyPath: ["port"], rawString: "sops://secrets.yaml#/port", origin: .environment(variable: "P")),
                SecretResolutionRequest(keyPath: ["obj"], rawString: "sops://secrets.yaml#/nestedObj", origin: .environment(variable: "O")),
            ],
            context: context
        )
        #expect(validBatch.issues.isEmpty)
        #expect(try validBatch.resolvedByKeyPath[["enabled"]]?.utf8Secret().expose() == "true")
        #expect(try validBatch.resolvedByKeyPath[["port"]]?.utf8Secret().expose() == "8443")
        #expect(try validBatch.resolvedByKeyPath[["obj"]]?.utf8Secret().expose() == #"{"a":1,"b":2}"#)

        // Invalid RFC 6901 escape (`~9`) -> exitCode 2; null pointer -> exitCode 6; KMS failure -> exitCode 6 without leaking AGE key; out-of-range pass line -> exitCode 6
        let errorBatch = await SecretResolver().resolveAll(
            [
                SecretResolutionRequest(keyPath: ["badEsc"], rawString: "sops://secrets.yaml#/bad~9escape", origin: .environment(variable: "B1")),
                SecretResolutionRequest(keyPath: ["nullVal"], rawString: "sops://secrets.yaml#/nullable", origin: .environment(variable: "B2")),
                SecretResolutionRequest(keyPath: ["kmsFail"], rawString: "sops://bad-kms.yaml#/port", origin: .environment(variable: "B3")),
                SecretResolutionRequest(keyPath: ["passLine"], rawString: "pass://prod/app#line:5", origin: .environment(variable: "B4")),
            ],
            context: context
        )
        #expect(errorBatch.issues.count == 4)

        let byPath = Dictionary(uniqueKeysWithValues: errorBatch.issues.map { ($0.keyPath, $0) })
        #expect(byPath[["badEsc"]]?.exitCode == 2)
        #expect(byPath[["nullVal"]]?.exitCode == 6)
        #expect(byPath[["kmsFail"]]?.exitCode == 6)
        #expect(byPath[["kmsFail"]]?.message.contains("AGE-SECRET-KEY-1SUPERSECRET") == false)
        #expect(byPath[["passLine"]]?.exitCode == 6)
    }
}
