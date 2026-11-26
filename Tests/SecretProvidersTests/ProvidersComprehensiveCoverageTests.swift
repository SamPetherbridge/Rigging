import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Security)
import Security
#endif
import RiggingBitwarden
import RiggingCore
import RiggingKeychain
import RiggingOnePassword
import RiggingTesting
import RiggingUnixPass
import Testing

@Suite("SecretProviders Comprehensive Error, Transport & Edge-Case Coverage")
struct ProvidersComprehensiveCoverageTests {

    @Test("OnePasswordProvider covers ConnectConfiguration, URLSession transport error, CLI error classifications, missing boundaries, unexpanded tokens, and Connect section/file/OTP edge cases")
    func onePasswordComprehensiveCoverage() async throws {
        // OnePasswordConnectConfiguration string token init & empty reference list
        let cfg = OnePasswordConnectConfiguration(host: URL(string: "https://connect.example.com")!, token: "str-token")
        #expect(cfg.token.expose() == "str-token")
        let emptyOut = try await OnePasswordProvider().resolveBatch([.env(EnvSecretReference(variableName: "FOO"))], context: .inMemory())
        #expect(emptyOut.isEmpty)

        // URLSessionOnePasswordHTTPTransport with custom failing URLProtocol
        final class MockFailProtocol: URLProtocol {
            override class func canInit(with request: URLRequest) -> Bool { true }
            override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
            override func startLoading() {
                client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost))
            }
            override func stopLoading() {}
        }
        let sessionCfg = URLSessionConfiguration.ephemeral
        sessionCfg.protocolClasses = [MockFailProtocol.self]
        let urlTransport = URLSessionOnePasswordHTTPTransport(session: URLSession(configuration: sessionCfg))
        await #expect(throws: (any Error).self) {
            _ = try await urlTransport.send(URLRequest(url: URL(string: "https://connect.example.com/v1/vaults")!))
        }

        // Invalid OP_CONNECT_HOST (ftp://)
        let badHostCtx = SettingsContext.inMemory(
            environment: [
                "OP_CONNECT_HOST": "ftp://bad.example.com",
                "OP_CONNECT_TOKEN": "tok123456",
            ]
        )
        let opRef = try SecretReference.parse("op://Eng/Item/field")
        await #expect(throws: SecretResolutionError.self) {
            _ = try await OnePasswordProvider().resolveBatch([opRef], context: badHostCtx)
        }

        //Executable not found, not executable, timedOut, generic error, missing boundary, unexpanded template, item not found & generic exit code
        await #expect(throws: SecretResolutionError.self) {
            _ = try await OnePasswordProvider(searchDirectories: ["/empty"]).resolveBatch([opRef], context: .inMemory())
        }
        let nonExecFS = InMemoryFileSystem(files: ["/usr/local/bin/op": ""], permissions: ["/usr/local/bin/op": 0o644])
        await #expect(throws: SecretResolutionError.self) {
            _ = try await OnePasswordProvider(executablePath: "/usr/local/bin/op").resolveBatch(
                [opRef],
                context: .inMemory(fileSystem: nonExecFS)
            )
        }

        let execFS = InMemoryFileSystem(executables: ["/opt/homebrew/bin/op"])

        // Runner throws timedOut & generic POSIXError
        let timeoutRunner = MockSubprocessRunner(scripted: [
            .failure(SubprocessSecurityError.timedOut(executablePath: "/opt/homebrew/bin/op", duration: .seconds(1))),
            .failure(POSIXError(.EIO)),
            // Missing boundary markers on exit 0
            .success(SubprocessResult(exitCode: 0, stdout: Data("corrupted-output".utf8))),
            // Unexpanded template pass-through
            .failure(SubprocessSecurityError.unsupportedPlatform("wasm")),
        ])
        let opProv = OnePasswordProvider()
        let tCtx = SettingsContext.inMemory(fileSystem: execFS, subprocessRunner: timeoutRunner)
        for _ in 0..<4 {
            await #expect(throws: SecretResolutionError.self) {
                _ = try await opProv.resolveBatch([opRef], context: tCtx)
            }
        }

        // Unexpanded placeholder + item-not-found stderr + generic exit code 2 stderr + OTP CLI failure
        let unexpandedRunner = MockSubprocessRunner { inv in
            if let tpl = inv.stdinString {
                // Return stdin unchanged so unexpanded {{ op://... }} detection triggers
                return SubprocessResult(exitCode: 0, stdout: Data(tpl.utf8))
            }
            return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("vault isn't a vault".utf8))
        }
        await #expect(throws: SecretResolutionError.self) {
            _ = try await opProv.resolveBatch([opRef], context: .inMemory(fileSystem: execFS, subprocessRunner: unexpandedRunner))
        }
        let otpRef = try SecretReference.parse("op://Eng/Item/otp?attribute=otp")
        await #expect(throws: SecretResolutionError.self) {
            _ = try await opProv.resolveBatch([otpRef], context: .inMemory(fileSystem: execFS, subprocessRunner: unexpandedRunner))
        }

        let genericFailRunner = MockSubprocessRunner(results: [
            SubprocessResult(exitCode: 2, stdout: Data(), stderr: Data("unexpected internal daemon failure".utf8)),
        ])
        await #expect(throws: SecretResolutionError.self) {
            _ = try await opProv.resolveBatch([opRef], context: .inMemory(fileSystem: execFS, subprocessRunner: genericFailRunner))
        }

        // Connect REST server: case-insensitive vault/item/section/purpose matching, OTP fallback via field.value, document fallback path without content_path, partial failures, HTTP 404 & 500
        let richConnectTransport = ClosureOnePasswordHTTPTransport { req in
            let url = req.url!
            let ok: (String) -> (Data, HTTPURLResponse) = { s in
                (Data(s.utf8), HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!)
            }
            switch url.path {
            case "/v1/vaults":
                return ok(#"[{"id":"v1","name":"ProdVault"}]"#)
            case "/v1/vaults/v1/items":
                return ok(
                    #"""
                    [{
                      "id": "i1",
                      "title": "ServiceLogin",
                      "sections": [{"id": "s1", "label": "Credentials"}],
                      "fields": [
                        {"id": "f_pw", "purpose": "PASSWORD", "value": "purpose-pw", "section": {"label": "Credentials"}},
                        {"id": "f_otp", "label": "mfa", "type": "OTP", "value": "112233"},
                        {"id": "f_no_otp", "label": "broken_otp", "type": "STRING", "value": "abc"}
                      ],
                      "files": [
                        {"id": "file_1", "name": "cert.pem"}
                      ]
                    }]
                    """#
                )
            case "/v1/vaults/v1/items/i1/files/file_1/content":
                return ok("DOC_CONTENT")
            default:
                return (Data(), HTTPURLResponse(url: url, statusCode: 500, httpVersion: "HTTP/1.1", headerFields: nil)!)
            }
        }
        let connectProv = OnePasswordProvider(
            connect: OnePasswordConnectConfiguration(host: URL(string: "https://connect.example.com")!, token: "tok"),
            httpTransport: richConnectTransport
        )
        let rPurpose = try SecretReference.parse("op://prodvault/servicelogin/credentials/password")
        let rOtpFallback = try SecretReference.parse("op://v1/i1/mfa?attribute=otp")
        let rDocFallback = try SecretReference.parse("op://v1/i1/document?type=document")
        let okBatch = try await connectProv.resolveBatch([rPurpose, rOtpFallback, rDocFallback], context: .inMemory())
        #expect(okBatch[rPurpose] == Data("purpose-pw".utf8))
        #expect(okBatch[rOtpFallback] == Data("112233".utf8))
        #expect(okBatch[rDocFallback] == Data("DOC_CONTENT".utf8))

        // Connect partial batch failures (missing vault, missing item, missing doc, missing OTP value, missing field)
        let badRefs = try [
            SecretReference.parse("op://NoSuchVault/i1/f"),
            SecretReference.parse("op://v1/NoSuchItem/f"),
            SecretReference.parse("op://v1/i1/missing.p12?document=true"),
            SecretReference.parse("op://v1/i1/broken_otp?attribute=otp"),
            SecretReference.parse("op://v1/i1/no_such_field"),
            rOtpFallback,
        ]
        await #expect(throws: SecretBatchPartialFailureError.self) {
            _ = try await connectProv.resolveBatch(badRefs, context: .inMemory())
        }

        // Connect HTTP 404 & 500 & transport network error
        let status404Prov = OnePasswordProvider(
            connect: cfg,
            httpTransport: ClosureOnePasswordHTTPTransport { req in
                (Data(), HTTPURLResponse(url: req.url!, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!)
            }
        )
        await #expect(throws: SecretResolutionError.self) {
            _ = try await status404Prov.resolveBatch([opRef], context: .inMemory())
        }
        let status500Prov = OnePasswordProvider(
            connect: cfg,
            httpTransport: ClosureOnePasswordHTTPTransport { req in
                (Data(), HTTPURLResponse(url: req.url!, statusCode: 500, httpVersion: "HTTP/1.1", headerFields: nil)!)
            }
        )
        await #expect(throws: SecretResolutionError.self) {
            _ = try await status500Prov.resolveBatch([opRef], context: .inMemory())
        }
    }

    #if canImport(Security)
    @Test("KeychainProvider covers empty batch, duplicate refs, nil data error, generic OSStatus error, and segment validation")
    func keychainComprehensiveCoverage() async throws {
        let nilDataProv = KeychainProvider { _ in
            KeychainBackendResponse(status: errSecSuccess, data: nil)
        }
        #expect(try await nilDataProv.resolveBatch([], context: .inMemory()).isEmpty)
        #expect(try await nilDataProv.resolveBatch([.env(EnvSecretReference(variableName: "X"))], context: .inMemory()).isEmpty)

        let kcRef = try SecretReference.parse("keychain://com.example.asc/token")
        await #expect(throws: SecretResolutionError.self) {
            _ = try await nilDataProv.resolveBatch([kcRef], context: .inMemory())
        }

        let unknownStatusProv = KeychainProvider { _ in
            KeychainBackendResponse(status: -25291, data: nil)
        }
        await #expect(throws: SecretResolutionError.self) {
            _ = try await unknownStatusProv.resolveBatch([kcRef], context: .inMemory())
        }

        // Duplicate reference deduplication + kind flag without value error + null/empty/control segment checks
        let okProv = KeychainProvider(accessGroup: "GRP", synchronizable: true) { _ in
            KeychainBackendResponse(status: errSecSuccess, data: Data("ok".utf8))
        }
        let dupOut = try await okProv.resolveBatch([kcRef, kcRef], context: .inMemory())
        #expect(dupOut.count == 1)

        #expect(throws: SecretResolutionError.self) {
            _ = try KeychainProvider.buildSecItemQuery(
                for: KeychainSecretReference(service: "svc", account: "acct", queryItems: [SecretQueryItem(name: "kind", value: nil)])
            )
        }
        #expect(throws: SecretResolutionError.self) {
            _ = try KeychainProvider.buildSecItemQuery(for: KeychainSecretReference(service: "", account: "acct"))
        }
        #expect(throws: SecretResolutionError.self) {
            _ = try KeychainProvider.buildSecItemQuery(for: KeychainSecretReference(service: "svc\0", account: "acct"))
        }
        #expect(throws: SecretResolutionError.self) {
            _ = try KeychainProvider.buildSecItemQuery(for: KeychainSecretReference(service: "svc\u{07}", account: "acct"))
        }
    }
    #endif

    @Test("BitwardenProvider covers totp/uri/case-insensitive custom fields, explicit tokens, CLI auth/404/generic errors, malformed JSON, and partial failures")
    func bitwardenComprehensiveCoverage() async throws {
        #expect(try await BitwardenProvider().resolveBatch([], context: .inMemory()).isEmpty)

        let bwItemJSON = #"""
        {
          "id": "item-1",
          "login": {
            "totp": "998877",
            "uris": [{"uri": "https://vault.example.com"}]
          },
          "fields": [
            {"name": "MixedCaseKey", "value": "ci-matched-val"}
          ]
        }
        """#
        let fs = InMemoryFileSystem(executables: ["/opt/homebrew/bin/bws", "/opt/homebrew/bin/bw"])
        let runner = MockSubprocessRunner { inv in
            if inv.executablePath.hasSuffix("/bw") {
                #expect(inv.environment?["BW_SESSION"] == "explicit-session")
                if inv.arguments.last == "locked-item" {
                    return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("Vault is locked.".utf8))
                }
                if inv.arguments.last == "missing-item" {
                    return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("Not found.".utf8))
                }
                if inv.arguments.last == "bad-json" {
                    return SubprocessResult(exitCode: 0, stdout: Data("{invalid".utf8))
                }
                return SubprocessResult(exitCode: 0, stdout: Data(bwItemJSON.utf8))
            }
            #expect(inv.environment?["BWS_ACCESS_TOKEN"] == "explicit-bws-tok")
            if inv.arguments[2] == "unauth" {
                return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("401 Unauthorized".utf8))
            }
            if inv.arguments[2] == "no-val" {
                return SubprocessResult(exitCode: 0, stdout: Data(#"{"id":"1"}"#.utf8))
            }
            if inv.arguments[2] == "bad-json" {
                return SubprocessResult(exitCode: 0, stdout: Data("not-json".utf8))
            }
            return SubprocessResult(exitCode: 2, stdout: Data(), stderr: Data("daemon crash".utf8))
        }

        let prov = BitwardenProvider(
            bwsAccessToken: Secret("explicit-bws-tok"),
            bwSession: Secret("explicit-session")
        )
        let ctx = SettingsContext.inMemory(fileSystem: fs, subprocessRunner: runner)

        // Valid totp, uri, and case-insensitive custom field
        let okRefs = try [
            SecretReference.parse("bw://item-1/totp"),
            SecretReference.parse("bw://item-1/uri"),
            SecretReference.parse("bw://item-1/mixedcasekey"),
        ]
        let okOut = try await prov.resolveBatch(okRefs, context: ctx)
        #expect(okOut[okRefs[0]] == Data("998877".utf8))
        #expect(okOut[okRefs[1]] == Data("https://vault.example.com".utf8))
        #expect(okOut[okRefs[2]] == Data("ci-matched-val".utf8))

        // Partial batch failure across bws & bw error branches
        let mixedFailRefs = try [
            SecretReference.parse("bw://item-1/totp"),
            SecretReference.parse("bw://item-1/missing_field"),
            SecretReference.parse("bw://locked-item/password"),
            SecretReference.parse("bw://missing-item/password"),
            SecretReference.parse("bw://bad-json/password"),
            SecretReference.parse("bws://unauth"),
            SecretReference.parse("bws://no-val"),
            SecretReference.parse("bws://bad-json"),
            SecretReference.parse("bws://crash"),
        ]
        await #expect(throws: SecretBatchPartialFailureError.self) {
            _ = try await prov.resolveBatch(mixedFailRefs, context: ctx)
        }

        // Missing binary error (exit 6) & non-executable binary error (exit 6)
        let singleBws = try SecretReference.parse("bws://abc")
        await #expect(throws: SecretResolutionError.self) {
            _ = try await BitwardenProvider(searchDirectories: ["/none"]).resolveBatch([singleBws], context: .inMemory())
        }
        let nonExecFS = InMemoryFileSystem(files: ["/usr/bin/bws": ""], permissions: ["/usr/bin/bws": 0o644])
        await #expect(throws: SecretResolutionError.self) {
            _ = try await BitwardenProvider(bwsExecutablePath: "/usr/bin/bws").resolveBatch(
                [singleBws],
                context: .inMemory(fileSystem: nonExecFS)
            )
        }
    }

    @Test("UnixPassProvider and SOPSProvider cover #full, storeOverride, GPG/not-found CLI errors, SOPS rawMode, dotted keys, array index bounds, and binary trust errors")
    func unixPassAndSopsComprehensiveCoverage() async throws {
        #expect(try await UnixPassProvider().resolveBatch([], context: .inMemory()).isEmpty)
        #expect(try await SOPSProvider().resolveBatch([], context: .inMemory()).isEmpty)

        let fs = InMemoryFileSystem(executables: ["/opt/homebrew/bin/pass", "/opt/homebrew/bin/sops"])
        let runner = MockSubprocessRunner { inv in
            if inv.executablePath.hasSuffix("/pass") {
                if inv.arguments.last == "missing/entry" {
                    return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("Error: missing/entry is not in the password store.".utf8))
                }
                if inv.arguments.last == "gpg/locked" {
                    return SubprocessResult(exitCode: 2, stdout: Data(), stderr: Data("gpg: decryption failed: No secret key".utf8))
                }
                if inv.arguments.last == "non/utf8" {
                    return SubprocessResult(exitCode: 0, stdout: Data([0xFF, 0xFE]))
                }
                if inv.arguments.last == "generic/fail" {
                    return SubprocessResult(exitCode: 9, stdout: Data(), stderr: Data("boom".utf8))
                }
                let store = inv.environment?["PASSWORD_STORE_DIR"] ?? ""
                return SubprocessResult(exitCode: 0, stdout: Data("pw-\(store)\r\nUserName: alice\r\n".utf8))
            }
            // SOPS
            if inv.arguments.first == "--decrypt" && inv.arguments.count == 2 {
                // rawMode (`?raw=true`)
                return SubprocessResult(exitCode: 0, stdout: Data([0xCA, 0xFE, 0xBA, 0xBE]))
            }
            if inv.arguments.last?.hasSuffix("missing.yaml") == true {
                return SubprocessResult(exitCode: 1, stdout: Data(), stderr: Data("no such file or directory".utf8))
            }
            if inv.arguments.last?.hasSuffix("badjson.yaml") == true {
                return SubprocessResult(exitCode: 0, stdout: Data("<<<not json>>>".utf8))
            }
            if inv.arguments.last?.hasSuffix("generic.yaml") == true {
                return SubprocessResult(exitCode: 3, stdout: Data(), stderr: Data("unexpected error".utf8))
            }
            return SubprocessResult(
                exitCode: 0,
                stdout: Data(#"{"dotted.key":"dotval","nested":{"leaf":"v"},"arr":["zero"]}"#.utf8)
            )
        }

        let passProv = UnixPassProvider(storeDirectory: "/default/store", fullEntryByDefault: true)
        let sopsProv = SOPSProvider()
        let ctx = SettingsContext.inMemory(fileSystem: fs, subprocessRunner: runner)

        // UnixPass: fullEntryByDefault, #full, case-insensitive metadata `#username`, `?store=/alt/store`
        let passOkRefs = try [
            SecretReference.parse("pass://app/db"),
            SecretReference.parse("pass://app/db#full"),
            SecretReference.parse("pass://app/db#username"),
            SecretReference.parse("pass://app/db?store=/alt/store#line:1"),
        ]
        let passOut = try await passProv.resolveBatch(passOkRefs, context: ctx)
        #expect(String(decoding: passOut[passOkRefs[2]]!, as: UTF8.self) == "alice")
        #expect(String(decoding: passOut[passOkRefs[3]]!, as: UTF8.self) == "pw-/alt/store")

        // UnixPass error cases in batch (`#line:0`, missing metadata key, missing entry, gpg error, non-utf8, generic fail)
        let passErrRefs = try [
            passOkRefs[2],
            SecretReference.parse("pass://app/db#line:0"),
            SecretReference.parse("pass://app/db#nosuchmeta"),
            SecretReference.parse("pass://missing/entry"),
            SecretReference.parse("pass://gpg/locked"),
            SecretReference.parse("pass://non/utf8"),
            SecretReference.parse("pass://generic/fail"),
        ]
        await #expect(throws: SecretBatchPartialFailureError.self) {
            _ = try await passProv.resolveBatch(passErrRefs, context: ctx)
        }

        // SOPS: rawMode (`?raw=true`), whole-file JSON (no pointer), direct dotted key, dotted traversal `nested.leaf`
        let sopsOkRefs = try [
            SecretReference.parse("sops://secrets/raw.bin?raw=true"),
            SecretReference.parse("sops://secrets/ok.yaml"),
            SecretReference.parse("sops://secrets/ok.yaml#dotted.key"),
            SecretReference.parse("sops://secrets/ok.yaml#nested.leaf"),
        ]
        let sopsOut = try await sopsProv.resolveBatch(sopsOkRefs, context: ctx)
        #expect(sopsOut[sopsOkRefs[0]] == Data([0xCA, 0xFE, 0xBA, 0xBE]))
        #expect(sopsOut[sopsOkRefs[2]] == Data("dotval".utf8))
        #expect(sopsOut[sopsOkRefs[3]] == Data("v".utf8))

        // SOPS error cases in batch (trailing `~`, leading-zero array index `01`, traverse into scalar, missing key, missing file, invalid JSON, generic exit)
        let sopsErrRefs = try [
            sopsOkRefs[3],
            SecretReference.parse("sops://secrets/ok.yaml#/trailing~"),
            SecretReference.parse("sops://secrets/ok.yaml#/arr/01"),
            SecretReference.parse("sops://secrets/ok.yaml#/nested/leaf/deeper"),
            SecretReference.parse("sops://secrets/ok.yaml#/nested/missing"),
            SecretReference.parse("sops://secrets/missing.yaml#/a"),
            SecretReference.parse("sops://secrets/badjson.yaml#/a"),
            SecretReference.parse("sops://secrets/generic.yaml#/a"),
        ]
        await #expect(throws: SecretBatchPartialFailureError.self) {
            _ = try await sopsProv.resolveBatch(sopsErrRefs, context: ctx)
        }

        // Missing executable errors for pass & sops
        await #expect(throws: SecretResolutionError.self) {
            _ = try await UnixPassProvider(searchDirectories: ["/none"]).resolveBatch([passOkRefs[0]], context: .inMemory())
        }
        await #expect(throws: SecretResolutionError.self) {
            _ = try await SOPSProvider(searchDirectories: ["/none"]).resolveBatch([sopsOkRefs[0]], context: .inMemory())
        }
    }
}
