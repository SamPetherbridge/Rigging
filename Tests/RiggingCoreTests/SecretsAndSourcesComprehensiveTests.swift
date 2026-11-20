import Foundation
import RiggingCore
import RiggingTesting
import Synchronization
import Testing

@Suite("Secrets, Sources, Validators & Watcher Comprehensive Coverage")
struct SecretsAndSourcesComprehensiveTests {

    // MARK: - Secret<T>, DiagnosticRedactor & EphemeralSecretFile

    @Test("Secret<T> map, byte buffers, Hashable, Codable policies, DiagnosticRedactor [UInt8]/CRLF, and EphemeralSecretFile [UInt8]/aux cleanup")
    func secretByteBuffersCodableRedactorAndEphemeral() async throws {
        let strSec = Secret("super-secret-string").map { $0.uppercased() }
        #expect(strSec.expose() == "SUPER-SECRET-STRING")
        #expect(!strSec.isEmpty)
        #expect(Secret("").isEmpty)
        let utf8Len = strSec.withExposedUTF8 { $0.count }
        #expect(utf8Len == 19)

        let dataSec = Secret(Data([0x10, 0x20, 0x30]))
        #expect(!dataSec.isEmpty)
        #expect(Secret(Data()).isEmpty)
        #expect(dataSec.withExposedBytes { Array($0) } == [0x10, 0x20, 0x30])
        #expect(dataSec.withExposedRawBytes { $0.count } == 3)

        let bytesSec = try Secret<[UInt8]>.decodeSettingValue(
            from: .data(Data([0xAA, 0xBB, 0xCC])),
            context: ValueDecodingContext()
        )
        #expect(!bytesSec.isEmpty)
        #expect(Secret([UInt8]()).isEmpty)
        #expect(bytesSec.withExposedBytes { Array($0) } == [0xAA, 0xBB, 0xCC])

        // Hashable & Codable (.redact vs .exposePlaintext)
        var secretSet: Set<Secret<String>> = [strSec]
        secretSet.insert(Secret("SUPER-SECRET-STRING"))
        #expect(secretSet.count == 1)

        let defaultEncoded = try JSONEncoder().encode(strSec)
        #expect(try JSONDecoder().decode(String.self, from: defaultEncoded) == "**********")

        let plaintextEncoder = JSONEncoder()
        plaintextEncoder.userInfo[.secretEncodingPolicy] = SecretEncodingPolicy.exposePlaintext
        let exposedEncoded = try plaintextEncoder.encode(strSec)
        let decodedSecret = try JSONDecoder().decode(Secret<String>.self, from: exposedEncoded)
        #expect(decodedSecret == strSec)

        // DiagnosticRedactor [UInt8] & CRLF PEM body
        let redactor = DiagnosticRedactor()
        redactor.register(Array("BYTE_SECRET_999".utf8))
        redactor.register("-----BEGIN PRIVATE KEY-----\r\nLINE_ONE_SECRET_BODY\r\n-----END PRIVATE KEY-----")
        let scrubbed = redactor.scrub("error with BYTE_SECRET_999 and LINE_ONE_SECRET_BODY")
        #expect(!scrubbed.contains("BYTE_SECRET_999"))
        #expect(!scrubbed.contains("LINE_ONE_SECRET_BODY"))

        // Secret<[UInt8]>.withEphemeralFile + auxiliary sibling file cleanup inside temp dir
        let (capturedDir, byteCountRead) = try await bytesSec.withEphemeralFile(prefix: "bytes", suffix: ".key") { fileURL in
            let dir = fileURL.deletingLastPathComponent()
            // Drop an extra auxiliary file in the ephemeral directory to exercise readdir cleanup
            let sibling = dir.appendingPathComponent("aux.tmp")
            try Data("aux".utf8).write(to: sibling)
            let readBack = try Data(contentsOf: fileURL)
            return (dir, readBack.count)
        }
        #expect(byteCountRead == 3)
        #expect(!FileManager.default.fileExists(atPath: capturedDir.path))

        // EphemeralSecretFileError LocalizedError descriptions
        let ephErrors: [EphemeralSecretFileError] = [
            .directoryCreationFailed(errno: 13),
            .fileOpenFailed(errno: 17),
            .fileWriteFailed(errno: 28),
            .fileSyncFailed(errno: 5),
        ]
        for err in ephErrors {
            #expect(err.errorDescription == err.description)
            #expect(!err.description.isEmpty)
        }
    }

    // MARK: - SecretReference, IndirectEnvProvider, FileSecretProvider & SecretResolver

    @Test("SecretReference parses all schemes, queries, fragments, and rejects malformed/unsafe inputs")
    func secretReferenceAllSchemesAndRejections() throws {
        // Error descriptions
        let refErrors: [SecretReferenceError] = [
            .containsNullByte,
            .containsControlCharacter(scheme: "op"),
            .invalidPercentEncoding(scheme: "op", component: "%ZZ"),
            .optionInjection(scheme: "op", segment: "-flag"),
            .pathTraversal(scheme: "pass", segment: ".."),
            .invalidFormat(scheme: "bw", message: "bad format"),
            .invalidQueryParameter(scheme: "keychain", name: "kind", value: "bad"),
        ]
        for err in refErrors {
            #expect(err.errorDescription == err.description)
            #expect(!err.description.isEmpty)
        }

        // 4-segment op:// with section + flag-only query item
        let opRef = try SecretReference(parsing: "op://Engineering/Database/Credentials/password?account=work&raw")
        #expect(opRef.scheme == "op")
        #expect(opRef.accountHint == "work")
        #expect(!opRef.isLiteral)
        #expect(opRef.description == "op://Engineering/Database/Credentials/password")
        if case .onePassword(let inner) = opRef {
            #expect(inner.section == "Credentials")
            #expect(inner.query["account"] == "work")
            #expect(inner.query["raw"] == "")
            #expect(inner.opReadURI == "op://Engineering/Database/Credentials/password?raw")
        } else {
            Issue.record("Expected .onePassword")
        }

        // keychain, bws, bw, pass, sops, file, env, custom, literal
        let kcRef = try SecretReference.parse("keychain://com.example.asc/token?synchronizable=no&accessGroup=GRP1")
        #expect(kcRef.scheme == "keychain")
        #expect(kcRef.accountHint == nil)
        #expect(kcRef.redactedDescription == "keychain://com.example.asc/token")
        if case .keychain(let kc) = kcRef {
            #expect(kc.synchronizable == false)
            #expect(kc.query["accessGroup"] == "GRP1")
        }

        let bwsRef = try SecretReference.parse("bws://uuid-1234?account=org1")
        #expect(bwsRef.scheme == "bws")
        #expect(bwsRef.accountHint == "org1")
        #expect(bwsRef.redactedDescription == "bws://uuid-1234")
        if case .bitwardenSecretsManager(let bws) = bwsRef {
            #expect(bws.query["account"] == "org1")
        }

        let bwRef = try SecretReference.parse("bw://item-99/password?account=vault1")
        #expect(bwRef.scheme == "bw")
        #expect(bwRef.accountHint == "vault1")
        #expect(bwRef.redactedDescription == "bw://item-99/password")
        if case .bitwardenVault(let bw) = bwRef {
            #expect(bw.query["account"] == "vault1")
        }

        let passNoFrag = try SecretReference.parse("pass://infra/prod/db?store=corp")
        #expect(passNoFrag.scheme == "pass")
        #expect(passNoFrag.accountHint == "corp")
        #expect(passNoFrag.redactedDescription == "pass://infra/prod/db")
        let passFrag = try SecretReference.parse("pass://infra/prod/db#username")
        #expect(passFrag.redactedDescription == "pass://infra/prod/db#username")
        if case .pass(let p) = passNoFrag {
            #expect(p.query["store"] == "corp")
        }

        let sopsNoPtr = try SecretReference.parse("sops://secrets/prod.enc.json?account=kms1")
        #expect(sopsNoPtr.scheme == "sops")
        #expect(sopsNoPtr.accountHint == "kms1")
        #expect(sopsNoPtr.redactedDescription == "sops://secrets/prod.enc.json")
        let sopsPtr = try SecretReference.parse("sops://secrets/prod.enc.json#/db/password")
        #expect(sopsPtr.redactedDescription == "sops://secrets/prod.enc.json#/db/password")
        if case .sops(let s) = sopsNoPtr {
            #expect(s.query["account"] == "kms1")
        }

        let fileLocalhost = try SecretReference.parse("file://localhost/etc/secrets/token")
        #expect(fileLocalhost.scheme == "file")
        #expect(fileLocalhost.accountHint == nil)
        #expect(fileLocalhost.redactedDescription == "file:///etc/secrets/token")
        let fileAtRel = try SecretReference.parse("@./keys/api.key")
        #expect(fileAtRel.redactedDescription == "@./keys/api.key")
        let fileAtParent = try SecretReference.parse("@../keys/api.key")
        #expect(fileAtParent.redactedDescription == "@../keys/api.key")

        let envRef = try SecretReference.parse("env://PROD_SECRET_TOKEN")
        #expect(envRef.scheme == "env")
        #expect(envRef.accountHint == nil)
        #expect(envRef.redactedDescription == "env://PROD_SECRET_TOKEN")

        let customRef = try SecretReference.parse(
            "vault://kv/prod/api?account=hcp#token",
            additionalSchemes: ["vault"]
        )
        #expect(customRef.scheme == "vault")
        #expect(customRef.accountHint == "hcp")
        #expect(customRef.redactedDescription == "vault://kv/prod/api#token")
        let customNoFrag = try SecretReference.parse("vault://kv/prod/api", additionalSchemes: ["vault"])
        #expect(customNoFrag.redactedDescription == "vault://kv/prod/api")

        let litRef = try SecretReference.parse("sk-live-123456")
        #expect(litRef.scheme == "literal")
        #expect(litRef.accountHint == nil)
        #expect(litRef.isLiteral)
        #expect(litRef.redactedDescription == "<literal>")

        // Invalid URI cases across all schemes
        let invalidInputs = [
            "op://onlytwo/segments",
            "op://a/b/c#frag",
            "op://a/b/c?bad=-inject",
            "op://a/b/c?=1",
            "op://a/b/c?a=1&&b=2",
            "op://a/%ZZ/c",
            "op://a/b/c\n",
            "keychain://onlyone",
            "keychain://svc/acct?accessGroup=",
            "keychain://svc/acct?synchronizable=maybe",
            "bws://two/segments",
            "bw://onlyone",
            "pass://",
            "pass://a/../b",
            "pass://a/b#",
            "pass://a/b#-inject",
            "sops://",
            "sops://-bad/file",
            "sops://dir/-bad",
            "sops://file#",
            "sops://file#-bad",
            "file:///path?query=1",
            "file://relative/path",
            "file:///",
            "file:///dir/-bad",
            "@/",
            "env://BAD/SLASH",
            "env://123_INVALID_START",
        ]
        for bad in invalidInputs {
            #expect(throws: SecretReferenceError.self) {
                _ = try SecretReference.parse(bad)
            }
        }
        #expect(throws: SecretReferenceError.self) {
            _ = try SecretReference.parse("vault://", additionalSchemes: ["vault"])
        }
        #expect(throws: SecretReferenceError.self) {
            _ = try SecretReference.parse("vault://kv#-bad", additionalSchemes: ["vault"])
        }
    }

    @Test("IndirectEnvProvider, FileSecretProvider, SecretResolutionCache, SecretTransforms, and SecretResolutionError")
    func indirectEnvFileCacheTransformsAndErrors() async throws {
        // SecretResolutionError exhaustive descriptions, remediations & exitCodes
        let resErrors: [(SecretResolutionError, Int32)] = [
            (.unsafePlaintextInProjectConfig(keyPath: ["k"], origin: .defaultValue), 4),
            (.insecureFilePermissions(path: "/k", actualPermissions: 0o644, requiredPermissions: 0o600), 4),
            (.unsafeExecutable(scheme: "op", path: "./op", reason: "relative"), 4),
            (.secretFileNotFound(path: "/missing"), 6),
            (.secretFileReadFailed(path: "/unreadable", reason: "EACCES"), 6),
            (.environmentVariableNotSet(variableName: "MISSING_VAR"), 6),
            (.unregisteredScheme(scheme: "vault", referenceRedacted: "vault://a"), 6),
            (.unresolvedReference(referenceRedacted: "op://v/i/f"), 6),
            (.authenticationFailed(scheme: "op", message: "not signed in", remediation: "Run op signin"), 6),
            (.itemNotFound(scheme: "op", referenceRedacted: "op://v/i/f", message: "no vault"), 6),
            (.itemNotFound(scheme: "op", referenceRedacted: "op://v/i/f", message: nil), 6),
            (.rateLimited(scheme: "op", message: "rate-limited", retryAfter: .seconds(30), remediation: "Wait"), 6),
            (.rateLimited(scheme: "op", message: "rate-limited", retryAfter: nil), 6),
            (.providerFailed(scheme: "bw", message: "locked", remediation: "Unlock"), 6),
            (.invalidReference(.containsNullByte), 2),
            (.transformFailed(transform: "decodeBase64", reason: "bad base64"), 2),
        ]
        for (err, expectedExit) in resErrors {
            #expect(err.exitCode == expectedExit)
            #expect(err.errorDescription == err.description)
            #expect(!err.description.isEmpty)
            _ = err.remediation
        }
        #expect(SecretResolutionError.formatFourDigitOctal(0o600) == "0600")
        #expect(SecretResolutionError.formatChmodOctal(0o040) == "040")

        // ValidationIssue Codable round-trip with & without rate-limit fields
        let rateIssue = ValidationIssue(
            keyPath: ["token"],
            kind: .providerFailure,
            message: "Rate limited",
            isRateLimited: true,
            retryAfter: .seconds(30)
        )
        let encodedIssue = try JSONEncoder().encode(rateIssue)
        let decodedIssue = try JSONDecoder().decode(ValidationIssue.self, from: encodedIssue)
        #expect(decodedIssue == rateIssue)
        #expect(decodedIssue.isRateLimited == true)
        #expect(decodedIssue.retryAfter == .seconds(30))

        let legacyIssueJSON = Data(#"{"keyPath":["port"],"kind":"invalidValue","message":"Bad port"}"#.utf8)
        let decodedLegacy = try JSONDecoder().decode(ValidationIssue.self, from: legacyIssueJSON)
        #expect(decodedLegacy.isRateLimited == false)
        #expect(decodedLegacy.retryAfter == nil)

        // IndirectEnvProvider: single hit, allowEmptyValue, partial batch failure
        let envContext = SettingsContext.inMemory(
            environment: [
                "SECRET_A": "alpha-secret-value",
                "EMPTY_SECRET": "",
            ],
            secretProviders: [.env(allowEmptyValue: false)]
        )
        let batchFail = await SecretResolver().resolveAll([
            SecretResolutionRequest(keyPath: ["a"], rawString: "env://SECRET_A", origin: .defaultValue),
            SecretResolutionRequest(keyPath: ["b"], rawString: "env://EMPTY_SECRET", origin: .defaultValue),
            SecretResolutionRequest(keyPath: ["c"], rawString: "env://MISSING_SECRET", origin: .defaultValue),
        ], context: envContext)
        #expect(try batchFail.resolvedByKeyPath[["a"]]?.utf8Secret().expose() == "alpha-secret-value")
        #expect(batchFail.issues.count == 2)
        #expect(batchFail.issues.allSatisfy { $0.kind == .providerFailure })

        let allowEmptyCtx = SettingsContext.inMemory(
            environment: ["EMPTY_SECRET": ""],
            secretProviders: [.env(allowEmptyValue: true)]
        )
        let allowedEmpty = try await SecretResolver().resolve(
            SecretResolutionRequest(keyPath: ["b"], rawString: "env://EMPTY_SECRET", origin: .defaultValue),
            context: allowEmptyCtx
        )
        #expect(try allowedEmpty.utf8Secret().expose() == "")

        // FileSecretProvider: custom permission override (0o640), missing file, partial batch failure
        let fs = InMemoryFileSystem()
        fs.writeString("group-secret\n", atPath: "/Users/jane/keys/group.key", permissions: 0o640)
        fs.writeString("ok-secret", atPath: "/repo/keys/ok.key", permissions: 0o600)
        let fileCtx = SettingsContext(
            workingDirectory: "/repo/sub",
            homeDirectory: "/Users/jane",
            fileSystem: fs,
            secretProviders: [FileSecretProvider()]
        )
        let customPermResolved = try await SecretResolver().resolve(
            SecretResolutionRequest(
                keyPath: ["grpKey"],
                rawString: "@~/keys/group.key",
                origin: .projectConfig(path: "/repo/.app.json", keyPath: ["grpKey"], profile: nil),
                transforms: [.expandFileReference(requirePermissions: 0o640), .trimWhitespace]
            ),
            context: fileCtx
        )
        #expect(try customPermResolved.utf8Secret().expose() == "group-secret")
        #expect(customPermResolved.dataSecret.expose() == Data("group-secret".utf8))
        #expect(customPermResolved.bytesSecret.expose() == Array("group-secret".utf8))

        let filePartial = await SecretResolver().resolveAll([
            SecretResolutionRequest(keyPath: ["k1"], rawString: "@../keys/ok.key", origin: .defaultValue),
            SecretResolutionRequest(keyPath: ["k2"], rawString: "@/missing/nope.key", origin: .defaultValue),
        ], context: fileCtx)
        #expect(filePartial.resolved.count == 1)
        #expect(filePartial.issues.count == 1)

        // SecretResolutionCache: single store, value(for:), count, invalidate, invalidateAll
        let clockNow = Mutex(ContinuousClock.now)
        let cache = SecretResolutionCache(ttl: .seconds(60), now: { clockNow.withLock { $0 } })
        let ref1 = try SecretReference.parse("op://V/I/f1")
        let ref2 = try SecretReference.parse("op://V/I/f2")
        await cache.store(Data("v1".utf8), for: ref1)
        await cache.store([ref2: Data("v2".utf8)])
        #expect(await cache.count == 2)
        #expect(await cache.value(for: ref1) == Data("v1".utf8))
        await cache.invalidate(ref1)
        #expect(await cache.value(for: ref1) == nil)
        clockNow.withLock { $0 = $0.advanced(by: .seconds(120)) }
        #expect(await cache.value(for: ref2) == nil)
        await cache.invalidateAll()
        #expect(await cache.count == 0)

        // SecretTransforms: binary trimWhitespace, expandTilde, URL-safe base64, single-line >64ch PEM, utf8Data, and error paths
        let nonUTF8 = Data([0x20, 0xFF, 0xFE, 0x0A])
        #expect(try SecretTransform.trimWhitespace.apply(to: nonUTF8, context: fileCtx).data == Data([0xFF, 0xFE]))
        #expect(
            try SecretTransform.expandTilde.apply(to: Data("~/keys/k".utf8), context: fileCtx).data
                == Data("/Users/jane/keys/k".utf8)
        )
        #expect(throws: SecretResolutionError.self) {
            _ = try SecretTransform.expandTilde.apply(to: nonUTF8, context: fileCtx)
        }
        #expect(throws: SecretResolutionError.self) {
            _ = try SecretTransform.expandFileReference().apply(to: Data("@".utf8), context: fileCtx)
        }
        // URL-safe base64 (`-_` without padding)
        let urlSafeB64 = Data("subjects?_d=1".utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        #expect(
            try SecretTransform.decodeBase64.apply(to: Data(urlSafeB64.utf8), context: fileCtx).data
                == Data("subjects?_d=1".utf8)
        )
        #expect(try SecretTransform.decodeBase64.apply(to: Data("   ".utf8), context: fileCtx).data == Data())
        #expect(throws: SecretResolutionError.self) {
            _ = try SecretTransform.decodeBase64.apply(to: nonUTF8, context: fileCtx)
        }
        #expect(throws: SecretResolutionError.self) {
            _ = try SecretTransform.decodeBase64.apply(to: Data("abcde".utf8), context: fileCtx)
        }
        #expect(throws: SecretResolutionError.self) {
            _ = try SecretTransform.decodeBase64IfPrefixed.apply(to: Data("base64:%%%".utf8), context: fileCtx)
        }
        // Single-line PEM with >64 char body wrapping
        let longBody = String(repeating: "A", count: 80)
        let inlinePEM = "-----BEGIN PRIVATE KEY----- \(longBody) -----END PRIVATE KEY-----"
        let normalizedPEM = try String(
            decoding: SecretTransform.normalizePEM.apply(to: Data(inlinePEM.utf8), context: fileCtx).data,
            as: UTF8.self
        )
        #expect(normalizedPEM.components(separatedBy: "\n").count == 4)
        #expect(throws: SecretResolutionError.self) {
            _ = try SecretTransform.normalizePEM.apply(to: nonUTF8, context: fileCtx)
        }
        #expect(try SecretTransform.utf8Data.apply(to: Data("valid".utf8), context: fileCtx).data == Data("valid".utf8))
        #expect(throws: SecretResolutionError.self) {
            _ = try SecretTransform.utf8Data.apply(to: nonUTF8, context: fileCtx)
        }

        // Unregistered scheme & non-scalar node & binary secret in projectConfig
        let miscBatch = await SecretResolver().resolveAll([
            SecretResolutionRequest(keyPath: ["unreg"], rawString: "op://V/I/f", origin: .defaultValue),
            SecretResolutionRequest(
                keyPath: ["binProj"],
                node: RawNode(value: .data(Data("raw".utf8)), origin: .projectConfig(path: "/p", keyPath: ["binProj"], profile: nil))
            ),
            SecretResolutionRequest(
                keyPath: ["intEnv"],
                node: RawNode(value: .int(123456), origin: .environment(variable: "INT_SEC"))
            ),
            SecretResolutionRequest(
                keyPath: ["arrBad"],
                node: RawNode(value: .array([]), origin: .environment(variable: "ARR"))
            ),
        ], context: SettingsContext.inMemory(secretProviders: []))
        #expect(miscBatch.resolved.count == 1)
        #expect(miscBatch.issues.count == 3)
    }

    // MARK: - DotEnvParser, PlistFileSource, JSONFileSource, ManagedPreferencesSource & SecretsDirSource

    @Test("DotEnvParser handles BOM, strict mode, unicode escapes, continuations, nested defaults, and syntax errors")
    func dotEnvParserEdgeCasesAndErrors() throws {
        // Invalid UTF-8 data
        #expect(throws: DotEnvParseError.self) {
            _ = try DotEnvParser.parse(data: Data([0xFF, 0xFE]), path: ".env")
        }

        let complexEnv = "\u{FEFF}" + #"""
        # Leading BOM + quoted keys + escapes + nested interpolation
        "QUOTED_KEY" = "line1\r\t\'\\\$\u0041\u{21}\uZZZZ\x" # trailing comment
        'SINGLE_KEY' = 'multiline
        literal'
        CONT_KEY = "joined\
        together"
        EMPTY_EOF_COMMENT = # comment after space
        HASH_NO_SPACE = abc#def
        NESTED = "${UNSET_OUTER:-${FALLBACK_INNER:-resolved_nested}}"
        EMPTY_AT_EOF=
        """#

        let entries = try DotEnvParser.parse(
            data: Data(complexEnv.utf8),
            strict: true,
            path: "/repo/.env"
        )
        let map = Dictionary(uniqueKeysWithValues: entries.map { ($0.key, $0.value) })
        #expect(map["QUOTED_KEY"] == "line1\r\t'\\$A!\\uZZZZ\\x")
        #expect(map["SINGLE_KEY"] == "multiline\nliteral")
        #expect(map["CONT_KEY"] == "joinedtogether")
        #expect(map["EMPTY_EOF_COMMENT"] == "")
        #expect(map["HASH_NO_SPACE"] == "abc#def")
        #expect(map["NESTED"] == "resolved_nested")
        #expect(map["EMPTY_AT_EOF"] == "")

        // expandVariables: false preserves literal ${VAR}
        let unexpanded = try DotEnvParser.parse("RAW=${DO_NOT_EXPAND}", expandVariables: false)
        #expect(unexpanded.first?.value == "${DO_NOT_EXPAND}")

        // Syntax errors + LocalizedError
        let badInputs = [
            "NO_EQUALS_IN_STRICT_MODE",
            "=missing_key",
            "BAD\0KEY=1",
            "UNTERM_SINGLE='abc",
            "UNTERM_DOUBLE=\"abc",
            "UNTERM_ESC=\"abc\\",
            "TRAILING_JUNK=\"ok\" unexpected_token",
            "UNTERM_PEM=-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8=",
            "UNTERM_INTERP=${OPEN",
        ]
        for input in badInputs {
            do {
                _ = try DotEnvParser.parse(input, strict: true, path: ".env.bad")
                Issue.record("Expected DotEnvParseError for: \(input)")
            } catch let err as DotEnvParseError {
                #expect(err.errorDescription == err.description)
                #expect(err.description.contains(".env.bad"))
            }
        }
        let noPathErr = DotEnvParseError(path: nil, line: 3, message: "oops")
        #expect(noPathErr.description == "line 3: oops")
    }

    @Test("PlistFileSource, JSONFileSource, ManagedPreferencesSource, SecretsDirSource & InitSource edge cases")
    func fileManagedAndSecretsDirSourcesEdgeCases() async throws {
        let arrayPlistData = try PropertyListSerialization.data(
            fromPropertyList: ["not", "a", "dict"],
            format: .xml,
            options: 0
        )
        let fs = InMemoryFileSystem()
        fs.writeFile(Data("<<<not a plist>>>".utf8), atPath: "/repo/bad.plist")
        fs.writeFile(arrayPlistData, atPath: "/repo/array.plist")
        fs.writeString("{ invalid json", atPath: "/repo/bad.json")
        fs.writeString("[1, 2, 3]", atPath: "/repo/array.json")
        fs.writeFile(Data([0xFF, 0x00, 0xFE]), atPath: "/run/secrets/binary_key")
        fs.writeString("keep-newline\n", atPath: "/run/secrets/raw_newline")

        let ctx = SettingsContext(
            workingDirectory: "/repo",
            homeDirectory: "/Users/jane",
            fileSystem: fs
        )
        let cfg = SettingsConfiguration(
            secretsDirectory: "/run/secrets",
            trimSecretTrailingNewline: false
        )

        // PlistFileSource errors
        let plistSrc = PlistFileSource(paths: ["/repo/missing.plist"], optional: false)
        #expect(plistSrc.sourceName == "PlistFileSource")
        await #expect(throws: (any Error).self) {
            _ = try await plistSrc.load(configuration: cfg, context: ctx)
        }
        await #expect(throws: ConfigFileParseError.self) {
            _ = try await PlistFileSource(path: "/repo/bad.plist", optional: false).load(configuration: cfg, context: ctx)
        }
        await #expect(throws: ConfigFileParseError.self) {
            _ = try await PlistFileSource(path: "/repo/array.plist", optional: false).load(configuration: cfg, context: ctx)
        }

        // JSONFileSource errors
        let jsonSrc = JSONFileSource(path: "/repo/missing.json", optional: false)
        #expect(jsonSrc.sourceName == "JSONFileSource")
        await #expect(throws: (any Error).self) {
            _ = try await jsonSrc.load(configuration: cfg, context: ctx)
        }
        await #expect(throws: ConfigFileParseError.self) {
            _ = try await JSONFileSource(path: "/repo/bad.json").load(configuration: cfg, context: ctx)
        }
        await #expect(throws: ConfigFileParseError.self) {
            _ = try await JSONFileSource(path: "/repo/array.json").load(configuration: cfg, context: ctx)
        }

        // SecretsDirSource binary data + untrimmed newline + missing dir
        let secDirSrc = SecretsDirSource()
        #expect(secDirSrc.sourceName == "SecretsDirSource")
        let secTree = try await secDirSrc.load(configuration: cfg, context: ctx)
        #expect(secTree.lookup(path: ["binary_key"])?.value == .data(Data([0xFF, 0x00, 0xFE])))
        #expect(secTree.lookup(path: ["raw_newline"])?.value == .string("keep-newline\n"))
        let emptySecTree = try await SecretsDirSource(directory: "/does/not/exist").load(configuration: cfg, context: ctx)
        #expect(emptySecTree.isEmpty)

        // ManagedPreferencesSource: mock nested object/array + key filter + macOS CFPreferences path
        let nestedMock: [String: RawValue] = [
            "allowed.nested": .object(["k": RawNode(value: .string("v"), origin: .defaultValue)]),
            "allowed.list": .array([RawNode(value: .int(1), origin: .defaultValue)]),
            "ignored.key": .string("skip"),
        ]
        let mockManaged = ManagedPreferencesSource(
            domain: "com.example.asc",
            keys: ["allowed.nested", "allowed.list"],
            mockValues: nestedMock
        )
        #expect(mockManaged.sourceName == "ManagedPreferencesSource")
        let managedTree = try await mockManaged.load(configuration: cfg, context: ctx)
        #expect(managedTree.lookup(path: ["allowed", "nested", "k"])?.value == .string("v"))
        #expect(managedTree.lookup(path: ["ignored", "key"]) == nil)

        // Empty domain & macOS real CFPreferences no-op lookup for nonexistent domain
        let emptyDomainTree = try await ManagedPreferencesSource().load(configuration: cfg, context: ctx)
        #expect(emptyDomainTree.isEmpty)
        let cfDiscoverTree = try await ManagedPreferencesSource(
            domain: "com.example.rigging.nonexistent.\(UUID().uuidString)"
        ).load(configuration: cfg, context: ctx)
        #expect(cfDiscoverTree.isEmpty)
        let cfExplicitKeysTree = try await ManagedPreferencesSource(
            domain: "com.example.rigging.nonexistent.\(UUID().uuidString)",
            keys: ["apiEndpoint"],
            requireForced: false
        ).load(configuration: cfg, context: ctx)
        #expect(cfExplicitKeysTree.isEmpty)
    }

    // MARK: - Validators, ValidationError & SettingsWatcher

    @Test("SettingValidator covers optional(), all custom() overloads, URL/String fileExists & url rules, and SettingsWatcher start/stop/onError")
    func validatorsErrorFormattingAndSettingsWatcher() async throws {
        let fs = InMemoryFileSystem()
        fs.writeString("CERT", atPath: "/Users/jane/cert.pem")
        fs.writeString("LOCAL", atPath: "/repo/local.txt")
        fs.makeDirectory(atPath: "/repo/subdir")
        let ctx = SettingsContext(
            workingDirectory: "/repo",
            homeDirectory: "/Users/jane",
            fileSystem: fs
        )

        // .optional() & .custom overloads & .maxLength & half-open .range
        let optMin = SettingValidator<String>.minLength(3).optional()
        #expect(optMin.validate(nil, context: ctx) == nil)
        #expect(optMin.validate("ab", context: ctx) != nil)
        #expect(SettingValidator<String>.maxLength(3).validate("abcd", context: ctx) != nil)
        #expect(SettingValidator<[String]>.nonEmpty.validate([], context: ctx) != nil)
        #expect(SettingValidator<Int>.range(0..<10).validate(10, context: ctx) != nil)
        #expect(SettingValidator<Int>.range(0..<10).validate(9, context: ctx) == nil)

        let ctxCustom = SettingValidator<String>.custom { val, c in
            c.homeDirectory.contains(val) ? nil : "not in home"
        }
        #expect(ctxCustom.validate("jane", context: ctx) == nil)
        let predCustom = SettingValidator<Int>.custom("must be even") { $0.isMultiple(of: 2) }
        #expect(predCustom.validate(3, context: ctx) == "must be even")
        #expect(predCustom.validate(4, context: ctx) == nil)

        // Invalid regex pattern + String .url + String .fileExists
        #expect(SettingValidator<String>.regex("[unclosed").validate("abc", context: ctx) != nil)
        #expect(SettingValidator<String>.url().validate("", context: ctx) != nil)
        #expect(SettingValidator<String>.url().validate("ftp://files.example.com", context: ctx) != nil)
        #expect(SettingValidator<String>.url().validate("https:///no-host", context: ctx) != nil)
        #expect(SettingValidator<String>.fileExists(mustBeDirectory: true).validate("local.txt", context: ctx) != nil)
        #expect(SettingValidator<String>.fileExists(mustBeDirectory: false).validate("subdir", context: ctx) != nil)
        #expect(SettingValidator<String>.fileExists().validate("~", context: ctx) == nil)
        #expect(SettingValidator<String>.fileExists().validate("~/cert.pem", context: ctx) == nil)

        // URL .url & URL .fileExists
        let urlRule = SettingValidator<URL>.url()
        #expect(urlRule.validate(URL(string: "/relative/no-scheme")!, context: ctx) != nil)
        #expect(urlRule.validate(URL(string: "ftp://example.com")!, context: ctx) != nil)
        #expect(urlRule.validate(URL(string: "https:///missing-host")!, context: ctx) != nil)
        #expect(urlRule.validate(URL(string: "https://api.example.com")!, context: ctx) == nil)

        #expect(SettingValidator<URL>.fileExists().validate(URL(fileURLWithPath: "/repo/missing"), context: ctx) != nil)
        #expect(SettingValidator<URL>.fileExists(mustBeDirectory: true).validate(URL(fileURLWithPath: "/repo/local.txt"), context: ctx) != nil)
        #expect(SettingValidator<URL>.fileExists(mustBeDirectory: false).validate(URL(fileURLWithPath: "/repo/subdir"), context: ctx) != nil)
        #expect(SettingValidator<URL>.fileExists(mustBeDirectory: false).validate(URL(fileURLWithPath: "/repo/local.txt"), context: ctx) == nil)

        // SettingsValidationError Equatable, errorDescription, warnings formatting
        let errA = SettingsValidationError(
            issues: [ValidationIssue(keyPath: ["a"], kind: .missingRequired, message: "missing a")],
            warnings: [ValidationIssue(keyPath: ["extra"], kind: .unknownKey, message: "unknown extra")]
        )
        let errB = SettingsValidationError(
            issues: [ValidationIssue(keyPath: ["a"], kind: .missingRequired, message: "missing a")],
            warnings: [ValidationIssue(keyPath: ["extra"], kind: .unknownKey, message: "unknown extra")]
        )
        #expect(errA == errB)
        #expect(errA.errorDescription?.contains("Warnings (1):") == true)

        // SettingsWatcher.start, updates() stream, onError callback, and stop()
        struct WatchedTiny: RiggedSettings, Equatable, Sendable {
            static let configuration = SettingsConfiguration(
                dotEnvFiles: ["~/.tiny.env"],
                projectConfigFiles: [".tiny.json"],
                xdgAppName: "tinywatch"
            )
            static let fieldDescriptors: [SettingFieldDescriptor] = [
                SettingFieldDescriptor(name: "port", keyPath: ["port"], typeName: "Int", schemaType: .integer),
            ]
            var port: Int
            var provenance: ProvenanceReport
            static func load(context: SettingsContext, overrides: [SettingOverride]) async throws -> WatchedTiny {
                var loader = try await SettingsLoader.prepare(for: Self.self, context: context, overrides: overrides)
                let p = loader.decodeRequired(Int.self, keyPath: ["port"])
                try loader.throwIfInvalid()
                return WatchedTiny(port: p!.value, provenance: loader.buildProvenanceReport())
            }
        }

        let watchFS = InMemoryFileSystem(
            files: ["/repo/.tiny.json": #"{"port": 8080}"#]
        )
        let recordedErrors = Mutex<[String]>([])
        let watchCtx = SettingsContext(
            environment: ["XDG_CONFIG_HOME": "/Users/jane/.xdg"],
            workingDirectory: "/repo",
            homeDirectory: "/Users/jane",
            fileSystem: watchFS
        )

        let watcher = try await SettingsWatcher<WatchedTiny>.start(
            context: watchCtx,
            pollInterval: .milliseconds(25),
            debounce: .milliseconds(10),
            onError: { err in
                recordedErrors.withLock { $0.append(String(describing: err)) }
            }
        )
        #expect(await watcher.current.port == 8080)

        let stream = await watcher.updates()
        let nextTask = Task { () -> WatchedTiny? in
            var iter = stream.makeAsyncIterator()
            return await iter.next()
        }

        // Trigger valid reload via background file change
        try await Task.sleep(for: .milliseconds(15))
        watchFS.writeString(#"{"port": 9090}"#, atPath: "/repo/.tiny.json")
        let emitted = await nextTask.value
        #expect(emitted?.port == 9090)

        // Trigger invalid file edit so checkForFileChanges invokes onError while preserving current == 9090
        watchFS.writeString(#"{"port": "not-an-int"}"#, atPath: "/repo/.tiny.json")
        try await Task.sleep(for: .milliseconds(80))
        #expect(await watcher.current.port == 9090)
        #expect(!recordedErrors.withLock { $0 }.isEmpty)

        await watcher.stop()
        // Calling updates() after stop() finishes immediately
        var postStopIter = await watcher.updates().makeAsyncIterator()
        #expect(await postStopIter.next() == nil)
    }

    // MARK: - RiggingTesting Comprehensive Helpers

    @Test("RiggingTesting InMemoryFileSystem, SettingsContext.inMemory(cli:), MockSecretProviders, and MockSubprocessRunner")
    func riggingTestingComprehensiveCoverage() async throws {
        // InMemoryFileSystem init with binaryFiles, directories, permissions, executables, defaultFilePermissions
        let fs = InMemoryFileSystem(
            files: [
                "/repo/.ssh/id_ed25519": "SSH_KEY",
                "/repo/api_token.txt": "TOKEN",
                "/repo/cert.p8": "P8",
                "/repo/config.yaml": "k: v",
            ],
            binaryFiles: ["/repo/secrets/raw.bin": Data([0x01, 0x02])],
            directories: ["/repo/.git", "/repo/sub/nested"],
            permissions: ["/repo/custom.sh": 0o755],
            executables: ["/usr/local/bin/op"],
            defaultFilePermissions: nil
        )
        #expect(fs.fileExists(atPath: "/repo/.git"))
        #expect(fs.isDirectory(atPath: "/repo/.git"))
        #expect(fs.isExecutableFile(atPath: "/usr/local/bin/op"))
        #expect(!fs.isExecutableFile(atPath: "/repo/.git"))
        #expect(try fs.posixPermissions(atPath: "/repo/.ssh/id_ed25519") == 0o600)
        #expect(try fs.posixPermissions(atPath: "/repo/api_token.txt") == 0o600)
        #expect(try fs.posixPermissions(atPath: "/repo/cert.p8") == 0o600)
        #expect(try fs.posixPermissions(atPath: "/repo/config.yaml") == 0o644)
        #expect(try fs.posixPermissions(atPath: "/repo/.ssh") == 0o700)
        #expect(try fs.contentsOfDirectory(atPath: "/repo").contains(".git"))
        #expect(throws: (any Error).self) { _ = try fs.readFile(atPath: "/repo/.git") }
        #expect(throws: (any Error).self) { _ = try fs.contentsOfDirectory(atPath: "/does/not/exist") }
        #expect(throws: (any Error).self) { _ = try fs.posixPermissions(atPath: "/does/not/exist") }

        // Dynamic mutation helpers: setPermissions, setExecutable, removeItem, normalizePath
        fs.setPermissions(0o755, atPath: "/repo/config.yaml")
        #expect(fs.isExecutableFile(atPath: "/repo/config.yaml"))
        fs.setPermissions(0o644, atPath: "/repo/config.yaml")
        #expect(!fs.isExecutableFile(atPath: "/repo/config.yaml"))

        fs.setExecutable(true, atPath: "/usr/local/bin/bw")
        #expect(fs.isExecutableFile(atPath: "/usr/local/bin/bw"))
        fs.setExecutable(false, atPath: "/usr/local/bin/bw")
        #expect(!fs.isExecutableFile(atPath: "/usr/local/bin/bw"))

        fs.removeItem(atPath: "/repo/sub")
        #expect(!fs.fileExists(atPath: "/repo/sub/nested"))
        fs.removeItem(atPath: "/") // guarded no-op
        #expect(fs.fileExists(atPath: "/repo/config.yaml"))

        #expect(InMemoryFileSystem.normalizePath("") == "/")
        #expect(InMemoryFileSystem.normalizePath("a/./b/../c") == "a/c")
        #expect(InMemoryFileSystem.normalizePath("../rel/path") == "../rel/path")
        #expect(InMemoryFileSystem.normalizePath("/a/b/../../c") == "/c")

        // SettingsContext.inMemory(cli: [String: Any]) across all scalar/collection/optional value conversions
        let nilOpt: String? = nil
        let someOpt: Int? = 42
        let sampleUUID = UUID()
        let sampleURL = URL(string: "https://api.example.com")!
        let cliDict: [String: Any] = [
            "flagBool": true,
            "--kebab-int": 7,
            "-s": Int8(1),
            "nested.i16": Int16(2),
            "nested__i32": Int32(3),
            "i64": Int64(4),
            "u": UInt(5),
            "uBig": UInt.max,
            "u64": UInt64(6),
            "u64Big": UInt64.max,
            "u32": UInt32(8),
            "u16": UInt16(9),
            "u8": UInt8(10),
            "dbl": 3.5,
            "flt": Float(1.5),
            "str": "hello",
            "sub": "world"[...],
            "dat": Data([0xAA]),
            "uid": sampleUUID,
            "url": sampleURL,
            "raw": RawValue.string("raw"),
            "arr": [1, "two"],
            "obj": ["inner": true],
            "nilSkipped": nilOpt as Any,
            "someUnwrapped": someOpt as Any,
            "   ": "empty-key-skipped",
            "---": "dashes-only-skipped",
        ]
        let cliCtx = SettingsContext.inMemory(
            cli: cliDict,
            includeBuiltInSecretProviders: false
        )
        #expect(cliCtx.cliOverrides.count >= 22)
        #expect(cliCtx.secretProviders.isEmpty)

        // MockOnePasswordProvider & MockKeychainProvider binary, mutations, partial failures, forced errors
        let opBin = MockOnePasswordProvider(binarySecrets: ["Engineering/Vault/bin": Data([0xDE, 0xAD])])
        await opBin.setSecret("updated-pw", for: "op://Engineering/Vault/pw")
        await opBin.setBinarySecret(Data([0xBE, 0xEF]), for: "op://Engineering/Vault/bin2")
        let rBin = try SecretReference.parse("op://Engineering/Vault/bin?account=corp")
        let rPw = try SecretReference.parse("op://Engineering/Vault/pw")
        let rMissing = try SecretReference.parse("op://Engineering/Vault/missing")
        let opResolved = try await opBin.resolveBatch([rBin, rPw], context: cliCtx)
        #expect(opResolved[rBin] == Data([0xDE, 0xAD]))
        #expect(await opBin.invocationCount == 1)
        #expect(await opBin.batchHistory.count == 1)

        await #expect(throws: SecretBatchPartialFailureError.self) {
            _ = try await opBin.resolveBatch([rPw, rMissing], context: cliCtx)
        }
        await opBin.setFailure(SecretResolutionError.authenticationFailed(scheme: "op", message: "expired"))
        await #expect(throws: SecretResolutionError.self) {
            _ = try await opBin.resolveBatch([rPw], context: cliCtx)
        }
        await opBin.setFailure(nil)
        await opBin.resetHistory()
        #expect(await opBin.invocationCount == 0)

        let opAlwaysFail = MockOnePasswordProvider(
            failingWith: SecretResolutionError.providerFailed(scheme: "op", message: "boom")
        )
        await #expect(throws: SecretResolutionError.self) {
            _ = try await opAlwaysFail.resolveBatch([rPw], context: cliCtx)
        }

        let kcBin = MockKeychainProvider(binarySecrets: ["com.example.asc/bin": Data([0x01, 0x02])])
        await kcBin.setSecret("kc-tok", for: "com.example.asc/tok")
        await kcBin.setBinarySecret(Data([0x03]), for: "keychain://com.example.asc/bin2")
        let kc1 = try SecretReference.parse("keychain://com.example.asc/bin?synchronizable=true")
        let kc2 = try SecretReference.parse("keychain://com.example.asc/tok")
        let kcMiss = try SecretReference.parse("keychain://com.example.asc/miss")
        let kcOut = try await kcBin.resolveBatch([kc1, kc2], context: cliCtx)
        #expect(kcOut[kc1] == Data([0x01, 0x02]))
        await #expect(throws: SecretBatchPartialFailureError.self) {
            _ = try await kcBin.resolveBatch([kc2, kcMiss], context: cliCtx)
        }
        await #expect(throws: SecretResolutionError.self) {
            _ = try await kcBin.resolveBatch([kcMiss], context: cliCtx)
        }
        await kcBin.setFailure(SecretResolutionError.providerFailed(scheme: "keychain", message: "locked"))
        await #expect(throws: SecretResolutionError.self) {
            _ = try await kcBin.resolveBatch([kc2], context: cliCtx)
        }
        await kcBin.setFailure(nil)
        await kcBin.resetHistory()
        #expect(await kcBin.invocationCount == 0)

        let kcFailInit = MockKeychainProvider(
            failingWith: SecretResolutionError.providerFailed(scheme: "keychain", message: "err")
        )
        await #expect(throws: SecretResolutionError.self) {
            _ = try await kcFailInit.resolveBatch([kc2], context: cliCtx)
        }

        // MockSubprocessRunner: results, scripted, enqueue, enqueueError, setHandler, reset, stdinString
        let rQueue = MockSubprocessRunner(results: [
            SubprocessResult(exitCode: 0, stdout: Data("one".utf8), stderr: Data()),
        ])
        _ = try await rQueue.run(executablePath: "/usr/bin/true", arguments: [], environment: nil, stdin: Data("in".utf8), timeout: .seconds(1))
        #expect(await rQueue.invocations.first?.stdinString == "in")
        #expect(await rQueue.invocationCount == 1)

        let rScripted = MockSubprocessRunner(scripted: [
            .success(SubprocessResult(exitCode: 0, stdout: Data("ok".utf8), stderr: Data())),
        ])
        await rScripted.enqueue(SubprocessResult(exitCode: 0, stdout: Data("two".utf8), stderr: Data()))
        await rScripted.enqueue(exitCode: 1, stdout: "", stderr: "bad")
        await rScripted.enqueueError(POSIXError(.EIO))
        _ = try await rScripted.run(executablePath: "/bin/a", arguments: [], environment: nil, stdin: nil, timeout: nil)
        #expect(await rScripted.invocations.first?.stdinString == nil)
        _ = try await rScripted.run(executablePath: "/bin/b", arguments: [], environment: nil, stdin: nil, timeout: nil)
        let third = try await rScripted.run(executablePath: "/bin/c", arguments: [], environment: nil, stdin: nil, timeout: nil)
        #expect(third.exitCode == 1)
        await #expect(throws: POSIXError.self) {
            _ = try await rScripted.run(executablePath: "/bin/d", arguments: [], environment: nil, stdin: nil, timeout: nil)
        }
        await rScripted.setHandler { inv in
            SubprocessResult(exitCode: 0, stdout: Data(inv.executablePath.utf8), stderr: Data())
        }
        let handled = try await rScripted.run(executablePath: "/bin/dyn", arguments: [], environment: nil, stdin: nil, timeout: nil)
        #expect(handled.stdoutString == "/bin/dyn")
        await rScripted.reset()
        #expect(await rScripted.invocationCount == 0)
    }
}
