import Foundation
import RiggingCore
import RiggingTesting
import Synchronization
import Testing

@Suite("SecretReference, Batched SecretResolver, TTL Cache, Transforms & File Permissions")
struct SecretResolutionTests {

    @Test("SecretReference parses valid URIs and rejects option-injection ('-', '%2D', NUL, control chars, '..')")
    func secretReferenceParsingAndOptionInjectionRejection() throws {
        // Valid references across supported schemes
        let op = try SecretReference.parse("op://Engineering/ASC%20Key/Credentials/private_key?account=work")
        #expect(op.scheme == "op")
        #expect(op.accountHint == "work")
        #expect(op.redactedDescription == "op://Engineering/ASC Key/Credentials/private_key")

        let kc = try SecretReference.parse("keychain://com.example.asc/default?accessGroup=TEAM.group&synchronizable=true")
        #expect(kc.scheme == "keychain")
        if case .keychain(let kcRef) = kc {
            #expect(kcRef.service == "com.example.asc")
            #expect(kcRef.account == "default")
            #expect(kcRef.accessGroup == "TEAM.group")
            #expect(kcRef.synchronizable == true)
        } else {
            Issue.record("Expected .keychain case")
        }

        let atFile = try SecretReference.parse("@~/.keys/AuthKey.p8")
        #expect(atFile.scheme == "file")
        #expect(atFile.redactedDescription == "@~/.keys/AuthKey.p8")

        let literal = try SecretReference.parse("sk-live-literal-secret")
        #expect(literal.isLiteral)
        #expect(literal.redactedDescription == "<literal>")

        // Option-injection rejection: leading '-' or percent-encoded '%2D'
        for unsafeURI in [
            "op://-vault/item/field",
            "op://vault/-item/field",
            "op://%2Dvault/item/field",
            "op://vault/item/field?account=-evil",
            "keychain://-service/account",
            "bws://--help",
            "bw://-item/password",
            "pass://work/-flag",
            "pass://work/entry#-flag",
            "sops://-flag.json#/key",
            "file:///-bad/secret.txt",
        ] {
            let err = #expect(throws: SecretReferenceError.self) {
                try SecretReference.parse(unsafeURI)
            }
            if case .optionInjection = err {
                // Expected
            } else {
                Issue.record("Expected .optionInjection for \(unsafeURI), got \(String(describing: err))")
            }
        }

        // Embedded NUL bytes ('\0' and '%00')
        #expect(throws: SecretReferenceError.containsNullByte) {
            try SecretReference.parse("op://vault/item\0/field")
        }
        #expect(throws: SecretReferenceError.containsNullByte) {
            try SecretReference.parse("op://vault/item%00/field")
        }

        // Path traversal in pass://
        #expect(throws: SecretReferenceError.self) {
            try SecretReference.parse("pass://vault/../etc/passwd")
        }
    }

    @Test("SecretResolver deduplicates op:// references and executes a single batch per (scheme, accountHint)")
    func singleBatchResolutionAndDeduplication() async throws {
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Eng/ASC/key_id": "XYZ9876543",
            "op://Eng/ASC/private_key": TestFixtures.sampleP8PEM,
            "op://Eng/Signing/cert_pass": "p12-passphrase-secret",
        ])
        let mockKC = MockKeychainProvider(secrets: [
            "keychain://asc/webhook_secret": "whsec_abcdef123456",
        ])

        let context = SettingsContext.inMemory(secretProviders: [mockOP, mockKC])
        let requests: [SecretResolutionRequest] = [
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
            // Duplicate URI on another field — must be deduplicated before calling provider!
            SecretResolutionRequest(
                keyPath: ["backupKeyId"],
                rawString: "op://Eng/ASC/key_id",
                origin: .environment(variable: "ASC_BACKUP_KEY_ID")
            ),
            SecretResolutionRequest(
                keyPath: ["signing", "certificatePassword"],
                rawString: "op://Eng/Signing/cert_pass",
                origin: .projectConfig(path: "/repo/.asc.json", keyPath: ["signing", "certificatePassword"], profile: nil)
            ),
            SecretResolutionRequest(
                keyPath: ["webhookSecret"],
                rawString: "keychain://asc/webhook_secret",
                origin: .userConfig(path: "/Users/test/.config/asc/config.json", keyPath: ["webhookSecret"], profile: nil)
            ),
        ]

        let result = await SecretResolver().resolveAll(requests, context: context)
        #expect(result.issues.isEmpty)
        #expect(result.resolved.count == 5)

        // All 4 fields referencing 3 unique op:// URIs resolved in ONE batch invocation!
        #expect(await mockOP.invocationCount == 1)
        let batches = await mockOP.batchHistory
        #expect(batches.count == 1)
        #expect(batches[0].count == 3)

        #expect(await mockKC.invocationCount == 1)

        let resolvedKeyId = try #require(result.resolvedByKeyPath[["keyId"]])
        #expect(try resolvedKeyId.utf8Secret().expose() == "XYZ9876543")
        #expect(
            resolvedKeyId.origin == .secretProvider(
                scheme: "op",
                referenceRedacted: "op://Eng/ASC/key_id",
                via: .projectConfig(path: "/repo/.asc.json", keyPath: ["auth", "keyId"], profile: nil)
            )
        )
    }

    @Test("SecretResolutionCache serves cached hits within TTL and re-fetches after TTL expiry")
    func secretResolutionCacheHitAndExpiry() async throws {
        let clockNow = Mutex(ContinuousClock.now)
        let cache = SecretResolutionCache(
            ttl: .seconds(60),
            now: { clockNow.withLock { $0 } }
        )
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Eng/ASC/api_token": "cached-token-value-123"
        ])
        let context = SettingsContext.inMemory(
            secretProviders: [mockOP],
            secretCache: cache
        )
        let req = SecretResolutionRequest(
            keyPath: ["apiToken"],
            rawString: "op://Eng/ASC/api_token",
            origin: .environment(variable: "ASC_API_TOKEN")
        )

        // First resolution misses cache -> invokes provider (count == 1)
        let first = try await SecretResolver().resolve(req, context: context)
        #expect(try first.utf8Secret().expose() == "cached-token-value-123")
        #expect(await mockOP.invocationCount == 1)

        // Advance 30s (< 60s TTL) -> cache hit, provider NOT invoked again!
        clockNow.withLock { $0 = $0.advanced(by: .seconds(30)) }
        let second = try await SecretResolver().resolve(req, context: context)
        #expect(try second.utf8Secret().expose() == "cached-token-value-123")
        #expect(await mockOP.invocationCount == 1)

        // Advance another 31s (61s total > 60s TTL) -> cache expired, provider invoked (count == 2)
        clockNow.withLock { $0 = $0.advanced(by: .seconds(31)) }
        await mockOP.setSecret("rotated-token-value-456", for: "op://Eng/ASC/api_token")
        let third = try await SecretResolver().resolve(req, context: context)
        #expect(try third.utf8Secret().expose() == "rotated-token-value-456")
        #expect(await mockOP.invocationCount == 2)
    }

    @Test("SecretTransform pipeline: .expandFileReference, .decodeBase64IfPrefixed, and .normalizePEM")
    func secretTransformPipeline() async throws {
        let context = SettingsContext.inMemory(
            files: [
                "/Users/test/.keys/AuthKey.p8": "  \(TestFixtures.samplePrefixedBase64P8PEM) \n"
            ],
            filePermissions: [
                "/Users/test/.keys/AuthKey.p8": 0o600
            ],
            homeDirectory: "/Users/test"
        )

        let pipeline: [SecretTransform] = [
            .expandFileReference(requirePermissions: 0o600),
            .decodeBase64IfPrefixed,
            .normalizePEM,
        ]

        // 1. Custom literal token '@Users/...' (without '~/') expanded via .expandFileReference + base64 + PEM
        let fileReq = SecretResolutionRequest(
            keyPath: ["privateKey"],
            rawString: "@/Users/test/.keys/AuthKey.p8",
            origin: .projectConfig(path: "/repo/.asc.json", keyPath: ["privateKey"], profile: nil),
            transforms: pipeline
        )
        let resolvedFromFile = try await SecretResolver().resolve(fileReq, context: context)
        #expect(try resolvedFromFile.utf8Secret().expose() == TestFixtures.sampleP8PEM)

        // 2. Escaped single-line PEM in environment variable normalized to clean multiline PEM
        let escapedReq = SecretResolutionRequest(
            keyPath: ["privateKey"],
            rawString: TestFixtures.sampleEscapedP8PEM,
            origin: .environment(variable: "ASC_PRIVATE_KEY"),
            transforms: pipeline
        )
        let resolvedFromEscaped = try await SecretResolver().resolve(escapedReq, context: context)
        #expect(try resolvedFromEscaped.utf8Secret().expose() == TestFixtures.sampleP8PEM)

        // 3. Base64-prefixed PEM in environment variable decoded & normalized
        let b64Req = SecretResolutionRequest(
            keyPath: ["privateKey"],
            rawString: TestFixtures.samplePrefixedBase64P8PEM,
            origin: .environment(variable: "ASC_PRIVATE_KEY_B64"),
            transforms: pipeline
        )
        let resolvedFromB64 = try await SecretResolver().resolve(b64Req, context: context)
        #expect(try resolvedFromB64.utf8Secret().expose() == TestFixtures.sampleP8PEM)

        // 4. Secret file whose plaintext starts with '@' is NOT double-expanded by .expandFileReference
        let atPrefixedSecretContext = SettingsContext.inMemory(
            files: ["/Users/test/.keys/pass.secret": "@ppleSuperSecretPass!"],
            filePermissions: ["/Users/test/.keys/pass.secret": 0o600],
            homeDirectory: "/Users/test"
        )
        let atPrefixedReq = SecretResolutionRequest(
            keyPath: ["password"],
            rawString: "@~/.keys/pass.secret",
            origin: .projectConfig(path: "/repo/.asc.json", keyPath: ["password"], profile: nil),
            transforms: [.expandFileReference(requirePermissions: 0o600)]
        )
        let resolvedAtPrefixed = try await SecretResolver().resolve(atPrefixedReq, context: atPrefixedSecretContext)
        #expect(try resolvedAtPrefixed.utf8Secret().expose() == "@ppleSuperSecretPass!")
    }

    @Test("allowLiteralInProjectConfig: false rejects repo-committed plaintext with exit code 4 while scrubbing value")
    func repoCommittedLiteralGuardExitCode4() async throws {
        let leakedKey = "sk-live-committed-in-git-999999"
        let context = SettingsContext.inMemory()
        let request = SecretResolutionRequest(
            keyPath: ["apiKey"],
            rawString: leakedKey,
            origin: .projectConfig(path: "/repo/.asc.json", keyPath: ["apiKey"], profile: nil),
            allowLiteralInProjectConfig: false
        )

        let error = await #expect(throws: SettingsValidationError.self) {
            try await SecretResolver().resolve(request, context: context)
        }
        let unwrapped = try #require(error)
        #expect(unwrapped.exitCode == 4)
        #expect(unwrapped.issues.first?.kind == .unsafeSecret)
        #expect(!unwrapped.description.contains(leakedKey))
        #expect(context.redactor.scrub("leaked: \(leakedKey)") == "leaked: **********")

        // Same literal in .environment is allowed
        let envReq = SecretResolutionRequest(
            keyPath: ["apiKey"],
            rawString: leakedKey,
            origin: .environment(variable: "ASC_API_KEY"),
            allowLiteralInProjectConfig: false
        )
        let allowed = try await SecretResolver().resolve(envReq, context: context)
        #expect(try allowed.utf8Secret().expose() == leakedKey)
    }

    @Test("FileSecretProvider rejects 0644 secret file with exit code 4 and 'Fix: chmod 600 <path>'")
    func insecureFilePermissionsExitCode4AndRemediation() async throws {
        let keyPath = "/Users/test/.keys/AuthKey.p8"
        let context = SettingsContext.inMemory(
            files: [keyPath: TestFixtures.sampleP8PEM],
            filePermissions: [keyPath: 0o644],
            homeDirectory: "/Users/test"
        )

        let request = SecretResolutionRequest(
            keyPath: ["privateKey"],
            rawString: "@~/.keys/AuthKey.p8",
            origin: .projectConfig(path: "/repo/.asc.json", keyPath: ["auth", "privateKey"], profile: nil)
        )

        let error = await #expect(throws: SettingsValidationError.self) {
            try await SecretResolver().resolve(request, context: context)
        }
        let unwrapped = try #require(error)
        #expect(unwrapped.exitCode == 4)
        let issue = try #require(unwrapped.issues.first)
        #expect(issue.kind == .unsafeSecret)
        #expect(issue.message.contains("0644"))
        #expect(issue.remediation == "Fix: chmod 600 /Users/test/.keys/AuthKey.p8")
        #expect(unwrapped.description.contains("Fix: chmod 600 /Users/test/.keys/AuthKey.p8"))
    }

    @Test("Executable trust checks reject relative paths and world-writable binaries")
    func executableTrustVerification() throws {
        let fs = InMemoryFileSystem(
            permissions: ["/usr/local/bin/world_writable_op": 0o777],
            executables: ["/opt/homebrew/bin/op", "/usr/local/bin/world_writable_op"]
        )

        // Trusted binary succeeds
        let resolved = try ProcessSubprocessRunner.resolveTrustedExecutable(named: "op", fileSystem: fs)
        #expect(resolved == "/opt/homebrew/bin/op")

        // Relative path './op' is rejected
        #expect(throws: SubprocessSecurityError.relativeExecutablePath("./op")) {
            try ProcessSubprocessRunner.verifyExecutableTrust(atPath: "./op", fileSystem: fs)
        }

        // World-writable 0777 binary is rejected
        #expect(
            throws: SubprocessSecurityError.worldWritableExecutable(
                path: "/usr/local/bin/world_writable_op",
                permissions: 0o777
            )
        ) {
            try ProcessSubprocessRunner.verifyExecutableTrust(
                atPath: "/usr/local/bin/world_writable_op",
                fileSystem: fs
            )
        }
    }
}
