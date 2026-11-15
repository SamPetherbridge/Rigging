import Foundation
#if canImport(Security)
import Security
#endif
import Synchronization
import Testing
import RiggingCore
import RiggingKeychain
import RiggingTesting

@Suite("KeychainProvider Tests")
struct KeychainProviderTests {

    #if canImport(Security)
    private struct CapturedQuery: Sendable, Equatable {
        let secClass: String?
        let service: String?
        let server: String?
        let account: String?
        let accessGroup: String?
        let synchronizable: Bool?
        let returnData: Bool?
        let matchLimit: String?

        init(_ raw: [String: Any]) {
            self.secClass = raw[kSecClass as String] as? String
            self.service = raw[kSecAttrService as String] as? String
            self.server = raw[kSecAttrServer as String] as? String
            self.account = raw[kSecAttrAccount as String] as? String
            self.accessGroup = raw[kSecAttrAccessGroup as String] as? String
            self.synchronizable = raw[kSecAttrSynchronizable as String] as? Bool
            self.returnData = raw[kSecReturnData as String] as? Bool
            self.matchLimit = raw[kSecMatchLimit as String] as? String
        }
    }

    @Test("Builds accurate SecItem query dictionaries for generic & internet passwords, accessGroup, and synchronizable")
    func buildsAccurateSecItemQueries() async throws {
        let captured = Mutex<[CapturedQuery]>([])
        let runner = MockSubprocessRunner()

        let provider = KeychainProvider(
            accessGroup: "DEFAULT.com.example.defaultGroup"
        ) { query in
            let snap = CapturedQuery(query)
            captured.withLock { $0.append(snap) }
            return KeychainBackendResponse(
                status: errSecSuccess,
                data: Data("resolved-\(snap.account ?? "unknown")".utf8)
            )
        }

        let context = SettingsContext.inMemory(
            subprocessRunner: runner,
            secretProviders: [provider]
        )

        let requests = [
            // 1. Standard generic password using provider's default accessGroup
            SecretResolutionRequest(
                keyPath: ["apiKey"],
                rawString: "keychain://com.peth.asc/prod-api-key",
                origin: .projectConfig(path: "/repo/.asc.json", keyPath: ["apiKey"], profile: nil)
            ),
            // 2. Generic password with explicit URI accessGroup and synchronizable=true
            SecretResolutionRequest(
                keyPath: ["syncedSecret"],
                rawString: "keychain://com.peth.asc/icloud-token?accessGroup=TEAM123.com.peth.shared&synchronizable=true",
                origin: .environment(variable: "ASC_SYNCED_SECRET")
            ),
            // 3. Internet password with kind=internet and synchronizable=false
            SecretResolutionRequest(
                keyPath: ["webPassword"],
                rawString: "keychain://api.fastmail.com/sam%40example.com?kind=internet&synchronizable=false",
                origin: .environment(variable: "FASTMAIL_PASSWORD")
            ),
        ]

        let batch = await SecretResolver().resolveAll(requests, context: context)
        #expect(batch.issues.isEmpty)
        #expect(await runner.invocationCount == 0)

        let queries = captured.withLock { $0 }
        #expect(queries.count == 3)

        // Query 1: Generic password + default accessGroup
        #expect(queries[0] == CapturedQuery([
            kSecClass as String: kSecClassGenericPassword as String,
            kSecAttrService as String: "com.peth.asc",
            kSecAttrAccount as String: "prod-api-key",
            kSecAttrAccessGroup as String: "DEFAULT.com.example.defaultGroup",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne as String,
        ]))

        // Query 2: Generic password + overridden accessGroup + synchronizable=true
        #expect(queries[1] == CapturedQuery([
            kSecClass as String: kSecClassGenericPassword as String,
            kSecAttrService as String: "com.peth.asc",
            kSecAttrAccount as String: "icloud-token",
            kSecAttrAccessGroup as String: "TEAM123.com.peth.shared",
            kSecAttrSynchronizable as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne as String,
        ]))

        // Query 3: Internet password + kSecAttrServer + synchronizable=false
        #expect(queries[2] == CapturedQuery([
            kSecClass as String: kSecClassInternetPassword as String,
            kSecAttrServer as String: "api.fastmail.com",
            kSecAttrAccount as String: "sam@example.com",
            kSecAttrAccessGroup as String: "DEFAULT.com.example.defaultGroup",
            kSecAttrSynchronizable as String: false,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne as String,
        ]))

        #expect(try batch.resolvedByKeyPath[["apiKey"]]?.utf8Secret().expose() == "resolved-prod-api-key")
        #expect(try batch.resolvedByKeyPath[["syncedSecret"]]?.utf8Secret().expose() == "resolved-icloud-token")
        #expect(try batch.resolvedByKeyPath[["webPassword"]]?.utf8Secret().expose() == "resolved-sam@example.com")
    }

    @Test("Maps errSecItemNotFound and errSecAuthFailed cleanly to exit code 6")
    func mapsErrSecItemNotFoundToExitCode6() async throws {
        let notFoundProvider = KeychainProvider { _ in
            KeychainBackendResponse(status: errSecItemNotFound, data: nil)
        }
        let context = SettingsContext.inMemory(secretProviders: [notFoundProvider])

        do {
            _ = try await SecretResolver().resolve(
                SecretResolutionRequest(
                    keyPath: ["privateKey"],
                    rawString: "keychain://asc/missing-account",
                    origin: .environment(variable: "ASC_PRIVATE_KEY")
                ),
                context: context
            )
            Issue.record("Expected SettingsValidationError with exitCode 6 for errSecItemNotFound")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 6)
            #expect(error.issues.first?.kind == .providerFailure)
            #expect(error.description.contains("keychain://asc/missing-account"))
        }

        let authFailedProvider = KeychainProvider { _ in
            KeychainBackendResponse(status: errSecAuthFailed, data: nil)
        }
        let authContext = SettingsContext.inMemory(secretProviders: [authFailedProvider])

        do {
            _ = try await SecretResolver().resolve(
                SecretResolutionRequest(
                    keyPath: ["privateKey"],
                    rawString: "keychain://asc/locked-account",
                    origin: .environment(variable: "ASC_PRIVATE_KEY")
                ),
                context: authContext
            )
            Issue.record("Expected SettingsValidationError with exitCode 6 for errSecAuthFailed")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 6)
            #expect(error.issues.first?.kind == .providerFailure)
        }
    }

    @Test("Rejects invalid kind query parameter and leading '-' option-injection payloads")
    func rejectsInvalidKindAndOptionInjection() async throws {
        let provider = KeychainProvider { _ in
            KeychainBackendResponse(status: errSecSuccess, data: Data("unused".utf8))
        }
        let context = SettingsContext.inMemory(secretProviders: [provider])

        do {
            _ = try await SecretResolver().resolve(
                SecretResolutionRequest(
                    keyPath: ["secret"],
                    rawString: "keychain://asc/account?kind=certificate",
                    origin: .environment(variable: "SECRET")
                ),
                context: context
            )
            Issue.record("Expected exitCode 2 for invalid keychain kind")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 2)
            #expect(error.issues.first?.kind == .invalidValue)
        }

        do {
            _ = try await SecretResolver().resolve(
                SecretResolutionRequest(
                    keyPath: ["secret"],
                    rawString: "keychain://-injected/account",
                    origin: .environment(variable: "SECRET")
                ),
                context: context
            )
            Issue.record("Expected exitCode 2 for option-injection segment")
        } catch let error as SettingsValidationError {
            #expect(error.exitCode == 2)
            #expect(error.issues.first?.kind == .invalidValue)
        }
    }
    #endif
}
