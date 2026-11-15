import Foundation
import RiggingCore
import RiggingTesting
import Synchronization
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

private struct SampleEncodedContainer: Codable, Equatable {
    let apiKey: Secret<String>
}

@Suite("Secret<T>, DiagnosticRedactor & EphemeralSecretFile")
struct SecretAndRedactionTests {

    @Test("Secret<T> redacts String(describing:), debugDescription, string interpolation, Mirror, dump, and default JSONEncoder")
    func secretLeakProofRedactionAndExplicitPlaintextEncoding() throws {
        let rawToken = "sk-live-super-secret-99887766"
        let secret = Secret(rawToken)

        #expect(String(describing: secret) == "**********")
        #expect(secret.debugDescription == "**********")
        #expect("Token=\(secret)" == "Token=**********")
        #expect(secret.expose() == rawToken)

        // Mirror has 0 children and dump() contains zero plaintext
        let mirror = Mirror(reflecting: secret)
        #expect(mirror.children.isEmpty)

        var dumped = ""
        dump(secret, to: &dumped)
        #expect(!dumped.contains(rawToken))

        // Default JSONEncoder emits "**********"
        let container = SampleEncodedContainer(apiKey: secret)
        let redactedJSON = try String(decoding: JSONEncoder().encode(container), as: UTF8.self)
        #expect(redactedJSON.contains(#""apiKey":"**********""#))
        #expect(!redactedJSON.contains(rawToken))

        // Explicit opt-in .exposePlaintext emits the underlying plaintext
        let explicitEncoder = JSONEncoder()
        explicitEncoder.userInfo[.secretEncodingPolicy] = SecretEncodingPolicy.exposePlaintext
        let exposedData = try explicitEncoder.encode(container)
        let exposedJSON = String(decoding: exposedData, as: UTF8.self)
        #expect(exposedJSON.contains(rawToken))

        // Decodable round-trip
        let decoded = try JSONDecoder().decode(SampleEncodedContainer.self, from: exposedData)
        #expect(decoded.apiKey.expose() == rawToken)

        // Scoped UTF-8 & byte buffers + map
        let byteLength = secret.withExposedUTF8 { $0.count }
        #expect(byteLength == rawToken.utf8.count)

        let upperSecret = secret.map { $0.uppercased() }
        #expect(String(describing: upperSecret) == "**********")
        #expect(upperSecret.expose() == rawToken.uppercased())

        let dataSecret = Secret(Data([0xDE, 0xAD, 0xBE, 0xEF]))
        #expect(dataSecret.withExposedBytes { Array($0) } == [0xDE, 0xAD, 0xBE, 0xEF])
    }

    @Test("DiagnosticRedactor scrubs secrets >= 6 chars, longest-match first, and individual PEM body lines")
    func diagnosticRedactorScrubbing() {
        let redactor = DiagnosticRedactor(minimumLength: 6)

        // Short strings (< 6 chars) are ignored to avoid false-positive redaction of common words
        redactor.register("short")
        #expect(redactor.registeredPatternCount == 0)
        #expect(redactor.scrub("short token") == "short token")

        // Longest-match-first prevents partial leftover suffixes
        redactor.register("abcdef")
        redactor.register("abcdef123456")
        #expect(redactor.scrub("error with abcdef123456 in stderr") == "error with ********** in stderr")

        // Multiline PEM: scrubs body lines while preserving public armor header/footer
        redactor.register(TestFixtures.sampleP8PEM)
        let singleBodyLine = "eyMaterialForRiggingUnitTests0123456789abcdefABCgYIKoZIzj0DAQehA"
        let leakedLog = """
            Failed to load key:
            -----BEGIN PRIVATE KEY-----
            \(singleBodyLine)
            -----END PRIVATE KEY-----
            """
        let scrubbedLog = redactor.scrub(leakedLog)
        #expect(!scrubbedLog.contains(singleBodyLine))
        #expect(scrubbedLog.contains("-----BEGIN PRIVATE KEY-----"))
        #expect(scrubbedLog.contains("**********"))
        #expect(scrubbedLog.contains("-----END PRIVATE KEY-----"))
    }

    @Test("withEphemeralFile creates 0700 parent dir + atomic 0600 file and cleans up on normal return")
    func withEphemeralFilePermissionsAndNormalCleanup() async throws {
        let secret = Secret(TestFixtures.sampleP8PEM)
        let capturedPaths = Mutex<(dir: String, file: String)?>(nil)

        let returnedByteCount = try await secret.withEphemeralFile(
            prefix: "AuthKey_",
            suffix: ".p8",
            permissions: 0o600
        ) { fileURL in
            let filePath = fileURL.path
            let dirPath = fileURL.deletingLastPathComponent().path
            capturedPaths.withLock { $0 = (dirPath, filePath) }

            #expect(fileURL.lastPathComponent.hasPrefix("AuthKey_"))
            #expect(fileURL.lastPathComponent.hasSuffix(".p8"))

            var dirStat = stat()
            #expect(stat(dirPath, &dirStat) == 0)
            #expect(UInt16(dirStat.st_mode) & 0o777 == 0o700)

            var fileStat = stat()
            #expect(stat(filePath, &fileStat) == 0)
            #expect(UInt16(fileStat.st_mode) & 0o777 == 0o600)

            let diskContents = try String(contentsOf: fileURL, encoding: .utf8)
            #expect(diskContents == TestFixtures.sampleP8PEM)
            return diskContents.utf8.count
        }

        #expect(returnedByteCount == TestFixtures.sampleP8PEM.utf8.count)
        let paths = try #require(capturedPaths.withLock { $0 })
        #expect(!FileManager.default.fileExists(atPath: paths.file))
        #expect(!FileManager.default.fileExists(atPath: paths.dir))
    }

    @Test("withEphemeralFile wipes and removes file + directory even when body throws an error")
    func withEphemeralFileCleanupOnThrownError() async throws {
        struct SimulatedToolFailure: Error, Equatable {}

        let binarySecret = Secret(Data(repeating: 0xAB, count: 256))
        let capturedPaths = Mutex<(dir: String, file: String)?>(nil)

        await #expect(throws: SimulatedToolFailure.self) {
            try await binarySecret.withEphemeralFile(suffix: ".p12", permissions: 0o400) { fileURL in
                let filePath = fileURL.path
                let dirPath = fileURL.deletingLastPathComponent().path
                capturedPaths.withLock { $0 = (dirPath, filePath) }

                var fileStat = stat()
                #expect(stat(filePath, &fileStat) == 0)
                #expect(UInt16(fileStat.st_mode) & 0o777 == 0o400)
                throw SimulatedToolFailure()
            }
        }

        let paths = try #require(capturedPaths.withLock { $0 })
        #expect(!FileManager.default.fileExists(atPath: paths.file))
        #expect(!FileManager.default.fileExists(atPath: paths.dir))

        // Reject unsafe affixes containing '/' or '..'
        await #expect(throws: EphemeralSecretFileError.self) {
            try await binarySecret.withEphemeralFile(prefix: "../escape-") { _ in }
        }
    }
}
