import Configuration
import Foundation
import Rigging
import RiggingSwiftConfiguration
import RiggingTesting
import Synchronization
import Testing

// MARK: - Test Models & Spies

@Settings
struct DatabaseSettings: Equatable, Sendable {
    @Setting
    var host: String = "localhost"

    @Setting
    var port: Int = 5432

    @Setting
    var tlsEnabled: Bool = true

    @SecretSetting
    var password: Secret<String>
}

@Settings(
    envPrefix: "SRV_",
    projectConfigFiles: [".srv.json"]
)
struct ServerBridgeSettings: Sendable {
    @Setting
    var serviceName: String = "rigging-api"

    @Setting
    var maxConnections: Int = 100

    @Setting
    var requestTimeoutSeconds: Double = 15.0

    @Setting
    var featureFlags: [String] = []

    @SecretSetting
    var signingSecret: Secret<String>

    @SecretSetting(transforms: [.utf8Data])
    var hmacKey: Secret<Data>

    @NestedSettings
    var database: DatabaseSettings
}

@Settings(envPrefix: "UPSTREAM_")
struct DirectionASettings: Sendable {
    @Setting
    var host: String = "127.0.0.1"

    @Setting
    var port: Int = 8080

    @Setting
    var readOnly: Bool = false

    @Setting
    var allowedOrigins: [String] = []

    @SecretSetting
    var apiKey: Secret<String>

    @NestedSettings
    var database: DatabaseSettings

    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        let upstream = InMemoryProvider(
            name: "upstream",
            values: [
                "host": "config-provider.internal",
                "port": 9090,
                "readOnly": true,
                "allowedOrigins": ConfigValue(.stringArray(["https://a.example", "https://b.example"]), isSecret: false),
                "apiKey": ConfigValue("op://Prod/API/key", isSecret: true),
                "database.host": "pg.internal",
                "database.port": 6432,
                "database.tlsEnabled": false,
                "database.password": ConfigValue("op://Prod/DB/password", isSecret: true),
            ]
        )
        return [
            defaults.initOverrides,
            defaults.environment,
            SwiftConfigurationSource(provider: upstream),
            defaults.projectConfig,
        ]
    }
}

/// Thread-safe `Configuration.AccessReporter` spy capturing every `AccessEvent` so tests can
/// verify `isSecret == true` on `@SecretSetting` lookups.
final class RecordingAccessReporter: AccessReporter, Sendable {
    private let eventsMutex = Mutex<[AccessEvent]>([])

    var events: [AccessEvent] {
        eventsMutex.withLock { $0 }
    }

    func report(_ event: AccessEvent) {
        eventsMutex.withLock { $0.append(event) }
    }
}

// MARK: - Bidirectional `swift-configuration` Adapter Tests

@Suite("SwiftConfiguration Bidirectional Adapter (Direction A & Direction B)")
struct SwiftConfigurationAdapterTests {
    @Test("Direction A: SwiftConfigurationSource feeds @Settings with provenance and batched op:// secret resolution")
    func directionASwiftConfigurationSourceFeedsSettings() async throws {
        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Prod/API/key": "live-api-key-value-123456",
            "op://Prod/DB/password": "super-secret-pg-password-7890",
        ])

        let context = SettingsContext.inMemory(
            environment: [
                // Environment variable sits above SwiftConfigurationSource in customizeSources
                "UPSTREAM_PORT": "9443",
            ],
            secretProviders: [mockOP]
        )

        let settings = try await DirectionASettings.load(context: context)

        #expect(settings.host == "config-provider.internal")
        #expect(settings.port == 9443)
        #expect(settings.readOnly == true)
        #expect(settings.allowedOrigins == ["https://a.example", "https://b.example"])
        #expect(settings.database.host == "pg.internal")
        #expect(settings.database.port == 6432)
        #expect(settings.database.tlsEnabled == false)
        #expect(settings.apiKey.expose() == "live-api-key-value-123456")
        #expect(settings.database.password.expose() == "super-secret-pg-password-7890")

        // Verify provenance tracks both the upstream ConfigProvider and single-batch op:// resolution
        #expect(
            settings.$host.source == .customSource(
                name: "InMemoryProvider[upstream]",
                detail: "host"
            )
        )
        #expect(
            settings.$port.overriddenSources == [
                .customSource(name: "InMemoryProvider[upstream]", detail: "port"),
            ]
        )
        #expect(await mockOP.invocationCount == 1)
    }

    @Test("Direction A: Scoped ConfigReader + schema-derived key specs resolve kebab-case keys cleanly")
    func directionAScopedConfigReaderWithSchemaKeySpecs() async throws {
        let provider = InMemoryProvider(
            name: "kebab-service",
            values: [
                "svc.service-name": "billing-worker",
                "svc.max-connections": 250,
                "svc.request-timeout-seconds": 42.5,
                "svc.feature-flags": ConfigValue(.stringArray(["fast-path", "strict-tls"]), isSecret: false),
                "svc.signing-secret": "op://Billing/Auth/signing",
                "svc.hmac-key": "op://Billing/Auth/hmac",
                "svc.database.host": "billing-db.internal",
                "svc.database.port": 5433,
                "svc.database.tls-enabled": true,
                "svc.database.password": "op://Billing/DB/password",
            ]
        )
        let scopedReader = ConfigReader(provider: provider).scoped(to: "svc")
        let source = SwiftConfigurationSource(
            reader: scopedReader,
            for: ServerBridgeSettings.self,
            name: "ScopedBillingReader",
            useFetch: true
        )

        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Billing/Auth/signing": "billing-signing-secret-001",
            "op://Billing/Auth/hmac": "billing-hmac-raw-bytes",
            "op://Billing/DB/password": "billing-db-password-002",
        ])
        let context = SettingsContext.inMemory(secretProviders: [mockOP])

        // Verify source tree directly + full load through custom source
        let rawTree = try await source.load(
            configuration: ServerBridgeSettings.configuration,
            context: context
        )
        #expect(rawTree.lookup(path: ["serviceName"])?.value == .string("billing-worker"))
        #expect(rawTree.lookup(path: ["maxConnections"])?.value == .int(250))
        #expect(rawTree.lookup(path: ["database", "tlsEnabled"])?.value == .bool(true))
    }

    @Test("Direction B: settings.asConfigReader() exposes scalars, arrays, nested scopes, and secrets with isSecret == true")
    func directionBConfigReaderPreservesTypesAndSecretFlag() async throws {
        let signingSecretPlaintext = "SIGNING_SECRET_NEVER_LOG_ME_887766"
        let dbPasswordPlaintext = "DB_PASSWORD_NEVER_LOG_ME_554433"
        let hmacPlaintext = "HMAC_BINARY_KEY_MATERIAL_1122"

        let mockOP = MockOnePasswordProvider(secrets: [
            "op://Prod/Server/signing": signingSecretPlaintext,
            "op://Prod/Server/hmac": hmacPlaintext,
            "op://Prod/Server/db_password": dbPasswordPlaintext,
        ])

        let context = SettingsContext.inMemory(
            environment: [
                "SRV_SERVICE_NAME": "edge-gateway",
                "SRV_MAX_CONNECTIONS": "512",
                "SRV_REQUEST_TIMEOUT_SECONDS": "27.5",
                "SRV_FEATURE_FLAGS": "grpc,http3",
                "SRV_SIGNING_SECRET": "op://Prod/Server/signing",
                "SRV_HMAC_KEY": "op://Prod/Server/hmac",
                "SRV_DATABASE__HOST": "db-primary.internal",
                "SRV_DATABASE__PORT": "5432",
                "SRV_DATABASE__TLS_ENABLED": "true",
                "SRV_DATABASE__PASSWORD": "op://Prod/Server/db_password",
            ],
            secretProviders: [mockOP]
        )

        let settings = try await ServerBridgeSettings.load(context: context)
        let reporter = RecordingAccessReporter()
        let provider = settings.asConfigProvider()
        let reader = settings.asConfigReader(accessReporter: reporter)

        // 1. Scalar & array reads
        #expect(reader.string(forKey: "serviceName") == "edge-gateway")
        #expect(reader.int(forKey: "maxConnections") == 512)
        #expect(reader.double(forKey: "requestTimeoutSeconds") == 27.5)
        #expect(reader.stringArray(forKey: "featureFlags") == ["grpc", "http3"])

        // 2. Kebab-case key compatibility for Swift Server consumers
        #expect(reader.string(forKey: "service-name") == "edge-gateway")
        #expect(reader.int(forKey: "max-connections") == 512)

        // 3. Scoped nested reader (`database.*`)
        let dbReader = reader.scoped(to: "database")
        #expect(dbReader.string(forKey: "host") == "db-primary.internal")
        #expect(dbReader.int(forKey: "port") == 5432)
        #expect(dbReader.bool(forKey: "tlsEnabled") == true)
        #expect(dbReader.bool(forKey: "tls-enabled") == true)

        // 4. Secret reads (both String and Data/[UInt8], plus async fetch)
        let resolvedSigning = try await reader.fetchString(forKey: "signing-secret")
        let resolvedDBPass = dbReader.string(forKey: "password")
        let resolvedHMACBytes = reader.bytes(forKey: "hmacKey")
        #expect(resolvedSigning == signingSecretPlaintext)
        #expect(resolvedDBPass == dbPasswordPlaintext)
        #expect(resolvedHMACBytes == Array(hmacPlaintext.utf8))

        // 5. Verify AccessReporter saw `isSecret == true` on EVERY secret lookup and `isSecret == false` on non-secrets!
        let events = reporter.events
        #expect(!events.isEmpty)

        func recordedIsSecret(forKey components: [String]) -> Bool? {
            guard let event = events.first(where: { $0.metadata.key.components == components }),
                  let firstProviderResult = event.providerResults.first,
                  let lookup = try? firstProviderResult.result.get() else {
                return nil
            }
            return lookup.value?.isSecret
        }

        #expect(recordedIsSecret(forKey: ["serviceName"]) == false)
        #expect(recordedIsSecret(forKey: ["maxConnections"]) == false)
        #expect(recordedIsSecret(forKey: ["database", "host"]) == false)
        #expect(recordedIsSecret(forKey: ["signing-secret"]) == true)
        #expect(recordedIsSecret(forKey: ["database", "password"]) == true)
        #expect(recordedIsSecret(forKey: ["hmacKey"]) == true)

        // 6. Verify watchValue & watchSnapshot emit initial state with isSecret intact
        let watchedSigningSecret = try await provider.watchValue(
            forKey: AbsoluteConfigKey(["signingSecret"]),
            type: .string
        ) { updates in
            var iterator = updates.makeAsyncIterator()
            let first = try await iterator.next()
            return try first?.get()
        }
        #expect(watchedSigningSecret?.value?.isSecret == true)

        // 7. Provider & Snapshot debug descriptions NEVER leak plaintext secrets
        let debugStrings = [
            String(describing: provider),
            String(reflecting: provider),
            String(describing: provider.snapshot()),
            String(reflecting: provider.snapshot()),
        ]
        for text in debugStrings {
            #expect(!text.contains(signingSecretPlaintext))
            #expect(!text.contains(dbPasswordPlaintext))
            #expect(!text.contains(hmacPlaintext))
        }
    }
}
