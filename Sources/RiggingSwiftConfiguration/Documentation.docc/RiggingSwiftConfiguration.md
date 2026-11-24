# ``RiggingSwiftConfiguration``

Bidirectional interoperability between Rigging `@Settings` models and Apple's `swift-configuration` (`ConfigProvider`, `ConfigSnapshot`, and `ConfigReader`).

## Overview

`RiggingSwiftConfiguration` connects Rigging's declarative application-level `@Settings` models, exhaustive startup validation, and batched secret hygiene with Apple's `apple/swift-configuration` provider abstraction in both directions:

1. **Direction A (Upstream `ConfigProvider` / `ConfigReader` → Rigging):** Wrap any `ConfigProvider`, `ConfigReader`, or `[AbsoluteConfigKey: ConfigValue]` snapshot in ``SwiftConfigurationSource`` so remote config stores, feature-flag providers, or `InMemoryProvider` participate in Rigging's source precedence, `op://` / `keychain://` secret resolution, schema validation, and `$field` provenance.
2. **Direction B (Rigging `@Settings` → Downstream `ConfigProvider` / `ConfigReader`):** Call `settings.asConfigProvider()` or `settings.asConfigReader()` on any loaded `RiggedSettings` value to hand a standard `Configuration.ConfigReader` to Hummingbird, gRPC Swift, or ServiceLifecycle components—automatically preserving `isSecret: true` on every `@SecretSetting` field.

### Exposing Rigging Settings as a `ConfigReader`

```swift
import Configuration
import Rigging
import RiggingSwiftConfiguration

let settings = try await AppSettings.load()
let reader = settings.asConfigReader()

// Supports canonical camelCase as well as idiomatic kebab-case and snake_case keys:
let host = reader.string(forKey: "http.bind-host", default: "127.0.0.1")
```

### Consuming a `swift-configuration` Provider in Rigging

```swift
import Configuration
import Rigging
import RiggingSwiftConfiguration

@Settings(envPrefix: "APP_")
struct AppSettings: Sendable {
    @Setting var maxConnections: Int = 32
    @SecretSetting var apiToken: Secret<String>

    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        [
            defaults.initOverrides,
            defaults.environment,
            SwiftConfigurationSource(
                provider: InMemoryProvider(values: [
                    "max-connections": 128,
                    "api-token": "op://Infra/API/token",
                ]),
                for: Self.self
            ),
        ]
    }
}
```

## Topics

### Consuming `swift-configuration` in Rigging

- ``SwiftConfigurationSource``
- ``SwiftConfigurationKeySpec``

### Exposing Rigging to `swift-configuration`

- ``RiggingConfigProvider``
- ``RiggingConfigSnapshot``
- ``RiggingConfigProviderError``
