# ``RiggingTOML``

Load TOML v1.0 project, user, and custom configuration files with zero external dependencies.

## Overview

`RiggingTOML` provides a pure-Swift, RFC-compliant TOML v1.0.0 parser alongside drop-in
`SettingsSource` implementations that mirror Rigging's built-in JSON configuration sources.
Every loaded setting preserves exact file-path, key-path, and named-profile provenance,
participates in two-phase batched secret resolution (such as `"op://..."` or `"keychain://..."`
references stored in `.toml` files), and enforces Rigging's repo-committed plaintext secret guard
when loaded via ``TOMLProjectConfigSource``.

```swift
import Rigging
import RiggingTOML

@Settings(
    envPrefix: "APP_",
    projectConfigFiles: [".myapp.toml"],
    xdgAppName: "myapp",
    extraKeys: .forbid
)
struct AppSettings: Sendable {
    @Setting var host: String = "127.0.0.1"
    @Setting var port: Int = 8080
    @SecretSetting var apiToken: Secret<String>

    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        [
            defaults.initOverrides,
            defaults.environment,
            defaults.dotEnv,
            TOMLProjectConfigSource(),
            TOMLUserConfigSource(),
        ]
    }
}
```

### Named Profile Overlays

Like `ProjectConfigSource` and `UserConfigSource`, all `RiggingTOML` sources automatically strip
root `"$schema"` and `"profiles"` metadata keys and deep-merge `[profiles.<name>]` over top-level
keys whenever an active profile is selected via `--profile`, `<ENV_PREFIX>PROFILE`, or
`SettingsConfiguration.profile`:

```toml
host = "prod.internal"
port = 8_443
apiToken = "op://Engineering/MyApp/api_token"

[profiles.staging]
host = "staging.internal"
```

## Topics

### Configuration Sources

- ``TOMLFileSource``
- ``TOMLFileSettingsSource``
- ``TOMLProjectConfigSource``
- ``TOMLUserConfigSource``
- ``TOMLSourceOriginStyle``

### TOML v1.0 Parser & AST

- ``TOMLParser``
- ``TOMLValue``
- ``TOMLParseError``
