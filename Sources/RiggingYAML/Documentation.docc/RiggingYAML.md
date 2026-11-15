# ``RiggingYAML``

Load YAML 1.2 project, user, and custom configuration files with anchors, merge keys, and profile overlays.

## Overview

`RiggingYAML` integrates `Yams` into Rigging's configuration cascade, providing drop-in YAML
equivalents for project, user XDG, and explicit file sources. It supports `.yml` and `.yaml`
extensions, YAML anchors and `*alias` references, `<<` merge keys, ISO 8601 timestamp normalization,
named `profiles:` overlays, and full provenance and secret-guard integration.

```swift
import Rigging
import RiggingYAML

@Settings(
    envPrefix: "APP_",
    projectConfigFiles: [".myapp.yml", ".myapp.yaml"],
    xdgAppName: "myapp",
    extraKeys: .forbid
)
struct ServiceSettings: Sendable {
    @Setting var endpoint: String = "https://api.example.com"
    @Setting var maxRetries: Int = 3
    @SecretSetting var webhookSecret: Secret<String>

    static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource] {
        [
            defaults.initOverrides,
            defaults.environment,
            defaults.dotEnv,
            YAMLProjectConfigSource(),
            YAMLUserConfigSource(),
        ]
    }
}
```

### Anchors, Merge Keys, and Profiles

`RiggingYAML` resolves YAML `<<` merge keys before stripping root `"$schema"` and `"profiles"`
metadata and overlaying the active profile:

```yaml
$schema: https://schemas.example.com/myapp.schema.json
endpoint: https://us.api.example.com
maxRetries: 5
webhookSecret: op://Engineering/MyApp/webhook_secret

profiles:
  eu:
    endpoint: https://eu.api.example.com
```

## Topics

### Configuration Sources

- ``YAMLFileSource``
- ``YAMLFileSettingsSource``
- ``YAMLProjectConfigSource``
- ``YAMLUserConfigSource``
- ``YAMLSourceOriginStyle``
