# Contributing to Rigging

Thank you for contributing to `Rigging`! This guide covers package architecture boundaries, local verification commands, extending `Rigging` with new sources and secret providers, documentation standards, and commit conventions.

---

## Architecture & Dependency Boundaries

`Rigging` is partitioned into focused SwiftPM products so CLI tools, mobile apps, and server services pay only for the dependencies they actually link:

```
Rigging (Umbrella: @_exported RiggingCore + Macro declarations)
 ├── RiggingMacros            (swift-syntax compiler plugin — build-time only)
 └── RiggingCore              (Foundation ONLY — zero external dependencies)
      ├── RiggingOnePassword  (RiggingCore + Foundation / FoundationNetworking)
      ├── RiggingKeychain     (RiggingCore + Apple Security.framework)
      ├── RiggingBitwarden    (RiggingCore)
      ├── RiggingUnixPass     (RiggingCore — pass & SOPS)
      ├── RiggingTOML         (RiggingCore — zero external dependencies, pure-Swift TOML 1.0)
      ├── RiggingYAML         (RiggingCore + Yams)
      ├── RiggingArgumentParser     (RiggingCore + swift-argument-parser)
      ├── RiggingSwiftConfiguration (RiggingCore + apple/swift-configuration)
      └── RiggingTesting      (RiggingCore — hermetic mocks & in-memory runtime)
```

### Non-Negotiable Rules
1. **`RiggingCore` and `RiggingTOML` are strictly zero-dependency:** Never add external packages to `RiggingCore` or `RiggingTOML`. Any integration requiring an external parser, SDK, or framework belongs in an existing or new satellite target.
2. **Strict Swift 6 Concurrency:** Every target builds under `swift-tools-version: 6.2` with complete `Sendable` checking. Prefer value types, `actor`s, or `Synchronization.Mutex` over `@unchecked Sendable`.
3. **Zero-Warning Policy:** All targets and tests must compile with zero warnings under `-Xswiftc -warnings-as-errors` on both macOS and Linux (`Glibc` and `Musl`).
4. **Hermetic Tests Only:** Never read/write the host user's real `$HOME`, login Keychain, or live `op` / `bw` / `pass` CLIs in tests. Use `RiggingTesting` (`SettingsContext.inMemory(...)`, `InMemoryFileSystem`, `MockSubprocessRunner`, `MockOnePasswordProvider`, `MockKeychainProvider`).

---

## Local Development & Pre-Push Verification

`Rigging` enforces all build, test, and documentation gates locally via a tracked Git `pre-push` hook (`.githooks/pre-push`) rather than GitHub Actions CI.

### Prerequisites
- **Swift 6.2+** (Xcode 26+ on macOS 15+, or `swift:6.2-noble` on Ubuntu 24.04)

### Enable the Local `pre-push` Hook
After cloning the repository, install the tracked Git hooks once:

```bash
./scripts/install-hooks.sh
```

This configures `git config core.hooksPath .githooks` so every `git push` automatically verifies zero-warning compilation, the full parallel `Swift Testing` suite, and multi-module DocC generation across all 11 library targets. You can also run the full gate manually at any time:

```bash
./.githooks/pre-push </dev/null
```

*(In an emergency, set `RIGGING_SKIP_PRE_PUSH=1` to bypass the hook for a single push.)*

### 1. Strict Zero-Warning Build
```bash
swift build --build-tests -Xswiftc -warnings-as-errors
```

### 2. Run `Swift Testing` Suite with Coverage
```bash
swift test --parallel --enable-code-coverage
```

Inspect per-module coverage on macOS:
```bash
BIN_PATH=$(swift build --show-bin-path)
PROFDATA="$BIN_PATH/codecov/default.profdata"
TEST_BIN=$(find "$BIN_PATH" -name "*PackageTests.xctest" -exec find {} -path "*/Contents/MacOS/*" \; | head -n 1)
xcrun llvm-cov report "$TEST_BIN" -instr-profile="$PROFDATA" -ignore-filename-regex='\.build|Tests'
```

### 3. Build & Validate DocC Archives (`--warnings-as-errors`)
Every `public` symbol across all 11 library products must have a complete `///` DocC comment following Apple's *API Design Guidelines* (third-person declarative summary sentence, discussion/code snippet where helpful, and `- Parameter` / `- Returns` / `- Throws` callouts) and be curated in its module's `Documentation.docc` catalog:

```bash
mkdir -p /tmp/docc
swift package --allow-writing-to-directory /tmp/docc \
  generate-documentation \
  --target Rigging \
  --target RiggingCore \
  --target RiggingOnePassword \
  --target RiggingKeychain \
  --target RiggingBitwarden \
  --target RiggingUnixPass \
  --target RiggingArgumentParser \
  --target RiggingSwiftConfiguration \
  --target RiggingTOML \
  --target RiggingYAML \
  --target RiggingTesting \
  --warnings-as-errors \
  --output-path /tmp/docc
```

---

## Adding a New `SecretProvider`

1. Conform a `Sendable` struct or actor to `SecretProvider` (`RiggingCore`):
   ```swift
   import Foundation
   import RiggingCore

   public struct VaultProvider: SecretProvider, Sendable {
       public let supportedSchemes: Set<String> = ["vault"]

       public init() {}

       public func resolveBatch(
           _ references: [SecretReference],
           context: SettingsContext
       ) async throws -> [SecretReference: Data] {
           var resolved: [SecretReference: Data] = [:]
           for reference in references {
               // 1. Validate URI segments against leading `-`, NUL bytes, and `..` traversal.
               // 2. Fetch secret bytes in a single batched network/IPC call where possible.
               // 3. Register resolved bytes in `context.redactor` immediately!
               let secretBytes = Data()
               context.redactor.register(secretBytes)
               resolved[reference] = secretBytes
           }
           return resolved
       }
   }

   extension SecretProvider where Self == VaultProvider {
       public static func vault() -> VaultProvider { VaultProvider() }
   }
   ```
2. Map failures to `SecretResolutionError` (`exitCode = 6` for provider/auth/missing-item errors; `exitCode = 4` for unsafe permissions) and scrub any raw error strings with `context.redactor.scrub(...)`.
3. If invoking a subprocess, always resolve the binary via `ProcessSubprocessRunner.resolveTrustedExecutable(...)` and `context.subprocessRunner.run(...)` — never `/bin/sh -c`.

---

## Adding a New `SettingsSource`

1. Conform a `Sendable` struct to `SettingsSource` (`RiggingCore`) and populate a `RawConfigTree` with accurate `SettingOrigin` metadata:
   ```swift
   import RiggingCore

   public struct ConsulKVSource: SettingsSource, Sendable {
       public let prefix: String

       public init(prefix: String) {
           self.prefix = prefix
       }

       public func load(
           configuration: SettingsConfiguration,
           context: SettingsContext
       ) async throws -> RawConfigTree {
           var tree = RawConfigTree()
           tree.set(
               path: ["database", "host"],
               value: .string("db.internal"),
               origin: .customSource(name: "consul", detail: "\(prefix)/database/host"),
               caseSensitive: configuration.caseSensitive
           )
           return tree
       }
   }
   ```
2. Consumers wire custom sources into any `@Settings` or `@Rigged` model via `static func customizeSources(_ defaults: DefaultSources) -> [any SettingsSource]`.

---

## Commit & Pull Request Conventions

We follow [Gitmoji](https://gitmoji.dev/) commit conventions:

```
<emoji> <imperative subject, 50 chars or less> (Closes #<issue>)

Optional body explaining *why*, wrapped at 72 characters.
```

Common prefixes:
- `✨` New feature (`✨ Add HashiCorp Vault secret provider`)
- `🐛` Bug fix (`🐛 Preserve escaped quotes in DotEnvParser`)
- `♻️` Refactoring without behavior change
- `📝` Documentation / DocC updates
- `✅` Adding or updating `Swift Testing` suites
- `🔒` Security hardening
- `🔧` Build / Git hook configuration updates
