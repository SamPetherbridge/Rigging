# Rigging — Technical Specification

Rigging is a Swift 6 typed configuration, validation, provenance, and leak-proof secret management framework inspired by `pydantic-settings`, built natively for Swift CLIs, daemons, server applications, and Apple platform apps.

---

## 1. Design Goals

1. **Declarative Macro Ergonomics:** Define typed, immutable `Sendable` configuration models with `@Settings`, `@Setting`, `@SecretSetting`, and `@NestedSettings`.
2. **Deterministic Source Cascade & Full Provenance:** Layer CLI overrides, environment variables, `.env` files, container secret directories, project config files, user XDG config files, and macOS managed preferences while tracking the exact `SettingOrigin` and shadowed `overriddenOrigins` for every resolved key.
3. **Leak-Proof Secrets by Construction:** Wrap sensitive values in `Secret<T>` (`CustomStringConvertible`, `CustomDebugStringConvertible`, `CustomReflectable`, and default `Encodable` all emit `"**********"`), scrub resolved plaintext from diagnostics via `DiagnosticRedactor`, enforce `0600` file permissions and repo-committed plaintext guards, and materialize ephemeral files atomically with `0700`/`0600` POSIX modes and zero-overwrite cleanup.
4. **Two-Phase Batched Secret Resolution:** Deduplicate secret URIs (`op://`, `keychain://`, `bws://`, `bw://`, `pass://`, `file://`, `@path`, `env://`) across the entire configuration tree and resolve each `(scheme, accountHint)` batch in a single provider call.
5. **Exhaustive Multi-Issue Validation & Exit Code Taxonomy:** Accumulate all missing, invalid, unknown-key, cross-field, unsafe-secret, and provider errors in one pass with deterministic human and JSON diagnostics:
   - Exit code `2`: Missing required setting, type/validator failure, forbidden extra key, or cross-field validation failure.
   - Exit code `4`: Unsafe secret storage (repo-committed plaintext secret in project config or group/world-accessible secret file).
   - Exit code `6`: Secret provider failure (authentication error, timeout, missing item, or untrusted provider binary).

---

## 2. Package Architecture

| Target | Dependencies | Role |
|---|---|---|
| `RiggingCore` | Foundation only (zero external deps) | Core protocols, `RawConfigTree`, `ValueDecoding`, built-in sources, `Secret<T>`, `SecretResolver`, `DiagnosticRedactor`, validators, `SettingsWatcher`, JSON Schema & `.env` exporters |
| `RiggingMacros` | `swift-syntax` | Compiler plugin implementing `@Settings`, `@Setting`, `@SecretSetting`, `@NestedSettings` |
| `Rigging` | `RiggingCore`, `RiggingMacros` | Primary umbrella module |
| `RiggingOnePassword` | `RiggingCore` | Batched 1Password (`op://`) secret provider (`op inject` / `op read`) |
| `RiggingKeychain` | `RiggingCore` | Apple Security framework Keychain (`keychain://`) provider |
| `RiggingBitwarden` | `RiggingCore` | Bitwarden Secrets Manager (`bws://`) & Vault (`bw://`) provider |
| `RiggingUnixPass` | `RiggingCore` | `pass` (`pass://`) secret provider |
| `RiggingArgumentParser` | `RiggingCore`, `ArgumentParser` | Non-clobbering CLI flag bridging for `swift-argument-parser` |
| `RiggingSwiftConfiguration` | `RiggingCore`, `Configuration` | Bidirectional adapter for `apple/swift-configuration` |
| `RiggingTOML` | `RiggingCore` | Pure-Swift TOML 1.0 parser and `TOMLFileSource` |
| `RiggingYAML` | `RiggingCore`, `Yams` | YAML configuration source (`YAMLFileSource`) |
| `RiggingTesting` | `RiggingCore` | In-memory `FileSystem`, mock `SubprocessRunner`, and fake `SecretProvider`s |

---

## 3. Precedence Cascade

Default source order (highest to lowest priority):

1. **`InitSource`** — Explicit programmatic overrides and non-nil CLI arguments (`.cliArgument` / `.initOverride`)
2. **`EnvironmentSource`** — Process environment (`envPrefix`, `envNestedDelimiter`, `envNestedMaxSplit`, `envIgnoreEmpty`, `envNullStrings`)
3. **`DotEnvSource`** — `.env` files in order (later files override earlier files, RFC quoting + `${VAR}` expansion + multiline PEM)
4. **`SecretsDirSource`** — `/run/secrets` style mounted secret files (`trimSecretTrailingNewline`, `secretsNestedSubdir`)
5. **`ProjectConfigSource`** — Project config files discovered upward to `.git` or `$HOME` boundary, with named `"profiles"` overlay
6. **`UserConfigSource`** — `$XDG_CONFIG_HOME/<app>/config.json` / `~/.config/<app>/config.json` (plus macOS Application Support fallback)
7. **`ManagedPreferencesSource`** — Enterprise MDM `CFPreferences` on macOS
8. **Declared Swift Property Defaults** (`.defaultValue`)

---

## 4. Security Hardening

- **No Shell Execution:** `ProcessSubprocessRunner` invokes `Foundation.Process` directly via `executableURL` and `arguments` array, never `/bin/sh -c`, and verifies executable path trust (absolute path, non-world-writable binary).
- **Option-Injection Rejection:** `SecretReference` rejects URI components with leading `-` or embedded NUL bytes before any CLI invocation.
- **Repo-Committed Plaintext Guard:** `@SecretSetting` refuses literal secrets originating from `.projectConfig` unless `allowLiteralInProjectConfig == true` (exit code `4`).
- **Ephemeral Secret Materialization:** `Secret.withEphemeralFile` creates a `0700` directory via `mkdtemp`, opens the file with `O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW` at `0600` atomically, `fsync`s, and overwrites with zeros before `unlink` and `rmdir` on scope exit.
