# Security Policy

`Rigging` is designed from the ground up to load, validate, dereference, and redact application credentials safely across developer machines, CI pipelines, and production servers.

## Supported Versions

| Version | Supported |
|---|---|
| `0.1.x` (`main`) | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, report suspected vulnerabilities privately via **[GitHub Private Vulnerability Reporting](https://github.com/SamPetherbridge/Rigging/security/advisories/new)** on this repository. Include:

1. Affected module(s) (`RiggingCore`, `RiggingOnePassword`, `RiggingKeychain`, `RiggingBitwarden`, `RiggingUnixPass`, etc.) and Swift / OS version.
2. Minimal reproduction steps or a hermetic `RiggingTesting` test case demonstrating the issue.
3. Impact assessment (e.g., unintended plaintext exposure, file-permission bypass, or argument injection).

We acknowledge vulnerability reports within **48 hours** and coordinate remediation and advisory disclosure prior to public release.

---

## Security Architecture & Invariants

Every change to `Rigging` is audited against the following non-negotiable security invariants:

### 1. Zero Shell Execution (`Foundation.Process` Direct Exec)
`ProcessSubprocessRunner` invokes external secret CLIs (`op`, `bws`, `bw`, `pass`, `sops`) exclusively through `Foundation.Process.executableURL` and structured `arguments: [String]` arrays — **never** `/bin/sh -c` or string command interpolation — eliminating shell metacharacter injection.

### 2. Executable Path Trust Verification
Before spawning any external secret provider binary, `ProcessSubprocessRunner.verifyExecutableTrust(atPath:fileSystem:)` enforces that:
- The executable path is an absolute POSIX path (`/`-prefixed), never a relative `./` or working-directory binary.
- The binary is not world-writable (`mode & 0o002 == 0`), blocking untrusted binary planting (`SubprocessSecurityError`).

### 3. Strict URI Option-Injection & Path-Traversal Rejection
`SecretReference` and provider-specific validators inspect every URI segment (`op://`, `keychain://`, `bws://`, `bw://`, `pass://`, `sops://`, `file://`, `@path`, `env://`) prior to constructing CLI flags or Keychain queries, rejecting:
- Leading hyphens (`-`, including percent-encoded `%2D` / `%2d`) that could be interpreted as CLI options.
- Embedded NUL bytes (`\0`, `%00`) and ASCII control characters.
- Relative parent traversal segments (`..`) in password-store and SOPS paths.

### 4. In-Memory Batched `op inject` Pipes (Zero Plaintext Temp Files)
`OnePasswordProvider` batches all `op://` references per `(scheme, accountHint)` into a single `op inject` invocation over in-memory `stdin`/`stdout` pipes using 128-bit cryptographic random boundary nonces — or resolves over HTTPS via 1Password Connect — writing **zero** temporary files to disk.

### 5. Atomic `0700` / `0600` Ephemeral Files with Zero-Overwrite Cleanup
When an external tool requires a filesystem path (for example `xcodebuild -authenticationKeyPath`, `openssl`, or `ssh -i`), `Secret.withEphemeralFile`:
1. Creates a private `0700` directory under `$TMPDIR` via POSIX `mkdtemp`.
2. Opens the secret file atomically with `O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW` and mode `0600` from birth (never creating a default-umask file and calling `chmod` afterward).
3. Flushes contents with `fsync` and executes the scoped async closure.
4. On scope exit (both normal return and thrown errors), reopens `O_WRONLY`, overwrites the exact byte length with zeros, `fsync`s, `unlink`s the file, and `rmdir`s the temporary directory.

### 6. Repo-Committed Plaintext Secret Guard (`allowLiteralInProjectConfig: false`)
By default, `@SecretSetting` refuses literal secret values whose winning `SettingOrigin` is a project configuration file (`.projectConfig`, such as `.asc.json` or `rigging.toml`), failing immediately with deterministic CLI exit code **`4`** (`UnsafeSecretStorage`) and remediation guidance (`op://`, `keychain://`, `.env`, or `0600` user config).

### 7. POSIX `0600` Secret File Enforcement
`FileSecretProvider` (`file://` and `@~/path`) inspects POSIX permissions via `FileSystem.posixPermissions(atPath:)` before reading secret bytes and rejects group- or world-accessible files (`perms & 0o077 != 0`) with exit code **`4`** and `Fix: chmod 600 <path>`.

### 8. Defense-in-Depth `Secret<T>` & `DiagnosticRedactor`
- **`Secret<Value>`** emits `"**********"` across `CustomStringConvertible`, `CustomDebugStringConvertible`, `CustomReflectable` (an empty-children `Mirror` so `dump()` never leaks plaintext), and default `Encodable` (plaintext encoding requires explicit `encoder.userInfo[.secretEncodingPolicy] = SecretEncodingPolicy.exposePlaintext`).
- **`DiagnosticRedactor`** (`Synchronization.Mutex`-backed `Sendable`) automatically registers every resolved secret (`>= 6` characters, plus individual body lines of multiline PEM keys) and scrubs longest-match-first across all `SettingsValidationError` diagnostics, `ProvenanceReport` outputs, and subprocess `stderr` messages.
