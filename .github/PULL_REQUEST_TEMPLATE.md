## Summary

- 

## Related Issue

Closes #

## Engineering & Security Checklist

- [ ] **Strict Swift 6 Concurrency & Zero Warnings:** Compiles cleanly under `swift build --build-tests -Xswiftc -warnings-as-errors` with full `Sendable` conformance.
- [ ] **Dependency Hygiene:** `RiggingCore` and `RiggingTOML` remain 100% free of external package dependencies.
- [ ] **100% DocC Coverage:** Every new or modified `public` symbol includes `///` documentation, curated under its module's `.docc` catalog, and passes DocC generation with `--warnings-as-errors`.
- [ ] **Secret Redaction & Threat Model:** `Secret<T>` redaction (`"**********"` across descriptions, `Mirror`, and default `Encodable`), `DiagnosticRedactor` registration, option-injection rejection, `0600` file-permission checks, and zero-shell subprocess execution are preserved.
- [ ] **Hermetic `Swift Testing` Suite:** Covered by `@Test` cases using `RiggingTesting` (`SettingsContext.inMemory(...)`) with zero host filesystem, Keychain, or live CLI side effects.
- [ ] **Cross-Platform Parity:** Linux (`Glibc` / `Musl` / `FoundationNetworking`) and Apple platform (`Darwin` / `Security`) conditional compilation verified.
