# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The on-wire protocol version (`CONSENT_PROTOCOL_VERSION`) and the specification
revision (`SPEC.md`) are versioned independently of the crate.

## [0.7.0] - 2026-06-03

### Fixed
- The MSRV CI job could not parse the version-4 `Cargo.lock`: it pinned Rust 1.74,
  which predates the v4 lock format (stabilised in 1.78). The declared MSRV is now
  `1.82.0`, so the MSRV job runs on a toolchain that understands the lockfile.
- The fuzz build targeted `x86_64-unknown-linux-musl` (the triple of the prebuilt
  `cargo-fuzz` binary), whose `std` is not installed on the runner and whose static
  libc is incompatible with AddressSanitizer. Both `cargo fuzz build` and the
  scheduled fuzz run now pin `--target x86_64-unknown-linux-gnu`.

### Added
- Tag-triggered release automation (`.github/workflows/release.yml`): pushing a
  `v*` tag runs the full test suite and publishes a GitHub release with notes
  extracted from this changelog.
- Dependabot configuration (`.github/dependabot.yml`) — weekly Cargo (root + fuzz)
  and GitHub-Actions dependency updates.

### Changed
- MSRV raised to `rust-version = 1.82.0`.

## [0.6.0] - 2026-06-03

### Fixed
- `fuzz/Cargo.toml` referenced the pre-0.3.0 crate name (`axonos-consent`), so the
  fuzz crate failed to resolve its path dependency and `cargo fuzz build` errored
  with "no matching package named `axonos-consent`". Renamed the fuzz package to
  `axonos-protocol-fuzz` and its dependency to `axonos-protocol` — completing the
  0.3.0 crate rename that had missed this manifest.

### Added
- `deny.toml` and a `cargo deny` CI job (license allow-list, RustSec advisories,
  and source policy).
- Declared MSRV (`rust-version = 1.74.0`) and an MSRV CI job that builds on that
  exact toolchain.
- Scheduled fuzzing workflow (`.github/workflows/fuzz.yml`) — weekly and on demand,
  bounded per target.

## [0.5.0] - 2026-06-03

### Changed
- CI installs `cargo-fuzz` and `cargo-audit` as prebuilt binaries via
  `taiki-e/install-action` instead of compiling them from source. This removes a
  nightly build failure in which an old transitive dependency (`rustix 0.36.5`)
  no longer compiles on current `rustc`, and makes CI faster and reproducible.

### Added
- `CHANGELOG.md` (this file).
- `CITATION.cff` — machine-readable citation metadata; GitHub renders a
  "Cite this repository" action from it.

## [0.4.0] - 2026-06-03

### Added
- Reworked CI: `rustfmt --check`, `clippy -D warnings`, a full feature matrix with
  doctests, `no_std` (thumbv7em) and `wasm32` builds, `cargo doc` with
  `-D warnings`, a fuzz build, and `cargo audit`.
- Frozen-vectors integrity guard via a committed `tests/vectors/SHA256SUMS`.

### Fixed
- Stale hard-coded conformance-vector checksum in CI (the 0.3.0 de-coupling change
  altered the vectors' metadata and invalidated the previous hash).
- Unused glob import in the integration tests that failed under `-D warnings`.

### Removed
- Helper shell scripts that had been committed to the repository.

## [0.3.0] - 2026-06-03

### Changed
- The crate is now the reference implementation of the **AxonOS Consent Protocol
  (ACP)**, specified in `SPEC.md`, developed and maintained entirely within the
  AxonOS project.
- Renamed the crate `axonos-consent` → `axonos-protocol`, resolving an identity
  collision with the kernel-level consent crate.

### Removed
- All references to external protocols from the specification, implementation, and
  conformance metadata. ACP is defined against AxonOS documents only.

### Fixed
- `LICENSE-APACHE` now contains the full Apache-2.0 text (previously a stub), and
  the redundant top-level `LICENSE` was removed so the dual license resolves
  correctly.

## [0.2.2] - 2026-05-25

### Added
- Initial public release: a `no_std`, zero-allocation consent protocol engine —
  security-bounded CBOR codec, exhaustive three-state consent machine, reason-code
  registry, StimGuard contract, and frozen interop vectors.

[0.7.0]: https://github.com/AxonOS-org/axonos-protocol/releases/tag/v0.7.0
[0.6.0]: https://github.com/AxonOS-org/axonos-protocol/releases/tag/v0.6.0
[0.5.0]: https://github.com/AxonOS-org/axonos-protocol/releases/tag/v0.5.0
[0.4.0]: https://github.com/AxonOS-org/axonos-protocol/releases/tag/v0.4.0
[0.3.0]: https://github.com/AxonOS-org/axonos-protocol/releases/tag/v0.3.0
[0.2.2]: https://github.com/AxonOS-org/axonos-protocol/releases/tag/V0.2.2
