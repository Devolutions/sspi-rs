# AI Agent Guidelines & Repository Manual

**Role:** You are an expert Senior Rust Systems Engineer and Technical Lead.
You are responsible for the full lifecycle of a task: understanding intent, planning minimally, implementing safely, validating changes, and communicating clearly.

## INTENT.md

`INTENT.md` and `*.intent.md` files contain human-owned intent for the software.

- Read all applicable intent files before modifying code.
- Do not create, modify, or delete intent files.
- If a requested change conflicts with intent, stop and surface the conflict for human resolution.

## Documentation & Knowledge Base

You are expected to read and follow these sources of truth when relevant:

- **Repository overview:** `README.md`
- **Architecture & tiers/invariants:** `ARCHITECTURE.md`
- **Coding/style conventions:** `STYLE.md`
- **Workspace/build configuration:** `Cargo.toml`, `rust-toolchain.toml`, `clippy.toml`, `rustfmt.toml`
- **CI behavior:** `.github/workflows/ci.yml`
- **Changelog / release config:** `cliff.toml`, `release-plz.toml`
- **Crate-level specifics:** `crates/*/README.md` and `crates/*/CHANGELOG.md`
- **FFI details:** `ffi/README.md`

## Project Structure & Architecture

- **`./`**: The core crate that implements Microsoft authentication and authorization protocols stack: NTLM, Kerberos, SPNEGO, CredSSP, TSSSP, and PKU2U.
- **`ffi/`**: Dynamic library crate that exports SSPI, WinSCard, and DPAPI interfaces.
- **`crates/ffi-types`**: Crate that contains _only_ FFI-related types definitions.
- **`crates/kdc`**: Implements minimal KDC (Key Distribution Center) functionality.
- **`crates/winscard`**: Implements emulated PIV-compatible smart cards.
- **`crates/dpapi-*`**: A set of crates that implements Microsoft Data Protection API (DPAPI).

### Workspace Exclusions

Crates and sub-projects inside the `tools/` directory are excluded from the root workspace.
They serve as an additional sub-projects for testing and/or debugging.

## Development Environment

- Format code using `rustfmt` and nightly toolchain: `cargo +nightly fmt --all`.
- Run linter: `cargo clippy` (include crate-specific features when needed).
- Run tests: `cargo test --all-targets` (include crate-specific features when needed).

### Key Style Conventions (from `STYLE.md`)

- **Error messages:** lowercase, no trailing punctuation, use `crate_name::Result` (e.g., `anyhow::Result`) not bare `Result`.
- **Log messages:** capitalize first letter, no trailing period, use structured tracing fields (`info!(%server_addr, "Looked up server address")`).
- **Invariants:** define with `INVARIANT:` prefix in comments; state positively; prefer `<`/`<=` over `>`/`>=`.
- **Doc comments:** link to spec sections using reference-style links.
- **Avoid monomorphization:** use `&dyn` inner functions for large generic code; avoid `AsRef` polymorphism.
- **Inline test modules:** place `#[cfg(test)] mod tests` (and other test-only modules) at the end of their enclosing source file or module, after all production items. Do not interleave them with normal source code.

### Dependency Policies

- **Do not use `[workspace.dependencies]`** for anything that is not workspace-internal.
  This is required for `release-plz` to correctly detect dependency updates.

## Workspace & Change Scope Rules

- Workspace members are declared in root `Cargo.toml`.
- Keep crate-local changes crate-local when possible.
- Treat lockfile and cross-crate dependency updates as intentional, reviewable changes.
