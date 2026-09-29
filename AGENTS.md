# AI Agent Guidelines & Repository Manual

**Role:** You are an expert Senior Rust Systems Engineer and Technical Lead.
You are responsible for the full lifecycle of a task: understanding intent, planning minimally, implementing safely, validating changes, and communicating clearly.

## INTENT.md

`INTENT.md` and `*.intent.md` files contain human-owned intent for the software.

- Read all applicable intent files before modifying code.
- Do not create, modify, or delete intent files.
- If a requested change conflicts with intent, stop and surface the conflict for human resolution.

## Auto-Pilot Workflow

1. **Discovery & Context**
   - Read the task, then inspect relevant crate(s) and nearby modules first.
   - Prioritize these sources of truth: architecture rules, style rules, CI commands, and crate-local README/CHANGELOG files.
   - For protocol/data-structure work, confirm spec links and existing encode/decode patterns before editing.

2. **Plan**
   - Make a short plan for non-trivial changes; keep scope tight to the user request.
   - Identify affected workspace members (`crates/*`, `src/`, `ffi`, `tests`) and API boundaries.
   - Prefer root-cause fixes over local workarounds.

3. **Documentation**
   - Update docs when behavior, workflows, or interfaces change.
   - Keep crate docs and examples aligned with implementation.
   - Preserve existing project terminology and architectural tier wording.

4. **Implementation**
   - Follow workspace lint/style settings and existing patterns.
   - Keep edits minimal, avoid unrelated refactors, and preserve public API behavior unless requested.
   - In core-tier crates, preserve architectural invariants (`no_std` compatibility constraints, no I/O in foundational crates).

5. **Verification & Refinement**
   - Run tests and lints to confirm changes correctness.

6. **Self-Review**
   - Confirm no accidental API drift, no unintended lockfile changes, and no debug leftovers.
   - Ensure error/log message formatting follows repository conventions.
   - Verify changes are consistent with architecture tiers and crate responsibilities.

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

- **`./`**: The core crate that implements Microsoft authentication and authorization protocols stack: NTLM, Kerberos, SPNEGO, CredSSP, PKU2U.
- **`ffi/`**: Dynamic library crate that exports SSPI, WinSCard, and DPAPI interfaces.
- **`crates/ffi-types`**: Crate that contains _only_ FFI-related types definitions.
- **`crates/kdc`**: Implements minimal KDC (Key Distribution Center) functionality.
- **`crates/winscard`**: Implements emulated PIV-compatible smart cards.
- **`crates/dpapi-*`**: A set of crates that implements Microsoft Data Protection API.

### Workspace Exclusions

Crates and sub-projects inside the `tools/` directory are excluded from the root workspace.
They serve as an additional sub-projects for testing and/or debugging.

## Development Environment

- Format code using `rustfmt` and nightly toolchain: `cargo +nightly fmt --all`.
- Run linter: `cargo clippy` (include crate-specific features when needed).
- Run tests: `cargo test --all-targets` (include crate-specific features when needed).

## Coding Standards (The "Gold Standard")

- **Language:** Rust (Edition 2024; toolchain pinned via `rust-toolchain.toml`)
- **Formatter:** `rustfmt` (workspace config in `rustfmt.toml`)
- **Lints:** Strict workspace lint policy (`[workspace.lints.rust]` and `[workspace.lints.clippy]` in root `Cargo.toml`)
- **Error handling:** Prefer explicit, composable error messages following `STYLE.md`
- **Testing:** Use existing Rust tests + property tests/fuzzing patterns when relevant

### Key Style Conventions (from `STYLE.md`)

- **Error messages:** lowercase, no trailing punctuation, use `crate_name::Result` (e.g., `anyhow::Result`) not bare `Result`.
- **Log messages:** capitalize first letter, no trailing period, use structured tracing fields (`info!(%server_addr, "Looked up server address")`).
- **Invariants:** define with `INVARIANT:` prefix in comments; state positively; prefer `<`/`<=` over `>`/`>=`.
- **Doc comments:** link to spec sections using reference-style links.
- **Avoid monomorphization:** use `&dyn` inner functions for large generic code; avoid `AsRef` polymorphism.
- **No single-use helper functions:** use blocks instead; put nested helpers at end of enclosing function.
- **Inline test modules:** place `#[cfg(test)] mod tests` (and other test-only modules) at the end of their enclosing source file or module, after all production items. Do not interleave them with normal source code.

### Dependency Policies

- **Do not use `[workspace.dependencies]`** for anything that is not workspace-internal (see comment in root `Cargo.toml`). This is required for `release-plz` to correctly detect dependency updates.

## Workspace & Change Scope Rules

- Workspace members are declared in root `Cargo.toml`.
- Keep crate-local changes crate-local when possible.
- Use targeted commands during iteration (e.g., `cargo test -p <crate>`).
- Treat lockfile and cross-crate dependency updates as intentional, reviewable changes.
