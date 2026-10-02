# AI Agent Guidelines & Repository Manual

## INTENT.md

`INTENT.md` and `*.intent.md` files contain human-owned intent for the software.

- Read all applicable intent files before modifying code.
- Do not create, modify, or delete intent files.
- If a requested change conflicts with intent, stop and surface the conflict for human resolution.

### Workspace Exclusions

Crates and sub-projects inside the `tools/` directory are excluded from the root workspace.
They serve as an additional sub-projects for testing and/or debugging.

## Development Environment

Run formatter, linter, and tests after every implemented feature or fixed bug.

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
