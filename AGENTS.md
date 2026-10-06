# AI Agent Guidelines & Repository Manual

## INTENT.md

`INTENT.md` and `*.intent.md` files contain human-owned intent for the software.

- Read all applicable intent files before modifying code.
- Do not create, modify, or delete intent files.
- If a requested change conflicts with intent, stop and surface the conflict for human resolution.

### Dependency Policies

- **Do not use `[workspace.dependencies]`** for anything that is not workspace-internal.
  This is required for `release-plz` to correctly detect dependency updates.

## Workspace & Change Scope Rules

- Keep crate-local changes crate-local when possible.
- Treat lockfile and cross-crate dependency updates as intentional, reviewable changes.
