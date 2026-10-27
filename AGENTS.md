Start a work session with `/contribute`, which picks the delivery flow by scale and the skills each step needs.

## Intent files

`INTENT*.md` and `*.intent*.md` files contain human-owned intent for the software.
Read all applicable intent files before modifying code.
Do not create, modify, or delete intent files.
If a requested change conflicts with intent, stop and surface the conflict for human resolution.

## Writing for the repository

Committed text (code, comments, docs, commit messages) and PR titles and descriptions never refer to work stages, decision identifiers, agent roles, sessions or planning documents.
State rationale, not history.

## Rust

Write Rust with the `rust-style` skill and tests with the `test-writer` skill.
Library crates expose typed errors, not `anyhow`; see `STYLE.md` § Error types.
Think before silencing a lint, then use `#[expect(<lint>, reason = "...")]` so the suppression explains itself and expires when it stops being needed.
Do not use `[workspace.dependencies]` for anything that is not workspace-internal, because `release-plz` must detect dependency updates.

## Untested-property comments

When code must keep a property that no test checks, mark it with an `UNTESTED:` comment at that code, because passing tests prove nothing about it.
The comment states the property, why it matters, and what to check when changing the code.
List `UNTESTED:` properties in a PR comment as well, not in the PR description, because the description becomes the squash commit body.
