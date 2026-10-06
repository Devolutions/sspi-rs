---
name: style-review
description: Checks changed Rust code against the repository style conventions.
---

# Style Review

Review the code you wrote or are reviewing against the conventions below.
These are the key conventions from `STYLE.md`; consult `STYLE.md` for rationale and more examples when a case is unclear.

## When to apply

- After every implemented feature or fixed bug, before reporting the work as done.
- On every code review.

## Scope

- Check only added or modified lines. Do not flag pre-existing code.
- Fix violations in your own changes.
  In a review of someone else's code, report them instead of editing.
- Style nits must not block a change.
  Report them as nits, separately from correctness issues.
- Never create, modify, or delete `INTENT.md` or `*.intent.md` files.

## Checklist

1. **Error messages**
   - Lowercase first letter, no trailing punctuation, a single short sentence.
   - Keep proper abbreviation casing (`IPv4`, `X.509`).
   - GOOD: `"invalid X.509 certificate"`. BAD: `"Invalid X.509 certificate."`.
   - Use `crate_name::Result` (e.g. `anyhow::Result`) instead of bare `Result`, unless the alias is already clear (e.g. `ConnectionResult`).
   - Library crates expose typed errors (e.g. `thiserror`), not `anyhow`.
     Avoid one umbrella error type for the whole library; use module-level error types convertible into the root error.

2. **Log messages**
   - Capitalize the first letter, no trailing period.
   - Use structured tracing fields instead of interpolation.
   - GOOD: `info!(%server_addr, "Looked up server address")`. BAD: `info!("looked up server address: {server_addr}.")`.
   - Name fields consistently; errors are recorded as `error` (`?error`, `%error`, `error = ?e`), never `e` or `err`.
   - Log levels in library crates:
     `info!` only for rare lifecycle milestones, never for anything repeating during normal operation;
     `debug!` for significant one-off events, no "entering function X" tracing;
     `trace!` for everything else.

3. **Invariants**
   - Document invariants with an `INVARIANT:` prefix in comments.
   - State them positively; prefer `<` / `<=` over `>` / `>=`.
   - Field invariants go in the doc comment on the field, loop invariants before or at the start of the loop, function output invariants in the function's doc comment.

4. **Doc comments**
   - Link to spec sections using reference-style links; quote the section name verbatim and keep links short.
   - Inline code comments are proper sentences: capital letter and trailing period.
     Brief tag-like comments (e.g. `// VER`, `// RSV`) are exempt.
   - In `.md` and `.adoc` files use one sentence per line; do not wrap lines.

5. **Avoid monomorphization**
   - Do not make large bodies generic.
     Keep a thin generic wrapper that delegates to a non-generic or `&dyn` inner function.
   - Avoid `AsRef` polymorphism (`impl AsRef<Path>`); take `&Path` and the like.

6. **Test module placement**
   - `#[cfg(test)] mod tests` (and other test-only modules) goes at the end of its enclosing file or module, after all production items.
   - Never interleave test modules with production code.

## Related conventions from `STYLE.md`

Also check these when relevant to the diff:

- No single-use helper functions (use a block), unless the helper needs `return` or `?`.
- Nested helper functions go at the end of the enclosing function (after a `return`), at most one level deep.
- Context parameters come first.
- Avoid needless allocations; let the caller allocate when allocation is unavoidable (take `String`, not `&str` followed by `.to_string()`).

## Output

If you are the author, apply the fixes and re-check.
If there are no violations, state that the style review passed.
