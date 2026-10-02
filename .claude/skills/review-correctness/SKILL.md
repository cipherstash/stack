---
name: review-correctness
description: The correctness lens of the automated Claude pull-request review — logic errors, behavioural regressions, compatibility breaks, and missing tests for changed behaviour. Use when the review workflow names this lens, or to run the same review locally on a branch.
---

# Review lens: correctness

Internal skill — lives in `.claude/skills/` on purpose. It is loaded by
`.github/workflows/claude-review.yml` from the base branch, so a pull request
cannot change the instructions its own review follows. Written to move to
`cipherstash/skills` as an organisation lens; keep it free of
repository-specific rules (those belong in `review-repo-rules`).

You are one of several parallel lenses. Report only what this lens covers;
security and repository-rule findings belong to the other lenses.

## What to report

- **Logic errors** — wrong conditions, off-by-one, inverted checks, unhandled
  `null` / `undefined`, a promise not awaited, an error swallowed or turned
  into success, a branch that can never run.
- **Behavioural regressions** — a caller, test, or documented behaviour that
  the change breaks. Read the callers of a changed function before deciding
  a change is safe.
- **Compatibility breaks** — a changed exported signature, return shape, error
  type, default, or file format that existing consumers rely on, made without
  a migration path or a major-version signal.
- **Contracts** — a function that no longer does what its name, type, or doc
  comment says.
- **Missing tests for changed behaviour** — new or changed behaviour with no
  test exercising it, where a test in the same package would be
  straightforward. Name the behaviour that is untested, not a coverage figure.

## What not to report

- Problems that existed before this pull request.
- Style, naming, formatting, or anything a linter or type checker catches.
- Speculative refactors and "consider" suggestions.
- A failure that needs a specific, unlikely input you cannot name.

## How to decide

- Confirm each finding against the code: name the input or state that produces
  the wrong result and what the result is. If you cannot, drop it.
- One inline comment per distinct issue, on the changed line that causes it.
- Prefer a short concrete fix in the comment over a description of the problem
  alone.
