---
name: review-security
description: The security lens of the automated Claude pull-request review — plaintext or secrets in logs and errors, weakened encryption, auth and lock-context flows, injection, GitHub Actions privilege, and supply-chain regressions. Use when the review workflow names this lens, or to run the same review locally on a branch.
---

# Review lens: security

Internal skill — lives in `.claude/skills/` on purpose. It is loaded by
`.github/workflows/claude-review.yml` from the base branch, so a pull request
cannot change the instructions its own review follows. Written to move to
`cipherstash/skills` as an organisation lens.

You are one of several parallel lenses. Report only security issues; general
bugs and repository-rule findings belong to the other lenses.

## What to report

- **Plaintext and secret exposure** — plaintext values, keys, tokens, client
  secrets, or credentials reaching a log line, an error message, an exception
  `cause`, telemetry, a URL, or a test snapshot. Libraries that encrypt data
  must never log what they encrypt.
- **Weakened cryptography** — encryption skipped or made optional on a path
  that used to require it, a fallback to plaintext, a nonce or key reused,
  integrity checks dropped, a payload accepted without validation.
- **Authentication and authorisation** — a token accepted without
  verification, an identity claim or lock context dropped between encrypt and
  decrypt, a permission check removed or moved after the action it guards.
- **Injection** — SQL built by string concatenation, shell commands built from
  untrusted input, unescaped values in generated code, path traversal.
- **GitHub Actions** — `pull_request_target` or `workflow_run` running
  pull-request code with secrets; untrusted `${{ github.event.* }}` text
  interpolated into a `run:` script; permissions widened beyond what a job
  needs; `id-token: write` on a job a fork can reach; a third-party action not
  pinned to a full commit SHA; `persist-credentials` left on.
- **Supply chain** — a dependency added from an unexpected source, a lockfile
  change that does not match the manifest change, an install-script allowance
  added, `--frozen-lockfile` dropped, a registry or cooldown setting relaxed.

## What not to report

- Problems that existed before this pull request.
- Hardening ideas unrelated to the change ("consider adding rate limiting").
- Theoretical issues with no path from attacker-controlled input.

## How to decide

- For each finding, name who controls the input and what they gain. If there
  is no attacker and no exposure, it is not a security finding.
- One inline comment per distinct issue, on the changed line that causes it,
  with the concrete fix.
