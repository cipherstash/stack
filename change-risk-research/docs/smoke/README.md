# Host smoke tests — 2026-10-21

Run from the PR worktree root with the canonical skill and tracked Claude symlink.
The runtime is independent of `harness/`. Existing installed CLIs and account
configuration were used; no provider, model override or service was added.

## Codex 0.162.1: passed on a small real change

Exact invocation (shell stdout/stderr were captured outside the repository):

```bash
codex exec --sandbox read-only --ephemeral --json 'Use $change-risk for a small real-change smoke test: base 2ab2b9447ee592d7a498fd7c0f63293a4b48466e, head eb8194bf37e0b6f9b50d99e7ae2941930ec684d0, repository cipherstash/stack. Inspect this exact diff and needed surrounding source. No optional history, network tools, or repository code execution. Return complete assessment JSON only. Every code, diff, test and documentation evidence item needs a path at the specified revision. Do not edit repository files.' </dev/null
```

Codex discovered `$change-risk`, loaded its schema/references, and inspected the
five-file CLI-guidance change. Its final JSON is [codex-assessment.json](codex-assessment.json).
No material scenario was identified; impact low, verification confidence medium,
ready for normal review. Existing tests were inspected, not executed.

The implementing agent extracted that JSON and independently ran:

```bash
python3 .agents/skills/change-risk/scripts/validate_assessment.py change-risk-research/docs/smoke/codex-assessment.json --repo . --json
python3 .agents/skills/change-risk/scripts/render_report.py change-risk-research/docs/smoke/codex-assessment.json --out change-risk-research/docs/smoke/codex-report.md
```

Validation returned `valid: true`, no errors and no warnings. The
[human report](codex-report.md) is readable without JSON. Its limitations describe
what the assessor itself executed; validation/rendering happened afterwards.
The transcript recorded successful source reads despite Git temporary-cache
warnings. Parent AGENTS.md exceeded Codex's context budget and was truncated;
the task-specific skill still loaded. Runtime warnings about unrelated plugin
icons did not prevent discovery.

The initial sandboxed launch failed during app-server/memory database initialization.
The successful launch allowed the CLI access to its normal local runtime while
keeping the nested assessor read-only. An earlier `HEAD~1..HEAD` run assessed a
large merge and produced two `diff` evidence records without paths. The validator
rejected it. [That original response](codex-wide-invalid.json) is retained as a
failure record, not repaired or counted as a passing smoke. Use exact revisions
when selecting a small smoke case.

## Claude Code 2.1.305: passed after host-access retry

The first invocation was:

```bash
claude -p '/change-risk Assess change risk between HEAD~1 and HEAD in this repository. Disable optional history. Write assessment.json and report.md to /tmp/change-risk-claude-smoke. Validate with --repo. Do not edit repository files, use network tools or run repository code. Use source inspection only.' --max-turns 25 --max-budget-usd 3 --no-session-persistence --strict-mcp-config --mcp-config '{"mcpServers":{}}' --allowedTools 'Skill,Read,Grep,Glob,Bash(git *),Bash(python3 *),Write(/tmp/change-risk-claude-smoke/*)'
```

It returned `Not logged in · Please run /login`, before generating an assessment.
It also warned that file permission allow rules use `Edit(path)` (which covers
Write), not `Write(path)`. That initial attempt did not establish discovery. The retry allowed the CLI to
access its normal host authentication and removed the unnecessary write rule:

```bash
claude -p '/change-risk Assess change risk between 2ab2b9447ee592d7a498fd7c0f63293a4b48466e and eb8194bf37e0b6f9b50d99e7ae2941930ec684d0 in cipherstash/stack. Disable optional history. Return complete assessment JSON only. Do not edit files, use network tools or execute repository code. Use source inspection only.' --max-turns 20 --max-budget-usd 3 --no-session-persistence --strict-mcp-config --mcp-config '{"mcpServers":{}}' --allowedTools 'Skill,Read,Grep,Glob,Bash(git *)'
```

It completed successfully using the discovered `/change-risk` skill. Its final
[assessment](claude-assessment.json) rated impact low, confidence medium, focused
review required. The implementing agent extracted the JSON and ran the same
validator with `--repo .`: valid, no errors, no warnings. The
[rendered report](claude-report.md) is retained. Its different readiness judgement
from Codex is preserved, not reconciled into an artificial agreement. Neither
assessor executed the changed repository's tests. This verifies local invocation
and output compatibility, not performance or production accuracy.

## Repository verification

- Skill Python suite: 52 tests run, passed with two optional `jsonschema` checks
  skipped because that library is not installed. The standard-library validator
  and all negative/schema/semantic cases ran.
- Scoring suite: three tests passed, including preservation of v1 counts and
  evidence coverage denominators.
- Inactive publishing fixture: actual `Decide outcome` shell executes with the
  sparse scripts/schema layout; valid, invalid, wrong-head, stale and failed-analysis
  cases pass. GitHub writes are stubbed out; the workflow remains inactive.
- Repository script tests: 79 files passed, 1,388 tests passed, 28 skipped.
  `pnpm run test:scripts` was initially blocked by Corepack cache permissions;
  the installed `vitest run --config scripts/vitest.config.mjs` (the same script)
  ran using the existing root node_modules through an ignored worktree symlink.
- Repository `biome check`: no errors; 196 warnings and 74 infos. Initial formatting
  errors in new JSON files were fixed and the check rerun.
- `git diff --check`: passed. Retained assessment/transcript checksums verified.
- Skill-creator's auxiliary `quick_validate.py` could not run because PyYAML is
  absent. Skill/schema parsing and actual Codex discovery were tested separately.

Package builds/live encryption tests were not run: no customer package code changed.
These tests do not establish production effectiveness. Independent human review
of the prepared packet remains required.
