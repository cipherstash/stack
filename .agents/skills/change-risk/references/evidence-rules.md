# Evidence rules

## Facts, inferences, unknowns

- **Fact**: something you read at a cited location (`path:line` at base or head), or output of a command you ran. Evidence `status: verified`.
- **Inference**: your reading of what the facts imply. Evidence `status: inferred`. Fine to report, must be labelled.
- **Unknown**: something you looked for and could not establish. Goes in `coverage_limitations` with its effect on the assessment.

## Citing

- Prefer `path` + `line_start`/`line_end` + `rev` (`base` or `head`). Line numbers refer to the file **at that revision**, not to diff hunk offsets. Get them with `git show $REV:path | grep -n ...` or `git grep -n pattern $REV -- path`.
- For a deleted line, cite it at `rev: base`.
- `kind: diff` for a change itself, `code` for surrounding code, `test` for a test file, `history_signal` with `signal` naming the collector field (e.g. `co_change.omitted_co_changes[2]`), `command_output` with the `command` you ran, `ci_result` only for CI results you were given, `pr_description` for the author's claims (claims, not facts).
- The validator checks that paths exist at the cited revision and lines are within the file.

## What deterministic signals support

| Signal | Can support | Cannot support |
|---|---|---|
| Change size, file count | "This is a large change, review is harder" | That it is risky |
| Components touched | "The change crosses N package boundaries" | That those packages interact at runtime |
| Path classes | Where to look | That a contract changed (read the code) |
| Churn / hotspots | "This file changes often" | That it is defective |
| Omitted co-change | "X usually changes with Y; Y is untouched here" — a prompt to check Y | That the change is incomplete |
| Ownership / familiarity | Who normally maintains this; whether the author has touched it | Anything about the author's competence |
| Dependency changes | Which versions moved | What changed inside the dependency (read its changelog if available; otherwise say unknown) |
| Test mapping | Which tests probably relate | That they cover the change, ran, or passed |

## Things never to present as fact without evidence

- That a test passed or ran.
- That a component depends on another.
- That a deployment is staged, reversible, or behind a flag.
- That a downstream consumer exists or does not exist outside this repository.
- That a change is safe because nothing failed.

## Failure handling

If a tool fails, a diff is truncated, a file cannot be read, or a revision is missing, record it in `coverage_limitations`. Do not lower impact because you could not see something.

## Lightweight default (1.1)

History is opt-in (`--max-history N`, default 0). Disabled history has explicit
`history_scope.status: unavailable`, no familiarity records, and empty historical
signals; this is not evidence of no coupling. Tests and dependency changes still
work. Use historical coupling to select a concrete omitted component to inspect,
then establish the real relationship in source. Path classes, size, churn and test
filename matches never establish danger, dependency impact, or missing coverage.
