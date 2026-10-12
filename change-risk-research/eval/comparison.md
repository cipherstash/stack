# Comparison: change-risk skill, CodeRabbit and a deterministic baseline

Holdout results on `cipherstash/stack`. Method, labels and metric definitions are in
[`../research/methodology.md`](../research/methodology.md) and were fixed before scoring; changes made
after scoring are listed at the end of that file.

**Read this first.**
- **The sample is small.** There are 31 holdout PRs, 8 with a known later defect (11 defects). Every
  interval below is a 95% Wilson interval, and most are wide. A 10-point difference between two
  evaluators is not evidence of a real difference.
- **One person did everything.** The same agent selected the corpus, wrote the ground truth, wrote the
  skill and adjudicated the findings, and the adjudication is not blind. That biases results toward the
  skill. Defect cases and low-confidence ground truth still need a second, human review.
- **PR-Agent was not run** (no approved provider), and **CodeScene could not be run** (no access). Neither
  is in these tables.

## Setup

| | |
|---|---|
| Repository | `cipherstash/stack`, full history to `origin/main` at 2026-10-12 |
| Cases | 41 merged PRs: 10 dev (used to try the skill), 31 holdout (scored here) |
| Skill | `change-risk` 1.0.0, schema version 1, unchanged between dev and holdout |
| Agent | Claude Code CLI 2.1.296, headless (`claude -p`), model `claude-opus-5-5`, one run per case per condition (plus repeats, below) |
| Isolation | Fresh repository with only the head commit's ancestry; private mount namespace; git `file` protocol only; no MCP, WebFetch or WebSearch; transcript audit ([`change-risk/audit-review.md`](change-risk/audit-review.md)) |
| Budget | `--max-budget-usd 15` per run (never reached) |
| CodeRabbit | Historical comments on the real PRs (reviewed intermediate commits too); it reviewed 19 of the 31 holdout PRs |
| Deterministic | `collect-evidence` 1.0.0 plus attention rule v1 (R1–R7), fixed before scoring |

Conditions: **A** diff, checkout and title. **B** A plus deterministic evidence. **C** B plus PR
description and CI check runs.

## Results

<!-- TABLES -->

### Which known defects each evaluator found

| PR | Defect | Impact | A | B | C | CodeRabbit |
|---|---|---|---|---|---|---|
<!-- DEFECTS -->

"–" means the evaluator did not assess that PR (CodeRabbit did not review it).

## What the numbers say

<!-- FINDINGS -->

## Representative examples

<!-- EXAMPLES -->

## Cost and runtime

<!-- COST -->

## Limitations

- **Selection and annotation bias.** The corpus, ground truth and skill have one author; the skill's
  references were generalised after the corpus was built, but contamination is likely. Model training
  data may also contain this public repository's history.
- **Non-blind adjudication.** Labels were assigned knowing the ground truth and which evaluator wrote
  each finding. `valid` judgements on controls rest on reading the cited code, often without running it.
- **Ground truth is incomplete.** Three dev-split findings turned out to be real defects that ground
  truth missed (recorded as post-hoc defects; excluded from the pre-registered metrics). Controls are
  "no known defect", not "no defect", so `valid` findings on controls cannot be confirmed as defects.
- **CodeRabbit is not like-for-like.** It reviewed each push, not only the final head, and it did not
  review 12 holdout PRs. Its findings are scored against the final head's known defects.
- **No test execution.** The evaluator checkouts have no `node_modules` and no network, so the skill
  never ran tests; it reports verification as `unknown` or cites CI where condition C provided it.
- **Single runs.** Each case has one run per condition except the stability subset. Run-to-run variation
  is of the same order as the differences between conditions (see Stability).
