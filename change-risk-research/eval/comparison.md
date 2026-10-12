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

All 31 holdout PRs completed in every condition, so the paired and unpaired tables are identical.
CodeRabbit is scored only on the 19 PRs it reviewed. The rule baseline produces a verdict, not findings.
Regenerate with `cd harness && python3 report_tables.py`; the numbers are in
[`results-summary.json`](results-summary.json).

| Metric | change-risk/C | change-risk/B | change-risk/A | coderabbit/original | deterministic/rule-v1 |
|---|---|---|---|---|---|
| Cases | 31 | 31 | 31 | 19 | 31 |
| Findings (per case) | 84 (2.71) | 87 (2.81) | 86 (2.77) | 119 (6.26) | 0 (0.0) |
| Precision, non-trivial findings | 68/78 (87%; 78%–93%) | 71/79 (90%; 81%–95%) | 69/79 (87%; 78%–93%) | 42/48 (88%; 75%–94%) | n/a |
| Known-defect recall | 4/11 (36%; 15%–65%) | 3/11 (27%; 10%–57%) | 4/11 (36%; 15%–65%) | 1/8 (12%; 2%–47%) | 0/11 (0%; 0%–26%) |
| Defect cases with ≥1 match | 4/8 (50%; 22%–78%) | 3/8 (38%; 14%–69%) | 4/8 (50%; 22%–78%) | 1/6 (17%; 3%–56%) | 0/8 (0%; 0%–32%) |
| Attention where warranted | 21/22 (96%; 78%–99%) | 21/22 (96%; 78%–99%) | 21/22 (96%; 78%–99%) | 11/15 (73%; 48%–89%) | 22/22 (100%; 85%–100%) |
| Attention on expert-low cases | 1/9 (11%; 2%–44%) | 1/9 (11%; 2%–44%) | 1/9 (11%; 2%–44%) | 0/4 (0%; 0%–49%) | 6/9 (67%; 35%–88%) |
| Attention rate overall | 22/31 (71%; 53%–84%) | 22/31 (71%; 53%–84%) | 22/31 (71%; 53%–84%) | 11/19 (58%; 36%–77%) | 28/31 (90%; 75%–97%) |
| High-impact cases rated high+ with attention | 8/10 (80%; 49%–94%) | 9/10 (90%; 60%–98%) | 9/10 (90%; 60%–98%) | 4/6 (67%; 30%–90%) | 10/10 (100%; 72%–100%) |
| Unsupported + incorrect per case | 0.32 | 0.26 | 0.32 | 0.32 | 0.0 |
| Impact within one level | 30/31 (97%; 84%–99%) | 30/31 (97%; 84%–99%) | 29/31 (94%; 79%–98%) | n/a | n/a |
| Impact exact | 20/31 (64%; 47%–79%) | 23/31 (74%; 57%–86%) | 21/31 (68%; 50%–81%) | n/a | n/a |
| Weighted kappa (impact) | 0.716 | 0.78 | 0.718 | None | None |
| Actionable (match/valid) | 65/68 (96%; 88%–98%) | 68/71 (96%; 88%–99%) | 67/69 (97%; 90%–99%) | 42/42 (100%; 92%–100%) | n/a |
| Mean cost USD | 1.51 | 1.48 | 1.5 | None | 0.0 |
| Mean wall seconds | 194.9 | 189.3 | 197.1 | None | None |

Known defects added after scoring (`added_post_hoc`) are excluded here; `score_results.py
--include-post-hoc` includes them.

### Which known defects each evaluator found

| PR | Defect | Impact | A | B | C | CodeRabbit |
|---|---|---|---|---|---|---|
| #314 | KD-1 config loader ignores the default export | medium | miss | miss | miss | miss |
| #349 | KD-1 pre-quoted type name breaks drizzle-kit SQL | high | miss | miss | miss | miss |
| #496 | KD-1 duplicated classes across declaration builds | medium | miss | miss | miss | miss |
| #547 | KD-1 `instanceof` detection fails, filters reach PostgREST in plaintext | critical | miss | miss | miss | miss |
| #666 | KD-1 version-skew check has no direction | medium | found | found | found | miss |
| #823 | KD-1 DDL in dollar-quoted blocks skipped by the guard | high | miss | miss | miss | miss |
| #823 | KD-2 schema and snapshot still declare the encrypted domain after sweep | medium | found | found | found | miss |
| #823 | KD-3 non-`Error` throw breaks the wizard's `catch` | low | miss | miss | miss | found |
| #941 | KD-1 asset jobs skipped by implicit `success()` | high | found | miss | miss | – |
| #941 | KD-2 assets gated on a flag set after publish | high | miss | found | found | – |
| #1002 | KD-1 musl target links glibc | high | found | miss | found | – |

"–" means the evaluator did not assess that PR (CodeRabbit did not review it).

## What the numbers say

- **The three conditions are indistinguishable.** Adding the deterministic evidence (B) or the PR
  description and CI (C) did not change precision, recall, attention or impact agreement beyond what one
  extra finding in either direction would explain. The attention verdict was identical across A, B and C
  on every PR it was scored on. The cheapest condition, A, is as good as any.
- **Findings are mostly sound.** 87–90% of non-trivial findings were a known defect or a plausible,
  change-caused, code-supported risk, about the same as CodeRabbit's non-trivial findings (88%). The skill
  writes far fewer findings (about 2.8 per PR against CodeRabbit's 6.3, of which 60% were trivial).
  The skill's own `basis` field is informative: in C, 7 of 12 findings marked `speculative` were
  unsupported, against 6 of 63 marked `plausible`.
- **Recall of known defects is low.** 3–4 of 11 (27–36%), with intervals reaching 65%. The same defects
  are missed in every condition and, in the stability subset, in every run. Five of the seven misses need
  knowledge of runtime or toolchain behaviour outside the diff: module interop under jiti, how drizzle-kit
  quotes types, declaration-build duplication, cross-bundle `instanceof`, and SQL lexing of dollar quotes.
  CodeRabbit found 1 of the 8 it could have found, a different one.
- **The attention verdict separates routine from non-routine PRs.** It asked for focused review on 21 of
  22 PRs where the expert's impact was medium or above, and on 1 of 9 the expert rated low. The rule
  baseline built from the same history and path signals flagged 28 of 31 PRs, including 6 of the 9 low
  ones, so it adds no information as a filter.
- **Impact ratings agree with the expert, within one level.** 29–30 of 31 within one level, weighted kappa
  0.72–0.78. With one non-blind annotator this is agreement with one person, not calibration.

## Representative examples

**Successes**

- *#547, risk the ground truth did not list (all conditions, all runs).* `stash eql upgrade
  --eql-version 3` applies a bundle that begins `DROP SCHEMA eql_v3 CASCADE`. Every customer column typed
  with an `eql_v3` domain depends on that schema, so an upgrade drops those columns. Labelled `valid`: the
  cited SQL and command path were read and agree.
- *#314, verified against the bundled SQL.* `stash-forge push` deactivates the active EQL config and then
  inserts one whose `cast_as` values the EQL `CHECK` constraint rejects, outside a transaction, leaving no
  active config.
- *#823 KD-2 and #666 KD-1 (all conditions, all stability runs).* The skill named the stale schema and
  snapshot after a sweep, and the version-skew check that steers users with newer packages to downgrade,
  both of which the repository later fixed.
- *#941 KD-2 (B, C).* Release assets gated on a flag that is only set after `changeset publish`
  succeeds, so a failed or re-run publish never builds them.

**False positives**

- *#860 (all conditions).* The skill claimed the native client no longer passes the strategy key after the
  change. The native call still passes `strategy` on `main` and nothing later changed it. Labelled
  `incorrect`.
- *Speculative findings generally.* Most unsupported findings were marked `speculative` by the skill
  itself, for example concurrency or partial-failure scenarios with no code path cited that reaches them.

**Misses**

- *#547 KD-1, the most severe defect in the corpus.* Encrypted-column detection uses `instanceof`, which
  fails when two copies of the package are bundled, so filter values are sent to PostgREST unencrypted.
  The skill rated the PR critical and asked for changes in every run, but always for other reasons
  (including the `DROP SCHEMA` risk above). It never traced how a filter value reaches the network.
- *#823 KD-1.* The already-encrypted guard ignores DDL inside dollar-quoted `DO` blocks. Finding it needs
  a SQL lexing edge case the diff does not show.
- *#349 KD-1.* drizzle-kit's output for a pre-quoted, schema-qualified type. Finding it needs knowledge of
  a third-party tool's quoting.

## Cost and runtime

| | |
|---|---|
| Runs | 119: 93 holdout (31 × A, B and C), 10 dev (B) and 16 stability repeats (C) |
| Total model spend | $184.50 as reported by the CLI |
| Per run | $1.48–$1.51 mean, about 3.2 minutes wall time |
| Monthly estimate | About 45 merged PRs a month (136 in the 90 days to 2026-10-12): roughly $70 for one run per PR on the model used, more if run per push |

A smaller model was not tested. Runs that timed out waiting on the API rate limit were discarded and
rerun; any spend from the discarded attempts is not in this total.

## Stability

Condition C was run three times on 8 holdout PRs (6 of the 8 defect PRs and 2 high-impact controls; see
[`stability.json`](stability.json), `harness/stability.py`).

| PR | Expert impact | Impact (3 runs) | Attention | Known defects found (of 3 runs) |
|---|---|---|---|---|
| #314 | medium | high, high, high | yes ×3 | KD-1: 0 |
| #547 | critical | critical ×3 | yes ×3 | KD-1: 0 |
| #666 | medium | medium ×3 | yes ×3 | KD-1: 3 |
| #823 | high | high ×3 | yes ×3 | KD-1: 0, KD-2: 3, KD-3: 0 |
| #860 | high | high ×3 | yes ×3 | – |
| #941 | high | medium, high, high | yes ×3 | KD-1: 0, KD-2: 3 |
| #961 | high | high ×3 | yes ×3 | – |
| #1002 | high | high, high, medium | yes ×3 | KD-1: 2 |

Attention was identical in all three runs on every PR, impact on 6 of 8, and the exact verdict
(`focused_review_required` versus `changes_or_verification_required`) on 4 of 8. Of the 9 known defects,
3 were found every time, 1 in two runs and 5 never. Misses are systematic rather than run-to-run noise.

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
