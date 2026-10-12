# Final recommendation: PR change-risk assessment for cipherstash/stack

2026-10-12. Evidence: [`../eval/comparison.md`](../eval/comparison.md). Method:
[`../research/methodology.md`](../research/methodology.md).

## Recommendation

**Adopt the `change-risk` skill as an advisory tool that people run on demand, alongside CodeRabbit.
Do not use it, or any tool evaluated here, to gate merges.** Revisit CI integration after a second,
human review of the ground truth and a shadow-mode trial.

| Option | Verdict | Why |
|---|---|---|
| Existing tool only (CodeRabbit) | Not sufficient on its own | It reviews lines, not release risk: 60% of its findings on the holdout were trivial, it gives no overall impact, and it found 1 of 8 scoreable known defects. It did find one defect the skill never found (#823, a `catch` that breaks on non-`Error` throws) |
| PR-Agent (Qodo) | Not evaluated | Configured, but needs an approved LLM provider. Its risk fields are a lighter version of the same idea: ≤3 failure modes from the diff alone, no repository search |
| CodeScene | Do not integrate now | No access; its documented CLI gives code-health deltas, not a risk model. A path-and-history rule built from the same signals flagged 90% of PRs, including 6 of 9 the expert rated low |
| **change-risk skill** | **Adopt, advisory and on demand** | Findings were mostly sound, the attention verdict separated routine from non-routine PRs well, and it found real, serious risks the ground truth did not list |
| Skill + CodeRabbit | **Recommended combination** | They overlap little. CodeRabbit covers line-level correctness; the skill covers blast radius, release, migration and contract risk |
| Discontinue | No | The evidence supports advisory use, though not gating |

## What the evidence supports (facts from the holdout, n = 31)

Main condition C (diff, history signals, PR description and CI results), one run per PR:

- **Most findings were sound.** 87% of non-trivial scenarios were a known defect or a plausible,
  change-caused, code-supported risk (68/78; 95% interval 78–93%). About one unsupported or incorrect
  scenario every three PRs (0.32 per case). Scenarios the skill itself marked `speculative` were the weak
  ones: 7 of 12 were unsupported.
- **The attention verdict was the most useful output.** It asked for more than routine review on 21 of
  the 22 PRs where that was warranted, and on 1 of the 9 the expert rated low. Overall impact was within
  one level of the expert's on 30 of 31 PRs.
- **It found serious risks nobody had listed.** For example, `stash eql upgrade --eql-version 3` runs a
  bundle that begins `DROP SCHEMA eql_v3 CASCADE`, which drops every customer column typed with an
  `eql_v3` domain (#547, all three runs). In #314, `stash-forge push` deactivates the active EQL config
  and then inserts a config whose `cast_as` values the EQL `CHECK` constraint rejects (verified against
  the bundled SQL). In the dev split, three findings were real defects the repository later fixed.
- **It is stable.** Across three runs of eight PRs, the attention verdict never changed, and impact
  changed on two PRs by one level. Of the 9 known defects in those PRs, 3 were found in all three runs,
  1 in two runs, and 5 in none.

## What it does not support

- **Merge gating.** Known-defect recall was 36% (4/11; interval 15–65%). It missed the most severe defect
  in the corpus in every run and condition: #547, where encrypted-column detection by `instanceof` fails
  across bundle copies and filter values reach PostgREST in plaintext. It also missed a jiti interop bug,
  a drizzle-kit type-quoting bug, duplicated classes across declaration builds, and dollar-quoted DDL
  being skipped. The misses are systematic, not noise, so rerunning will not recover them.
- **Calibration claims.** With 31 PRs and one non-blind adjudicator, no interval is narrow enough to call
  the impact ratings calibrated.
- **The deterministic evidence layer as a signal.** The history and path signals did not measurably help
  the agent (A, B and C are within noise of each other on every metric), and as a rule on their own they
  flag almost everything. Condition A (diff, checkout and title only) did as well as
  C. Keep `collect-evidence` in the skill because it is cheap and gives the agent pointers, but do not
  surface its output to reviewers as a risk score.

## How to use it now

1. **On demand.** A reviewer or author runs the skill locally (any agent that loads Agent Skills) on a
   PR that touches release workflows, migrations or installers, encryption paths, auth, or public API.
   The skill is at `change-risk-research/.agents/skills/change-risk/`.
2. **Read the verdict and the top scenario, not the score.** Treat `focused_review_required` and
   `changes_or_verification_required` as "a second reviewer should look at these scenarios". Treat
   scenarios marked `speculative` as prompts, not findings.
3. **Keep CodeRabbit** for line-level review.

## Before putting it in CI

The proposal is ready ([`ci-integration.md`](ci-integration.md), not active). It should wait for:

1. A second, human annotator on the 12 defect cases and the low-confidence ground truth.
2. A shadow-mode trial: run on every ready-for-review PR for about four weeks, publish nothing, and ask
   reviewers afterwards whether each assessment changed what they looked at.
3. PR-Agent run on the same corpus, once a provider is approved, so the cheaper option has been compared.
4. A cost decision. At the measured $1.51 per run and about 45 merged PRs a month (136 in the last 90
   days), one run per PR is roughly $70 a month on the model used here; one run per push is a multiple of
   that. A smaller model was not tested.

Never mark the check as required. The example workflow reports `neutral` rather than `failure` for
exactly that reason.

## Open questions

- Would a smaller model keep the precision and verdict quality at a fraction of the cost?
- Would a prompt that walks the specific runtime paths of encrypted data (where plaintext could escape
  encryption) find the #547 class of defect? This was deliberately not tuned on the holdout.
- Does PR-Agent's diff-only approach reach similar verdict quality for far less money?
