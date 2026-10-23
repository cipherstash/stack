> Status: inactive proposal. Qodo/CodeScene evaluation, a shadow trial and CI
> activation are not part of on-demand adoption. No additional paid service is
> authorized. Any future activation needs its own decision and verified controls.

# CI integration proposal (not active)

**Status: proposal only.** Nothing here runs. The example workflow is
[`examples/change-risk-advisory.yml`](examples/change-risk-advisory.yml), deliberately outside
`.github/workflows`. Turning it on is a CipherStash decision, and it should wait for the evidence in
[`../eval/comparison.md`](../eval/comparison.md) and the conditions at the end of this page.

## What it would do

On each non-draft, same-repository pull request, assess the change at its exact head SHA with the
`change-risk` skill and publish **one** advisory result: a check run named `change-risk (advisory)` and a
single sticky comment that is edited in place on later pushes.

| Outcome | When | Check conclusion |
|---|---|---|
| `pass` | Valid assessment, readiness `ready_for_review` | `success` |
| `attention` | Valid assessment, readiness `focused_review_required` or `changes_or_verification_required` | `neutral` |
| `inconclusive` | Valid assessment, readiness `insufficient_evidence` | `neutral` |
| `error` | The assessor failed, hit its budget, or produced output that failed validation | `neutral` |
| `stale` | The PR head moved while assessing | nothing is published; the newer run reports |

The check never concludes `failure`. That is the lesson of the existing
[`claude-review.yml`](../../.github/workflows/claude-review.yml), which is switched off because a turn
limit, a cancellation or an API error marked pull requests with a failed check. An assessor problem says
nothing about the change and must not look like a finding about it.

## Security design

It reuses the patterns already in `claude-review.yml` (Anthropic workload-identity federation, a pinned
`anthropics/claude-code-action`, `github_token` set to the job token, base-branch instructions) and adds a
split between reading and writing.

| Concern | Control |
|---|---|
| Untrusted code and diffs steering the agent | Two jobs. `assess` reads the PR but holds only `contents: read` and `id-token: write`; it has no token that can comment, label, push or create checks. `publish` can write a comment and a check but checks out **only base-branch scripts** and never executes PR code |
| PR rewriting the assessor's instructions | The skill, its references and `AGENTS.md` are copied from the **base** SHA into the workspace after `.claude`, `AGENTS.md` and `CLAUDE.md` from the PR are deleted |
| Forged or malformed output | `publish` re-validates the artifact with the **base** branch's validator, passing `--expected-base` and `--expected-head` so that both `base_sha` and `head_sha` inside it must equal the merge base and head SHA `assess` computed (`assess` applies the same check before uploading) |
| Assessing the wrong revision | Checkout is by `pull_request.head.sha`, not the branch. The SHA is pinned as a job output and travels with the artifact name |
| Stale results | `concurrency` cancels older runs on a new push; because cancellation is best-effort, `publish` also compares the assessed SHA with the PR's current head and publishes nothing if they differ |
| Network and exfiltration from the agent | `WebFetch`, `WebSearch`, `Task`/`Agent` and `NotebookEdit` are disallowed. Bash is an allowlist of read-only `git` subcommands and the skill's own scripts. File writes are allowed only by `Edit(//<runner temp>/out/**)`; Claude Code file rules use `Edit(path)`, which also governs `Write`, and a `Write(path)` rule is ignored. No other path is writable because tools outside the allowlist are denied in non-interactive mode. `.git/config` (where the action writes its token) is unreadable |
| Forks | Skipped (`head.repo.full_name == github.repository`), as in `claude-review.yml`. Supporting forks needs `pull_request_target` and a different design; not proposed |
| Cost runaway | `--max-budget-usd` and `--max-turns` on the agent, `timeout-minutes` on both jobs, `paths-ignore` for changesets and Markdown |
| Supply chain | Actions pinned to a full commit SHA for the third-party action; the two `actions/*` steps should be pinned the same way before activation (`claude-review.yml` uses `actions/checkout@v6` by tag; the repository's own lint rules decide) |
| Comment content | The report is model output derived from untrusted input. It is published as a PR comment only; it is never executed, used as a label, or fed to another job. `render_report.py` treats every model-written string as untrusted: prose is kept on one line with Markdown and HTML neutralised and `@` mentions broken by a zero-width space, and paths and commands are shown as code spans |
| Data sharing | The diff and repository files go to the Anthropic workspace configured by the federation variables, the same data flow `claude-review.yml` already has. No other provider |

What it does **not** give the agent, and why that matters for the results: CI results (they are not
finished when the assessment starts) and the PR description (excluded to keep the untrusted surface small
and because condition B, which has neither, is what the evaluation measured closest). Adding CI would
need a second trigger on `check_suite: completed`, and the evaluation of condition C is what says whether
that is worth it.

## Activation conditions

Turning this on should require all of:

1. The holdout results in `eval/comparison.md` support it: at minimum, attention on most high-impact
   cases, an unsupported-finding rate a reviewer will tolerate, and no fabricated test results.
2. A second, human annotator has reviewed the ground truth for the defect cases (see
   `research/methodology.md` §3).
3. CipherStash has approved sending repository content to the configured Anthropic workspace for this
   purpose (it already does so for `claude-review.yml`, but that workflow is disabled).
4. A repository variable `CHANGE_RISK_ENABLED` is set to `true`, so it can be switched off without a PR.
5. A complete `assess` job has been dry-run under the exact `--allowedTools` and `--disallowedTools`
   above, and wrote and validated `assessment.json`. The recorded smoke tests did not do this: the
   successful Claude run returned JSON on stdout with no write rule at all.
6. It is **not** added to branch protection as a required check. Merge gating is out of scope, and the
   evaluation sample cannot show that the verdicts are calibrated enough to gate on.

## Moving the skill

The workflow reads the canonical `.agents/skills/change-risk` at the trusted base SHA.
Both sparse checkouts use that location; publishing includes scripts and schema.
The root `skills/` directory ships to customers inside the `stash` npm tarball and
is separate from this internal skill.


## Validation boundary after the completion pass

The publish checkout includes both trusted base-branch `scripts/` and `schemas/`
under `.agents/skills/change-risk`. Publishing validates structure and semantic
relationships without `--repo`; it does **not** independently verify source paths,
line ranges, test execution or the truth of claims. The analysis job runs the
trusted validator with `--repo` and passes its `evidence_valid` job output; a
missing/false result produces a neutral assessment error. Source existence and
line bounds still do not prove a claim's meaning or that tests actually passed.

Publishing checks the artifact's head SHA against the pinned assessed SHA and
suppresses results when the current PR head differs. Keep analysis read-only,
trusted base instructions, execution budgets and timeouts, separate publishing,
and neutral errors. A head can move after the final freshness check; exact-SHA
check association limits this race but cannot make a comment atomic with pushes.
The fixture tests exercise the publishing shell from its actual sparse layout,
including invalid, stale and wrong-head artifacts. No live GitHub write is tested
or enabled. This file remains outside `.github/workflows`.
