# Qodo PR-Agent: risk assessment capability

Researched 2026-10-12 from the PR-Agent source at the pinned commit
(`330f0813b5fe0d1f54b794077c2d02aa85a1fb63`) and its documentation. Reproduction details are in
[`../eval/qodo/README.md`](../eval/qodo/README.md).

**Status: configured and checked up to the model call, not run.** Running it sends each diff and the
changed files to an LLM provider, and which provider may receive CipherStash source is CipherStash's
decision. It was asked in the project thread; there is no answer yet. Nothing in this document is a
PR-Agent result.

## What it offers (facts, from source)

PR-Agent's `review` tool asks one model call (more for large PRs, which it splits) to fill a fixed
YAML structure. Four risk-related fields are opt-in, all `false` by default
(`pr_agent/settings/configuration.toml`, lines 179–182):

| Setting | Output | Definition in the prompt |
|---|---|---|
| `require_risk_assessment` | `risk_level`: low / medium / high | high "only when the PR introduces a clear bug, security concern, or major logic risk"; medium "non-trivial areas that require careful human verification" |
| `require_merge_recommendation` | `no_concerns_found` / `needs_review` / `changes_required` | Can take a CI artifact into account when one is supplied |
| `require_failure_modes` | up to **3** `{what, where, trigger, detected_by, covered_in_this_pr}` | "grounded in the visible code rather than a speculative defect"; "Do not claim a test was executed" |
| `require_priority_files` | list of files to read first | |

Plus the long-standing `key_issues_to_review`, `security_concerns`, tests review and effort estimate.
`require_failure_modes` was added after the 0.47.0 release (commit `dac1cad`), so the PyPI release lacks
it; hence the pin to `main`.

## How it compares with the change-risk skill (design, not measured)

| | PR-Agent review | change-risk skill |
|---|---|---|
| Model access to the repository | The diff plus surrounding hunks / full changed files; no tools, cannot search callers | Agentic: reads any file at base or head, runs `git grep`, `git log`, `git blame` |
| History | None | Deterministic collector: churn, omitted co-change, ownership, dependency diff, history cut at the base |
| Impact scale | 3 levels; definitions mix "is there a bug" with "how bad" | 4 levels plus `unknown`, kept separate from verification confidence and release readiness |
| Failure scenarios | ≤3, each with trigger and detector | ≤5, each with trigger, mechanism, consequence, basis, cited evidence ids |
| Evidence | Free text `where` | Structured, line-ranged, revision-tagged, checked by a validator against the repository |
| Output contract | YAML parsed by PR-Agent; not schema-validated | JSON Schema plus semantic validator; invalid output is an error, not a result |
| Cost per PR | One or a few LLM calls (expected cents to tens of cents; not measured) | ~$1–2.4 per PR on the model used here (measured, `eval/comparison.md`) |
| Runs as | GitHub App, Action, CLI, or plain-diff mode with no Git provider | Any agent that loads Agent Skills; CLI in the harness |
| Providers | Any LiteLLM provider, including Anthropic, Bedrock, Vertex, Azure OpenAI and local models | Whatever runs the agent |

Inference: PR-Agent's failure modes are the closest open-source equivalent to the skill's scenarios,
and its single-pass design is much cheaper. Its limit is that it cannot look beyond the diff, and most
of the dev-split defects the skill found (e.g. the CLI runtime dependency in #336, the overrides block
pnpm ignores) needed a file outside the hunk to see. Whether that matters in practice is exactly what
the unrun comparison would measure.

## What would be measured

The harness (`harness/run_pr_agent.py`) runs PR-Agent in plain-diff mode from the same isolated
checkout as condition A, so it has no PR description, no CI and no history. Adjudication uses the same
labels: each `key_issues_to_review` entry and each failure mode is a finding; `attention` is
`risk_level == high` or a recommendation other than `no_concerns_found`; `risk_level` maps to impact
for agreement metrics (its 3 levels against the 4-level ground truth, with critical folded into high).

## Not evaluated

- **Qodo Merge** (the hosted product). It shares code with PR-Agent but differs in models, context
  gathering and hosted-only features; nothing here is evidence about it. Evaluating it means installing
  a GitHub App, which the handover rules out without approval.
- Running PR-Agent on live PRs or publishing its comments.
