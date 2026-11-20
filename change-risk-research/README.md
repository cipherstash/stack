# On-demand change-risk assessment

Use `change-risk` for evidence-backed impact assessment of consequential PRs.
Keep CodeRabbit for general code review and use human judgement for merge decisions.
Nothing here activates a workflow, publishes comments, or adds a merge gate.

## Normal use

Open an existing checkout in Claude Code or Codex and ask:

> Assess the release risk of PR #1296 using change-risk.

Or, without GitHub access:

> Assess change risk between BASE_SHA and HEAD_SHA using change-risk.

Both commits must exist locally. For PRs the agent uses existing GitHub tooling
(for example `gh pr view 1296 --json baseRefOid,headRefOid`), fetches missing commits
when authorized, and assesses the merge-base-to-head diff. Direct revision input
compares the exact supplied base/head. The agent inspects code, writes
`assessment.json`, validates it against the repository, and renders `report.md`.
Read the report first; it names consequences, supporting source, missing
verification and concrete reviewer actions. No hand-written input JSON or `harness/`
is needed. Missing inputs and uncertain external contracts stay explicit.

Canonical source: [`../.agents/skills/change-risk`](../.agents/skills/change-risk).
Codex discovers this repository-local directory; Claude uses the tracked
`.claude/skills/change-risk` symlink to it. Start a new agent session after updating
the checkout. The old research-local path is a compatibility symlink, not another
editable copy. Git checkouts must preserve symlinks; on hosts that cannot, install
one copy of the canonical directory into the host's supported skills location.
For another repository, install that same skill directory or explicitly give the
agent its absolute `SKILL.md` path. The skill only needs Git and Python 3.9+.
See [official Codex skill documentation](https://learn.chatgpt.com/docs/build-skills).

The root customer `skills/` directory is deliberately untouched: the CLI's
`tsup.config.ts` copies it into `dist/skills`, and its npm `files` includes `dist`.
`.agents/skills` is outside that packaging path. No customer package or changeset
is required. The skill has no runtime dependency on Qodo, CodeScene, the evaluation
corpus, ground truth, transcripts, or a new provider/service.

Optional helpers, from the repository root:

```bash
SKILL_DIR="$PWD/.agents/skills/change-risk"
"$SKILL_DIR/scripts/collect-evidence" --repo . --base "$BASE" --head "$HEAD" --repository owner/repo --out /tmp/evidence.json
"$SKILL_DIR/scripts/validate-assessment" /tmp/assessment.json --repo .
"$SKILL_DIR/scripts/render-report" /tmp/assessment.json --out /tmp/report.md
```

History is disabled by default. Add `--max-history 500` only when historical
coupling can identify a component to investigate. Size, filenames, author
familiarity and test-name matches are hints, never risk scores or proof of coverage.

## Verification and host smoke tests

Exact invocations, results, limitations, and the real assessment are recorded in
[smoke results](docs/smoke/README.md). Both installed hosts produced assessments that passed strict validation on a small
real change; their initial sandbox limitations are documented there.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s .agents/skills/change-risk/scripts/tests
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s change-risk-research/harness/tests
```

Tests include typed references, impact/readiness invariants, deleted-file revisions,
line ranges, execution claims, optional history, report rendering and execution of
the inactive CI publishing shell in its sparse filesystem layout. They never publish.

## Evaluation and historical evidence (optional)

- [Recommendation](docs/final-recommendation.md) and [v2 comparison](eval/comparison.md).
- [Methodology](research/methodology.md): v1 protocol plus the explicitly versioned v2 amendment.
- [Human review packet](docs/human-review.md): independent human review is still required.
- [Missed failure modes](docs/missed-failure-modes.md): small method changes, no fresh recall claim.
- [Artifact retention](docs/artifact-retention.md): checksums, provenance, and validation audit.
- [Inactive CI proposal](docs/ci-integration.md): future design only, outside `.github/workflows/`.
- `eval/corpus.json`, `eval/ground-truth`, assessments and both adjudications retain the experiment.

Recompute metrics from recorded outputs (no new model calls):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 change-risk-research/harness/report_tables.py
PYTHONDONTWRITEBYTECODE=1 python3 change-risk-research/harness/score_results.py --split holdout --adjudication change-risk-research/eval/adjudication-blind --out change-risk-research/eval/results-blind-v2.json
PYTHONDONTWRITEBYTECODE=1 python3 change-risk-research/harness/prepare_human_review.py
PYTHONDONTWRITEBYTECODE=1 python3 change-risk-research/harness/audit_record.py
```

Apply repository JSON formatting to regenerated v2 summaries/audit before committing.
Original v1 summaries, assessment bytes and labels remain unchanged. The stricter
validator rejects four recorded assessments; the audit lists why. They remain
readable rather than silently rewritten. The 1.1 skill was informed by these
results, so this corpus is no longer an untouched holdout for that revision.

Historical model-run reproduction uses `harness/run_evaluation.py` and requires
the original Linux isolation environment, existing Claude credentials, exact case
revisions and the 1.0 skill at reviewed revision
`cf0e8b6f41a957fc32a02be83f7c5076fc82a753`. Running the current 1.1 skill creates a
new experiment and cannot reproduce the original one. This harness is optional,
not part of normal use. Qodo and CodeScene are closed historical research options.
