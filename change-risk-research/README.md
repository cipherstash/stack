# PR change-risk assessment: research and prototype

Research, a prototype agent skill and an evaluation harness for assessing the release risk of a pull
request in `cipherstash/stack`. Nothing here is wired into CI or touches production code.

| Path | What it is |
|---|---|
| [`docs/final-recommendation.md`](docs/final-recommendation.md) | The answer: what to adopt, what not to, and why |
| [`eval/comparison.md`](eval/comparison.md) | Results: metrics with intervals, successes, false positives, misses, cost |
| [`research/methodology.md`](research/methodology.md) | Pre-registered corpus, reconstruction, leakage controls, labels and metrics |
| [`research/codescene.md`](research/codescene.md) | CodeScene delta analysis research (documentation only; no access) |
| [`research/qodo.md`](research/qodo.md) | PR-Agent risk-assessment research (configured, not run) |
| [`docs/ci-integration.md`](docs/ci-integration.md) | Proposed advisory workflow, **not active** ([example](docs/examples/change-risk-advisory.yml)) |
| [`.agents/skills/change-risk/`](.agents/skills/change-risk/) | The portable skill: `SKILL.md`, references, JSON schema, evidence collector, validator, renderer, tests |
| `eval/corpus.json`, `eval/selection.json` | 41 historical PRs (12 with a validated later defect), dev/holdout split |
| `eval/ground-truth/` | One file per case, written before any evaluator ran |
| `eval/change-risk/results/` | Every skill run: assessment, rendered report, full transcript (`transcript.jsonl.gz`), cost and audit |
| `eval/adjudication/` | Per-finding labels for every evaluator |
| `eval/adjudication-blind/`, `eval/agreement.json` | Blind second adjudication of every holdout finding and its agreement with the first |
| `eval/deterministic/` | Collector output and the rule-based baseline |
| `eval/coderabbit/`, `eval/pr-descriptions/`, `eval/ci/` | Historical CodeRabbit comments, PR text and check runs, collected read-only |
| `harness/` | Corpus building (SZZ), case isolation, runners, scoring |

## Reproduce

```bash
# skill unit tests (stdlib only)
cd .agents/skills/change-risk/scripts && python3 -m unittest discover -s tests

# one case, condition C (needs the claude CLI, an API credential and util-linux unshare)
python3 harness/run_evaluation.py --condition C --pr 314

# score
python3 harness/score_results.py --split holdout
```

The skill is kept under `change-risk-research/.agents/skills/` on purpose. The repository's root
`skills/` directory ships to customers in the `stash` npm tarball; this one does not.
