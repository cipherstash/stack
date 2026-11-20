# PR-Agent baseline: environment and reproduction

## What is being evaluated

The open-source **PR-Agent** (`The-PR-Agent/pr-agent`), not the commercial Qodo Merge. The two share a code base but differ in hosted features, models and defaults; nothing here is evidence about Qodo Merge.

## Pinned version

| | |
|---|---|
| Repository | https://github.com/The-PR-Agent/pr-agent |
| Commit | `330f0813b5fe0d1f54b794077c2d02aa85a1fb63` (main, 2026-10-11) |
| Package version string | `0.47.0` (unchanged on main) |
| Why not the 0.47.0 release | `require_failure_modes` was added in `dac1cad` (2026-10-09, "feat(review): add opt-in failure modes (#4012)"), after 0.47.0. The PyPI 0.47.0 wheel has `require_risk_assessment`, `require_merge_recommendation` and `require_priority_files` but **no failure-modes option**, although the documentation already describes it. |

## Install

```bash
git clone https://github.com/The-PR-Agent/pr-agent pr-agent-src
git -C pr-agent-src checkout 330f0813b5fe0d1f54b794077c2d02aa85a1fb63
python3 -m venv pra && ./pra/bin/pip install ./pr-agent-src
```

## Configuration

`eval/qodo/pr_agent.toml` enables risk assessment, failure modes, merge recommendation, priority files, tests review and security review, with `num_max_findings = 5`. Verified to load with the pinned build by running PR-Agent's `config` command in plain-diff mode (no model call):

```
pr_reviewer.require_risk_assessment = True
pr_reviewer.require_failure_modes = True
pr_reviewer.num_max_findings = 5
```

## Run

Plain-diff mode, from inside an isolated checkout at the PR head so PR-Agent reads full files (it reverse-applies the diff to get the base). No GitHub token is used and nothing is posted anywhere.

```bash
export ANTHROPIC__KEY=...           # or the approved provider's variable; never written to disk
python3 harness/run_pr_agent.py --model anthropic/<model-id> --pr 314 --pr 349 ...
```

Per case it writes `results/stack-<N>/review.md`, `review.json` (parsed review plus token usage), `stderr.txt` and `run.json` (commit, model, command, time, usage).

## Status

**Not run.** This container has no LLM provider key, and running PR-Agent sends each diff and the changed files to the configured provider. Which provider is approved for CipherStash source is the user's decision; it was asked in the project thread on 2026-10-12. Everything up to the model call is in place and checked.
