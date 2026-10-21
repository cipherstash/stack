# Analysis method in detail

## Budget and order of work

Spend effort in proportion to what the change can break, not to its size.

1. Read the full list of changed files and optional collector evidence.
2. Skim the whole diff once. Sort changes into: behaviour, refactor with no behaviour change, tests, docs, generated, configuration, dependency, build/release.
3. For behaviour, configuration, dependency and build/release changes: read the code around each hunk at both revisions.
4. For each behaviour change, search for its consumers at HEAD.
5. Only then write scenarios.

For a large diff, say which parts you read closely and which you only skimmed, in `coverage_limitations`. Prefer depth on the riskiest parts over shallow coverage of everything.

## Useful commands

```bash
git diff --stat $BASE $HEAD
git diff $BASE $HEAD -- path
git show $BASE:path | sed -n '40,80p'          # code before
git show $HEAD:path | grep -n 'functionName'    # code after, with line numbers
git grep -n 'symbol' $HEAD -- 'packages/*/src'  # consumers at HEAD
git log --oneline -n 20 $BASE -- path           # recent history (before the change only)
```

Never read history after `$HEAD` (e.g. `git log main`) when assessing a historical change: later commits reveal outcomes.

If you can run the project's tests without network access or secrets, you may run the ones that cover a scenario, and cite the result as `command_output`. Never run scripts that the change itself adds or modifies with credentials present.

## Writing scenarios

A good scenario is specific enough that a reviewer can check it in a few minutes:

> **FS-1 · Retries resend the webhook after a timeout** (high, plausible_failure)
> Trigger: the downstream endpoint responds after the 5 s client timeout.
> Mechanism: `send()` now retries on `TimeoutError` (`src/notify.ts:88`, head) but the request carries no idempotency key (`src/notify.ts:60-72`, head).
> Consequence: the customer's endpoint receives the same event twice; billing events are double-counted.
> Existing verification: `notify.test.ts` covers retry on 503 only (exists_not_run).
> Missing: a test for retry after timeout; a check that the receiver deduplicates.
> Mitigation: send an idempotency key; or retry only on connection errors before the request was sent.

A weak scenario names a category and a file ("this touches auth code, which could break authentication"). Leave those out.

## Calibration checks before you finish

- Would a maintainer of this code agree each scenario is caused by **this** change, not something already true at the base? Pre-existing problems belong in `coverage_limitations` or a short note in `summary`, not in `failure_scenarios`.
- Is any `high`/`critical` impact justified by a mechanism you cited?
- Did you mark anything as tested or passing without seeing a result?
- Did you list a dependency as `confirmed` without reading a reference?
- For a docs-only, test-only or trivial change, is the verdict `ready_for_review` with zero or one scenario? It usually should be.

## Output skeleton

```json
{
  "schema_version": "1",
  "repository": "owner/repo",
  "base_sha": "<40 hex>",
  "head_sha": "<40 hex>",
  "assessor": {"agent": "<agent>", "model": "<model id>", "skill_version": "1.0.0"},
  "inputs": {
    "diff": {"status": "available"},
    "source_checkout": {"status": "available"},
    "pr_description": {"status": "available"},
    "ci_results": {"status": "unavailable"},
    "architecture_docs": {"status": "partial", "note": "AGENTS.md at head"},
    "dependency_graph": {"status": "unavailable"},
    "codeowners": {"status": "available"},
    "history_signals": {"status": "available", "source": "collect-evidence 1.0.0"},
    "deployment_context": {"status": "unavailable"}
  },
  "summary": "…",
  "behaviour_changes": [],
  "impact": "low",
  "verification_confidence": "medium",
  "release_readiness": "ready_for_review",
  "affected_components": [],
  "failure_scenarios": [],
  "verification_gaps": [],
  "recommended_controls": [],
  "coverage_limitations": [],
  "evidence": []
}
```

Identifiers: `BC-n`, `AC-n`, `FS-n`, `VG-n`, `RC-n`, `CL-n`, `E-n`. The full contract is `schemas/assessment.schema.json`.

## Data paths and external contracts

For a change to a sensitive-value guarantee, trace one representative value from
input through transformation, encryption, serialization and its storage/network
boundary. Check what selects the protected path, and whether the guarantee survives
runtime/package boundaries. Cite the actual path before raising a scenario.

When correctness depends on a parser, language format, serializer, or third-party
consumer, identify the exact external contract and which boundary cases tests cover.
Use version-matched primary documentation or an executed focused reproduction when
available. If the repository cannot establish the external behaviour, record that
assumption as a coverage question and name the verification needed; do not promote
it to a defect. These are investigation prompts, not a specialized security review.
