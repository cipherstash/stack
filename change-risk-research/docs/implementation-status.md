# Completion pass — 2026-10-21

Implemented locally against PR #1296 head
`cf0e8b6f41a957fc32a02be83f7c5076fc82a753`, on `codex/change-risk-refinement`.
No PR comment, workflow activation or merge gate was performed.

## Changes

| Area | Files and result |
|---|---|
| Runtime skill | Canonical `.agents/skills/change-risk/`; Claude and historical-path symlinks; explicit PR/base-head invocation; no harness dependency |
| Correctness | `scripts/validate_assessment.py`, schema, `references/risk-model.md`: typed references, strict impact aggregation, explicit unknown policy, readiness justification, verified execution evidence, empty-file line bounds |
| Investigation/reporting | Collector defaults to no history; data-path/external-contract prompts; renderer moves hypotheses to coverage questions, links pinned source, and provides review actions |
| Tests | Skill suite 52 tests run, passing with two optional jsonschema skips; scoring suite three passed; actual sparse publishing fixture included |
| Metrics | Scoring/report-table scripts and new `*-v2.json`; scenario validity distinguished from defect detection; checked/pass/fail/unassessed evidence counts; original outputs retained |
| Research/docs | README normal-use workflow, recommendation, concise closed Qodo/CodeScene notes, missed-failure analysis, methodology amendment |
| Human review | `docs/human-review.md` and generator: 12 defect cases, A/B/C detection, fixes, extra risks, C disputes, full disagreement index, low-confidence truth and three controls; all human annotations blank |
| Retention | Nine bytecode files and 119 byte-identical regenerable reports removed; checksum manifests; all 150 unique transcripts retained; approximately 0.9 MB net reduction |
| Inactive CI | Trusted scripts and schema in publishing checkout, analysis validation output required, exact-head and stale checks, documented source-validation boundary; YAML remains under docs/examples |
| Repository guidance | AGENTS.md and SECURITY.md distinguish internal skill from packaged customer skills |

[Host smoke record](smoke/README.md): Claude Code and Codex each assessed a pinned
five-file real change; both final outputs passed schema, semantic and repository
path/line validation with no warnings. Initial failures are documented and the
invalid Codex response is preserved. Reports are readable without JSON.

Repository checks: Vitest script suite 79 files passed, 1,388 tests passed and 28
skipped; Biome no errors (196 warnings, 74 infos); `git diff --check` passed.
The installed Vitest binary ran after pnpm/Corepack cache access failed. Package
builds and live encryption tests were not applicable. Auxiliary skill-creator
validation lacked PyYAML; frontmatter/YAML parsing and real host discovery passed.

## Remaining acceptance and limits

Independent human adjudication of the prepared package remains required. Findings
have not been independently validated at production scale; important known defects
remain missed. This refinement used old evaluation evidence and claims no improved
recall or untouched holdout for 1.1. Four historical assessments fail stricter
semantics but remain unchanged and readable. Unique transcripts remain in Git
until a maintainer chooses accessible archive storage; the heuristic credential
scan found no matches and cannot guarantee absence of sensitive content.

Recommendation: use the skill on demand for consequential PRs, keep CodeRabbit for
general review, and use human judgement for merge decisions.
