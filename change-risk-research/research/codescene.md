# CodeScene: delta analysis and what can be reproduced without it

Researched 2026-10-12 from CodeScene's public documentation. **No CodeScene account, licence or trial was available to this project, so no CodeScene analysis was run.** Nothing below is a CodeScene result; where this document reports numbers they come from this project's own collector.

Sources:
[Automated delta analyses](https://docs.enterprise.codescene.io/latest/guides/delta/automated-delta-analyses.html) ·
[CLI command reference](https://codescene.io/docs/cli/command-reference.html) ·
[CLI overview](https://codescene.io/docs/cli/index.html) ·
[Language support](https://codescene.io/docs/usage/language-support.html)

## 1. Two different things called "delta"

| | CodeScene platform delta analysis | `cs delta` (CLI) |
|---|---|---|
| Where it runs | CodeScene Cloud or Enterprise, triggered by PR webhooks / GitHub App, or its REST API | Locally, in hooks, or in CI |
| Needs | A CodeScene project that has analysed the repository's history | A CodeScene sign-in (`cs auth login`) or `CS_ACCESS_TOKEN` from a project admin |
| Risk classification | Yes: a "risk profile" from technical factors (depth and diffusion of the change) and social factors (the author's experience in the repository, measured from history). Docs refer to risk categories but do not publish the scale or formula | **Not documented.** The CLI reference describes delta only as comparing current work to a previous state |
| Quality gates | Hotspot goals; code-health decline; low health in new code; **absence of expected change** (temporal coupling); positive reinforcement on improved hotspots | Reports **new code-health issues only** when machine-readable output is requested ("no improvements or explanations") |
| Change coupling | Yes ("absent change patterns" warning, self-clearing as coupling decays) | Not documented |
| Knowledge / ownership | Mentions code owners when a gate fails; links to knowledge distribution | Not documented |
| Output | PR comment / GitHub check; API | `--output-format json` or `edn`; `--include-metadata` wraps results with scope, status and file counts. **Field names are not documented** |

So: the CLI's JSON should be treated as a **code-health delta**, not as the platform's historical risk model. The handover's warning about conflating the two is borne out by the documentation.

Other notes from the docs:
- Platform delta uses a full scan for PR integrations; API requests fall back to a hotspot-only scan above 50 files unless `DELTA_ANALYSIS__LIMIT_DELTA_SCAN_TO_MAX_FILES` is raised.
- Rust, Go, TypeScript and JavaScript have full support (code health, hotspots, change coupling, method-level X-Ray). SQL, YAML and shell are not listed; "all text-based content" gets file-level hotspots, coupling and knowledge metrics, which may or may not include them.
- The CLI docs do not say whether source is sent to CodeScene servers. Sign-in is required, so at minimum it contacts them. Treat it as a SaaS data flow until confirmed otherwise.
- Pricing and licensing terms are not on the documentation pages; third-party listings exist but were not treated as authoritative.

## 2. Can it be used here?

| Question | Answer |
|---|---|
| Licensed or on trial? | Not that this project could find. No CodeScene config, workflow or app reference exists in `cipherstash/stack` (searched `origin/main` for "codescene"). |
| API exposing recommended review levels? | The platform has a delta API. Not verified, no access. |
| Historical commits? | The CLI takes two refs (`cs delta main~30 main`), so code-health delta for a historical base..head is possible in principle. Platform risk for an old PR would need the platform to have history up to that point; whether it can be computed "as of" a past date is not documented. |
| Full history needed? | Platform: yes for hotspots, coupling and author experience. CLI code-health delta: not documented; likely only the two revisions. |
| Self-hosted? | CodeScene Enterprise exists (`CS_ONPREM_URL`). |
| Data sharing | Requires a CodeScene account; repository content or metrics go to CodeScene Cloud unless self-hosted. Needs the same provider approval as any SaaS. |

**To proceed with a real CodeScene evaluation**: someone at CipherStash would need to start a trial (a paid-service decision, out of scope for this project without approval), connect `cipherstash/stack` or install the CLI with an access token, and run `cs delta --output-format json --include-metadata <base> <head>` for each corpus case. `harness/` would need a small runner like `run_pr_agent.py`. Expect to receive code-health findings, not a risk level.

## 3. What this project reproduced instead

`collect-evidence` (`.agents/skills/change-risk/scripts/collect_evidence.py`) implements the transparent subset of CodeScene's model that git can supply, with history cut at the base:

| CodeScene concept | Collector signal | Limitation |
|---|---|---|
| Change diffusion / depth | `change_size`, `dispersion.components` (nearest package manifest), `top_level_dirs`, `languages` | Components are manifest directories, not runtime boundaries |
| Hotspots | `churn.hotspots`: commits per changed file over base ancestry, recent window, distinct authors | No code-health score; lockfiles dominate unless filtered by class |
| Temporal coupling, absence of expected change | `co_change.omitted_co_changes`: confidence = co-commits / commits touching the changed file; bulk commits (>40 files) ignored | Support threshold is arbitrary (3); subtree imports and renames distort counts |
| Author experience | `ownership.author_familiarity`: prior commits by the PR's authors touching the changed files | Emails are anonymised in output; squash/merge workflows and bots skew it; contextual only |
| Code owners | `ownership.owners_by_file` from CODEOWNERS at base | Most of this repository maps to one team |
| — (not CodeScene) | path classes (security, schema, CI/release, public API…), manifest dependency diffs, name-based test mapping | Regex classes over-match (see below) |
| Code health delta | **Not reproduced.** It needs a maintainability model per language; building one would be a CodeScene clone, which the handover rules out | |

Tests: `scripts/tests/test_collect_evidence.py` (12 tests), including a leakage test that fails if any commit after the base is counted.

## 4. Validation findings

Run over all 41 corpus cases (`eval/deterministic/results/`; 13 s total, no network, no cost).

A deliberately simple rule was fixed before scoring (`harness/deterministic_baseline.py`, rule v1): flag for attention if a non-test file is security- or serialization-classed, a schema file or CI/release file changes, a runtime dependency changes, three or more components are touched, a strong co-change is omitted, or more than 400 non-test lines change.

It flagged **36 of 41** cases, including **all 12** defect cases, **19 of 24** controls that are not expert-rated high, and **7 of 12** expert-low cases (see `eval/comparison.md` for the scored numbers). That is the expected behaviour of path- and size-based rules in a repository where almost everything touches encryption, authentication, schemas or release tooling: the signals separate "docs/lockfile-only" from "everything else" and very little beyond that. Specific weaknesses seen:

- The `security_sensitive` and `serialization_or_protocol` path regexes match most of `packages/stack/src` (`encrypt`, `schema`, `format`).
- `database_schema` matched `packages/drizzle/package.json` because the package is named `drizzle`.
- A strong omitted co-change (rule R6) fired on 15 cases. In #301, the one inspected closely, the omitted partners were a CHANGELOG, a type test and an index re-export: plausible prompts, not risk evidence.

## 5. Recommendation

- **Do not integrate CodeScene for change-risk on present evidence.** Its distinctive value (code-health model, calibrated historical risk) could not be evaluated without a trial, and the documented CLI output is a code-health delta that overlaps with what CodeRabbit already comments on. Revisit only if CipherStash already licenses CodeScene for other reasons; then run `cs delta` on this corpus with the existing harness and compare.
- **Keep three deterministic signals** as evidence for the agent, not as a gate: change size/dispersion, omitted co-change (as a prompt to check, never a finding), and the dependency diff. Whether they help the agent is measured by the A/B ablation in `eval/comparison.md`.
- **Do not use the attention rule** as a CI signal: it flags nearly every PR in this repository.
