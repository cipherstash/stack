# Evaluation methodology

Written on 2026-10-12, before any evaluator output was scored. Changes after scoring are listed at the end with their reason.

## 1. Corpus

**Repository.** `cipherstash/stack` (TypeScript, Rust, Go, SQL, CI/release YAML). Full history was fetched (6,232 commits; 546 PR merge commits on `main`).

**Finding defect-introducing PRs (SZZ, then manual validation).**

1. List every merged PR whose title starts with `fix` (`gitutil.pr_merges` in `harness/gitutil.py`).
2. For each fix PR, take its review-time diff and `git blame` (at the fix's base) every source line it deletes or modifies, skipping tests, docs, changesets and lockfiles (`harness/szz.py`). Map each blamed commit to the PR that merged it.
3. Read the fix PR description and diff, and the candidate introducer's diff, and keep a pair only when the introducer **added** the faulty lines (not merely moved them) and the fix describes the failure. Candidates rejected at this step are listed in `eval/selection.json` (`excluded`), e.g. #43, which SZZ blamed for #58 but which only moved existing lock-context code.
4. One defect (#547, plaintext filter operands through the Supabase adapter) was found by reading a code comment in a later fix and tracing the commit (`41a04a6`) by `git log -S`, not by SZZ.

**Controls.** PRs with no known later defect, chosen to cover: encryption and public API, authentication and token handling, database migrations, release and CI pipelines (including retry and ordering), dependency upgrades, documentation and refactoring. "No known defect" is not "risk-free": scenarios reported on controls are adjudicated individually.

**Size limit.** PRs above roughly 150 files or a 30k-line hand-written diff were excluded (#885, #286, #535) because a per-case agent budget cannot cover them; this biases the corpus away from very large changes and is a limitation. #547 (92 files, +120k lines, most of it a vendored SQL bundle) was kept as a deliberate stress case.

**Result.** 41 cases: 12 with a validated defect, 29 controls. 10 cases are the **dev** split (may be used to adjust the skill); 31 are **holdout** (never used to adjust it). Split fixed in `eval/selection.json` before any run.

Gaps the corpus cannot cover from this repository: multi-region / distributed-state behaviour and event processing. `cipherstash/stack` is a client SDK and release monorepo; the ZeroKMS and CTS services are not in it.

## 2. Historical reconstruction

For a PR merged by merge commit `M` with parents `P1` (base branch tip) and `P2` (PR head), the case pins `base = merge-base(P1, P2)` and `head = P2`. That is the three-dot diff GitHub showed reviewers at merge time. It is exact for the final head; earlier review rounds are not reconstructed (`baseline_caveat` in `eval/corpus.json`).

**Leakage controls.**
- Each evaluator run gets a fresh git repository containing **only the ancestry of `head`** (fetched by sha; no refs, no remotes). The isolation check in `prepare_case.py` fails the run if any other commit is present.
- `collect-evidence` reads history from ancestors of `base` only. A unit test fails if commits after the base are counted (verified by mutation: replacing the base with `--all` fails it).
- The skill evaluator runs inside a private mount namespace where this research directory, the orchestrating session's scratchpad and all Claude session transcripts are hidden by empty tmpfs mounts; git is limited to the `file` protocol; MCP servers are disabled; WebFetch and WebSearch are disallowed. Every transcript is audited for network-looking commands and paths outside the case.
- PR descriptions are given only in condition C, with review-bot output removed. They are the current GitHub text, so a description edited after merge could carry later information; this is a residual risk, noted per case if found.
- Ground truth (`eval/ground-truth/`) is never copied into a case directory.

**Residual leakage that cannot be removed.** The person (here, an agent) who selected the corpus, wrote the ground truth and wrote the skill is the same. The skill's reference prompts were reviewed after the corpus was built and every prompt that encoded a specific corpus defect mechanism was generalised (e.g. "removing `| null` from a type removes a runtime guard" became "does runtime behaviour still match the type for callers that bypass it"). Some contamination of the method by knowledge of the corpus is still likely. Model training data may also include this public repository's history. Both bias results upward for the skill.

## 3. Ground truth

One file per case. Fields: `outcome` (`defect` / `no_known_defect`), `known_defects[]` (each with mechanism, the fixing PR, **match criteria** and its own impact), `expert_impact` (worst plausible consequence of the change; for defects, the consequence of the observed defect), `attention_warranted`, `impact_confidence`, and a rationale.

Distinctions kept:
- **Observed** defects (fixed later, with a link) versus **expert-assessed** impact (a judgement).
- One defect (#666) is a **latent** risk raised in review and deferred, never an incident.

**Annotators.** One (the research agent). The handover asks for two independent reviewers on ambiguous or high-impact cases; that has **not** happened yet. Every `expert_impact` with `impact_confidence: low` and every defect case should get a second, human review before results are relied on. Disagreements and their resolution go in the case file.

## 4. Conditions and evaluators

| Evaluator | What it sees | Notes |
|---|---|---|
| CodeRabbit (historical) | What it saw on the real PR | Collected from the PR's review comments; no rerun possible |
| PR-Agent | Diff, run from the head checkout (full-file context) | Needs an approved LLM provider; see `research/qodo.md` |
| Deterministic rule v1 | Collector output only | Attention flag only; cannot name scenarios |
| change-risk A | Diff + checkout + title | Ablation |
| change-risk B | A + deterministic evidence | Ablation |
| change-risk C | B + PR description + CI check runs | Main condition |

The main comparison uses holdout cases only.

## 5. Adjudication (pre-registered)

Each reported finding (a skill failure scenario, a PR-Agent key issue or failure mode, a CodeRabbit comment) gets exactly one label:

| Label | Rule |
|---|---|
| `match` | Same mechanism and same consequence class as a known defect, per that defect's `match_criteria`. Naming the subsystem or file of a known defect is **not** a match. |
| `valid` | Not a known defect, but technically plausible, caused by this change, and supported by the code it cites (cited lines spot-checked). |
| `unsupported` | The mechanism is not supported by the cited code, or the finding is not shown to be caused by this change. |
| `incorrect` | Factually wrong about what the code does, or describes a pre-existing condition as caused by the change. |
| `trivial` | True but immaterial to release risk (style, naming, comment wording). |

Also per finding: `evidence_ok` (do the cited locations exist and show what is claimed) and `actionable` (for match/valid only: does it propose a verification or mitigation a maintainer could do).

Per case: the evaluator's overall impact (if it gives one) and whether it asked for more than routine review (`attention`): for the skill, a verdict of `focused_review_required` or `changes_or_verification_required`; for PR-Agent, risk `high` or a recommendation other than `no_concerns_found`; for CodeRabbit, at least one non-nitpick finding labelled `match` or `valid` (it gives no overall rating, so its attention is inferred from findings).

Adjudication is done by reading the code at the case revisions. It is **not blind**: the adjudicator knows the ground truth. That is unavoidable with one adjudicator and is recorded as a limitation.

## 6. Metrics

Computed by `harness/score_results.py`, all with counts and Wilson 95% intervals.

- Scenario precision: (match + valid) / findings; also excluding trivial.
- Known-defect recall and defect-case recall.
- High-impact attention: of cases with expert impact high/critical, the share where the evaluator asked for attention **and** (if it rates impact) rated it high or critical.
- False-positive burden: unsupported + incorrect findings per case.
- Low-impact over-flagging: of expert-low cases, the share rated high or critical.
- Impact agreement: exact, within one level, quadratic-weighted kappa.
- Evidence quality and actionability, as defined above.
- Cost (USD, from the CLI's own accounting) and wall-clock time.
- Stability: a subset is run three times; agreement on impact and verdict, and overlap of matched defects.

## 7. Targets (from the handover; experimental, not standards)

≥80% material findings valid; ≥80% of high-impact cases get attention; ≤1 unsupported finding per case on average; every high-impact finding has evidence and a mitigation; no systematic over-flagging; no fabricated test results or dependencies. With 31 holdout cases, an observed 80% has a 95% interval of roughly ±14 points; none of these targets can be shown to hold with confidence at this sample size.

## Changes after scoring

1. **Post-hoc known defects (2026-10-12, during dev-split adjudication).** Three evaluator findings on dev cases described real defects that ground truth had missed and that the repository later fixed: #119 hyphenated field keys in bulk model reconstruction (fixed in the stack copy by #548), #336 the CLI binary importing `@cipherstash/stack` at runtime while declaring it only as a devDependency (commit `aa06dd126`), and #336 security overrides moved to an npm-format block pnpm ignores (commit `d2322980e`). They were added to the ground-truth files with `added_post_hoc: true`. Findings that describe them keep their pre-registered label (`valid`) and carry `post_hoc_matches`. **Pre-registered metrics exclude them**; `score_results.py --include-post-hoc` reports recall with them. The same check is applied to holdout findings: a finding that names a defect later fixed in the repository is recorded the same way, never relabelled.
2. **Audit rule refinements (before any holdout result was read).** The transcript audit first flagged the evaluator's own scratchpad, its own session directory (where the CLI writes long tool output) and `https` strings inside the assessment it wrote. These are not access outside the case. The rules were narrowed and `harness/reaudit.py` re-ran them over every finished transcript. Remaining flags are read by hand and listed in `eval/change-risk/audit-review.md`.
3. **No skill changes after the dev split.** All ten dev runs produced valid output and invoked the skill, so there was no implementation defect to fix. The dev misses (#336, #878, #119 known defects; #548 rated low) were judged to be ordinary recall misses, not method defects; changing the skill to target them would have tuned it to the dev set. Holdout runs use the same skill revision as dev.
4. **CodeRabbit labelling rules (2026-10-12, before its labels were compared with the skill's).** CodeRabbit reviewed intermediate pushes, so duplicate comments on the same issue are counted once, and comments it marked as nitpicks default to `trivial` unless they describe a behaviour change. Its findings are scored against the final head's known defects. It reviewed 19 of the 31 holdout PRs; the other 12 have no CodeRabbit adjudication. Labels and rules are in `harness/adjudicate_coderabbit.py`.
5. **Strict reading of `match`.** A finding counts as a match only when it names the known defect's failure, not when it points at the same code for a different reason. Adjacent findings (#349 FS-2/FS-3; #1002 condition B FS-2) are labelled `valid`, not `match`. This lowers recall for every condition equally.
6. **Rate-limit interruption.** Running twelve evaluators at once hit API rate limits; several runs waited for hours and hit the 3600 s timeout. Those runs were discarded and rerun at a concurrency of three, from the same case directories and the same skill revision. No completed run was rerun or replaced.
7. **Stability subset and condition A coverage.** The stability subset (three runs of condition C) is 6 of the 8 holdout defect PRs and 2 high-impact controls. Condition A was completed for all 31 holdout PRs, so the ablation compares the same cases in every condition.
8. **Blind second adjudication (2026-10-13, after the results were written).** At the user's request every holdout finding was labelled again by a second adjudicator blind to the first labels, evaluator names and expert impact (`harness/blind_rescore.py`, results in `eval/adjudication-blind/` and `eval/agreement.json`). The first labels stay the pre-registered result; the blind labels are reported beside them in `eval/comparison.md`, not substituted.
