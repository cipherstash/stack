# Advisory ImpactGate rollout evidence

Calibration date: 2026-10-08. This implements [Stack issue #1137](https://github.com/cipherstash/stack/issues/1137). No branch-protection or existing FTA/CRAP policy changes are intended.

## Tool and source provenance

- Stack base: `14bcc638769504ebc4dbb062d0c48fa7e935fe43`.
- Hyper reproduction source: `cd294f1c02e9718c7627a8d7fe7dd35ecd3ee407`, `.scratch/impact-gate/issues/05-reduce-the-lizard-typescript-span-defect.md`.
- Installed and exercised: `impact-gate==0.4.1`, `lizard==1.23.0`. Lizard 1.24.0 is excluded by upstream ImpactGate package metadata; it is not an upgrade candidate for this rollout.
- Local measurement runtime: Python 3.13 on macOS arm64. Dependencies resolved during calibration: PyYAML 6.0.3, pygments 2.21.0, pathspec 1.1.1. Runtime timings are local evidence, not hosted-runner guarantees.
- Official release source: [CLI](https://github.com/officefloor/ImpactGate/blob/v0.4.1/impact_gate/cli.py), [baseline](https://github.com/officefloor/ImpactGate/blob/v0.4.1/impact_gate/baseline.py), [measurement scope](https://github.com/officefloor/ImpactGate/blob/v0.4.1/impact_gate/core/config.py). Flags and baseline serialization were also inspected in the installed wheel.

## Parser checks

Both of Hyper's minimal synthetic reproductions were rerun through the selected Lizard parser. They remain defective:

| Input | Observed parser output | Expected source span |
| --- | --- | --- |
| TSX `f<{ a: 1 }>()` preceding two functions | No functions | `small` 3–5 and `big` 7–10 |
| Same source with `.ts` suffix | `small` 3–5, CC 1; `big` 7–10, CC 2 | Matches |
| Callable parameter `first(cb: (t: string) => string)` in TS and TSX | `first` 1–1, CC 1 | 1–4, including its conditional |
| Following `probe` function in that reproduction | 6–10, CC 3 | Matches |

Manual comparison of representative Stack source at the base SHA also found a real TypeScript span problem. In `languages/typescript/packages/stack/src/eql/v3/selector-path.ts`, `parseSelectorSegments` occupies lines 32–69 but is reported as 32–72 (CC 9); `jsonPathOf` occupies 72–74 but is reported as 72–83 (CC 1). The parser absorbs the start of the next function. Therefore ordinary TypeScript can be mismeasured even without either synthetic trigger.

The inspected Rust `is_fresh_at` in `packages/stack-encrypt/src/keyset.rs` is correctly reported at 103–105 (CC 1). Go `StatusError` and `PackedResult` in `languages/golang/internal/guest/status.go` are correctly reported at 45–106 (CC 29) and 111–116 (CC 2). These are sample checks, not proof that either parser is universally correct.

Keep the report advisory. Do not modify production source to satisfy this parser. These silent span defects are different from process failures: successful CLI exit cannot establish accurate function boundaries.

## Coverage and interpretation

Both reports use the same generated-output exclusions. The second excludes test files; it cannot remove inline Rust `#[cfg(test)]` modules from production files. SQL and TypeScript `.mts`/`.cts` are outside upstream's default language map. A no-eligible-source result is no assessment of those changes.

The upstream baseline serializes `_meta` (`tool`, `n`, `head`, `base_ref`) plus an ascending integer `distribution`. Empty source observations are omitted. Its history walk follows the mainline and recursively extracts landed branch changes; a mainline limit does not strictly cap observations. The project contribution to grading is `n / (n + 200)` with the selected prior weight.

## Actions verification still required

Local calibration and tests cannot verify GitHub cache scoping, main-run cache saves, later PR restores, or the rendered job summary. After the workflow is available in Actions, record links to a cold run, a main run saving the pair, and a PR run restoring it. Verify both report sections, policy/version cache invalidation, malformed-pair rebuilding, and explicit seed-only disclosure. Do not mark these checks complete based on local cache simulation.

## Imported history and rename checks

The candidate 200-entry mainline window runs from `f435ce5764ea24e5c3af0904ea7efe22eed188a0` (2026-07-09) through the base SHA (2026-10-08). It includes the protect-ffi and EQL imports, the stack-crate import, and the TypeScript directory move. No subject exclusion is proposed: legitimate large changes stay in calibration.

A diagnostic pass with upstream's default scope scored historical first-parent net diffs through the installed engine (not a replacement score formula):

| Revision and change | Eligible files | Impact |
| --- | ---: | ---: |
| `7109994002e277074765662c8ff35d41ef6c10f9`, exact TypeScript directory move | 856 | 0 |
| `d2772b0c520e32546873a73d70cc6dec89507257`, Prisma package-name rename | 132 | 531,564 |
| `f1895d8bbf6c9753ed48787df6abc32f253bbedb`, stack-crate import merge net diff | 261 | 104,199,813 |
| `4a203453c1973c849f540079c69e7fffcf16fc62`, Go generator merge net diff | 158 | 169,721,862 |

Git reports 1,017 exact, zero-line-change renames for the directory move. ImpactGate detects these as zero impact while still counting eligible files. A mechanical rename that edits source text can score materially, as the package-name rename shows. Merge net scores above are diagnostic comparisons; the baseline walker recursively extracts branch observations rather than necessarily inserting each displayed merge net score.

There were no entirely test-only, SQL-only, or generated-only net diffs in the selected mainline sample. For coverage diagnostics, path-filtered subsets were therefore used and must not be mistaken for complete PR scores: 51 generated paths from `c851db593af30767c5f0dc028aec53aa845253e6` produced no eligible files; three SQL paths from `f61542b7eb529e673dcf505db3a61ee426512c76` produced no eligible files. The Go-test subset of `4a203453c1973c849f540079c69e7fffcf16fc62` contains 45 changed paths and scores 35 eligible files at 14,164,500 under default scope. The isolated real-CLI tests separately exercise complete small Git changes.

The same historical Go-test subset was checked with the rollout policies: `all.yml` retains those 35 eligible files (impact 14,164,500), while `source.yml` has no eligible files (impact 0). This confirms the test-file distinction against actual repository content, in addition to isolated test histories.

## Reproducing baseline and reporting measurements

Install the pinned tools in a disposable virtual environment. From the repository root, repeat the following for `all` and `source`; keep generated JSON outside the checkout:

```sh
impact-gate baseline --base-ref 14bcc638769504ebc4dbb062d0c48fa7e935fe43 \
  --max-commits 200 --baseline-file /tmp/stack-impact-all.json \
  --measure-config .github/impact-gate/all.yml
impact-gate score --mode range --base 415b62cd7bdd957f6b9df277115ce1e955a10510 \
  --curve --enforcement warn --warn-percentile 90 --block-percentile 98 \
  --curve-prior-weight 200 --format markdown \
  --baseline-file /tmp/stack-impact-all.json \
  --measure-config .github/impact-gate/all.yml
```

The historical reporting range intentionally covers the latest three mainline entries at the recorded base (through the EQL plan targets and Go generator changes), providing a nonempty mixed-language report. It is a timing sample, not this infrastructure branch's PR score.

A preliminary all-source baseline using the earlier scope finished in 217.45 seconds with 418 observations. That run preceded the final generated-Go exclusions and is not the adopted baseline. A default-scope exploratory run was interrupted after 177.30 seconds to avoid contention with the policy run; interruption was not a tool failure. Final-policy measurements below supersede those exploratory runs.

At the recorded base, applying the final scope to tracked filenames yields the following eligibility inventory (eligibility does not guarantee accurate function parsing):

| Language | Including test files | Excluding test files |
| --- | ---: | ---: |
| TypeScript | 985 | 541 |
| Rust | 337 | 168 |
| Go | 151 | 106 |
| JavaScript | 109 | 29 |
| Python | 5 | 3 |

There are also 281 tracked SQL files and seven `.mts`/`.cts` files outside the language map. The EQL `eql-domains/src/fixtures` tree is a production catalog DSL and remains eligible; fixture exclusions deliberately do not blanket-match every directory named `fixtures`. Shared `test-kit` code and Go's fake allocator backend in `internal/guest/testing.go` are excluded only by the test-file policy. Generated Go `_stash.go`/`_gen.go` files and declaration outputs are excluded from both.

## Final calibration and operational budget

The final matching baseline pair was generated sequentially from the pinned base SHA using the exact policies below. Each process exited 0; generation was fresh, with no restored baseline. Git objects and the OS filesystem cache were already present, so “cold” here means cold derived baseline, not a cold machine or repository clone. Installation and checkout time are excluded.

| Policy | Generation time | Observations (`n`) | Distribution minimum | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Including test files | 194.15 s | 418 | 0 | 55,662,006,240 |
| Excluding test files | 85.40 s | 344 | 0 | 210,644,488 |
| Sequential pair | **279.55 s** | | | |

Policy SHA-256 digests used for these measurements:

- `all.yml`: `2e45fcb24fe9535a26c99d1685c0b3fbce1c1285e65f5c4474cbba179110b655`
- `source.yml`: `810eaafd26b3c5df42b5992395855ac40a5c2f1c516be469fc9c8626f489bb6e`

Using those existing baseline files, the sample range described above took 1.02 seconds including test files and 0.60 seconds excluding them, **1.63 seconds combined**. This measures local baseline reuse, not an Actions cache hit. The all-source report counted 172 files, impact 545,037,040, p99.51; the report excluding test files counted 119 files, impact 310,445,058, p99.82. Both exceeded p98, showed WARN, and exited **0**, directly confirming advisory behavior on a large real Stack change. The underlying CLI's canned wording about future blocking does not change the configured warn enforcement.

Adopt **200 recent first-parent entries** and a **20-minute workflow timeout**. The observed cold pair fits with more than four times its local measured runtime available for a slower runner, tool installation, checkout, and reporting. This is an operational allowance, not a hosted-runner SLA. There is no reason from these timings to narrow the window to omit the imports; 50- or 30-entry alternatives were therefore not needed. The recursive history yielded more observations than mainline entries, so report `n` rather than describing the baseline as “200 changes.” The project weights are approximately 0.6764 and 0.6324; the remaining grading weight comes from the shipped seed distribution.

The large historical maximum and parser defects argue for retaining advisory enforcement. Do not trim large observations to make scores look better. Revisit the time budget if future imports or unusually deep merge histories approach the timeout; failed analysis must remain visible.

## Implementation validation

- The nine real-tool tests passed against temporary Git histories: cold generation, reuse/refresh, invalid and incompatible cache rebuilding, target ancestry, production-fixture retention, test-file filtering, unsupported/generated changes, renames, explicit seed-only grading, high-impact advisory success, and visible operational failure. Generation calls the pinned upstream baseline API because its CLI rejects a genuinely empty distribution; reporting still invokes the real CLI.
- The repository script suite passed: 72 files, 1,269 tests, 28 skips. A subsequent review added one generated-scope parity guard; the focused workflow suite then passed all four tests. That guard keeps the duplicated exclusion policies aligned.
- Repository-wide typechecking passed all 16 Turbo tasks. The workflow test also passed direct TypeScript check-JS validation; the Python driver/tests passed mypy 1.18.2 with `--ignore-missing-imports --follow-imports skip --check-untyped-defs`. Keep mypy's cache outside the checkout when running locally, since Biome otherwise scans its generated JSON.
- All 28 supply-chain tests passed. The workflow passed `actionlint`; the repository Biome check exited successfully with existing warnings/information diagnostics and no errors.
- The full package suite was attempted with `pnpm test --continue`: 12 of 19 Turbo tasks passed. Auth, profile, Stack, migrate, wizard, CLI, and Supabase tasks failed with missing local native bindings. Two auth package-packing tests additionally failed: sandboxed npm could not write its cache; rerunning just those tests outside the sandbox removed that error but exposed their existing assumption about the shape of npm's JSON output (`[0].files` was undefined). No package runtime or packaging source is changed by this work, and the full package suite is not claimed green.
- Separate standards/spec reviews found no documented-standard or implementation-correctness violations. The standards review's shared-exclusion drift concern is covered by the new guard. Final calibration evidence resolves the timing-evidence gap; the hosted Actions checks described above remain rollout work.
