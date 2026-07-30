# Differential Review Report — PR #772

## Executive Summary

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 3 |
| Medium | 3 |
| Low | 0 |

**Overall risk:** High  
**Recommendation:** Conditional — reconcile the release contract and changesets before merge/release.

**Key metrics:**

- Range: `origin/main...origin/remove-v2` at `3a6395c2`
- PR size: 397 files, +20,083 / -30,091
- Pending changesets inspected: 124; changed changeset markdown files: 42
- Current GitHub checks: all reported checks passing
- Security regressions found: none in the focused scope

## What Changed

PR #772 removes EQL v2 authoring surfaces across core packages and adapters while retaining selected legacy read/migration paths. The review concentrated on public API consistency, the CLI handoff prompt, and the pending changesets that will be consolidated for the 1.0.0 release.

## Findings

### HIGH — Supabase handoff names a nonexistent EQL domain

**Files:**

- `packages/cli/src/commands/init/lib/setup-prompt.ts:103`
- `packages/cli/src/commands/init/lib/__tests__/setup-prompt.test.ts:190-192`
- `.changeset/decrypt-chaining-docs.md:34-36`

The generated `stash init` agent prompt tells Supabase users to declare `eql_v3_encrypted`. EQL v3 has no catch-all domain; columns must use a concrete `public.eql_v3_*` domain such as `public.eql_v3_text_search`. The test and changeset repeat the invalid name, so CI currently preserves the defect.

**Recommendation:** Name the appropriate concrete-domain family (with an example), and update the test and changeset together.

### HIGH — The consolidated changelog advertises APIs removed by the same release

**Primary files:**

- `.changeset/adapter-package-split.md:12-24`
- `.changeset/adapter-split-skills.md:7-9`
- `.changeset/eql-v3-drizzle.md:5-13`
- `.changeset/eql-v3-adapter-type-robustness.md:26-28`
- `.changeset/eql-v3-drizzle-fail-open-guards.md:7-37`
- `.changeset/eql-v3-rename-contains-to-matches.md:14`
- `.changeset/init-drizzle-eql-v3.md:11-14`
- `.changeset/init-placeholder-eql-v3.md:15-23`
- `.changeset/eql-v3-supabase-adapter.md:25-66`

A simulated `changeset pre exit` followed by `changeset version` generated 1.0.0 notes that direct users to `@cipherstash/stack-drizzle/v3`, `createEncryptionOperatorsV3`, and `extractEncryptionSchemaV3`, while the same section later says those have no aliases and are removed. The Supabase entry also says encrypted ordering is always rejected, free-text uses `contains`, and the v2 wrapper is unchanged; later entries respectively add OPE ordering, rename the operator to `matches`, and remove the v2 wrapper.

**Recommendation:** Rewrite the consumed changesets to describe the final 1.0 surface, rather than retaining intermediate RC states or a “superseded later” paragraph.

### HIGH — The release notes promise v3-only authoring while the exported client code on `remove-v2` still emits v2

**Files:**

- `.changeset/stack-audit-on-decrypt.md:51-54`
- `.changeset/reject-v2-wire-over-v3-schemas.md:22-30`
- `packages/stack/src/encryption/index.ts:85-95,140-154`

Here, “exported client” means the consumer-reachable `Encryption()` API in the
code on this branch, not the version currently published to npm. One changeset
states that the client authors EQL v3 only. Another says an EQL v2 schema plus
`eqlVersion: 2` still emits v2 and recommends building that client; the branch
implementation also defaults an all-v2 schema set to the FFI's v2 wire format.
The consolidated changelog therefore gives incompatible guarantees, and the
implementation follows the latter.

**Recommendation:** Decide the final supported contract. If v2 emission remains a migration escape hatch, document it consistently; if authoring is v3-only, reject the public v2 write path and mint compatibility fixtures through an internal test mechanism.

### MEDIUM — Adapter fixes are assigned to the core package changelog

**Files/frontmatter:**

- `.changeset/eql-v3-adapter-type-robustness.md:2`
- `.changeset/eql-v3-drizzle-fail-open-guards.md:2`
- `.changeset/eql-v3-drizzle.md:2`
- `.changeset/eql-v3-supabase-adapter.md:2`
- `.changeset/supabase-in-list-operands.md:2`
- `.changeset/supabase-is-null-operands.md:2`
- `.changeset/supabase-or-string-parser.md:2`
- `.changeset/supabase-v3-order-by-ope-term.md:2`

These entries describe code that ends the release in `@cipherstash/stack-drizzle` or `@cipherstash/stack-supabase`, but their frontmatter targets only `@cipherstash/stack`. The simulated GA changelogs put the details in core and omit them from the adapter package that actually exposes the behavior.

**Recommendation:** Re-home each changeset to the final owning adapter package; retain a core bump only where the entry also describes a real core API change.

### MEDIUM — DynamoDB changeset contradicts the typed decrypt audit surface

**Files:**

- `.changeset/dynamodb-eql-v3.md:10-12,39-40`
- `.changeset/stack-audit-on-decrypt.md:6-18`
- `.changeset/stack-skills-eql-v3-audit.md:6-12`

`dynamodb-eql-v3.md` says the typed `EncryptionV3` client has no decrypt audit surface and that audit requires the nominal client. The same release adds audit chaining to the typed client and explicitly removes that caveat.

**Recommendation:** Update the original DynamoDB entry to the final `Encryption` typed-client behavior and remove the nominal-client-only warning.

### MEDIUM — `@cipherstash/nextjs` receives an unrelated deletion changelog entry

**Files:**

- `.changeset/remove-eql-v2-packages.md:2-4`
- `packages/nextjs/package.json:4,33`

The changeset bumps `@cipherstash/nextjs`, but its body only discusses deleting `protect`, `schema`, and `protect-dynamodb`. The actual Next.js changes are a package-description correction and a typecheck script, so the generated Next.js changelog claims work that package did not perform.

**Recommendation:** Split the Next.js metadata change into its own changeset or add a package-specific paragraph that accurately explains its patch.

## Test Coverage Analysis

- `git diff --check origin/main...origin/remove-v2`: passed.
- GitHub's current lint, unit, E2E, integration, CodeQL, OSV, and complexity checks: passed.
- Changesets validation: ran `changeset status`, then simulated prerelease exit and `changeset version` in an isolated clone; generated versions were 1.0.0 and reproduced the contradictions above.
- No live ZeroKMS tests were run locally.

The invalid Supabase-domain prompt has a unit assertion, but the assertion checks the wrong literal rather than validating it against the EQL domain catalog.

## Blast Radius Analysis

The code defect affects every Supabase `stash init` handoff that follows the generated schema-authoring step. The changeset issues affect the first stable 1.0 changelogs for the fixed release train and can direct all Drizzle/Supabase adopters to removed APIs.

## Historical Context

The contradictory entries were introduced across prerelease work and remain editable because Changesets retains consumed markdown during prerelease mode for the final stable aggregation. Several branch changes already corrected individual entries, but the final release simulation shows the remaining set still needs reconciliation.

## Recommendations

### Immediate

- Correct `eql_v3_encrypted` in the CLI prompt, test, and changeset.
- Normalize pending changesets to the final API surface before exiting prerelease mode.
- Resolve and document the v2-emission contract.

### Before release

- Generate the 1.0 changelogs in a disposable worktree and lint them for removed specifiers/symbols.
- Add a test that validates domain names used in generated prompts against the concrete EQL domain family.

## Analysis Methodology

**Strategy:** Surgical/focused because the PR spans 397 files.

Techniques used:

- Established the live PR base/head from GitHub and refreshed refs.
- Reviewed the full changeset set, not only changed changesets.
- Compared claims against final exports, implementation, tests, and repository guidance.
- Simulated the final Changesets prerelease-exit/version workflow.
- Checked existing PR reviews to avoid treating already-resolved comments as new findings.

**Limitations:** This was not a line-by-line audit of all 397 files. Product-code review concentrated on public API boundaries implicated by the changesets and the newly generated CLI guidance. No credentialed live encryption tests were run locally.

**Confidence:** High for the listed findings; medium for the untouched portions of the overall PR.
