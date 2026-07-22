# EQL v2 removal — PR 1 step-plan (delete published v2 packages)

Executes PR 1 of `docs/plans/2026-07-22-eql-v2-final-removal-design.md`.
Branch: `feat/remove-eql-v2-pr1-delete-packages` (worktree). Scoped against `origin/main` = `6ce53817`.

## Goal
Delete the closed v2-only dependency chain — `@cipherstash/protect-dynamodb` →
`@cipherstash/protect` → `@cipherstash/schema` — and remove every reference so the
build, lockfile, and changeset state stay consistent. Mergeable in isolation.

## Verified scope (live-code survey, not just design line-counts)
Closed-chain claim CONFIRMED for code imports: nothing outside the three imports them,
and `@cipherstash/stack` depends only on `@cipherstash/protect-ffi` (a different, external
package), not on any of the three.

Corrections vs. the design's PR-1 paragraph:
- `.changeset/config.json` — the three are NOT in the `fixed` group and `ignore` is `[]`.
  No config edit required (design assumed a fixed-group removal).
- `pnpm-workspace.yaml` uses globs (`packages/*`), no explicit entries to remove.
- No `tsconfig` `references` anywhere — nothing to unpick.
- Extra build blockers the design folded under "root config": `e2e/package.json` dep edge
  and root `package.json` `build:js` turbo filter.
- Extra changeset-state fixes: pending `schema-stevec-standard-pin.md` targets the doomed
  `@cipherstash/schema`; `pre.json` pins all three in `initialVersions`.

## Steps

### 1. Delete the three package directories
- `rm -rf packages/protect-dynamodb packages/protect packages/schema`

### 2. Fix build blockers (dangling references that break compile/CI)
- `e2e/package.json` — remove the `"@cipherstash/protect": "workspace:*"` dependency line.
- root `package.json` — `build:js`: drop `--filter './packages/protect'`, keep `./packages/nextjs`.

### 3. Clean stale (non-breaking) references
- `scripts/lint-no-hardcoded-runners.mjs` — remove the `packages/protect/src/bin/runner.ts`
  allowlist entry (verify the script doesn't assert the path exists — if it does, this is
  actually a blocker).
- `packages/nextjs/package.json` — description references `@cipherstash/protect`; repoint to
  `@cipherstash/stack`.
- `skills/stash-drizzle/SKILL.md:38` — inspect the `@cipherstash/protect` mention; fix only if
  the deletion made it wrong (a historical note about the legacy protect-based package may stay).

### 4. Changeset / RC-mode housekeeping
- Delete `.changeset/schema-stevec-standard-pin.md` (only target is the deleted `@cipherstash/schema`;
  already consumed in a prior rc per `pre.json`).
- `.changeset/pre.json` — remove the three from `initialVersions`; remove `schema-stevec-standard-pin`
  from the `changesets` array (keeps it consistent with the deleted file).
- Add deletion-notice changeset `.changeset/remove-eql-v2-packages.md`:
  `'@cipherstash/stack': patch` (successor surface for all three; group already major via
  `stack-1-0-0-rc`) and `'@cipherstash/nextjs': patch` (its `package.json` description changes
  from `@cipherstash/protect` to `@cipherstash/stack` — a published-metadata edit), prose body
  naming each removed package and its migration path
  (`@cipherstash/protect` → `@cipherstash/stack`; `@cipherstash/schema` → `@cipherstash/stack/schema`;
  `@cipherstash/protect-dynamodb` → `@cipherstash/stack/dynamodb` `encryptedDynamoDB`).
  Follows the `remove-legacy-drizzle-package.md` precedent.

### 5. Meta-file honesty (trim what described the removed packages)
- `SECURITY.md` — drop the three rows from the package list.
- `AGENTS.md` — Repository Layout entries (protect, schema, protect-dynamodb) + prose mentions;
  keep the "maintained implementation is `packages/stack/src/dynamodb`" guidance.

### 6. Regenerate lockfile
- `pnpm install` (updates `pnpm-lock.yaml` for removed packages + e2e edge). CI is
  `--frozen-lockfile`, so the committed lockfile must match.

## Verification (green gate before commit)
- `pnpm changeset status` — no changeset references a missing package.
- `pnpm run build` — whole-repo turbo build; proves no dangling import/reference.
- `pnpm run code:check` — biome, error-free.
- `git grep -nP "@cipherstash/protect(?!-ffi)|@cipherstash/schema|@cipherstash/protect-dynamodb"` —
  only intentional survivors (e.g. migration-path prose). The `(?!-ffi)` lookahead (PCRE, hence
  `-P`) excludes the unrelated `@cipherstash/protect-ffi`; a plain `\b` would not, since a word
  boundary sits between `protect` and `-ffi`.
