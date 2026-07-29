---
'stash': minor
'@cipherstash/wizard': patch
---

Add a `stash-deployment` agent skill and install it for every integration.

The rollout/cutover lifecycle was documented in `stash-encryption` and
`stash-cli` as a *command sequence*, with the deploy boundaries described in
passing. In practice the boundaries are the hard part: an agent that treats the
lifecycle as one unit of work — twin column, dual-write, backfill, read switch,
drop — produces a plan that loses data, because ciphertext can only be written
by the application and the plaintext column must stay authoritative until every
row has a ciphertext twin and the deployed code reads it.

The new skill makes the deploy shape the primary subject:

- The three-deploy ladder (rollout → read cutover → drop plaintext) with the two
  out-of-band steps and two human gates between them, plus what each gate is
  actually verifying.
- A failure table: for each way of collapsing the ladder, the data that is lost.
- Rollback per stage, making explicit that only the final drop is irreversible.
- `CS_*` credentials as a **build-time** input on platforms that construct the
  encryption client at module load, and the keyset rule for backfills — ciphertext
  written under credentials the deployed app does not resolve to fails only at
  read time.
- A Prisma Postgres / Prisma Compute section: EQL installing through the Prisma
  Next migration graph, one merge deploying one stage, the additive-only deploy
  policy that makes the plaintext drop fail the build (and the apply-before-merge
  sequence that avoids it), preview-branch databases masking destructive
  migrations and inviting a wrong-database apply, and running one-off jobs
  against a hosted database.

`stash-deployment` joins `stash-encryption`, `stash-indexing` and `stash-cli` in
the set every integration installs.
