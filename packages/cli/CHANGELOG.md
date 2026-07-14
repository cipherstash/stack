# @cipherstash/cli

## 1.0.0-rc.0

### Major Changes

- 7c7dbca: CipherStash Stack 1.0 (release candidate).

  This is the first 1.0-line release of `@cipherstash/stack`, the first published
  release of the split-out EQL v3 adapters `@cipherstash/stack-drizzle` and
  `@cipherstash/stack-supabase`, and moves the `stash` CLI to 1.0 alongside them.
  These four packages now version together as the Stack 1.0 family.

### Minor Changes

- 229ce59: `stash eql install --eql-version 3` now installs the eql-3.0.0 GA bundle,
  vendored from the pinned `@cipherstash/eql` package (sha256-verified).

  Since eql-3.0.0 one artifact installs everywhere: the operator-class
  statements self-skip when the role lacks superuser (managed Postgres,
  Supabase) and the bundle disables the ORE-backed encrypted domains it cannot
  support. The separate v3 Supabase bundle variant is gone — `--supabase` and
  `--exclude-operator-family` no longer select a different v3 file (the role
  GRANTs for `eql_v3` / `eql_v3_internal` still apply with `--supabase`).

  The bundled skills are also refreshed for the eql-3.0.0 naming convention
  (`public.eql_v3_<name>` column domains) and the EQL v3 typed-schema surface.

- 0b9b192: Add an EQL v3 install path to `stash eql install` via a new `--eql-version <2|3>`
  flag (default `2`). v3 installs the native concrete-domain schema (`public.*`
  type domains, `eql_v3` operators, `eql_v3_internal` constructors) from bundles
  vendored into `packages/cli/src/sql` by `scripts/build-eql-v3-sql.mjs` (full
  bundle + a Supabase variant with the two superuser-only operator-class chunks
  stripped). v3 currently supports the direct install path only —
  `--drizzle`/`--migration`/`--migrations-dir`/`--latest` are rejected — and the
  installer keys `isInstalled`/version checks and Supabase grants to the `eql_v3`
  schema.
- 0b9b192: Rename `stash db install` to `stash eql install`. The command scaffolds
  `stash.config.ts` and installs the EQL extensions, so it now lives under a
  dedicated `eql` command group. `stash db install` keeps working as a
  deprecated alias that prints a warning pointing at the new name. All help
  text, hints, generated migration headers, and wizard steps now reference
  `stash eql install`.
- e25eb22: Default EQL to v3 and stop the CLI recommending `stash db push` (#585).

  - **EQL v3 is now the default.** `stash eql install` and `stash eql upgrade` target v3 (the native `eql_v3.*` domain schema) without `--eql-version 3`. The v2-only paths — `--drizzle`, `--migration`, `--migrations-dir`, and `--latest` — now require an explicit `--eql-version 2` and error with clear guidance otherwise (v3 installs via the direct path only). `stash init` pins v2 automatically when it drives the Drizzle migration flow. **Note:** for a Supabase project, `stash init` now runs a v3 direct install rather than offering the v2 migration-file flow; run `stash eql install --supabase --migration --eql-version 2` if you want a checked-in migration file.
  - **`stash db push` is no longer recommended in CLI output.** `db push` writes the `public.eql_v2_configuration` table, which is a v2 + CipherStash Proxy artifact — EQL v3 has no configuration table (config lives in each column's `eql_v3.*` type) and nothing in the v3 stack reads it. The push recommendations are removed from `eql status`, the help banner, and the init/plan/cutover guidance. `db push` (and `db activate`) remain available for EQL v2 + Proxy users; they're now labelled as such.
  - **`eql status` is v3-aware.** On a v3-only database it reports that encrypt config lives in the column types instead of hitting a "table not found" dead-end that told users to run `db push` (which neither creates that table nor applies to v3).
  - **`stash db push` guards a v3-only database** with a clear "not needed under EQL v3" message instead of a raw `relation "public.eql_v2_configuration" does not exist` error.

### Patch Changes

- 31ca318: Update the bundled `stash-drizzle`, `stash-supabase`, and `stash-encryption` agent
  skills (and the stack README / Supabase reference doc) for the adapter package
  split: the Drizzle and Supabase integrations import from `@cipherstash/stack-drizzle`
  (+ `/v3`) and `@cipherstash/stack-supabase` respectively, installed alongside
  `@cipherstash/stack`, rather than from `@cipherstash/stack/{drizzle,supabase,eql/v3/drizzle}`
  subpaths. Skills ship inside the `stash` tarball, so the stale import paths would
  otherwise become wrong guidance in a user's project.
- 82f2e69: Document EQL v3 JSON columns in the bundled skills: `types.Json` in the
  `stash-encryption` typed-schema catalog (capability suffix, family, and an
  encrypted-JSONB query section), and `contains(col, subObject)` JSON containment
  on the v3 Drizzle operators in `stash-drizzle`.
- f23f952: Remove the leftovers from the secrets removal (`1929c8fe`), which deleted
  `packages/stack/src/secrets/` but left its export, build entry, skill, and docs
  behind. Secrets tooling is not ready; nothing here was functional.

  - **Drop the dead `@cipherstash/stack/secrets` subpath export.** It pointed at
    `./dist/secrets/index.js`, which has no source and is not in the tarball, so
    `import '@cipherstash/stack/secrets'` has been throwing `ERR_MODULE_NOT_FOUND`
    for every consumer since the source was removed. Also drops the dangling
    `src/secrets/index.ts` entry from `tsup.config.ts`. Removing an export that
    cannot resolve breaks nothing.
  - **Remove the `stash-secrets` agent skill** and its references in `AGENTS.md`
    and the init setup-prompt skill index. It was never installed by `stash init`
    (it is absent from `SKILL_MAP`), so no user project ever received it.
  - **Remove the secrets documentation** from both published READMEs: the
    `Secrets` class API and the `npx stash secrets` command reference in
    `@cipherstash/stack`, and the `npx stash secrets` section in `stash`. The CLI
    command does not exist — `stash secrets` returns `Unknown command`.

- 1a9d190: Refresh the bundled `stash-cli` agent skill and the CLI README against the current
  command surface. The skills directory ships inside the `stash` tarball and is copied
  into the user's `.claude/skills/` / `.codex/skills/` (or inlined into `AGENTS.md`) at
  handoff time, so a stale skill becomes stale guidance in the user's project.

  - **New `Start here` and `Authentication` sections.** Setup is driven through the CLI:
    agents read `stash manifest --json` first, then trigger `stash auth login --json` and
    surface the verification URL for a human to approve, then run `stash init`. Authenticating
    before `init` matters — `init`'s auth step is interactive and would otherwise try to open
    a browser on the agent's host.
  - **New `Never read these` invariant**, mirrored into the `AGENTS.md` doctrine: agents must
    never read `~/.cipherstash/secretkey.json`, `~/.cipherstash/auth.json`, anything under
    `~/.cipherstash/workspaces/`, or `.env*`. The wizard already blocks these paths in code;
    the other handoff targets had no written rule.
  - **Documents `manifest`, `doctor`, `wizard`, and `auth regions`**, which the skill omitted
    entirely, plus the non-interactive interface (per-command escape hatches, exit codes, the
    `DATABASE_URL` resolution order, the `auth login --json` NDJSON event contract).
  - **Corrects the `db` → `eql` move.** `db install`, `db upgrade`, and `db status` are
    deprecated aliases that warn and forward; `db push`, `db activate`, `db validate`,
    `db test-connection`, and `db migrate` remain in the `db` group.
  - **Scopes `db push` / `db activate` as EQL v2 + CipherStash Proxy only**, in both the skill
    and the README's recommended flow. SDK users hold their encryption config in application
    code and don't need them.
  - Adds the missing `--database-url`, `--eql-version`, `--prisma-next`, `--proxy`/`--no-proxy`,
    and `--region` flags; corrects six programmatic API signatures; fixes the README's claim
    that `stash init` ends in an agent-handoff menu (that belongs to `stash plan` / `stash impl`);
    and marks `stash env` as the non-functional stub it currently is.

- 161f17b: Correct the `stash-drizzle` skill: `inArray` / `notInArray` now encrypt the whole
  list in a single `encryptQuery` batch crossing (the `bulkEncrypt`/concurrency
  fallback was removed when v3 query operands moved to `encryptQuery` — #622). The
  skill ships inside the `stash` tarball, so this keeps the bundled guidance in step
  with the adapter's behaviour.
- e40c3da: Update the `stash-drizzle` and `stash-supabase` skills for the EQL v3
  `contains()` → `matches()` rename (#617): the encrypted free-text operator is now
  `matches()` (fuzzy bloom token matching), `contains()` is reserved for exact
  containment, and Supabase `like()`/`ilike()` on encrypted columns are documented
  as an approximate compatibility shim delegating to `matches()`. Skills ship inside
  the `stash` tarball, so they must track the adapter surface.
- 58d7439: Correct the bundled `stash-supabase` agent skill: EQL v3 `contains()` matches
  substrings. The skill previously carried the reverse — that `contains()` matched
  only exact values because the query's bloom filter appended the whole search term
  as an extra token. That was never true: `include_original` is inert in
  protect-ffi (the match bloom is trigram-only either way), so any substring of at
  least the tokenizer's `token_length` (3 characters) matches, and shorter terms are
  rejected rather than silently matching every row. The skills directory ships
  inside the `stash` tarball and is copied into the user's `.claude/skills/` /
  `.codex/skills/` (or inlined into `AGENTS.md`) at handoff time, so the stale
  sentence was shipping wrong guidance into customer repos.
- Updated dependencies [31ca318]
- Updated dependencies [c4787c0]
- Updated dependencies [66a0e02]
- Updated dependencies [cfd46ee]
- Updated dependencies [7eba32d]
- Updated dependencies [0ebf57e]
- Updated dependencies [d73a03c]
- Updated dependencies [89b903f]
- Updated dependencies [229ce59]
- Updated dependencies [50c0a9c]
- Updated dependencies [63ca540]
- Updated dependencies [5d23e80]
- Updated dependencies [1aa9a11]
- Updated dependencies [af2d04e]
- Updated dependencies [b8a3d20]
- Updated dependencies [a0f3b2c]
- Updated dependencies [f23f952]
- Updated dependencies [7c7dbca]
- Updated dependencies [5411a13]
- Updated dependencies [99f8b0a]
- Updated dependencies [fd33aad]
- Updated dependencies [8cd485d]
- Updated dependencies [9b65ae8]
  - @cipherstash/stack@1.0.0-rc.0
  - @cipherstash/migrate@1.0.0-rc.0

## 0.17.1

### Patch Changes

- cb8fa1d: Fix two config-scaffold dead-ends in the CLI (#578, #579).

  - **Missing config is now actionable.** When a command that needs a
    `stash.config.ts` can't find one, the error recommends `stash init` /
    `stash eql install` (runner-aware) instead of only telling you to hand-write
    the file.
  - **`stash eql install` no longer requires a `stash.config.ts`.** It only needs
    a database URL, so it now resolves one directly (`--database-url` → env →
    `supabase status` → prompt) instead of scaffolding a config and loading it.
    That means a standalone `npx stash eql install --database-url ...` works in a
    bare project with **zero dependencies** — no more crash with a raw
    `Cannot find module 'stash'` from the config's `import`. A plain
    `stash eql install` still honours an existing config (later workflow commands
    rely on it) and offers to scaffold one otherwise. An explicit `--database-url`
    is a one-shot install: it resolves that URL directly and leaves the project
    untouched — no config or client is scaffolded, and an existing config is
    bypassed so the flag can't be silently overridden by a hand-edited literal
    `databaseUrl` (including one in a parent directory).
  - As a safety net, `loadStashConfig` translates a missing-module load failure
    (a project that _has_ a config but lacks the CLI packages) into the same
    actionable guidance for every command, instead of a jiti/Node stack trace.

- cbece82: Render per-command `--help` from the command-descriptor registry, and slim the
  global banner. This is the documented follow-on to the manifest/registry work in
  `docs/plans/cli-help-and-manifest.md`.

  - `stash <command> --help` now prints command-specific help instead of the global
    banner. A leaf command (`stash eql install --help`, `stash auth login --help`)
    shows its usage, summary, long description, flags, and examples; a command
    group (`stash eql --help`, `stash auth --help`) lists its subcommands and points
    at their own `--help`. All of it renders from `src/cli/registry.ts`, so it can't
    drift from `stash manifest`.
  - `-h` is now honoured after a command too (`stash eql install -h`), not just as a
    bare `stash -h`.
  - The global `stash --help` banner no longer inlines every command's flags; it
    lists the commands and directs users to `<command> --help` for the detail.

## 0.17.0

### Minor Changes

- cc62407: Add EQL v3 Supabase support, baselined on the `eql-3.0.0-alpha.2` release.

  `@cipherstash/stack/supabase` gains `encryptedSupabaseV3` — the EQL v3
  counterpart of `encryptedSupabase` for schemas authored with
  `@cipherstash/stack/eql/v3`. The public surface and call shape are identical
  to v2 (same filter methods, `withLockContext`, `audit`); only the schema type
  and wire encoding differ.

  **The v3 surface** is the `eql-3.0.0-alpha.2` release artifact: domains use
  SQL-standard type names (`eql_v3.integer_ord`, `eql_v3.timestamp_ord`,
  `eql_v3.boolean`, … mirrored by `types.IntegerOrd`, `types.TimestampOrd`,
  `types.Boolean`, …), SEM internals live in a separate `eql_v3_internal`
  schema (grant it roles, never expose it — only `eql_v3` goes in Supabase's
  Exposed schemas), and envelopes are versioned `v: 3`. Envelope production
  rides on `@cipherstash/protect-ffi` 0.27, which takes an `eqlVersion` so the
  same client emits v2 or v3 payloads per schema.

  **Adapter behaviour:**

  - columns are stored in their native `eql_v3.*` domains (raw jsonb payloads,
    no composite wrap), with JS property → DB column name resolution and `Date`
    reconstruction from `cast_as` on decrypted rows;
  - **INTERIM:** filter operands are full storage envelopes — every `eql_v3.*`
    domain CHECK requires the storage keys, and the SQL operators coerce their
    operand into the domain, so a term-only operand is rejected today. This is
    a tracked workaround (Linear CIP-3402), not the design: a full-envelope
    operand carries a real decryptable ciphertext plus all of the column's
    index terms, and PostgREST filters travel in GET query strings, so operands
    can land in URL logs, proxies, and Supabase request logs (query terms are
    index-terms-only by design). The fix is an EQL-side term-only scalar query
    envelope (the scalar analog of `eql_v3.jsonb_query`);
  - `like`/`ilike` on encrypted columns are emitted as PostgREST `cs`
    (bloom-filter `@>`) — the v3 domains define no LIKE operator. Substring
    search currently also requires `include_original: false` on the match
    index; that requirement is a symptom of the same interim full-envelope
    operand and goes away with CIP-3402;
  - filters on storage-only columns (e.g. `types.Boolean`) and null filter
    values are rejected at the type level and at runtime.

  The v3 builder's default row type is exactly the table's inferred plaintext
  shape (no index-signature widening — widening would disable the storage-only
  filter guard). Filtering or inserting plaintext passthrough columns requires
  an explicit row type: `es.from<typeof users, UserRow>('users', users)`.

  The CLI gains an EQL v3 path: `stash eql install --eql-version 3` installs the
  vendored `eql-3.0.0-alpha.2` bundle (`--supabase` selects the opclass-stripped
  variant and applies the role grants for both `eql_v3` and `eql_v3_internal`);
  `stash db upgrade` also accepts `--eql-version`, and `stash db status` reports
  v2 and v3 installs independently. The v2 `SUPABASE_PERMISSIONS_SQL` block is
  now generated from a shared `supabasePermissionsSql(schemaName)` helper, with
  `SUPABASE_PERMISSIONS_SQL_V3` covering the v3 schemas.

- eb94ac8: Add guards for missing native binaries. When npm skips the platform-specific
  optional dependency (a known npm bug), stash now prints actionable fix
  guidance instead of a raw `MODULE_NOT_FOUND` stack trace. Adds a new
  `stash doctor` command that diagnoses the runtime and native modules and works
  even when a binary is missing.
- 64fdeb2: Rename `stash db install`, `stash db upgrade`, and `stash db status` to
  `stash eql install`, `stash eql upgrade`, and `stash eql status`. These
  commands manage the EQL extension itself, so they now live under a dedicated
  `eql` command group. The old `db` spellings keep working as deprecated
  aliases that print a warning pointing at the new names. All help text,
  hints, generated migration headers, and wizard steps now reference the
  `eql` commands.
- 5e23384: Add a command-descriptor registry and `stash manifest --json` — a structured,
  versioned command surface for the docs generator and agents to consume instead
  of scraping `--help`.

  - `stash manifest --json` emits `{ name, version, groups[] }`, where each command
    carries its summary, optional long description, examples, and flags. `version`
    comes from the CLI's own `package.json`, so a page generated from the manifest
    is always stamped with the version it describes.
  - `stash manifest` (no flag) prints a grouped, human-readable command list.
  - The registry (`src/cli/registry.ts`) is intended to become the single source of
    truth for command metadata. This is phase 1 of
    `docs/plans/cli-help-and-manifest.md`; it is additive — `bin/main.ts` still
    hand-maintains the `HELP` string that renders `--help`, so until the documented
    follow-on renders `--help` from the registry the two are kept in sync by hand.

- 72a3356: Add non-interactive / agent-friendly affordances so `stash init` and
  `stash auth login` can run without a TTY (agents, CI, pipes). All changes are
  additive — interactive behaviour in a real terminal is unchanged.

  - `--region <slug>` / `STASH_REGION` on `stash auth login` and `stash init`
    skip the interactive region picker. An unknown or missing region in a
    non-TTY context now exits with an actionable message instead of hanging on
    the picker (region resolution mirrors the `DATABASE_URL` resolver's
    `TTY && !CI` gate).
  - `stash auth login --json` emits newline-delimited device-code events. The
    first event (`authorization_required`) carries the verification URL, so an
    agent can trigger auth and hand the browser step to a human — only a human
    completes it in the browser. `--no-open` suppresses the browser launch.
  - `stash auth regions` lists the regions valid for `--region` / `STASH_REGION`;
    `stash auth regions --json` emits `[{ slug, label }]` for programmatic use.

### Patch Changes

- aa9c4b1: Documentation: refresh package READMEs after the protectjs → stack repository rename. Fixed repository and license links, replaced dead in-repo docs links with cipherstash.com/docs URLs, rewrote the incorrect @cipherstash/nextjs README, and added guidance pointing new projects to @cipherstash/stack.
- a5f5422: Bump `@cipherstash/auth` (and its per-platform native bindings) from `0.40.0` to `0.41.0`, and migrate to its new `Result`-returning API.

  **What changed in `@cipherstash/auth` `0.41`.** Every fallible auth operation now returns a `@byteslice/result` `Result<T, AuthFailure>` (`{ data }` on success, `{ failure }` on error) instead of throwing. This covers strategy construction (`AccessKeyStrategy.create`, `OidcFederationStrategy.create`, `AutoStrategy.detect`, `DeviceSessionStrategy.fromProfile`), `getToken()`, and the device-code flow (`beginDeviceCodeFlow`, `pollForToken`, `openInBrowser`, `bindClientDevice`). Consumers now write `if (result.failure) …` and read `result.data` rather than `try/catch`. The `AuthError` type was renamed to **`AuthFailure`** — a discriminated union keyed by `type` (`"NOT_AUTHENTICATED"`, `"WORKSPACE_MISMATCH"`, …), replacing the old `error.code` string.

  **`@cipherstash/stack` (breaking type surface).**

  - **`AuthError` is renamed to `AuthFailure`** in the public re-exports from `@cipherstash/stack`. `AuthErrorCode` and `TokenResult` are unchanged. Anyone importing `AuthError` from `@cipherstash/stack` must switch to `AuthFailure`.
  - The WASM-inline access-key path (`resolveStrategy`, used by `@cipherstash/stack/wasm-inline`'s `Encryption()`) now unwraps the `Result` from `AccessKeyStrategy.create`. A construction failure (e.g. an invalid CRN or access key) throws a descriptive `[encryption]` error naming the `AuthFailure.type` instead of surfacing the raw auth error.
  - Bump `@cipherstash/protect-ffi` from `0.27.0` to `0.28.0`. auth `0.41`'s `getToken()` returns the token inside a `Result` envelope; protect-ffi `0.28` unwraps it (`.data.token`) inside its WASM `newClient`, whereas `0.27` read `.token` off the envelope and got `undefined` — which failed the WASM encrypt/decrypt round-trip with `token field is not a string`. `0.28` is the floor for the WASM path under auth `0.41`.

  **`stash` (CLI) and `@cipherstash/wizard`.** Internal auth call sites (`stash auth login`, device binding, `init` auth check, and the wizard's token acquisition / prerequisite check) were updated to unwrap `Result` and branch on `failure.type`. Behaviour is preserved — auth failures still surface the same way to end users; no CLI/wizard API changed.

  - @cipherstash/migrate@0.2.0

## 0.16.0

### Minor Changes

- f743fcc: Upgrade `@cipherstash/protect-ffi` to `0.23.0` and the bundled CipherStash EQL extension to `eql-2.3.1`.

  Breaking upstream changes adopted in this release:

  - **Encrypt-config schema version**: `buildEncryptConfig` now emits `{ v: 1, ... }` (was `{ v: 2, ... }`). protect-ffi `0.22.0` started validating this field and rejects any value other than `1` with the new `UNSUPPORTED_CONFIG_VERSION` error code.
  - **Storage and query payloads are now distinct types** (protect-ffi `0.23.0`): the previously-conflated `Encrypted` type splits into `Encrypted` (storage-only, `c` required) and a new `EncryptedQuery` (search terms — scalar `unique`/`match`/`ore` lookups and `ste_vec_selector` JSON path queries; no `c`). JSON containment queries (`ste_vec_term`) still return a storage-shaped `Encrypted` payload. `encryptQuery` / `encryptQueryBulk` now return `Encrypted | EncryptedQuery`, and the stack's `EncryptedSearchTerm` / `EncryptedQueryResult` unions widen to match. `decrypt` rejects query payloads at the type level. The DynamoDB `SearchTermsOperation` narrows via `'hm' in term` rather than `term.hm`.
  - **SteVec encoding default flipped**: protect-ffi's default `mode` for `ste_vec` indexes changed from `compat` to `standard`. The two encodings are not cross-compatible. Existing JSON-searchable data that was indexed under `compat` will need to be re-encrypted to be queryable. The stack adopts the new `standard` default — there is no longer a way to pin `compat` from the SDK.
  - **EQL extension bumped to `eql-2.3.1`**: the new SteVec `standard` encoding requires matching support in the database EQL extension. The CLI's bundled SQL (`packages/cli/src/sql/*.sql`) and the `@cipherstash/prisma-next` install bundle (`migrations/20260601T0000_install_eql_bundle/ops.json` + `eql-install.generated.ts`) are updated to `eql-2.3.1`. Databases installed with an older EQL extension must be reinstalled (`stash db install`) before containment / contained-by queries against SteVec columns will work. `eql-2.3.1` ships the `_encrypted_check_c` fix for SteVec storage payloads ([cipherstash/encrypt-query-language#232](https://github.com/cipherstash/encrypt-query-language/issues/232)).
  - **New error codes**: `ProtectErrorCode` (re-exported from `@cipherstash/protect-ffi`) gains `MATCH_REQUIRES_TEXT` and `UNSUPPORTED_CONFIG_VERSION`. Exhaustive switches over `ProtectErrorCode` will need additional cases.
  - **`match` index validation**: protect-ffi now rejects `match` indexes on columns whose `cast_as` is not text-family (`'text'` / `'string'`) with `MATCH_REQUIRES_TEXT`. The stack's `freeTextSearch()` builder is unaffected because it only targets string-typed columns.
  - **`Encrypted` ciphertext shape**: protect-ffi's `Encrypted` type is now a discriminated union keyed on `k` (`'ct'` for scalars, `'sv'` for SteVec). SteVec storage payloads now place the root document ciphertext at `sv[0].c`. The stack's `isEncryptedPayload` runtime check continues to work because storage payloads still carry `c` (scalar) or `sv` (SteVec). The DynamoDB helpers (`toEncryptedDynamoItem`, `SearchTermsOperation`) now narrow on `k` before reading variant-only fields.
  - **Config-validation error message wording**: error messages for config-validation failures now come from upstream `ConfigError`. `ProtectError.code` values are preserved; consumers that string-match on `err.message` for config-validation errors must update.

- bb9764d: `stash db push` is no longer included by default in `stash plan` / `stash impl` agent prompts or the wizard's post-agent step. SDK users (Drizzle, Supabase, plain PostgreSQL) no longer see `stash db push` baked into their rollout/cutover walkthroughs — the encryption config lives in app code, so the database doesn't need a copy.

  Pass `--proxy` to `stash init` (or answer the new interactive prompt) if you query encrypted data via [CipherStash Proxy](https://github.com/cipherstash/proxy). The choice is persisted to `.cipherstash/context.json` as `usesProxy` and is honoured by `stash plan`, `stash impl`, and the wizard's post-agent step. Existing `.cipherstash/context.json` files without the field default to SDK-only.

  Known gap: `stash encrypt cutover` currently requires a pending EQL config registered via `stash db push`, so SDK-only users running the migrate-existing-column flow will hit a "No pending EQL configuration" error from cutover. Workaround: run `stash db push` once before `stash encrypt cutover`. Decoupling cutover from EQL config for SDK-only users is tracked as a follow-up to [#447](https://github.com/cipherstash/stack/issues/447).

### Patch Changes

- 8fe2496: `stash impl` and `stash plan` no longer hang in non-TTY contexts (CI, pipes, automation harnesses). The agent-target picker previously read from `/dev/tty` and waited forever. You can now pass `--target <claude-code|codex|agents-md|wizard>` to select a handoff target non-interactively, and when neither `--target` nor a TTY is available the command prints a hint and exits cleanly instead of blocking.
  - @cipherstash/migrate@0.2.0

## 0.15.0

### Minor Changes

- dc02d0b: Add `@cipherstash/prisma-next` — searchable application-layer encryption for Postgres with Prisma Next. The framework's migration system installs the EQL bundle in the same `prisma-next migration apply` sweep that creates the application schema; no separate `stash db install` step.

  **`@cipherstash/prisma-next` (new package, initial release)**

  - **Six encrypted column types** — `EncryptedString`, `EncryptedDouble`, `EncryptedBigInt`, `EncryptedDate`, `EncryptedBoolean`, `EncryptedJson` — declared via PSL constructors (`cipherstash.Encrypted*()`) or TS factories (`encryptedString()`, etc.).
  - **17 query operators** — 13 predicate operators surfaced as column methods (`cipherstashEq`, `cipherstashIlike`, `cipherstashGt`, `cipherstashBetween`, `cipherstashInArray`, `cipherstashJsonbPathExists`, …) and 4 free-standing helpers (`cipherstashAsc`, `cipherstashDesc`, `cipherstashJsonbPathQueryFirst`, `cipherstashJsonbGet`).
  - **Per-codec search-mode flags** (`equality`, `freeTextSearch`, `orderAndRange`, `searchableJson`) drive the EQL search-config indices the codec lifecycle hook emits at migration time. Defaults to `true` across the board.
  - **One-call setup** via `cipherstashFromStack({ contractJson })` from `@cipherstash/prisma-next/stack` — derives the stack `encryptedTable` / `encryptedColumn` schemas from `contract.json` (single source of truth, no duplicate hand-written declarations), constructs the `@cipherstash/stack` `EncryptionClient`, builds the framework-native `CipherstashSdk` adapter, and returns ready-to-spread `{ extensions, middleware, encryptionClient }` for `postgres<Contract>({...})`.
  - **Layered API** — `deriveStackSchemas(contractJson)` and `createCipherstashSdk(client, schemas)` exposed as primitives for advanced users (custom keysets, multi-tenant routing, non-stack KMS).
  - **Bulk-encrypt middleware** (`bulkEncryptMiddleware(sdk)`) coalesces every plaintext placeholder across a query into one `bulkEncrypt` SDK round-trip per `(table, column)` group. `decryptAll(rows)` does the symmetric coalescing on the read side.
  - **Misconfig diagnostic** — if the user constructs the runtime descriptor but forgets to register `bulkEncryptMiddleware(sdk)` against the same SDK, the codec's encode throws a `RUNTIME.ENCODE_FAILED` envelope with a copy-pasteable wiring snippet at the first encrypted write.
  - **Subpath exports** — `./stack`, `./control`, `./runtime`, `./middleware`, `./pack`, `./column-types`; tree-shakable along the control / runtime / middleware seams.
  - **Contributes an EQL contract space** — installs the `eql_v2` schema, `eql_v2_encrypted` composite type, `ore_*` types, EQL functions / operators / casts via the cipherstash extension's baseline migration. Runs in the same control-plane sweep as the application schema.
  - **Full docs**: https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next.

  **`stash` (new feature)**

  - **`stash init --prisma-next`** — new init provider for Prisma Next projects. Reuses `authenticate` + `resolve-database` + `install-deps` (additionally installs `@cipherstash/prisma-next`), skips `install-eql` (the framework handles it via `prisma-next migration apply`) and `build-schema` (`cipherstashFromStack` derives schemas from the contract — no hand-written encryption client file). Detected automatically when a `prisma-next.config.*` or `@cipherstash/prisma-next` dependency is present in the project.
  - **`detectPrismaNext(cwd)`** — new export from `commands/db/detect.ts` mirroring the existing `detectDrizzle` / `detectSupabase` helpers.

## 0.14.1

### Patch Changes

- 3a38f1a: `stash status` now detects when a plan has been drafted but the rollout hasn't started yet. Previously, with no `cs_migrations` activity, status reported "your encryption rollout has not begun" and pointed the user at `stash plan` — even when `.cipherstash/plan.md` already existed. It now recognises that case and points the user at `stash impl` to execute the plan instead.

## 0.14.0

### Minor Changes

- 1a97d40: Add plan-mode support to the wizard so `stash plan` can hand off to the CipherStash Agent. The wizard now accepts `--mode <plan|implement>` (default `implement` for back-compat). In plan mode it skips the column-selection TUI, forwards `mode: 'plan'` to the gateway (which returns a planning prompt whose deliverable is `.cipherstash/plan.md`), and skips the post-agent install/push/migrate and call-site-scan steps. Implement mode is unchanged.

  `stash plan`'s handoff picker now offers all four targets (Claude Code, Codex, AGENTS.md, CipherStash Agent) — the wizard is no longer gated out of plan mode. `stash impl`'s picker is unchanged.

### Patch Changes

- 440879b: feat(cli): pass `--allow-dangerously-skip-permissions` when `stash init` launches Claude Code, so the user can opt in to skip-permissions mode mid-session without relaunching. Codex and Wizard handoffs are unchanged.

## 0.13.0

### Minor Changes

- e16b282: Split agent handoff out of `stash init` into a new `stash impl` command. `init` now owns scaffolding only (auth, database, encryption client, EQL extension) and exits at a clean checkpoint pointing at `stash impl`. `stash impl` derives plan-vs-implement mode from disk state — if `.cipherstash/plan.md` is missing it asks the agent to draft a plan; if it exists, the agent executes the plan as the source of truth. `--continue-without-plan` skips the planning checkpoint after an interactive confirmation. The earlier in-init `Plan first / Go straight to implementation` picker is removed in favour of the new command boundary.
- db163e1: `stash impl` now renders a plan summary panel and asks the user to confirm before launching the implementation agent. When a plan exists, the CLI parses a machine-readable `<!-- cipherstash:plan-summary {...} -->` block (the planning agent is instructed to emit one at the top of `.cipherstash/plan.md`) and prints column counts, per-column paths, and whether the work is single-deploy or staged across 4 deploys. Default-yes on the confirm so the path of least resistance is to proceed; saying No exits cleanly. Older plans without the summary block fall back to a soft "open in your editor" panel — never an error. Non-TTY runs (CI, pipes) skip the confirm and proceed.
- 59b138b: Extract planning into its own `stash plan` command. Three commands now own the setup lifecycle:

  - `stash init` — scaffold (auth, db, deps, EQL). Ends with a chain prompt to `stash plan`.
  - `stash plan` — draft a reviewable plan at `.cipherstash/plan.md`. Ends with a chain prompt to `stash impl`.
  - `stash impl` — execute. With a plan, shows the summary panel and confirms. Without one, presents a `Draft a plan first / Continue without a plan` picker (the second option goes through a security confirm). `--continue-without-plan` skips the picker.

  `stash status` reflects the new flow — its "Plan written" stage and `Next:` line route to `stash plan` when init is done but no plan exists. Non-TTY runs of `stash impl` without a plan now error out with a clear next-action rather than guessing intent.

- db163e1: Add `stash status` — a top-level lifecycle map for the project. Reads `.cipherstash/context.json`, `.cipherstash/plan.md`, and `.cipherstash/setup-prompt.md` from disk to render a panel showing whether init is done, whether a plan has been written, and whether an agent has been engaged. Points at `stash db status` for EQL install info and `stash encrypt status` for per-column migration phase. Runs in milliseconds — no auth, no database connection required. The existing `stash db status` is unchanged.

## 0.12.1

### Patch Changes

- 439c63e: Fix backfill CLI wrapper to resolve schema column metadata correctly and surface configuration errors with author-controlled messages while keeping generic diagnostics for unexpected failures.

## 0.12.0

### Minor Changes

- f315334: `stash init` can now hand off the rest of setup to whichever coding agent the user is set up with — and it leaves them with a project-specific action plan and the right reference material, not just generic rules.

  The new pipeline:

  1. **Authenticate** (unchanged).
  2. **Resolve `DATABASE_URL`** — uses the same resolver as `stash db install` (flag → env → `supabase status` → interactive prompt). Hard-fails with an actionable message if nothing resolves.
  3. **Build the encryption client.** When the database has tables, `init` introspects them and generates a real client from the user's selection. When the database is empty, it falls back to a placeholder so fresh projects still work — and the action prompt notes the placeholder so the agent reshapes it later.
  4. **Install dependencies** — `@cipherstash/stack` (runtime) + `stash` (CLI dev dep).
  5. **Install EQL into the database** — y/N confirm, then runs `stash db install` programmatically against the URL we already resolved. No second prompt for credentials.
  6. **Pick a handoff** from the four-option menu. Each handoff installs the right artifacts for the chosen tool:
     - **Hand off to Claude Code** — copies the per-integration set of authored skills (`stash-encryption` + `stash-<integration>` + `stash-cli`) into `.claude/skills/`, writes `.cipherstash/context.json` and `.cipherstash/setup-prompt.md`, spawns `claude`. Default when `claude` is on PATH.
     - **Hand off to Codex** — writes a sentinel-managed `AGENTS.md` (durable doctrine) + copies the same skills into `.codex/skills/` (procedural workflows), writes `context.json` + `setup-prompt.md`, spawns `codex`. Default when `codex` is on PATH and `claude` is not. Follows OpenAI's Codex guidance: AGENTS.md for repo doctrine, skills for repeatable workflows.
     - **Use the CipherStash Agent** — writes `context.json` and runs `stash wizard`. Fallback for users without a local CLI agent. The wizard installs its own skills.
     - **Write AGENTS.md** — for editor agents (Cursor, Windsurf, Cline) that don't auto-load skill directories. Writes a single `AGENTS.md` with the doctrine _plus_ the relevant skill content inlined under a sentinel block, so the agent has the API details without needing to follow file references. Plus `context.json` + `setup-prompt.md`. No spawn.

  Detection is non-blocking: if the chosen CLI agent (`claude` or `codex`) isn't installed, init still writes the artifacts and prints install + manual-launch instructions. Progress is never wasted.

  `.cipherstash/setup-prompt.md` is the headline artifact. It's the project-specific action plan — _"init has done X and Y; you need to do Z next, with these exact commands and paths"_ — generated from the current init state. The launch prompt for Claude / Codex points the agent at this file first; the installed skills provide the reusable rulebook the prompt references. For IDE users, it's ready to paste into the first chat.

  Per-integration skill subset:

  ```text
  drizzle    → stash-encryption + stash-drizzle  + stash-cli
  supabase   → stash-encryption + stash-supabase + stash-cli
  postgresql → stash-encryption + stash-cli
  ```

  The skills themselves are the authored ones at the repo root (`/skills/`); they ship inside the CLI tarball via `tsup` so init can copy them locally without a network round-trip. The AGENTS.md doctrine fragment ships the same way.

  Re-running `init` is safe — `AGENTS.md` uses sentinel-marker upsert (`<!-- cipherstash:rulebook start/end -->`), so the managed region is replaced in place and any user edits outside it are preserved. Skill directories are overwritten so the user always gets the latest content. `setup-prompt.md` is regenerated wholesale each run since it's meant to reflect the current state.

  `.cipherstash/context.json` is the universal "what shape is this project" payload — integration, encryption client path, schema, env key names (never values), package manager, install command, CLI version, names of installed skills, generation timestamp.

- ce70b4d: Add `stash wizard` as a thin wrapper subcommand around `@cipherstash/wizard`.

  The wizard ships as a separate npm package so the heavy agent SDK stays out of the `stash` CLI bundle. Until now, users had to remember a second tool name (`npx @cipherstash/wizard`); the wrapper exposes the same capability under the existing `stash` surface so the user only has to think about one CLI.

  `stash wizard` detects the project's package manager and spawns the wizard via the matching one-shot runner — `npx`, `pnpm dlx`, `yarn dlx`, or `bunx` — with `stdio: 'inherit'` so the wizard owns the terminal cleanly. Any flags after `wizard` are forwarded verbatim, so `stash wizard --debug` works.

  On a cold cache (the wizard package isn't installed in the project) the runner downloads it before launching — a few seconds. The wrapper prints an explicit "first run downloads ~5s" line in that case so the CLI doesn't appear hung. On a warm cache, just a "Launching the CipherStash wizard…" line, then the wizard takes over.

  Existing copy that pointed at `npx @cipherstash/wizard` (init's next-steps for base / Drizzle / Supabase, `db install`'s post-install note) now uses `stash wizard`.

- add4357: Add `stash encrypt` command group and `@cipherstash/migrate` library for plaintext → encrypted column migrations.

  New CLI commands:

  - `stash encrypt status` — per-column migration status (phase, backfill progress, drift between intent and state, EQL registration).
  - `stash encrypt plan` — diff `.cipherstash/migrations.json` (intent) vs observed state.
  - `stash encrypt backfill --table <t> --column <c>` — resumable, idempotent, chunked encryption of plaintext into `<col>_encrypted`. Uses the user's encryption client (Protect/Stack). SIGINT-safe; re-run to resume. The first run on a column prompts to confirm dual-writes are deployed (or accept `--confirm-dual-writes-deployed` for non-interactive contexts), records the `dual_writing` transition in `cs_migrations`, then runs the chunked encryption loop. `--force` re-encrypts every plaintext row regardless of current state — recovery path for drift caused by an earlier backfill running before dual-writes were actually live.
  - `stash encrypt cutover --table <t> --column <c>` — runs `eql_v2.rename_encrypted_columns()` inside a transaction; optionally forces Proxy config refresh via `CIPHERSTASH_PROXY_URL`. After cutover, apps reading `<col>` transparently receive the encrypted column.
  - `stash encrypt drop --table <t> --column <c>` — generates a migration file that drops the old plaintext column.

  `stash db install` now also installs a `cipherstash.cs_migrations` table used to track per-column migration runtime state (current phase, backfill cursor, rows processed). The table is append-only (event-log shape) and kept separate from `eql_v2_configuration` which remains the authoritative EQL intent store used by Proxy.

  The new `@cipherstash/migrate` package exposes the same primitives as a library for users who want to embed backfill in their own workers or cron jobs — all commands are thin wrappers around its exports (`runBackfill`, `appendEvent`, `latestByColumn`, `progress`, `renameEncryptedColumns`, `reloadConfig`, `readManifest`, `writeManifest`).

### Patch Changes

- 39af183: Make `--help` banners and the post-install "Next steps" panel show commands using the package manager the user actually invoked the CLI with, instead of always emitting `npx`.

  A user who runs `bunx @cipherstash/cli --help` now sees:

  ```
  Usage: bunx @cipherstash/cli <command> [options]
  …
  Examples:
    bunx @cipherstash/cli init
    bunx @cipherstash/cli auth login
    bunx @cipherstash/cli db install
  ```

  instead of `npx @cipherstash/cli …` regardless of how they invoked it. Same for `pnpm dlx`, `yarn dlx`, and the default `npx` path.

  Concretely:

  - `--help` (top-level) — usage line and all six examples in `bin/stash.ts`.
  - `--help` (auth) — usage line and the two `auth login` examples in `commands/auth/index.ts`.
  - `db install`'s "Next steps" note — the `wizard` invocation now matches the user's runner.
  - The `@cipherstash/stack is required for this command` hint shown by `requireStack` (when `db push`/`validate`/`schema build` are run before the runtime SDK is installed) now suggests the package manager's install command and the user's runner for the follow-up `init` invocation.

  No public-API change. Detection sources unchanged from #379: `npm_config_user_agent` first, then lockfile, then `npx` fallback.

- a8dbb65: Render every user-facing CLI string and execute every shell-out under the detected package manager (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`), completing the work started in #379. Affected surfaces: `@cipherstash/cli` top-level + `auth` + `env` help, `db install` Drizzle migration steps, `db migrate` not-implemented warning, the Supabase migration SQL header, the Supabase status fallback exec, the `@cipherstash/protect` `stash` Stricli help (set/get/list/delete), the `@cipherstash/wizard` usage line and agent command allowlist, and the `@cipherstash/drizzle` `generate-eql-migration` help + drizzle-kit invocation. A new `pnpm run lint:runners` lint runs in CI and fails on any reintroduction of a hardcoded runner literal.
- Updated dependencies [add4357]
  - @cipherstash/migrate@0.2.0

## 0.11.0

### Minor Changes

- de9c02c: Rename the CLI package from `@cipherstash/cli` to `stash`. The published code, commands, and flags are unchanged — this is a pure rename so the day-to-day invocation drops from `npx @cipherstash/cli ...` to `npx stash ...`.

  **Migration**

  1. Update your `package.json` devDependencies:

     ```diff
     -  "@cipherstash/cli": "^0.10.0"
     +  "stash": "^0.10.1"
     ```

  2. Update the `defineConfig` import in `stash.config.ts`:

     ```diff
     - import { defineConfig } from '@cipherstash/cli'
     + import { defineConfig } from 'stash'
     ```

  3. Update any `npx @cipherstash/cli ...` / `bunx @cipherstash/cli ...` / `pnpm dlx @cipherstash/cli ...` / `yarn dlx @cipherstash/cli ...` invocations in scripts, CI, READMEs, and team docs to use `stash` instead. Programmatic exports (`defineConfig`, `loadStashConfig`, `EQLInstaller`, `loadBundledEqlSql`, `downloadEqlSql`, `PermissionCheckResult`) are re-exported from `stash` with the same shapes.

  **Wizard impact (`@cipherstash/wizard`)**

  The wizard's post-agent step and its prerequisite / agent-error hints now reference `stash` (e.g. `Run: bunx stash auth login`, `Running bunx stash db install...`) rather than `@cipherstash/cli`. The wizard package name and `stash-wizard` binary are unchanged — only the strings the wizard prints and the commands it shells out to are affected.

- 8ee11fd: Layered `DATABASE_URL` resolution for DB / schema commands.

  Previously, any DB-touching command (`db install`, `db push`, `db upgrade`, `db status`, `db validate`, `db test-connection`, `schema build`) failed with the cryptic Zod error:

  ```
  Error: Invalid stash.config.ts
    - databaseUrl: Invalid input: expected nonoptional, received undefined
  ```

  if `DATABASE_URL` wasn't already in the environment. The CLI auto-loaded `.env.local` / `.env.development.local` / `.env.development` / `.env`, but had no story for `--database-url` flags, local Supabase, or pasted-once values.

  The scaffolded `stash.config.ts` now calls a resolver directly:

  ```ts
  import { defineConfig, resolveDatabaseUrl } from "stash";

  export default defineConfig({
    databaseUrl: await resolveDatabaseUrl(),
    client: "./src/encryption/index.ts",
  });
  ```

  `resolveDatabaseUrl()` walks sources in order; first hit wins:

  1. `--database-url <url>` flag — new, accepted on all seven DB / schema commands. Used for this run only; never written to disk.
  2. `process.env.DATABASE_URL` — covers shell exports, mise, direnv, dotenv-cli, the existing dotenv loads.
  3. `supabase status --output env` → `DB_URL` — auto-engaged when `--supabase` is set or a `supabase/config.toml` is detected. Useful for local Supabase users who haven't exported the URL yet.
  4. Interactive prompt — opens with a tip listing the alternatives (flag, env, the user's actual dotenv file). Skipped under `CI=true` or non-TTY stdin.
  5. Hard fail with a source-naming error message.

  The connection string is **never persisted to disk** — `stash.config.ts` only contains the `await resolveDatabaseUrl()` call, never a literal URL. The resolver also doesn't mutate `process.env`; CLI flag context is threaded into the config evaluation via `AsyncLocalStorage` so concurrent loads stay isolated. Source labels are logged on non-env paths (`Using DATABASE_URL from --database-url flag` / `from supabase status` / `from prompt`) but the URL itself is never echoed.

  `db test-connection`'s connection-failure hint is now source-aware: it points users at `--database-url`, the env var, and the actual dotenv file in their project (`.env.local` if present, `.env` otherwise) — not the misleading `stash.config.ts` it used to suggest.

## 0.10.1

### Patch Changes

- f34fe9d: Show and execute commands using the detected package manager's runner (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`) instead of always emitting `npx`. A user who runs `bunx @cipherstash/cli init` now sees a "Next Steps" panel that suggests `bunx @cipherstash/cli db install` and `bunx @cipherstash/wizard`, and the wizard's post-agent step both displays and shells out to `bunx @cipherstash/cli db push` (was: `Failed: npx @cipherstash/cli db push`). Wizard prerequisite messages and AI-agent error hints (e.g. on a 401, `Run: bunx @cipherstash/cli auth login`) follow the same rule. Detection sources are unchanged: `npm_config_user_agent` first, then lockfile, then `npx` fallback.

## 0.10.0

### Minor Changes

- 79f4a0b: Fix `loadStashConfig` to correctly unwrap the default export from `stash.config.ts`. Previously, any database-touching command (`db install`, `db push`, `db validate`, `db status`, `db test-connection`, `schema build`) would fail validation against a perfectly valid config with:

  ```
  Error: Invalid stash.config.ts

    - databaseUrl: Invalid input: expected nonoptional, received undefined
  ```

  The issue: in jiti 2.x, the `interopDefault: true` option passed to `createJiti(...)` only applies to the deprecated synchronous `jiti(id)` callable form. The async `jiti.import()` ignores it and always returns the full module namespace. With `export default defineConfig({...})` that meant Zod was validating `{ default: { databaseUrl, client } }` and reporting `databaseUrl` as undefined even when the user's config plainly set it.

  Switched to jiti's per-call `{ default: true }` option, which does work on `jiti.import()`. Added an integration test that exercises real jiti against a real temp `stash.config.ts` so future regressions get caught — the previous mocked test was passing the bug straight through.

  This bug surfaced after `db install` started loading `stash.config.ts` (during the onboarding overhaul), but affected every other command that reads the config.

## 0.9.0

### Minor Changes

- 5d3eb13: Reduce friction in `stash init`.

  - **No more "How will you connect to your database?" prompt.** Init now auto-detects Drizzle (from `drizzle.config.*` or `drizzle-orm`/`drizzle-kit` in `package.json`) and Supabase (from the host in `DATABASE_URL`), and silently picks the matching encryption client template. Falls back to a generic Postgres template otherwise.
  - **No more "Where should we create your encryption client?" prompt.** Init writes to `./src/encryption/index.ts` by default. The "file already exists, what would you like to do?" prompt still appears so existing client files aren't silently overwritten.
  - **Single combined dependency-install prompt.** Previously init asked twice (once for `@cipherstash/stack`, once for `@cipherstash/cli`). It now asks once, listing both, and runs the installs in sequence. When both packages are already in `node_modules`, no prompt appears at all.
  - **Already-authenticated users skip the "Continue with workspace X?" prompt.** Init logs `Using workspace X` and proceeds. Run `stash auth login` directly to switch workspaces.

  `stash db install` now also calls into the same encryption-client scaffolder as a safety net — users who run `db install` without `init` first still get a working client file generated at the path their `stash.config.ts` points to.

- 5d3eb13: **Breaking:** the `stash wizard` command has been removed. The AI-guided encryption setup is now its own package — run it via `npx @cipherstash/wizard` (or `pnpm dlx`, `bunx`, `yarn dlx`).

  The wizard was pulling `@anthropic-ai/claude-agent-sdk` (47MB unpacked) into every `npx @cipherstash/cli` invocation, even for fast commands like `init`, `auth`, and `db install`. Splitting it out keeps cli's dependency tree small and lets each package manager handle the wizard's install natively — no more shelling out to `npm` from inside the cli, no Yarn PnP / Bun-only failure modes.

  The next-steps output from `init` and `db install` still recommends `npx @cipherstash/wizard` as the automated path. The `schema build` command no longer offers a wizard/builder selection prompt — it goes straight to the schema builder.

## 0.8.0

### Minor Changes

- 34432e9: Added --migration and --direct options to Supabase EQL install steps

## 0.7.1

### Patch Changes

- a0760f6: Detect the package manager from `npm_config_user_agent` when running `stash init`. Running `bunx @cipherstash/cli init`, `pnpm dlx @cipherstash/cli init`, or `yarn dlx @cipherstash/cli init` now uses the invoking tool for dependency installation (`bun add`, `pnpm add`, `yarn add`) instead of falling back to `npm install`. Lockfile detection is still preferred when present, so projects with an existing convention are unaffected. Fixes `EUNSUPPORTEDPROTOCOL` failures on `workspace:*` deps in Bun-managed projects.

## 0.7.0

### Minor Changes

- 7f5a05a: Fixed issue where the wizard was checking CipherStash auth based on path and now leverages the auth npm package.

## 0.6.1

### Patch Changes

- 8513705: Fix mangled `eql_v2_encrypted` type in drizzle-kit migrations.

  - `@cipherstash/stack/drizzle`'s `encryptedType` now returns the bare `eql_v2_encrypted` identifier from its Drizzle `customType.dataType()` callback. Returning the schema-qualified `"public"."eql_v2_encrypted"` (0.15.0) triggered a drizzle-kit quirk that wraps the return value in double-quotes and prepends `"{typeSchema}".` in ALTER COLUMN output — producing `"undefined".""public"."eql_v2_encrypted""`, which Postgres cannot parse.
  - `stash db install` / `stash wizard`'s migration rewriter now matches all four forms drizzle-kit may emit (`eql_v2_encrypted`, `"public"."eql_v2_encrypted"`, `"undefined"."eql_v2_encrypted"`, `"undefined".""public"."eql_v2_encrypted""`) and rewrites each into the safe `ADD COLUMN … DROP COLUMN … RENAME COLUMN` sequence.

  Users on 0.15.0 who hit this in generated migrations should upgrade and re-run `npx drizzle-kit generate` + `stash db install` (or re-run the wizard).

## 0.6.0

### Minor Changes

- 9944a25: Update cipherstash auth to 0.36.0

## 0.5.0

### Minor Changes

- 1929c8f: Mark secrets as a coming soon feature and remove existing SDK integration.

## 0.4.0

### Minor Changes

- 1e0d4c1: Support CipherStash rebrand with new docs links.

## 0.3.0

### Minor Changes

- 0d21e9b: Fix invalid client error.

## 0.2.0

### Minor Changes

- 4d0dfc5: Fixed peer dependency by lazy loading commands requiring @cipherstash/stack.

## 0.1.0

### Minor Changes

- 068f820: Release the consolidated CipherStash CLI npm package.

> Renamed from `@cipherstash/stack-forge`. The standalone `@cipherstash/wizard` package was absorbed into this CLI as `npx @cipherstash/cli wizard`. The single binary is now invoked via `npx @cipherstash/cli` (replaces `stash-forge` and `cipherstash-wizard`).

## 0.4.0

### Minor Changes

- 5245cd7: Improved CLI setup and initialization commands.

## 0.3.0

### Minor Changes

- 6f27ec3: Improve CLI user experience for developer onboarding.

## 0.2.0

### Minor Changes

- 3414761: Add additional CLI tools for validate, status, init. Fixed push command to work with CipherStash Proxy.

## 0.1.0

### Minor Changes

- 60ce44a: Initial release of the `stash-forge` CLI utility.
