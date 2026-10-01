# stash

## 1.1.1

### Patch Changes

- 44e2921: Fix `stash eql migration --drizzle`, which aborted for every project with a `drizzle.config.ts` (#924).

  - **Stop passing `--out` to `drizzle-kit generate`.** drizzle-kit reads its config file _or_ its command-line options, never both: any of `--schema`/`--out`/`--dialect` switches it into CLI mode, where it then aborts demanding the two we cannot supply (`Please provide required params: [x] schema [x] dialect`). Verified against drizzle-kit 0.28.5, 0.30.6 and 0.31.4 — this was never version-specific. Your `drizzle.config.ts` now decides the output directory and stash follows the path drizzle-kit reports, warning when it differs from a `--out` you passed. `--out` remains the fallback directory to search.
  - **Pass the resolved `DATABASE_URL` into the drizzle-kit child process.** A `drizzle.config.ts` that reads `process.env.DATABASE_URL` (and often throws when it is missing) previously saw nothing, because the project's usual `dotenv -e .env.local -- drizzle-kit …` wrapper never runs when stash invokes drizzle-kit directly. stash already loads `.env`/`.env.local` at startup; it now also threads down a URL only the CLI can find, such as a running local Supabase.
  - **Report the actual failure.** drizzle-kit writes its errors to stdout, not stderr, so the abort printed nothing but "Make sure drizzle-kit is installed and configured" — the one thing that was never wrong. Both streams are now surfaced, and a config that could not read `DATABASE_URL` gets a follow-up naming that instead.

- 67b137a: `stash init` installs the agent skills again, and does it first.

  Since 1.0.0-rc.4 the only callers of the skills installer were the `plan` and
  `impl` handoff steps, which `stash init` never reaches — so `stash@1.1.0`
  installed no `stash-*` skills for anyone, in any mode. The most common flow, a
  coding agent running `npx stash init --supabase` inside a project, completed
  with a green summary, a plausible-looking `.cipherstash/context.json`, and zero
  guidance: the skills sat unread in `node_modules/stash/dist/skills/` unless the
  agent thought to go digging. Fixes #923.

  Init now copies the per-integration skills into `.claude/skills/` (Claude Code
  detected via the `claude` binary or a `.claude/` directory) and `.codex/skills/`
  (Codex), installing to both when both are detected, and records them in
  `context.json`.

  It runs as init's **first** step, ahead of authentication. Installing skills
  needs no network, no credentials and no database, while authenticate,
  resolve-database and install-eql each need one and each can exit non-zero —
  so the guidance now survives a run that fails partway, which is when it is
  needed most. One behaviour change falls out of that: a run cancelled at the
  first prompt leaves the skills directory behind where previously it wrote
  nothing.

  Also:

  - **New optional `stash init --target <claude-code|codex>`** names the skills
    destination and skips detection. Unlike `plan --target` / `impl --target` it
    selects the destination only — `init` still performs no handoff. Existing
    invocations are unaffected.
  - **The summary reports the outcome either way.** A run that installs nothing
    now says so, and prints the command that will install them, instead of a
    silent `installedSkills: []`.
  - **`--target` is validated properly on `init`, `plan` and `impl`.** A
    trailing `--target` with no value, and `--target=`, were both treated as
    "flag absent" — so the command silently did whatever it does with no flag at
    all, rather than telling you the value was missing. All three commands share
    one validator now.
  - **A later handoff no longer erases the record.** `stash plan --target
agents-md` installs no skill directories of its own and used to overwrite
    `installedSkills` with an empty list, dropping skills that were on disk.
    Deliveries are merged across hops now.

- ec0c5a7: `stash-managed-platforms` skill: fold in what a live Lovable Cloud integration actually hit.

  Four additions, each from a verified failure in the 2026-08-19 skilltester run
  (cipherstash/skilltester branch `20260819-01-lovable`):

  - **Command-time ceilings.** Replaying the ~2.6 MB EQL bundle with `psql -f` sends one statement
    per round trip and dies partway under Lovable's 600 s ceiling, leaving a half-installed schema.
    The skill now says to prefer `stash eql install` / the generated migration, gives the
    chunk-and-apply recipe for when raw SQL is unavoidable, and covers the ownership trap when
    cleaning up a half-install.
  - **Data API grants.** The EQL install grants nothing to `authenticated` / `anon` /
    `service_role`, so every PostgREST function-form call fails until an explicit
    `GRANT USAGE / EXECUTE` — now stated with the exact SQL.
  - **Install cooldowns.** Lovable's `bunfig.toml` `minimumReleaseAge` and Deno's
    `--minimum-dependency-age` both refuse a same-day CipherStash release; the skill names the
    exclude-list workaround and says to disclose it.
  - **Lovable secrets.** Who sets them depends on where the agent runs: Lovable's in-product agent
    can store project secrets itself, while the external Lovable MCP surface has no secrets tool —
    there the values are handed to the human (they run `stash env` themselves, or copy from the
    agent-written 0600 file and delete it), never through chat or logs.
  - @cipherstash/migrate@1.0.0

## 1.1.0

### Minor Changes

- a2b0b45: The CLI now handles database TLS properly, so the discoverable fix for a certificate failure is never `NODE_TLS_REJECT_UNAUTHORIZED=0`.

  - Every CLI database connection honours `sslmode` and `sslrootcert` from the connection string — and `PGSSLMODE` / `PGSSLROOTCERT` from the environment when the URL carries no TLS parameters (URL wins; unlike raw node-postgres, `PGSSLROOTCERT` is actually consumed): `verify-full` (and `require`/`verify-ca`/`prefer`, kept as full verification — node-postgres's current behaviour) verifies the server certificate; `no-verify` is honoured with a one-line stderr warning; `disable` turns TLS off. Client-certificate setups (`sslcert`/`sslkey`) pass through untouched.
  - CA resolution: `sslrootcert=<path>` (libpq semantics — sole trust anchor; `sslrootcert=system` selects the system store) → `PGSSLROOTCERT` → for `*.supabase.co`/`*.supabase.com` hosts a **bundled Supabase root CA** (appended to the system roots) → the system store. `sslmode=verify-full` against Supabase — direct hosts and the pgBouncer pooler — now verifies out of the box.
  - Certificate-verification failures — shaped centrally in the connection factory, so every command surfaces them — name the host and the supported remedies in order (`sslrootcert=…`, then `sslmode=no-verify` as a last resort with the consequence spelled out), and explicitly warn against `NODE_TLS_REJECT_UNAUTHORIZED=0`, which is process-wide and would also disable verification for the connections carrying CipherStash credentials.
  - The node-postgres "SSL modes … are treated as aliases for verify-full" SECURITY WARNING no longer appears on every invocation against `sslmode=require` URLs: the CLI decides the TLS config itself and hands pg a URL with the TLS params stripped (fixes the upstream-advisory passthrough).

- a2b0b45: EQL installs no longer abort on managed platforms whose database role is not `postgres`, and a new `stash eql preflight` command reports role capability before anything is attempted.

  - `stash eql install` (and `eql upgrade`) now run the EQL v3 bundle in its own transaction and the Supabase role grants after it commits, so a grants failure can no longer roll back a working install. When the connecting role is not a member of `postgres` (e.g. Lovable's `sandbox_exec`), the three owner-scoped `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements are skipped and the install completes without them — they are optional (they only cover EQL objects `postgres` might later create outside stash tooling, and stash re-grants every object on each install/upgrade); the SQL is printed as "Optional SQL — requires postgres" for operators who want it. Every plain `GRANT` still runs. Previously that single refused statement rolled back the entire install (~194 functions).
  - Re-running `stash eql install` on an already-installed Supabase database now re-applies the role grants (idempotent) instead of exiting early, so an install whose grants step failed heals on a plain re-run.
  - The migration generated by `stash eql migration --supabase` wraps the owner-scoped statements in a `pg_has_role` guard, so it applies cleanly whatever role the project's migration runner uses — a non-member role skips them instead of aborting the whole migration.
  - New read-only `stash eql preflight` (`--json` for agents): reports `current_user`, superuser, membership of `postgres` (guarded for databases with no `postgres` role), `CREATE` on the database and on `public` (guarded for databases without a `public` schema), `pgcrypto` presence _and placement_ (a pgcrypto outside `extensions`/`public` aborts the bundle, even for superusers), and the EQL v3 schemas' presence and drop-ownership (a reinstall begins with `DROP SCHEMA ... CASCADE`) — each blocked row naming the statement it blocks. Exits 1 on blocking gaps; membership of `postgres` never blocks. `--json` stdout is pure JSON in every outcome: `{ status: 'ok' | 'blocked', ... }`, or the shared `{ status: 'error', code, message }` envelope — including when no DATABASE_URL is configured. The same check runs at the head of `eql install`.
  - Install failure messages now state recoverability: a bundle failure says nothing was applied (rolled back); a grants failure says the install itself was kept.
  - Library surface: `EQLInstaller.preflight()` (rich `PreflightResult`) supersedes `checkPermissions()`, which remains as a deprecated adapter with its `PermissionCheckResult` shape unchanged — no breaking change for existing `stash@1.x` consumers. `install()` now returns `InstallResult` with the skipped SQL, if any, and `applySupabaseGrants()` re-applies the grants alone. The exact `SUPABASE_PERMISSIONS_SQL_V3` block is unchanged byte-for-byte; new exports expose its immediate (`SUPABASE_IMMEDIATE_GRANTS_SQL_V3`), owner-scoped (`SUPABASE_DEFAULT_PRIVILEGES_SQL_V3`), guarded (`SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3`), and migration (`SUPABASE_MIGRATION_GRANTS_SQL_V3`) forms.

- a2b0b45: New `stash eql verify`: assert the installed EQL surface is complete and coherent, independent of any application schema. A partial install — domains present, some of their comparison functions or operators absent — used to report success at install time and fail at query time on a specific predicate (e.g. `weight >= x`); nothing detected it. `eql verify` compares the database against everything the pinned bundle installs (every domain, function overload, operator, cast, and the ORE operator class) via read-only catalog queries, reports damage grouped per domain, and distinguishes expected absence from damage: the ORE operator class being skipped on managed Postgres, with its loud-failure fallback in place, reads as the supported configuration it is rather than a failed install. Exit 0 means exactly one thing — the surface was checked and found complete; damage, EQL absent, and a version mismatch with the pinned bundle (nothing verifiable) all exit 1. `--json` emits the structured report for agents. `stash eql install` now runs the same check automatically before declaring success, on the fresh-install path and the already-installed early exit alike — there, only damage fails the install: a version mismatch warns and continues, so a no-op re-run over an older EQL stays exit 0 for idempotent provisioning scripts. A valueless `--database-url` (booleanised by the parser when the next token is another flag) is now rejected up front on every command instead of silently falling back to `DATABASE_URL` — previously `eql install --database-url --force` could drop and reinstall the EQL schemas on a database the command never named.
- a2b0b45: Add a `lovable` handoff target to `stash plan` and `stash impl` (`--target lovable`, plus a new agent-target picker entry). It writes the same AGENTS.md as the editor-agent handoff — doctrine plus the per-integration skills inlined — but the next-steps guidance is Lovable-specific: commit and push the generated files through Lovable's GitHub sync, then add a Knowledge note in the Lovable project settings pointing the agent at `AGENTS.md` and `.cipherstash/setup-prompt.md`. Without repo-local guidance, Lovable's agent answers CipherStash questions from stale training data (the pre-EQL-v3 "needs a Postgres extension and superuser" story) and talks users out of a supported Supabase setup.
- a2b0b45: Report the ORE-unavailable case once, at install time, instead of leaving it to surface as a failing predicate the first time a column is cast.

  The EQL bundle skips the ORE btree operator class when the installing role cannot create one and poisons every `_ord_ore` domain with a loud-failure CHECK in its place. That is a supported configuration — but nothing said so where the choice between `types.*Ord` and `types.*OrdOre` is actually made, so the trade was discovered at query time.

  - **`stash eql preflight` now probes whether the role can create an operator class** and reports it as a non-blocking `ORE operator class` row (`creatable` / `not creatable` / `unknown`; `canCreateOperatorClass` in `--json`). It is _probed_, not inferred from `superuser`: `CREATE OPERATOR CLASS` is superuser-gated in stock PostgreSQL, but AWS RDS and Aurora let their admin role create one while cloud-hosted Supabase does not, so `rolsuper` is not evidence either way. The probe attempts the DDL inside a transaction it always rolls back, leaving preflight read-only; a probe that could not ask reports `unknown` rather than guessing.
  - **`stash eql install` names the consequence and the remedy** on its own line when the fallback was installed, rather than as a parenthetical on the "verified" line.
  - **`stash eql status` reports the ORE state** on a v3 install, so the answer survives past the install output.
  - **The remedy now names a type that exists.** The previous wording pointed at the `_ord_ope` domains; the bundle creates those, but `@cipherstash/stack` ships no `types.*OrdOpe` factory, so it named a column type no schema author could declare. Every command now says `types.*Ord` (`public.eql_v3_*_ord`), which is the same CLLW-OPE ordering and has a factory behind it.
  - The ORE state machine, the catalogue probe, and this copy now live in one module shared by `eql preflight`, `eql install`, `eql status`, `eql verify`, and `eql validate`, so the five commands cannot drift into disagreeing about the same catalogue fact.
  - The scaffolded encryption client's type cheat-sheet now says why ordered columns should be `*Ord` rather than `*OrdOre`.

- a2b0b45: Rewrite `db validate` as `eql validate`, for the EQL v3 domain-type vocabulary.

  **Fixes a false finding on the most ordinary v3 columns.** The old rule set
  checked for `ore` / `unique` / `match` / `ste_vec` indexes and never learned
  about `ope`. EQL v3's default ordering domains emit `ope`, so
  `types.IntegerOrd('age')` and `types.TimestampOrd('created_at')` were both
  reported as "Column is encrypted but has no indexes — it will not be
  searchable". They are now silent.

  The command reads your tables through the new
  `EncryptionClient.getSchemas()`, so it sees each column's **concrete domain**
  rather than the lossy encrypt config, and gains a database pass when one is
  reachable.

  Schema checks (no database needed):

  | Rule                                                                      | Severity |
  | ------------------------------------------------------------------------- | -------- |
  | An `_ord_ore` domain is declared — its ORE operator class needs superuser | Warning  |
  | Storage-only column: encrypts and decrypts, carries no query terms        | Info     |
  | Searchable `boolean` column                                               | Error    |
  | Free-text `match` index on a non-text domain                              | Error    |
  | Encrypted-JSONB (`ste_vec`) index without `types.Json`                    | Error    |

  Database checks (skipped with a notice, not a failure, when no database is
  reachable):

  | Rule                                                                                  | Severity |
  | ------------------------------------------------------------------------------------- | -------- |
  | EQL v3 is not installed — reported once, remaining database checks skipped            | Error    |
  | A declared table lives in a different schema than the one searched                    | Warning  |
  | A declared table is in the searched schema but invisible to the connected role        | Warning  |
  | A declared table name carries a schema qualifier (`schema.table`) — not checked       | Warning  |
  | A declared table exists in no schema at all                                           | Error    |
  | A declared column is missing from a table that was found                              | Error    |
  | The database column's domain differs from the declared one                            | Error    |
  | The database column is still plain (no EQL domain)                                    | Error    |
  | An `_ord_ore` domain where the EQL install could not create the ORE operator class    | Error    |
  | A queryable column with no functional index over its term extractor                   | Info     |
  | A declared table name that resolved in the searched schema also exists in another one | Info     |

  `--exclude-operator-family` is removed: it warned that an `ore` index would not
  support `ORDER BY` without operator families, and the pinned EQL v3 bundle
  self-adapts. `eql install` / `eql upgrade` had already rejected the flag;
  `validate` was its last consumer.

  The database pass inspects `current_schema()` only, and distinguishes four
  reasons a declared table can be missing from it, so that only the last fails
  the command. In another schema (Prisma `multiSchema`, a tenant schema): a
  Warning naming that schema. Present but invisible to the connected role: a
  Warning carrying the `GRANT SELECT` to run — `information_schema` reports only
  what the role holds a privilege on, so a missing grant is not a missing
  migration. Declared as `schema.table`: a Warning saying it was not checked,
  because validate matches table names unqualified. Absent everywhere: an Error.
  Reported once per table rather than once per column.

  The relation lookup that answers those questions excludes `pg_*` and
  `information_schema`. Unscoped it matched the system views named `columns`,
  `domains`, `parameters`, `routines`, `sequences`, `tables` and `triggers` — all
  ordinary application table names — so a project declaring one of them that had
  not run its migration was told the table "exists in schema information_schema",
  as a Warning, and the command exited 0 on a genuinely unapplied migration.

  An unqualified name found in more than one schema is now reported as an Info
  naming the relation that was actually checked (`"public"."users"`) and the
  other schemas holding that name. A bare name resolves through `search_path`, so
  `users` in both `public` and Supabase's `auth` left it ambiguous which relation
  every other finding described. Info, not Warning: it must not fail or
  de-clean an ordinary Supabase project.

  Two of those used to exit 1 and no longer do: a privilege-invisible table and
  a schema-qualified declaration were both reported as "does not exist in any
  schema", which sent people to re-run a migration that had already run.

  Against a project whose `@cipherstash/stack` predates `getSchemas()`, validate
  says so and falls back to the encrypt config, running the index-derived rules
  and skipping the domain ones.

  `stash db validate` keeps working as a deprecated alias, like `db install` /
  `db upgrade` / `db status`. Exits 1 on errors only.

- a2b0b45: **Reading this release.** These packages share one version line with
  `@cipherstash/stack-prisma`, so all six move together:

  - `stash`
  - `@cipherstash/stack`
  - `@cipherstash/stack-drizzle`
  - `@cipherstash/stack-supabase`
  - `@cipherstash/stack-prisma`
  - `@cipherstash/wizard`

  They are versioned together on purpose. `stash init` pins the versions of the
  packages it installs and the CLI embeds that map at build time, so a package
  shipping alone would leave the CLI recommending versions that no longer match
  what is published, and warning about a skew it had itself created.

  Two changes in this release can need action from some users. They are named
  here so you do not have to read six changelogs to find them:

  - **`@cipherstash/stack` — `clientKey` is hex-only.** A decoder fallback that
    also accepted standard padded base64 is gone, and such a key is now rejected
    at client construction with `invalid clientKey: expected a hex-encoded key`.
    Hex is the only encoding ever documented, and the only one `stash env` or any
    part of the JavaScript stack has ever produced — the base64 tolerance was an
    accident of the underlying Rust decoder, which accepts base64 solely to read
    its own profile store. A key pasted out of `~/.cipherstash/secretkey.json`
    (which stores base64) stops working; re-encode it, or drop the explicit key
    and let the client read the profile store directly, which is unaffected. The
    full entry is "Adopt protect-ffi 0.31.0" in the **`@cipherstash/stack`**
    changelog; it also narrows which `error.code` values DynamoDB operations
    report.
  - **`stash` — `stash eql validate` lost `--exclude-operator-family`,** and two
    checks that used to exit 1 no longer do. A script passing that flag, or a CI
    gate relying on those exit codes, needs updating. The full entry is under
    `eql validate` in the **`stash`** changelog.

  `@cipherstash/stack-prisma` also moves to Prisma Next 0.17 in this release,
  which requires migration steps from its consumers — see its own changelog
  entry.

- a2b0b45: Add `stash eql migration --supabase`, so an EQL v3 install survives `supabase db reset` (#613).

  Supabase projects previously had only `stash eql install --supabase`, which applies the SQL directly to a running database. `supabase db reset` — the ordinary local development loop — drops that database and replays `supabase/migrations/`, so the install was wiped and the next query failed with `type "eql_v3_encrypted" does not exist`. There was no supported way to get EQL into the migrations directory.

  `stash eql migration --supabase` now writes `supabase/migrations/<timestamp>_cipherstash_eql.sql`, carrying the EQL v3 bundle, the `anon` / `authenticated` / `service_role` grants, and the `cipherstash.cs_migrations` tracking schema — so one `supabase db reset` provisions everything `stash encrypt` needs. The file is timestamped at generation time, so it sorts after everything already applied and pushes without `--include-all`. A second run exits rather than adding a duplicate install; `--force` regenerates the existing one in place.

  The command now warns when the migrations directory already holds EQL-referencing migrations that sort _before_ the install it is about to write. A project that ran `stash eql install` directly and then added `public.eql_v3_*` columns against the live database gets an install stamped today — after those migrations — and `supabase db reset`, which replays in version order with no dependency awareness, then fails with `type "eql_v3_text_search" does not exist`. The warning names the specific files and the remedy (rename the install below the earliest of them, then reconcile each remote — see below). It fires on `--dry-run` too, and nothing is renamed automatically — the ordering of someone else's deployed history is not ours to change silently.

  That warning's remote guidance now requires you to verify the remote before writing to its ledger. It splits by whether the remote already has EQL: one where it does needs only the ledger row (`supabase migration repair --status applied <version>`, which runs no SQL — pushing the file instead re-runs a bundle opening with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`), and one where it does not needs the SQL genuinely applied (`supabase db push --include-all`, the back-dated version being a gap in the middle of that history). Previously the first branch was recommended on an assumption the user was never asked to check, and it is the one operation here with no self-correcting failure: mark a version applied on a remote that never ran the SQL and EQL is permanently absent _and_ permanently marked applied, so no future push installs it and the first migration referencing `eql_v3` fails with nothing pointing at the cause. The warning now prints the check first — `psql "$REMOTE_DATABASE_URL" -Atc "select eql_v3.version()"` — and says never to mark applied when it errors. It asks for `eql_v3.version()` rather than the `eql_v3` schema deliberately: that function is created by the bundle's closing statements, so it cannot resolve on an install that aborted partway, while the schema is created by its opening ones and survives one. The same correction lands in the `stash-cli` and `stash-supabase` skills and the CLI README, and a guard test now fails the build if a shipped skill recommends the ledger-only repair without that check above it.

  `--force`'s follow-up guidance was wrong and is now correct. It said to re-apply with `supabase db reset` (local) **or `supabase db push` (remote)**, but a push never re-applies a rewritten migration: the Supabase CLI decides what is pending by comparing versions, never file content, so an in-place rewrite keeping its version is skipped and push reports `Remote database is up to date.` The remote recipe is now `supabase migration repair --status reverted <version>` (tracking table only — it applies no SQL) followed by `supabase db push`, with `--include-all` called out as a conditional: it is needed only when migrations sort _after_ the install, which leaves the reverted version as a gap in the middle of remote history. Reverting the newest version leaves it at the tail, where a plain push applies it — and the flag applies every out-of-order migration you have, so recommending it unconditionally was itself a hazard. The warning also names the hazard it never mentioned: the EQL bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`, so re-applying drops every index, constraint, and RLS policy that references `eql_v3` / `eql_v3_internal` — free on a fresh `db reset`, destructive on a populated remote.

  `--out` on a bare `--supabase` now warns. The Supabase CLI's migrations directory is not configurable — `supabase db reset` and `supabase db push` read `<project>/supabase/migrations` and nothing else, `config.toml` has no key for it, and `--workdir` relocates the whole `supabase/` directory rather than this subdirectory — so an install written elsewhere is never applied, which is the original bug relocated. The flag still writes the file (a project may apply that directory through its own tooling) but names the consequence, on `--dry-run` too. `--out` alongside `--drizzle --supabase` is unaffected: there it is drizzle-kit's output directory.

  `--supabase` keeps its existing meaning alongside `--drizzle` (append the role grants to the Drizzle migration); only a bare `--supabase` selects the new emitter.

  `stash init --supabase` now generates that migration instead of installing directly, when the project has local `supabase/` scaffolding — a hosted project without it still installs directly. Re-running init over a project that already has an install migration reports it and moves on, rather than treating the duplicate refusal as a failed setup. Its next steps no longer tell you to run `eql install --supabase` and then `supabase db reset`, which was the exact sequence that destroyed the install.

  `stash init`'s EQL summary line now distinguishes the migration it wrote from one it merely found. A re-run over an existing install migration says "EQL migration **already present**" instead of "EQL migration generated" — same apply guidance, same successful exit, but no claim about work the run did not do.

  `stash init`'s EQL prompt now names the action for the route it is actually on. On the migration-first routes it asks whether to generate a migration (naming `supabase/migrations/` or your Drizzle migrations folder) rather than whether to install into your database, which described the wrong action on both. Declining is fixed the same way: the retry hint is now `stash eql migration --supabase` / `--drizzle` on those routes instead of `stash eql install`, which on Supabase would reinstate the very bug above.

  `stash init` now routes on the integration flags themselves rather than on the provider's display name, so combining them works. `stash init --drizzle --supabase` is accepted — and is the natural invocation for a Drizzle project on Supabase — but init joined the matched flags into a single provider name (`drizzle-supabase`) for referrer tracking and then compared that name against `'drizzle'` and `'supabase'` everywhere it had a decision to make. Every comparison went false. A local Supabase stack answers on `127.0.0.1:54322`, so host detection reports plain Postgres and the flags are the only signal left: the run installed EQL directly instead of writing a migration — nothing in `supabase/migrations/`, no `anon` / `authenticated` / `service_role` grants — which is the #613 failure this release exists to fix, reached through a flag combination the CLI accepts. The same fall-through dropped the `supabase status` hint when resolving `DATABASE_URL` (the one lookup that finds a local stack's URL), lost the Prisma Next branch for `--prisma --supabase` — scaffolding a client Prisma Next never uses and running a duplicate EQL install that races `prisma-next migrate`'s journal — and installed no integration adapter at all, where a combined run needs both `@cipherstash/stack-drizzle` and `@cipherstash/stack-supabase`. The provider now carries the matched flags alongside its name and every step reads those; the combined name is still exactly what gets recorded as the referrer, it is simply no longer what the CLI branches on. Drizzle still wins the migration route when both flags fire — it owns the migration history, and `--supabase` is the grants modifier there. Single-flag runs behave exactly as before.

  Also corrects the remote apply command across the Supabase guidance: a bare `supabase migration up` targets the local database, so the instructions now say `supabase db push`.

  Also corrects the `eql install --migration` removal message, which pointed every Supabase user at `--drizzle`.

  The Supabase CLI behaviour all of the above depends on is now pinned by a live test rather than by reading the CLI's source. `supabase-push.live.test.ts` drives the real binary against a real Postgres — `db push --db-url` needs neither Docker nor a linked project — and covers: the generated install applying with no `--include-all`; `anon` reaching `eql_v3` via `SET ROLE` through the grants carried in the emitted file (not just the ones `eql install --direct` applies); an out-of-order version aborting the whole push rather than being skipped; a `--force`-replaced file never re-applying; `--include-all` being needed only for the gap case; and a leaked `.tmp` file being ignored. Gated on `STASH_TEST_SUPABASE_DB_URL` + `STASH_TEST_SUPABASE_CLI`, so the default suite is unchanged.

### Patch Changes

- a2b0b45: Correct the Dependabot section of the bundled `stash-supply-chain-security`
  skill. It described two monitored ecosystems (`npm`, `github-actions`); there
  are now three, because the in-tree Rust workspace at `packages/protect-ffi`
  brought a `Cargo.lock` that nothing proposed updates for. The skill now names
  the `cargo` entry, its non-root `directory`, its monthly cadence, and the
  exact-pinned CipherStash crates it ignores.

  Two things the section previously got wrong are also fixed. Major bumps do not
  "stay un-grouped — one PR each": every entry ignores
  `version-update:semver-major`, so Dependabot proposes no major bumps at all and
  they are applied by hand. And `ignore` conditions suppress Dependabot _security_
  PRs as well as version updates — the skill now says so, and points at
  `osv-scanner.yml` (which scans every lockfile in the tree, `Cargo.lock`
  included) as the compensating control.

- a2b0b45: `stash eql status` no longer reports ORE damage on a healthy database running a
  different EQL version. The `_ord_ore` domains its poison CHECKs are counted over
  come from the bundle this CLI pins, so a fallback install of an older EQL poisons
  domains the pinned list only partly sees — which classified as an incoherent
  half-install and told the operator to reinstall with `--force`, on the ordinary
  "CLI upgraded, database not yet" case. The ORE probe now gates on the installed
  version the same way `eql verify` does and reports that the state could not be
  compared, pointing at `eql upgrade`.

  Two hardening fixes to `stash eql verify` alongside it. Its cast check now
  matches an EQL endpoint on either side, so a future bundle cast to or from a
  `pg_catalog` type (`jsonb`, `text`) cannot enter the expected surface while being
  unreadable as installed — which would have reported "Cast missing" on every
  healthy database. And the parser that derives the expected surface from the
  pinned bundle now fails loudly on any statement it does not model, instead of
  silently omitting the objects it creates: a bundle that outgrows the parser can
  no longer make `verify` report a partial install as complete.

- a2b0b45: Document in the bundled `stash-auth` skill that `CS_CLIENT_KEY` must be
  hex-encoded. Hex is what `stash env` emits and what the skill's variable table
  already stated, but the decoder underneath used to fall back to standard padded
  base64 — the encoding the Rust `stash-profile` crate uses for
  `~/.cipherstash/secretkey.json` on disk — so a key copied out of that file
  happened to work despite never being a supported input. That fallback is gone
  and such a key is now rejected at client construction, with a message that
  deliberately withholds detail — so the skill names the symptom and the fix.

  The recovery advice is split by entry point: falling back to the profile store
  works on the native entry, but not on `@cipherstash/stack/wasm-inline`, where
  `clientId` and `clientKey` are required config and the target runtimes have no
  profile store to read. Re-encoding as hex is the fix that works on both.

- a2b0b45: Correct the release-workflow section of the bundled `stash-supply-chain-security`
  skill. It described the no-Actions-cache rule as a property of one file — "no
  `cache:`, `package-manager-cache: false`, `pnpm/action-setup` with
  `cache: false`" — which is no longer the whole rule.

  The gate now follows any local composite action or reusable workflow the job
  reaches, so the constraint is on the whole call tree rather than the workflow
  file. And every published `uses:` must appear in the script's `AUDITED_ACTIONS`
  allowlist: the check cannot open a published action to prove it does not cache,
  and caching actions are not reliably named — a `setup-<tool>` action that caches
  by default has no `cache:` input and nothing in its name to match. The list is
  therefore what is permitted, not what is forbidden, and adding a step to
  `release.yml` or `tests-supply-chain.yml` means auditing the action and adding
  it there in the same PR.

- a2b0b45: Correct two inaccuracies in the bundled `stash-cli` skill. The `stash init` overview said the **Supabase** flow always generates an EQL migration; it now says **local Supabase**, matching `resolveMigrationRoute` — only a project with local `supabase/` CLI scaffolding takes the migration-first route, while a hosted Supabase project with no `supabase/` directory falls through to a direct `stash eql install`. And the guidance for back-dating the Supabase install migration no longer recommends `supabase db push --include-all` unconditionally: on a remote where `stash eql install` has already run, pushing the file re-runs a bundle that opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`, dropping every index, constraint, and RLS policy on those schemas. That case is now `supabase migration repair --status applied <version>` (ledger only, no SQL) — after confirming EQL is genuinely installed on that remote with `psql "$REMOTE_DATABASE_URL" -Atc "select eql_v3.version()"`; `--include-all` stays for a remote that still needs the SQL applied.

  The same correction lands in the CLI itself, and in the two other places that repeated the old advice — the `stash-supabase` skill and the CLI README. `stash eql migration --supabase` warns when the project already has EQL-referencing migrations that sort before the install it is about to write, and that warning carried the identical blanket `--include-all` advice. Since this warning only fires on projects that ran `stash eql install` directly — so the remote usually already has the bundle and is missing only the ledger row — it now names `supabase migration repair --status applied <version>` as the remedy, spells out the `DROP SCHEMA IF EXISTS eql_v3 CASCADE` hazard of pushing the file instead, and keeps `--include-all` for the remote that has not had the SQL applied.

- a2b0b45: Upgrade the Prisma Next integration to Prisma Next 0.17 (the `prisma/prisma` "Prisma 8" main line). Consuming apps must move to the 0.17 publish surface to use this release.

  This ships as a minor release rather than a major: Prisma Next itself is still pre-1.0 and every consumer of this integration is tracking a moving upstream surface, so the version number signals "upgrade deliberately" the same way the upstream 0.x line does. The changes below are still breaking for existing 0.16-based setups — read them before upgrading.

  Changes required of consumers:

  - **Dependencies**: the `@prisma-next/*` scope is retired. An application now depends on exactly one database facade — `@prisma/orm-postgres@0.17.0` — plus this extension. `@cipherstash/stack-prisma` itself builds against `@prisma/orm-framework`, `@prisma/orm-family-sql`, and `@prisma/orm-toolchain`, and declares `@prisma/orm-target-postgres` as a peer dependency.
  - **Generated imports**: the emitted `contract.d.ts` now imports this extension's types from `@cipherstash/stack-prisma/{codec-types,operation-types,runtime}` (previously the stale `@prisma-next/extension-cipherstash/*` names, which no longer resolve). Re-run `prisma-next contract emit` after upgrading.
  - **Contract and migration hashes**: 0.17 renames the contract's `extensionPacks` key to `extensions` and drops the `sha256:` prefix from every content hash, so every contract `storageHash` and `migrationHash` changes. The shipped migration set is re-anchored accordingly; consumer repos convert their checked-in `migrations/` trees with the upstream `strip-sha256-hash-prefixes` codemod and `scripts/migrate-migrations-layout.mjs` (the content-addressed `migrations/snapshots/` store replaces per-migration `end-contract.*` files). Vendored `migrations/cipherstash/` copies must be refreshed (delete and re-run `prisma-next migration plan`, or copy the shipped artefacts).
  - **Codec descriptors**: the v3 codec descriptors are now Postgres target descriptors (`nativeTypeFor` / `projectJson` via `postgresCodec`), replacing the deleted `meta.db.sql.postgres` channel, and the pack meta publishes them through `types.codecTypes.codecDescriptors` (0.17 removed `codecInstances`).
  - **Config**: in `prisma-next.config.ts` use the facade's `defineConfig` from `@prisma/orm-postgres/config` with `extensions: [cipherstash]` (`extensionPacks` fails loudly on 0.17).

  The `stash` CLI now also detects Prisma Next projects that depend on the 0.17 packages (`prisma-next` or any `@prisma/orm-*` package), and the bundled `stash-prisma` skill documents the 0.17 surface.

- a2b0b45: Correct the bundled `stash-prisma` and `stash-indexing` skills for Prisma Next 0.17's functional-index support: `@@index` now takes an `expression` argument, so the `eql_v3.*` functional indexes are declared directly in `schema.prisma` (expression indexes require a `name` or `map`) instead of hand-written raw-SQL migration operations. Also documents the physical-name rule (`name:` gains a content-hash suffix, `map:` pins the exact name), the TS contract form (`type` requires `options`), and that `CREATE INDEX CONCURRENTLY` cannot run through the migration runner's transaction — via `rawSql` or otherwise.
- a2b0b45: Document the Dependabot major-version policy in `skills/stash-supply-chain-security`: no entry configures a `semver-major-days` cooldown, because every entry ignores `version-update:semver-major` and cooldown applies to version updates only. The supply-chain e2e suite now pins both halves of that relationship.
- a2b0b45: New `stash-managed-platforms` skill: implementing CipherStash on a managed AI app platform (Lovable, v0, Bolt, Replit).

  These platforms share a shape — no shell the developer controls, an edge/Workers runtime, a database role that is not `postgres`, and schema changes only through the platform's own migration tool — and every one of those changes the setup. The skill covers the WASM entry, running `stash auth login --json` headlessly in an ephemeral sandbox, minting `CS_*` with `stash env`, installing EQL as a non-`postgres` role (including generating a migration instead of installing directly), which predicates survive PostgREST, and why `encryptedSupabase` cannot be constructed inside a Worker.

  The costly one is first, because it decides whether anyone gets any further: **use `@cipherstash/stack` with the `@cipherstash/stack/wasm-inline` entry.** `@cipherstash/protect` is the deprecated predecessor, and reasoning from its `@cipherstash/protect-ffi` dependency to "there is no way to run this on an edge runtime" is a wrong conclusion drawn from the wrong package. That dead end cost an agent a full turn on a real project before it found `stash`. The same correction is now stated in `stash-edge`'s entry table, where an agent comparing runtimes will hit it.

  Two things were also lifted above the fold in `stash-supabase`: a pointer to the new skill, and a one-line summary of what does and does not survive PostgREST (`eq`/`neq`/`in`/`match()` and the range filters do; encrypted `matches()` and JSON containment do not). The full treatment was correct but ~500 lines down, which is not where a time-pressured agent finds it.

  Registered for the `supabase` and `postgresql` integrations in both the CLI and wizard skill maps, so it installs into `.claude/skills` / `.codex/skills` and inlines into `AGENTS.md` on those paths.

- a2b0b45: Skills: `encryptedSupabase` can now be constructed in a Worker, so the guidance that said it could not has been corrected.

  `skills/stash-managed-platforms` replaces its "cannot be constructed in a Worker" section with the two things that must both be right — import `@cipherstash/stack-supabase/wasm-inline` rather than the package root, and declare your `schemas` so nothing introspects — plus what declared mode gives up (`select('*')`, `from()` on an undeclared table, and the drift check) and how to keep the drift check on Node by passing `databaseUrl` as well.

  `skills/stash-supabase` and `skills/stash-edge` gain the same correction where each would be read: the above-the-fold managed-platform callout, and the runtime-entry table respectively.

- a2b0b45: Add a type → predicate → domain → index capability matrix to the `stash-encryption` skill, cross-linked from `stash-indexing` and `stash-postgres`.

  Picking the wrong `types.*` factory is silent at authoring time — there is no type error and no runtime warning, just a predicate that never runs. The skills documented the capability _suffixes_ and the families they apply to, but never the 40 concrete factories in one lookup, so answering "can `types.Double` do a range query" meant composing two tables and knowing the exceptions. It cannot: `types.Double` is storage-only.

  The new matrix has one row per factory with its Postgres column domain, the predicates it supports, the extractor to index it through, and whether it works on managed Postgres. Alongside it: a note on which schema holds what (`public` for column domains, `eql_v3` for query domains and operator functions, `eql_v3_internal` for index-term types) and why the Supabase grants have to cover the last two.

  Two corrections came out of writing it:

  - The `Ord` vs `OrdOre` callout said the install "disables the `_ord_ore` domains" on managed Postgres. Precisely: the bundle adds an always-raising `eql_ore_unavailable` CHECK to them, so a _write_ fails — the domain is unusable, not merely unindexed. The callout now says that, notes that RDS and Aurora do support ORE while cloud-hosted Supabase does not, and points at `stash eql preflight` / `eql status` rather than asking the reader to guess.
  - The `stash-postgres` naming table omitted `types.TextOrdOre` entirely (its `<N>` shorthand covers only the numeric and temporal families). Added.

  A new test derives the matrix from the `types` namespace and fails if the skill disagrees — every factory present exactly once, mapped to the domain it actually builds, naming the extractors it actually emits and none it does not, with every ORE row marked unusable where the operator class is absent.

- a2b0b45: `stash doctor` now detects a missing native binary. Both of its checks had stopped doing so, in different ways, and each reported a green row instead.

  **The encryption engine check never loaded anything.** Since the protect-ffi native load became lazy, importing the package resolves no platform binary — `@neon-rs/load`'s proxy resolves on first use — so the probe passed with nothing installed and the failure surfaced later, at the first encrypt. It now calls `assertNativeBindingAvailable()` through the new `@cipherstash/stack/diagnostics` subpath, which forces the load.

  **It was also reporting the wrong package.** Importing `@cipherstash/stack` reaches `@cipherstash/auth`, whose binding is eager, so the encryption row was really a second auth check: one signal rendered as two rows. The diagnostics subpath does not reach auth, so each row now means what it says.

  **A missing `@cipherstash/auth` binary produced a bare `Fatal error`.** That package's napi loader swallows the resolver's `MODULE_NOT_FOUND` and throws a summary carrying no error `code`, which the CLI's native-binary classifier did not recognise — so every command, not only `doctor`, skipped the recovery guidance and printed a raw message. The classifier now recognises that shape, and prints the missing package with the reinstall steps.

  `stash doctor` exits non-zero when either platform package is missing, and reports an install of `@cipherstash/stack` that predates the diagnostics subpath as unprobeable rather than failing on it. A run that could not complete a check now ends with "stash doctor could not run every check." instead of claiming they all passed — still exit 0, since an unrunnable check is not a diagnosis.

  **A package that is installed but broken is no longer reported as "not installed".** The check for an absent package matched the package name anywhere in the failure message, and the probe's own import path contains it — so a partially installed or partially built `@cipherstash/stack` was reported as one you simply had not installed yet, in green, with nothing to suggest looking further. It now matches on the specifier Node failed to resolve.

- a2b0b45: Document the native-binding publish path in the bundled
  `stash-supply-chain-security` skill, and correct what it claims about
  frozen-lockfile coverage.

  `@cipherstash/protect-ffi` and its six platform packages ship compiled binaries,
  which `changeset publish` cannot produce — it packs from the workspace, where
  `index.node` is a build output. The skill now describes the pipeline that does:
  a registry-state gate, a target-explicit build matrix in a reusable workflow,
  and a publish step that ships the six platform packages before the wrapper and
  tags all seven itself, because changesets tags only what it published. It also
  records two npm requirements that fail late and quietly — `repository.url` must
  match the publishing repository exactly (and `repository.directory` resolves
  from that repository's root), and trusted-publisher configurations created after
  2026-05-20 need an explicit "Allowed actions" selection.

  It also now states, per action, which input disables that action's built-in
  caching and what that input defaults to. Two of the three default to caching
  ON — `actions/setup-node`'s `package-manager-cache` and `jdx/mise-action`'s
  `cache` — so omitting the key is not "no caching", it is caching spelled
  invisibly, and the gate's generic rule only sees a _truthy_ value rather than a
  missing one.

  The OIDC section said `permissions: id-token: write` is what mints the token and
  left it there. It now says where that grant belongs: on the publishing jobs, not
  at the workflow level. A trusted publisher is registered against a repository
  _and a workflow filename_, so npm accepts a token minted by any job in the
  registered file — declaring the scope at the top hands the publish credential to
  every job that does not override it, including ones added later.

  The frozen-lockfile section said the rule was enforced in `tests.yml`, which was
  true and misleading: that is where it was _checked_, and `release.yml` ran a
  bare `pnpm install` from the day it was written — so the single install permitted
  to resolve outside the lockfile was the one whose output goes to the registry.
  The install is fixed and the check now scans every workflow and every local
  composite action.

  - @cipherstash/migrate@1.0.0

## 1.0.0

### Major Changes

- 19cff11: Remove the remaining EQL v2 installation and rollout surface. CLI installs,
  upgrades, backfills, and drops now mutate EQL v3 state only, while legacy v2
  status diagnostics and migration-manifest compatibility remain read-only.
- 7c7dbca: CipherStash Stack 1.0.

  This is the first 1.0-line release of `@cipherstash/stack`, the first published
  release of the split-out EQL v3 adapters `@cipherstash/stack-drizzle` and
  `@cipherstash/stack-supabase`, and moves the `stash` CLI to 1.0 alongside them.
  These four packages now version together as the Stack 1.0 family.

### Minor Changes

- 134fd43: Add anonymous, opt-out usage analytics to the `stash` CLI, plus a
  `stash telemetry [status|enable|disable]` command to manage it.

  Only coarse events are collected — command name, CLI version, OS/arch, Node
  version, success/failure, duration, and a coarse caller class (e.g.
  `claude-code`, `cursor`, `interactive`) derived from environment markers so we
  can gauge agent- vs human-driven usage. Events carry a random install
  identifier (a locally generated UUID, not derived from any machine or user
  attribute) used only to de-duplicate events in aggregate. Plaintext, schema,
  table/column names,
  connection strings, argument values, and any session/trace identifier are never
  collected — enforced by a property-key allowlist at the emitter boundary plus
  closed-vocabulary coercion of every argv- or error-derived value (unrecognised
  commands, subcommands, and error class names all collapse to `<other>`). A
  one-time notice is shown on first run, and nothing is sent on that run.

  Telemetry is off by default in CI and can be disabled with `DO_NOT_TRACK=1`
  (the cross-tool standard), `STASH_TELEMETRY_DISABLED=1`, or
  `stash telemetry disable` (persisted to `~/.cipherstash/telemetry.json`).

  Events are sent via a first-party proxy and never block or slow the CLI. The
  feature ships dormant — no events are sent until a PostHog project key is
  embedded at release. Updates the `stash-cli` skill to document the command and
  opt-out controls.

- 229ce59: `stash eql install` now installs the eql-3.0.0 GA bundle,
  vendored from the pinned `@cipherstash/eql` package (sha256-verified).

  Since eql-3.0.0 one artifact installs everywhere: the operator-class
  statements self-skip when the role lacks superuser (managed Postgres,
  Supabase) and the bundle disables the ORE-backed encrypted domains it cannot
  support. The separate v3 Supabase bundle variant is gone — `--supabase` and
  `--exclude-operator-family` no longer select a different v3 file (the role
  GRANTs for `eql_v3` / `eql_v3_internal` still apply with `--supabase`).

  The bundled skills are also refreshed for the eql-3.0.0 naming convention
  (`public.eql_v3_<name>` column domains) and the EQL v3 typed-schema surface.

- 7fdc30f: `stash init` now takes `--prisma`, the Prisma Next setup flag, replacing
  `--prisma-next`. This makes the integration flags consistent — `--supabase`,
  `--drizzle`, `--prisma` — and matches how `--supabase` is used for referrer
  tracking. `--prisma` selects the same Prisma Next flow (EQL bundle installed via
  `prisma-next migrate`, no encryption-client scaffold) and records `prisma` as the
  referrer.

  **Breaking:** `stash init --prisma-next` is no longer recognized. Init errors with
  guidance to re-run with `--prisma`. The bundled `stash-cli` skill is updated to
  document the new flag.

- 0811330: Add `stash eql migration` — generate an EQL **v3** install migration for your ORM
  instead of running the SQL directly against the database (`stash eql install`).
  Migration-first is the preferred path: the install lands in your migration history
  and ships to every environment through the ORM's own migrate step.

  ```bash
  stash eql migration --drizzle              # Drizzle custom migration
  stash eql migration --drizzle --supabase   # also grants eql_v3 to anon/authenticated/service_role
  ```

  The migration carries the CLI's bundled v3 install SQL (one source of truth) plus
  the `cs_migrations` tracking schema, so a single `drizzle-kit migrate` covers
  everything `stash encrypt …` needs. `--supabase` appends the `eql_v3` +
  `eql_v3_internal` role grants for PostgREST/RLS access.

  `--prisma` is registered but not available yet — the Prisma Next migration
  emitter is a follow-up (tracked in cipherstash/stack#690) that will let
  prisma-next drop its baked install baseline. It fails with a pointer for now.

- 4528536: Add `stash eql repair --drizzle` — repair a migration directory that `drizzle-kit
generate` filled with an un-runnable in-place `ALTER COLUMN … SET DATA TYPE
<eql_v3_*>`, without generating anything (cipherstash/stack#710).

  ```bash
  stash eql repair --drizzle                        # sweep drizzle/
  stash eql repair --drizzle --dry-run              # preview; writes nothing
  stash eql repair --drizzle --database-url …       # leave applied migrations alone
  ```

  Until now the only way to run that sweep was `stash eql migration --drizzle`,
  which generates a redundant EQL install migration as a side effect purely to
  trigger it — the sweep runs before `drizzle-kit generate` has emitted the broken
  statement, so recovery meant creating a migration you did not want. `eql repair`
  runs the same rewriter and prints the same report (both commands now share one
  reporting path, so the two surfaces cannot drift).

  **New: applied-migration awareness.** The sweep has always been unfiltered. That
  is harmless for almost every match, because an ALTER to an EQL domain cannot run
  — so the migration failed and was never applied. The exception is a `jsonb`
  column changed to an EQL domain on an empty table, which applies successfully;
  rewriting it afterwards leaves the `.sql` describing a shape the database never
  got from it, and a fresh CI or staging database replaying the rewritten file
  diverges from the original, silently.

  `eql repair` therefore reads `meta/_journal.json` offline and, given
  `--database-url` (or `DATABASE_URL`), the latest `created_at` in
  `drizzle.__drizzle_migrations`. A migration is applied when its journal `when` is
  at or below that watermark — the same timestamp comparison `drizzle-kit migrate`
  makes, hashes being written but never compared. Applied migrations are reported
  as their own outcome, left untouched, and the command exits non-zero. Without a
  database URL the repair proceeds and warns that applied state could not be
  verified; if the check is requested but cannot run, nothing is rewritten.

  A ledger that is not where the probe looked is reported as **unverified**, not as
  "nothing applied" — it means either `drizzle-kit migrate` never ran, or
  `drizzle.config.ts` overrode `migrations.table` / `migrations.schema` and the
  query went to the wrong relation. `--migrations-table <[schema.]table>` names the
  ledger for that case; the value must be a plain (optionally schema-qualified)
  identifier and is rejected before connecting otherwise.

  An applied migration whose statement the sweep would have skipped regardless — an
  undeclared source column, an already-encrypted one, an existing twin — is
  reported with that skip reason rather than as an applied-migration refusal.

  `rewriteEncryptedAlterColumns` gained `dryRun`, and its `skip` option now accepts
  several paths as well as one. The wizard's copy of the rewriter carries the same
  change so the two stay in sync; its own sweep is unaffected.

- d20e48a: `stash init` is honest non-interactively — it no longer reports success for a
  setup that didn't fully complete.

  - **Fails on version skew.** A non-interactive run can't reconcile an
    already-installed `@cipherstash/*` package that's _older_ than this CLI
    expects (it won't mutate an install without consent), so instead of warning
    and proceeding — scaffolding against mismatched packages and then claiming
    success — it now refuses with a non-zero exit and the exact align command.
    Interactive runs still offer to align. A _newer_ install stays a warn (the
    install is likely fine; update the CLI instead).
  - **No false "Setup complete".** If the EQL extension isn't installed at the
    end — and the integration isn't one that installs it out-of-band — the
    summary reads "Setup incomplete" and init exits non-zero, pointing at
    `stash eql install`. Integrations that install EQL via a migration are
    reported honestly rather than as failures: Prisma Next (installs it via
    `migration apply`) and the Drizzle flow, which _generates_ an EQL migration
    and now says "EQL migration generated — apply it with `drizzle-kit migrate`"
    instead of claiming the extension is already installed.
  - **Honest checkmarks.** The summary no longer claims "Database connection
    verified" (init resolves a URL but doesn't open a connection) — it now says
    "Database URL resolved" — and only shows "Encryption client scaffolded" when
    a client was actually written (skipped for Prisma Next).
  - **No false "skills loaded".** The agent handoff prompt only points at the
    skills directory when skills were actually copied (a stripped build installs
    none), instead of telling the agent to read files that aren't there.

- 3a86939: EQL v3 support for the encryption rollout lifecycle (#648). The `stash
encrypt *` commands (and `@cipherstash/migrate` underneath) now resolve a
  column's EQL version and its encrypted counterpart from the **Postgres domain
  types** — the EQL v3 types are self-describing, so the `<col>_encrypted`
  naming is a convention only, never enforced or relied upon — and follow the
  right lifecycle, no new flags:

  - **`encrypt backfill`** works on v3 columns unchanged (the engine was always
    version-agnostic; pass an `Encryption` client and real v3 envelopes land
    in the concrete `eql_v3_*` domain column — verified live against a real
    database, including the domain CHECK and a decrypt round-trip). The
    manifest records the detected version, the encrypted column's name, and the
    v3 target phase, and the command prints v3-appropriate next steps.
  - **`encrypt drop`** is version-aware: v3 runs from the `backfilled` phase,
    **verifies live coverage** (refuses to generate the migration while any row
    still has the plaintext set and the encrypted column NULL — the
    `countUnencrypted` check), and drops the ORIGINAL plaintext column (there
    is no `<col>_plaintext` under v3). The generated
    v3 migration **re-verifies coverage at apply time** — it locks the table,
    re-counts, and aborts without dropping if plaintext-only rows appeared
    after generation. And because dropping is the one irreversible step, it
    requires a positively asserted plaintext↔ciphertext pairing (the
    manifest's recorded `encryptedColumn` or the naming convention): a match
    found only by being the table's sole EQL column is refused with
    instructions, and an ambiguous table (several EQL columns, none
    identifiable) fails closed listing the candidates.
  - **`encrypt status`** classifies each column from the observed domain type
    (manifest as fallback), shows `v3` in the EQL column, and no longer raises
    the v2-only `not-registered` / `plaintext-col-missing` drift flags for v3
    columns. `stash status`'s quest ladder and the `stash init` agent handoff
    prompt teach the version-appropriate next step (no more "run cutover" on
    v3 columns).
  - New `@cipherstash/migrate` exports: `classifyEqlDomain`,
    `resolveEncryptedColumn`, `pickEncryptedColumn`, `listEncryptedColumns`
    (domain-type resolution — case-exact for quoted/mixed-case table names),
    `countEncrypted` / `countUnencrypted` (coverage counts), and manifest
    `eqlVersion` + `encryptedColumn` fields. `EqlVersion` is numeric (`2 | 3`),
    matching the manifest and the installer. Resolved columns carry `via:
'hint' | 'convention' | 'sole'` so callers can tell a positively asserted
    pairing from a by-elimination guess.
  - Fixed: `encrypt drop` precondition failures now actually exit 1 — the
    early-return guards previously skipped the exit-code path entirely, so failed
    preconditions exited 0. Scripted pipelines that relied on the erroneous exit 0
    will now see the documented exit 1.

  The `stash-cli` and `stash-encryption` skills and the `@cipherstash/migrate`
  README document the v3 lifecycle: backfill → switch the application to the
  encrypted column by name → drop the plaintext column.

- b0634df: `stash plan --complete-rollout` is now automatable and has an honest exit code.
  It skips the production-deploy gate, so it needs explicit consent — previously
  that was an interactive prompt with no bypass, so a non-interactive run
  auto-cancelled (default-no) and exited **0** without drafting a plan, leaving
  automation to assume a plan existed.

  - New `--yes` flag confirms the gate-skip without a prompt (for CI/agents).
  - Without `--yes`, a non-interactive `--complete-rollout` run now **refuses
    with a non-zero exit** and points at `--yes`, instead of silently succeeding.
  - Interactive behaviour is unchanged (default-no confirm).

- 0b9b192: Rename `stash db install` to `stash eql install`. The command scaffolds
  `stash.config.ts` and installs the EQL extensions, so it now lives under a
  dedicated `eql` command group. `stash db install` keeps working as a
  deprecated alias that prints a warning pointing at the new name. All help
  text, hints, generated migration headers, and wizard steps now reference
  `stash eql install`.
- d2772b0: Renamed `@cipherstash/prisma-next` to **`@cipherstash/stack-prisma`** (#842),
  matching the `@cipherstash/stack-drizzle` / `@cipherstash/stack-supabase`
  adapter naming. Only the npm name changes: the `prisma-next` CLI,
  `prisma-next.config.ts`, and the `@prisma-next/*` framework packages are the
  Prisma Next framework's own surface and keep their names. Update imports
  (`@cipherstash/prisma-next/stack` → `@cipherstash/stack-prisma/stack`, and the
  other subpaths likewise) and the `extensionPacks` import in
  `prisma-next.config.ts`.

  `stash init` and the bundled skills now install and document the new name; the
  `stash-prisma-next` skill is now `stash-prisma`.

- 8817cfb: Add a `stash-auth` agent skill and install it for every integration (#794).

  Authentication had no canonical home: the guidance was scattered across
  skills that each mention one slice of it, and the gap had already produced a
  wrong explanation in shipped material (conflating `config.authStrategy` with
  lock context). The new skill is the single source of truth; other skills
  should point at it rather than restate it.

  What it documents:

  - The service-token model: every request to a CipherStash service carries a
    short-lived JWT minted by CTS; access keys and IdP JWTs are exchanged at
    CTS, never sent to ZeroKMS directly. The token carries the workspace, the
    role-derived scopes, and the regional ZeroKMS endpoint in its `services`
    claim — which is why endpoints are never hand-configured and `CS_*_HOST`
    stays debug-only.
  - The three separable concerns (client credentials, end-user identity,
    key binding) and the canonical statement that an auth strategy decides who
    the client is while a lock context decides who can retrieve a value's data
    key — the claim from the encrypting caller's service token is bound to the
    key, and retrieval requires presenting the same claim. Orthogonal, and
    only combined deliberately.
  - The `@cipherstash/auth` strategies (`AutoStrategy`, `AccessKeyStrategy`,
    `OidcFederationStrategy`, `DeviceSessionStrategy`), including the Result
    trap: `create()` returns `Result<Strategy, AuthFailure>` and
    `config.authStrategy` takes the unwrapped `.data`, plus the `AuthFailure`
    codes worth recognising (`NOT_AUTHENTICATED`, `WORKSPACE_MISMATCH`, …).
  - Credential discovery vs explicit config (native env/profile vs the WASM
    entry's explicit four values), the mutual-exclusion rule on the WASM entry,
    the four `CS_*` variables and `stash env`, and client lifetime with
    user-scoped strategies (one client per request — a shared client binds
    whoever arrived first).
  - Lock context usage and the deprecations around it
    (`LockContext.identify()` / `getLockContext()`, `config.strategy`), the
    explicit rule that agents never read `~/.cipherstash`, and a note that
    Proxy authentication is a different path (dedicated skill to come).

  `stash-zerokms` gains a companion section: ZeroKMS accepts only CTS-minted
  service tokens, runs in multiple regions, and its endpoint is determined by
  CTS — with the bulk deferred to `stash-auth`.

- c005345: Add a `stash-deployment` agent skill and install it for every integration.

  The rollout/cutover lifecycle was documented in `stash-encryption` and
  `stash-cli` as a _command sequence_, with the deploy boundaries described in
  passing. In practice the boundaries are the hard part: an agent that treats the
  lifecycle as one unit of work — twin column, dual-write, backfill, read switch,
  drop — produces a plan that loses data, because ciphertext can only be written
  by the application and the plaintext column must stay authoritative until every
  row has a ciphertext twin and the deployed code reads it.

  The new skill makes the deploy shape the primary subject:

  - The four-deploy ladder (rollout → read cutover → stop dual-writes → drop
    plaintext) with the out-of-band backfill and index build between the first
    two, three human gates, and what each gate is actually verifying.
  - A failure table: for each way of collapsing the ladder, the data that is lost.
  - Rollback per stage, making explicit that only the final drop is irreversible.
  - `CS_*` credentials as a **build-time** input on platforms that construct the
    encryption client at module load, and the keyset rule for backfills — the
    backfill must encrypt under the same keyset the deployed app resolves
    (credentials may differ, keyset may not); ciphertext under any other keyset
    fails only at read time.
  - A Prisma Postgres / Prisma Compute section: EQL installing through the Prisma
    Next migration graph, one merge deploying one stage, the additive-only deploy
    policy that makes the plaintext drop fail the build (and the apply-before-merge
    sequence that avoids it), preview-branch databases masking destructive
    migrations and inviting a wrong-database apply, and running one-off jobs
    against a hosted database.

  `stash-deployment` joins `stash-encryption`, `stash-indexing` and `stash-cli` in
  the set every integration installs.

- f188c7a: `stash env` now works: it mints deployment credentials from your device-code
  session and prints them as env vars — no dashboard copy-paste. The command
  creates a fresh ZeroKMS client and a member-role CipherStash access key (named
  via `--name`; the role is pinned in the request and verified on the response —
  the CLI deliberately cannot mint admin keys), then emits `CS_WORKSPACE_CRN`,
  `CS_CLIENT_ID`, `CS_CLIENT_KEY`, and `CS_CLIENT_ACCESS_KEY`.

  Output goes to stdout by default — and stdout is pipe-clean (progress UI is on
  stderr), so `stash env --name x > prod.env` and pipes into secret stores are
  safe. `--write [path]` writes a file instead (default `.env.production.local`,
  enforced mode 0600 even when overwriting), confirming before overwriting and
  refusing non-interactively — always _before_ anything is minted, so a refusal
  never discards the shown-exactly-once access key. `--json` emits NDJSON; with
  `--write` the confirmation event is deliberately secret-free. API responses
  are schema-validated so a service change can never print `undefined` into a
  credentials file. Creating access keys requires the admin role in the
  workspace.

  This is also the supported credential path for WASM/edge local development
  (Supabase Edge Functions, Cloudflare Workers, Deno), where the runtime cannot
  read the `~/.cipherstash` device profile: mint a key and feed it via
  `supabase functions serve --env-file` or the platform's secret store.

  The `STASH_EXPERIMENTAL_ENV_CMD` gate is removed.

- 239f79b: New bundled agent skill: `stash-indexing` — how to index EQL v3 encrypted
  columns. Integrations that were otherwise correct shipped with no index on any
  encrypted predicate because nothing in the installed skills said encrypted
  columns _can_ be indexed (#753). The skill covers the functional-index recipes
  over the term extractors (`eql_v3.eq_term` / `ord_term` / `ord_term_ore` /
  `match_term` / `to_ste_vec_query`) mapped to the `types.*` domains, what works
  without superuser on Supabase and managed Postgres versus the ORE opclass
  restriction, which domains are storage-only by design, the query shapes that
  engage an index (`ORDER BY` sort-key and `GROUP BY` traps), building indexes on
  large tables, an `EXPLAIN` verification checklist, and when to create indexes
  during an encryption rollout (after backfill, before switching reads).

  `stash init` / `stash impl` handoffs — and the `@cipherstash/wizard` skills
  prompt — now install it for **every** integration (Drizzle, Supabase, Prisma
  Next, plain PostgreSQL) — the gap is cross-cutting.
  The existing per-integration skills gained pointers to it (including the
  missing `stash-prisma` one-line purpose in the setup prompt, which
  previously rendered "(no description)").

- 17393b9: Two new bundled agent skills for the integrations that don't use an ORM —
  `stash-postgres` and `stash-edge` (#754).

  Everything a raw-SQL or edge integration needed was reachable only from
  `dist/*.d.ts` JSDoc, the Postgres catalog, or experiment: grepping the skills
  `stash init` installs for `postgres-js|::jsonb::eql|sql.json|query_text_search`
  returned a single hit, in an unrelated code comment.

  **`stash-postgres`** — hand-written SQL over `pg` / `postgres-js`, no ORM. The
  column-domain-to-query-domain operator matrix (which of `=`, `<>`, `<`, `>=`,
  `@@`, `@>` each encrypted domain accepts, and against which `eql_v3.query_*`
  operand), the storage-vs-query payload distinction, per-driver parameter
  binding, recipes for equality / free-text / range / `ORDER BY` / JSON
  containment / JSON field selectors, and the `information_schema` drift check.
  Two failure modes get their mechanism spelled out: pre-stringifying a payload
  on postgres-js double-encodes it into a jsonb _string_ scalar, tripping the
  domain CHECK with a message naming neither JSON nor encoding; and leaving an
  operand as bare `jsonb` silently selects a different operator overload — one
  that coerces to the _storage_ domain and so rejects the ciphertext-free query
  term. It also scopes itself against the two things a hand-written-SQL reader
  is otherwise left to infer: **CipherStash Proxy** (where you write plaintext
  SQL and none of the skill applies — the `usesProxy` fork `stash init` already
  asked about), and the provenance of the operator surface itself (the EQL
  bundle from `cipherstash/encrypt-query-language`, version-checkable with
  `SELECT eql_v3.version()`, and where operator gaps should be filed). Its
  domain and operator tables are explicitly marked as a snapshot of a versioned
  surface, with a ranked list of authorities to confirm current types against —
  the EQL skill first, then the generated `@cipherstash/eql` types and install
  SQL, both of which need only `node_modules` and no database.

  **`stash-edge`** — the `@cipherstash/stack/wasm-inline` entry for Deno,
  Supabase Edge Functions, Cloudflare Workers, and Bun. Import specifier per
  runtime, the four mandatory `CS_*` variables and minting them with
  `stash env`, how the WASM client surface differs from the native typed client
  (no `.audit()`, no `.withLockContext()`, per-item bulk shape, a required
  `table` argument on `decryptModel` / `bulkDecryptModels`, ESM-only), and the
  auth-strategy `Result` that must be unwrapped before it reaches
  `config.authStrategy`.

  It also separates the two mechanisms behind identity-bound encryption, which
  are routinely conflated — and which the source comment on the entry itself got
  wrong. An auth strategy decides _who the client is_; a lock context decides
  _which key the value is encrypted under_. Only the first exists on this entry,
  so an `authStrategy` alone still writes values encrypted under the workspace
  key, and the entry cannot read what the native one wrote under a lock context.
  That is a silent read split between the two entries, and the skill says so
  rather than leaving it to be discovered as a failed decrypt.

  Both carry **the credential-identity rule**, a silent data-loss footgun now
  also stated in `stash-cli` (under `env` and `encrypt backfill`) and
  `stash-supabase`: EQL index terms derive from the ZeroKMS client key, so rows
  written under one credential and queried under another decrypt correctly and
  never match a query, with no error.

  `stash-encryption` now states that the two entries' schema types **do not
  interchange** — their column classes carry private fields, so TypeScript
  compares them nominally and rejects a shared schema module in both directions.
  It works at runtime, which makes a type assertion the tempting fix; the
  guidance is to author the schema against exactly one entry instead.

  `stash init` / `stash impl` handoffs and the `@cipherstash/wizard` skills
  prompt install both skills for the `postgresql` and `supabase` integrations.
  Drizzle and Prisma Next get cross-links from their own skills instead, since
  those integrations emit correctly-typed operands themselves.

  Also fixes the `@cipherstash/stack/wasm-inline` module JSDoc, which showed
  `OidcFederationStrategy.create(...)`'s `Result` being passed straight to
  `config.authStrategy` without unwrapping — the same JSDoc the raw-SQL surface
  was being reverse-engineered from.

- 8872d1e: `stash init`, `stash plan`, and `stash impl` no longer crash on a Prisma Next
  project. `SKILL_MAP` was missing a `prisma-next` entry, so the skills-install
  and AGENTS.md-builder steps hit `SKILL_MAP[integration]` → `undefined` and threw
  "not iterable" for any repo the CLI detected as Prisma Next. The entry is added
  and both consumers now resolve skills through a `skillsFor()` helper that
  degrades an unmapped integration to the base skill set instead of crashing
  (`tsup` ships without type-checking, so the `Record<Integration>` type alone
  didn't protect the build).

  Ships a new **`stash-prisma`** agent skill documenting the EQL v3 Prisma
  Next surface — the domain-named encrypted column types (`EncryptedTextSearch`,
  `EncryptedDoubleOrd`, …), `cipherstashFromStackV3` wiring, the runtime value
  envelopes, the `eql*` query operators, and EQL installation via
  `prisma-next migration apply`. It is installed for Prisma Next projects and
  inlined into `AGENTS.md` for editor agents.

  `stash eql install` now refuses to run in a Prisma Next project (pointing you
  at `prisma-next migration apply`, which owns EQL installation) unless you pass
  `--force` — closing the manual-invocation hole that `stash init --prisma-next`
  already avoided.

- 8817cfb: Add a `stash-zerokms` agent skill and install it for every integration.

  The keyset/client access model had no canonical home: several skills described
  credentials and keysets in passing, and some of that wording contradicts how
  ZeroKMS actually works. The new skill is the single source of truth for the
  model, and other skills should point at it rather than restate it.

  What it documents:

  - The four-level key hierarchy (root key → per-keyset authority key →
    per-client client key → per-value data key) and why revoking one client
    blocks all of its future key operations immediately, without
    re-encryption (not retroactive — already-held plaintext is beyond recall,
    but per-value keys bound the blast radius to what was already accessed).
  - The scoping rule and its asymmetry: encrypt and query always use the
    client's **bound** keyset, while decrypt follows each payload's keyset
    subject to grants. An unreachable bound keyset (no grant, revoked,
    disabled) fails loudly at the ZeroKMS round trip, as does decrypting a
    payload under an ungranted keyset. The one **silent** case is a reader
    granted the writer's keyset but bound to a different one: decrypt works,
    while its query terms derive under its own keyset and encrypted search
    returns zero rows. The same-keyset rule therefore binds writers and query
    readers; decrypt-only readers need just a grant.
  - Clients and grants: creation binds a client to one keyset (the workspace
    default unless named), `grant`/`revoke` manage further access per
    (client, keyset) pair, and two different credentials interoperate fully as
    long as both reach the encrypting keyset — "identical credentials
    everywhere" was never the requirement.
  - The workspace default keyset (`default`, reserved name, cannot be disabled
    or renamed) and multi-tenant isolation via `config.keyset` with one
    `Encryption()` client per tenant.
  - The ZeroKMS API surface for automation (`/create-keyset`, `/grant-keyset`,
    `/revoke-keyset`, `/list-clients`, …) with required token scopes, the exact
    failure surfaces (404 no-grant, 403 disabled-keyset, 403 missing-scopes,
    per-value lock-context denials), and a diagnostic runbook that separates the
    client-level keyset gate from the value-level lock-context gate.

  `stash-zerokms` joins the set every integration installs, alongside
  `stash-encryption`, `stash-indexing`, `stash-deployment` and `stash-cli`.

### Patch Changes

- e155956: Finish the EQL v2-removal release gates and adapter correctness pass.

  - **Supabase encrypts leaves nested inside a PostgREST boolean group.** This
    is a disclosure fix, not a formatting one. The `.or()` string parser had
    no group recursion, so `.or('and(createdAt.gte.2026-01-01,note.eq.x)')`
    came back from the top-level split as one part and the leaf parser cut it
    at the first dot into the pseudo-column `and(createdAt`. That name matched
    no encrypted column, so the whole expression took the verbatim branch: the
    operand `2026-01-01` reached PostgREST **as plaintext, against an
    encrypted column**, under the JS property name `createdAt` rather than the
    DB column name `created_at`. Every encrypted leaf nested inside `and(...)`
    / `or(...)` / `not.and(...)` leaked its operand to the database and
    returned wrong results. Nested groups and `referencedTable` are now
    preserved while each encrypted leaf is substituted in place.
  - Supabase never sends nullish encrypted search operands as plaintext, honours
    escaped LIKE metacharacters, rejects CSV result mode before decryption, and
    diagnoses the removed object-form factory call. The bundled `stash-supabase`
    skill no longer lists `csv()` among the transforms passed through to
    Supabase — it throws, and the skill now says so and shows serializing the
    decrypted rows instead.
  - Native, WASM, and Supabase model decryption reconstruct valid date and
    timestamp values consistently, including nested paths, aliases, and bulk
    results, while leaving invalid values unchanged. That last clause is a
    behavioural change on the native typed client and the Supabase adapter,
    which previously pushed every date-like column through `new Date(...)`
    unconditionally: a stored value that does not parse used to come back as an
    Invalid `Date` and now comes back as the raw string, matching what the WASM
    entry already did. The declared column type is still `Date`, so code that
    assumed `instanceof Date` held for every date column — or called a `Date`
    method on it unguarded, so that `.getTime()` used to yield `NaN` and now
    throws a `TypeError` — has to handle the raw value.
  - `stash init` names the concrete `public.eql_v3_*` domain family and gives
    `public.eql_v3_text_search` as a valid Supabase example.
  - CLI and wizard skill selection stay in parity for every integration,
    including the Prisma Next skill, and verify that each selected skill has a
    `SKILL.md`.

  The final 1.0 integration surface is `Encryption` from
  `@cipherstash/stack/v3`, the `@cipherstash/stack-drizzle` package root, and
  `encryptedSupabase` from `@cipherstash/stack-supabase`. DynamoDB decrypt
  operations retain `.audit()` on the typed `Encryption` client. Existing EQL v2
  ciphertext remains readable through the core client; authoring and adapter
  writes use EQL v3.

- 31ca318: Update the bundled `stash-drizzle`, `stash-supabase`, and `stash-encryption` agent
  skills (and the stack README / Supabase reference doc) for the adapter package
  split: the Drizzle and Supabase integrations import from `@cipherstash/stack-drizzle`
  and `@cipherstash/stack-supabase` respectively, installed alongside
  `@cipherstash/stack`, rather than from `@cipherstash/stack/{drizzle,supabase,eql/v3/drizzle}`
  subpaths. Skills ship inside the `stash` tarball, so the stale import paths would
  otherwise become wrong guidance in a user's project.
- 8b2551a: Fix "Failed to load native binding" on project-local installs of the CLI/SDK
  (npm). `@cipherstash/auth` was pinned at 0.41.0 while the six
  `@cipherstash/auth-*` platform bindings declared in stack/stash/wizard's
  optionalDependencies were pinned at 0.42.0. Because auth pins its bindings as
  exact-version optional peer dependencies, the skew made npm nest per-consumer
  binding copies that the hoisted `auth` package could not resolve — any command
  or import touching auth then died at startup. All seven packages now move in
  lockstep at 0.42.0, Dependabot is barred from bumping any of them
  independently, and a supply-chain CI test fails on any future skew.
- 7fdc30f: `stash auth login` now accepts `--prisma`, bringing the integration referrer
  flags to parity with `stash init`: `--supabase`, `--drizzle`, `--prisma`. A
  multi-flag referrer is now ordered alphabetically, so it no longer depends on
  argv order.

  This closes a documentation/implementation gap: the bundled `stash-cli` skill
  listed `--prisma` among `auth login`'s referrer flags, but the command did not
  register it — and because the CLI's argument parser does not reject unknown
  flags, `stash auth login --prisma` was silently dropped rather than erroring.

  The `stash-cli` skill also now records that `init` writes no encryption-client
  placeholder for Prisma Next, which derives its schemas from `contract.json` —
  previously the scaffold step and the generated-file table both claimed the file
  was always written.

- 487dc9b: `stash encrypt backfill` now distinguishes a missing encrypted column from a
  legacy EQL v2 one. The domain probe returns the same "not v3" answer for both,
  so a user who had simply not added the `<col>_encrypted` column yet was told
  they were on a legacy EQL v2 column and advised to migrate a domain that did not
  exist. The command now reports that the column is absent, points at adding an
  `eql_v3_*`-domain column and applying the migration, and mentions
  `--encrypted-column` for non-standard names. The EQL v2 message is unchanged for
  columns that really are present.
- 761bdd9: Trim the leading comment block from near-miss statements reported by the Drizzle
  migration rewriter (`stash eql migration --drizzle`, `stash eql install`).

  The broad near-miss scan is anchored on the previous `;`, so a
  `SET DATA TYPE … USING …` it could not safely repair was quoted back to the user
  with every preceding comment and blank line glued to its front — in a file
  opening with a comment block, that meant the whole header. The reported
  statement is now the offending statement alone. Detection is unchanged; only the
  text shown to the user is affected.

  Keeps this rewriter in sync with its sibling in `@cipherstash/wizard`.

- 98156ac: Fix the Codex handoff installing zero skills — and losing `AGENTS.md` and `.cipherstash/` with them — when `.codex/` is not writable.

  Codex sandboxes deny writes under `.codex/`. `installSkills` created its destination with an unguarded `mkdirSync`, sitting directly above a per-skill copy loop that _was_ guarded — so the failure threw past that fallback and past the caller, aborting the whole handoff step. Because the skills install runs first, nothing after it ran either: no `AGENTS.md`, no `.cipherstash/context.json`, no `.cipherstash/setup-prompt.md`. All five Codex runs of the rc.3 skilltester matrix landed here, and it was identified in that report as the primary driver of the Claude→Codex quality gap.

  The fix, hardened by a follow-up review of the first cut:

  - **`installSkills` never throws, and reports what happened.** It returns `{ copied, failed }` instead of a flat list, so callers can tell "unwritable destination" from "stripped build" from "partial copy" without re-deriving it — every filesystem failure degrades to a warning plus a `failed` entry.
  - **The Codex handoff inlines exactly the skills that failed.** Whatever could not be copied into `.codex/skills/` — all of them under a sandbox, or a subset after a partial failure — has its body inlined into `AGENTS.md` via the same `doctrine-plus-skills` path the editor-agent handoff uses. The launch prompt points at wherever each skill actually ended up, including both locations after a partial copy. A stripped build that ships no skills stays `doctrine-only` and says nothing.
  - **The doctrine now ships where the published CLI can find it.** The bundled AGENTS.md doctrine was copied to `dist/commands/init/doctrine`, but the compiled resolver probes ancestor directories of the chunk in `dist/bin/` — so every published build silently wrote the minimal `AGENTS.md` stub instead of the doctrine (and the inline fallback would have inlined nothing). It now lands at `dist/doctrine`, like the skills bundle. `buildAgentsMdBody` also honours `doctrine-plus-skills` even when the doctrine fragment is missing, so inlined skills are never dropped with it.
  - **The generated artifacts describe the fallback honestly.** `context.json` gains an `inlinedSkills` field, and `setup-prompt.md` distinguishes installed / inlined / failed skills instead of mislabelling an unwritable destination as a "stripped build". The Claude handoff now warns when skills exist but could not be installed, and the AGENTS.md handoff records what it inlined.
  - **The rest of the handoff is guarded too.** The `AGENTS.md` upsert (which refuses malformed sentinel pairs) and the bundled-file reads degrade to warnings instead of aborting the step before `.cipherstash/` is written.

  `@cipherstash/wizard` carries its own copy of `installSkills` with the same unguarded `mkdirSync` above the same guarded copy loop. It targets `.claude/skills` rather than `.codex/skills`, so the Codex sandbox case does not apply, but an unwritable destination crashed it identically — now guarded the same way, with a confirmed-then-failed install recorded in the wizard changelog instead of vanishing with the terminal output.

- ace2a4f: Correct the shipped documentation for `decryptModel` / `bulkDecryptModels`.

  Three places in `skills/stash-encryption` and four in `packages/stack/README.md`
  said these return "a plain `Promise<Result<...>>` (not a chainable operation)"
  and that there is therefore "no `.withLockContext()` to chain". They return an
  `AuditableDecryptModelOperation`, which is thenable and carries both
  `.withLockContext()` and `.audit()` — the same `.audit()` chain the
  audit-on-decrypt work advertises. The skill contradicted itself: its own
  reference table already listed the correct return type.

  The skill ships inside the `stash` tarball and `installSkills()` copies it into
  customer repos, so this was steering agents away from an API that exists. The
  README ships in the `@cipherstash/stack` tarball.

  The equivalent statement about the **WASM entry** is correct and unchanged —
  `@cipherstash/stack/wasm-inline` really does return a plain promise from decrypt,
  with no lock-context argument.

  Also fixes the setup prompt `stash init` writes for coding agents, which
  referenced `protectOps.eq` — an API that does not exist anywhere in the repo.
  Every step naming an integration-specific API now branches on the project's
  actual integration, instead of naming Drizzle's and Supabase's and leaving the
  other two to guess:

  - **Query paths.** `createEncryptionOperators(client)` (conventionally `ops`)
    for Drizzle, the `encryptedSupabase` wrapper's own filters for Supabase, the
    `eql*` column operators for Prisma Next, and `client.encryptQuery(...)` for a
    plain Postgres project.
  - **Schema authoring.** The `types.*` column factories for Drizzle, a concrete
    `public.eql_v3_*` domain such as `public.eql_v3_text_search` in migration SQL
    for Supabase, the `cipherstash.*`
    field constructors in `schema.prisma` for Prisma Next, and `encryptedTable`
    for plain Postgres. Prisma Next was previously sent at `types.*` /
    `encryptedTable` — the client `stash schema build` explicitly refuses to
    scaffold for that integration.
  - **Read paths.** `decryptModel(row, usersSchema)` where that applies, and the
    wrapper's transparent decryption where it does not.
  - **Skill pointers.** A plain Postgres project installs no integration-specific
    skill, so each "see the integration skill" was a pointer at a file that was
    never written. Those now point at `stash-encryption`, which it does get.

  `client.encryptQuery` is also shown taking the schema objects themselves
  (`{ table: usersSchema, column: usersSchema.email }`) rather than an
  object-shorthand that read as three required strings — `queryType` is inferred
  from the column's configured indexes.

  The cutover and complete-rollout **plan templates** now describe the EQL v3
  rollout. Both described a rename swap (`<col>` → `<col>_plaintext`, twin →
  `<col>`) as the only cutover path, which EQL v3 does not have — the application
  switches to the encrypted column by name. The implement prompt already carried
  the v3 story; the plan templates did not.

  The "already encrypted" stop-and-ask now recognises `eql_v3_*` domains
  alongside the legacy `eql_v2_encrypted` udt, so it can fire on the default
  path at all.

  **`stash init` now detects already-encrypted columns on EQL v3.** Database
  introspection marked a column as CipherStash-managed only when its udt was
  exactly `eql_v2_encrypted`. v3 columns carry per-domain types
  (`eql_v3_text_search`, `eql_v3_integer_ord`, …), so on the default path every
  encrypted column was reported as plaintext — shown with its `dataType` and left
  unticked in the column picker, inviting a re-run to encrypt it a second time.
  The picker also labelled any encrypted column with the literal string
  `eql_v2_encrypted`; it now shows the column's real domain.

- b8cb599: Fix invalid DDL from `drizzle-kit generate`/`push` for EQL v3 encrypted columns.
  A v3 column declared its SQL type as the schema-qualified domain
  (`public.eql_v3_text_search`), but drizzle-kit wraps a custom type's whole name
  in a single pair of double quotes — emitting `"public.eql_v3_text_search"`, which
  Postgres reads as one dotted identifier and rejects with `type
"public.eql_v3_text_search" does not exist`. Generated migrations had to be
  hand-repaired.

  The v3 column now emits the **unqualified** domain (`eql_v3_text_search`), which
  drizzle-kit renders as the valid `"eql_v3_text_search"` and which resolves via the
  search path (the domains live in `public`). This also matches how drizzle-kit
  reads the type back during a `push` introspection diff, so the two sides no
  longer disagree.
  Builder recovery still yields the canonical `public.eql_v3_*` identity, so
  operators and schema extraction are unchanged.

  The bundled `stash-drizzle` skill is updated to describe the unqualified generated
  type and the search-path requirement (hence the `stash` bump — the skill ships in
  its tarball).

- d26950d: `encryptedDynamoDB` now accepts EQL v3 tables.

  Pass a table built with `encryptedTable` + the `types.*` domains from
  `@cipherstash/stack/v3` to any of `encryptModel`, `bulkEncryptModels`,
  `decryptModel`, or `bulkDecryptModels`. Build the typed client with
  `Encryption({ schemas: [table] })`.

  Existing EQL v2 items continue to be **readable**: pass the corresponding EQL v3
  table plus `{ storedEqlVersion: 2 }` to `decryptModel` /
  `bulkDecryptModels`. Writes accept EQL v3 tables only.

  This fixes a latent bug that made v3 unusable: the write path detected an
  encrypted value by its `k: 'ct'` tag, but EQL v3 scalars carry no `k`
  discriminator at all. Every v3 scalar fell through to the nested-object branch
  and was written as a raw map instead of being split into `<attr>__source` and
  `<attr>__hmac`.

  Notes on capability:

  - Only equality is usable on DynamoDB. `<attr>__hmac` is written for domains
    that mint an `hm` term — the `*Eq` family, plus `TextOrd`/`TextOrdOre`/
    `TextSearch`. Ordering and bloom-filter terms have no DynamoDB query surface
    and are not stored, so those columns remain decryptable but not queryable.
  - Nested attributes are supported in v3. There is no nested-group authoring
    form (that is a compile error), so declare the column flat with a dotted
    path — `{ 'profile.ssn': types.TextEq('profile.ssn') }`. The model is
    matched by dotted path, so `{ profile: { ssn } }` resolves, and the nested
    attribute keeps its `__hmac` for key conditions.
  - The typed `Encryption` client supports `.audit()` on `decryptModel` and
    `bulkDecryptModels`, including when used through the DynamoDB adapter.

  The DynamoDB adapter also gains its first test coverage — across the v2 and v3
  paths, where it previously had none.

  Robustness, from review:

  - Passing a v3 table to a client that never registered it (one built for a
    different schema set, so it is not in v3 mode for that table) now throws a
    clear, actionable error naming the table, instead of failing opaquely deep in
    the FFI.
  - A malformed decrypt result from a non-conforming client is surfaced as a
    failure rather than resolving as a silent `undefined` success.
  - Reading back a `<attr>__source` attribute that matches no declared column now
    logs a debug diagnostic instead of silently returning the raw ciphertext.
  - Caller input that cannot be structurally cloned no longer reaches the FFI by
    reference — the "encryption never mutates a caller's object" guarantee holds
    on that path too.
  - The write path now splits only declared columns, matched on the same property
    path the read path rebuilds from. A pre-encrypted payload placed under an
    undeclared nested name is stored whole (and round-trips) instead of being
    split into a `<attr>__source` the read path could never reassemble.
  - A degenerate payload with an empty-string ciphertext is split like any other
    ciphertext rather than falling through and being written as a raw map, which
    had leaked its `v`/`i` envelope metadata into storage.
  - Arrays are documented as a deliberate carve-out: the mapping does not descend
    into them, so a payload inside a list is stored whole (still decryptable, but
    not queryable and not part of the `__source`/`__hmac` layout).

  The v3 overloads are strongly typed. `encryptModel` / `bulkEncryptModels` check
  the input model against the table's column domains, and return the DynamoDB
  attribute map that is actually written — the new exported `EncryptedAttributes`
  type, where a declared column `email` becomes `email__source` (plus
  `email__hmac` for the equality domains that mint one) rather than surviving as
  `email`. `decryptModel` / `bulkDecryptModels` invert it via `DecryptedAttributes`.
  `AnyEncryptedTable`, `DynamoDBEncryptionClient` and `AuditConfig` are now
  exported from `@cipherstash/stack/dynamodb` so these signatures can be named.
  Legacy reads use the explicit storage-version option rather than an EQL v2 table
  overload; the v2 encrypt overloads are removed in this release.

- 966978a: The `stash-dynamodb` and `stash-encryption` skills now state which entries serve
  a legacy EQL v2 DynamoDB read: both of them. Schema authoring is EQL v3-only
  everywhere, but the read is not — it reconstructs the v2 envelope around the
  current v3 table, and `decrypt` accepts either wire generation. Deno, Bun,
  Cloudflare Workers and Supabase Edge Functions can therefore read pre-migration
  items through `@cipherstash/stack/wasm-inline`.

  The `stash-dynamodb` API reference also claimed audit metadata forwards to
  ZeroKMS "regardless of client shape". It does not: the wasm-inline client's
  operations return a plain promise with no `.audit()`, so its audit metadata is
  dropped (logged at debug). The reference now says so, and says the operation
  still succeeds.

- 659423a: `stash encrypt backfill` now names the cause when the encryption client has no
  initialized encrypt config, instead of reporting a missing table.

  The guard that refuses an unusable client file existed twice — once in
  `loadEncryptConfig` (`stash db validate`) and once, hand-copied, in
  `loadEncryptionContext` (`stash encrypt backfill`). The copies had already
  drifted: for a client whose `getEncryptConfig()` returns nothing, `db validate`
  exited 1 with `Encryption client in <file> has no initialized encrypt config`,
  while `encrypt backfill` fell through to `Table "users" was not found in the
encryption client exports. Available: (none)` — naming the symptom rather than
  the cause, which is precisely the failure the guard was added to eliminate.

  Both loaders now call one shared guard, so a single file cannot produce two
  different diagnoses, and the refusals are pinned at both public entry points.
  The un-replaced `stash init` scaffold is unaffected — it was already refused by
  both, with the same message.

- c54f19c: Fix `prisma-next db init` failing with PN-RUN-3020 on fresh databases, and bump the pinned EQL bundle to 3.0.4.

  The cipherstash space's EQL install migration is re-emitted with `additive` operation class (it only CREATEs its own schemas/domains/functions, and the genesis edge is not a self-edge, so the integrity checker accepts it) and now bakes the eql-3.0.4 bundle while carrying the upgrade invariants, so fresh-database `db init` — including Prisma Compute preview deploys — satisfies the head ref from a single all-additive edge. A new `data`-classed 3.0.4 upgrade self-edge covers databases installed at an older bundle via `migrate`. Consumers with a vendored `migrations/cipherstash/` should delete the space directory and re-run `prisma-next migration plan` to pick up the re-emitted artefacts.

- 8817cfb: `stash eql migration --prisma`: say "not needed", not "not yet".

  The command's registry copy, error message, and the `stash-cli` skill all
  described a Prisma Next emitter as a coming follow-up. Prisma Next doesn't
  need one — its extension pack installs the EQL bundle through prisma-next's
  own migration framework (the `migrations/cipherstash/` contract space). The
  `--prisma` flag now exists purely to route people there: the error explains
  the mechanism and points at `prisma-next migration plan` / `prisma-next
migrate`.

- 59b994e: Add EQL v3 JSON **selector-with-constraint** querying to the Drizzle integration
  (#623). `ops.selector(col, '$.path')` returns comparison methods bound to a
  JSONPath into a `types.Json` column — `eq`/`ne`/`gt`/`gte`/`lt`/`lte` — emitting
  `col->'<selector>' <op> <value>` over the encrypted document. Its unique power
  over `contains` is **ordering at a path** (`col->'$.age' > 21`), which
  containment cannot express.

  Complements the existing `contains` (JSONB `@>`) containment operator. Core
  `@cipherstash/stack` needs no change — the selector hash and comparison entry are
  produced by `encryptQuery`/`encrypt` on the existing `types.Json` surface. v1
  supports dot-notation object paths; array-index/wildcard paths are rejected with
  a clear error. The Supabase adapter is tracked separately.

  The right-hand comparison operand is currently a storage-encrypted needle (its
  ste_vec entry carries the ordering term), pending a ciphertext-free ordering
  query needle from protect-ffi (cipherstash/protectjs-ffi#137); until then the
  value's ciphertext appears in the WHERE clause.

  The bundled `stash-encryption` and `stash-drizzle` skills document the new
  `ops.selector(...)` surface (they previously said JSONPath selector queries were
  not yet implemented).

- 82f2e69: Document EQL v3 JSON columns in the bundled skills: `types.Json` in the
  `stash-encryption` typed-schema catalog (capability suffix, family, and an
  encrypted-JSONB query section), and `contains(col, subObject)` JSON containment
  on the v3 Drizzle operators in `stash-drizzle`.
- e297f64: Docs: EQL v3 is now the sole documented approach. The `stash-encryption`,
  `stash-drizzle`, and `stash-supabase` skills and the `@cipherstash/stack`
  README teach only the v3 typed surface (`Encryption`, the `types.*` concrete
  domains, the `@cipherstash/stack-drizzle` package root, `encryptedSupabase`);
  EQL v2 shrinks to read-compatibility notes. Two places keep more detail because
  stored EQL v2 data is still reachable there:

  - **DynamoDB reads.** `encryptedDynamoDB` writes EQL v3 only, but `decryptModel`
    / `bulkDecryptModels` can read previously stored v2 items when passed the
    corresponding v3 table and `{ storedEqlVersion: 2 }`, so the
    `stash-dynamodb` skill documents that explicit compatibility path (#657).
  - **The encrypt rollout lifecycle.** `stash encrypt *` and `@cipherstash/migrate`
    classify a column from its Postgres domain type: a `public.eql_v3_*` domain is
    recognised as v3, and anything else — including a legacy `eql_v2_encrypted`
    column — does not classify. The documented lifecycle is the v3 one
    (backfill → switch the application to the encrypted column → drop the
    plaintext); legacy v2 columns are read-only, covered under a version callout
    (#648).

  Also corrects the legacy `@cipherstash/drizzle` README's pointer to the removed
  `@cipherstash/stack/drizzle` subpath (now the separate `@cipherstash/stack-drizzle`
  package).

- 175eeb7: The EQL **v3** install SQL is now read from the `@cipherstash/eql` package at
  runtime instead of a copy vendored into this repo. `@cipherstash/eql` becomes a
  runtime dependency of `stash`, and a version bump now flows straight through — no
  re-vendor step, no drift between the pin and the shipped bundle.

  This removes ~44k lines of generated plpgsql from the repository (which had made
  GitHub classify the whole repo as plpgsql — CIP-3518) along with the
  `gen:eql-v3-sql` vendor script and its CI drift-check.

  No behaviour change: v3 installs the same one-artifact bundle (which self-adapts to
  non-superuser environments like Supabase), and the v2 path is unchanged.

- 0e2ce93: Fix `stash impl` and `stash init` hanging on CI runners that allocate a TTY.

  Four prompts decided whether to run interactively without going through the
  shared TTY helper, so on a CI runner with an allocated TTY they rendered a clack
  prompt and blocked forever on `/dev/tty` — a silent hang with no error and no
  timeout:

  - `stash impl` gated on an inline `process.env.CI !== 'true'`, which only
    recognised the exact lowercase spelling. Runners that set `CI=1` or `CI=TRUE`
    blocked on the plan-summary confirmation or the agent-target picker.
  - `stash init`'s offer to chain into `stash plan`, and its Proxy-vs-SDK
    question, gated on `process.stdout.isTTY` and did not consult `CI` at all —
    so they hung on any CI runner with a TTY, whatever the spelling. Gating on
    stdout was also the wrong stream: a redirected stdin still hangs a prompt.
  - `stash impl --continue-without-plan` confirmed the flag with a second prompt
    that was not gated at all, so a CI run with no plan on disk blocked there even
    though the flag had already granted consent. The flag is now taken as consent
    in non-interactive runs and only re-confirmed interactively.

  All four now use the shared `isInteractive()` helper (stdin is a TTY and `CI`
  is not set to `1`/`true` in any case), matching `stash plan`. Non-interactive
  runs take the path they always should have: `stash init` skips the chain offer
  and prints the `plan --target` hint, the Proxy-vs-SDK question defaults to
  SDK-only, and `stash impl` proceeds without prompting.

- c8726cd: `stash init --drizzle` installs EQL v3.

  The Drizzle init flow used to provision a v2 database — the only
  migration-generating install path at the time was v2-only — while the
  `stash-drizzle` skill init copies into the same project documents the v3
  `@cipherstash/stack-drizzle` surface (`types.*` domains, `Encryption`). The
  user's agent would have authored v3 code against a v2 database.

  Init's Drizzle flow now routes through `stash eql migration --drizzle`, so it
  stays migration-first (the install lands in your Drizzle migration history and
  ships to every environment via `drizzle-kit migrate`) while emitting v3 SQL.
  The generated migration also carries the `cs_migrations` tracking schema, so one
  `drizzle-kit migrate` covers everything `stash encrypt …` needs. If `drizzle-kit`
  isn't installed or configured, init now reports EQL as not installed and points
  at `stash eql migration --drizzle` rather than aborting the run.

  The CLI installation and mutation surface is v3-only. Legacy v2 remains readable
  and visible in diagnostics. Generate a checked-in install migration with
  `stash eql migration --drizzle`.

- 6fcb967: `stash init` now pins the packages it installs (`@cipherstash/stack`, the
  integration adapter, and `stash` itself) to the exact versions this CLI
  release was built alongside, instead of installing bare package names that
  resolve through npm dist-tags (#661). During a pre-release window dist-tags
  lag or point at placeholders, so an unpinned `init` could silently deliver a
  different release than the CLI driving the setup — stale `@cipherstash/stack`,
  or an empty placeholder adapter — breaking `/v3` imports out of the box. The
  versions are embedded at build time from the release train itself
  (`src/release-train.ts`, the single source both the build and the runtime
  check against), so they can never disagree with what was published together.

  Init also now surfaces **version skew** on already-installed packages —
  unconditionally, before any prompt or early exit, including when the install
  is declined or partially fails. Interactively it offers to align the skewed
  packages in the same confirm as the missing installs (keeping `stash` a dev
  dependency); non-interactively it never mutates an existing install — it
  warns and prints the exact align commands. A package whose manifest exists
  but can't be read (an aborted install) is reported as skew, not treated as
  matching. All other install guidance is pinned the same way: the
  missing-package hints, `.cipherstash/context.json`'s `installCommand`, the
  `install-eql` manual note, the native-module recovery hint (previously
  `stash@latest`), and the `stash wizard` one-shot spawn (previously an
  unpinned `npx @cipherstash/wizard`). The `stash-cli` skill documents the
  behaviour, and the other bundled skills' manual install commands now carry a
  verify-what-resolved note.

- 04f5a13: `stash init` now scaffolds an EQL **v3** encryption client, matching the EQL v3
  database it installs.

  The placeholder client (`DRIZZLE_PLACEHOLDER` / `GENERIC_PLACEHOLDER`) and the
  introspection-driven client generator previously emitted legacy EQL v2
  authoring patterns. Since init installs a v3 database, this handed the
  customer's coding agent v2 guidance against a v3 schema (follow-up to #732 /
  #705).

  Scaffolds now teach the v3 surface: `Encryption` from `@cipherstash/stack/v3`,
  the concrete-domain `types.*` factories (`types.TextSearch`, `types.IntegerOrd`,
  `types.Text`, `types.Json`, …), and `extractEncryptionSchema` from the
  `@cipherstash/stack-drizzle` package root for Drizzle. The `encryptionClient`
  export shape and the empty-schema "no schemas yet" error path are unchanged.

- 31b9e69: The client file `stash init` writes now compiles.

  Both placeholder templates emitted `await Encryption({ schemas: [] })`, and
  `Encryption` requires at least one table — an empty schema set is a deliberate
  compile error, so it cannot be relaxed. Every `stash init` therefore left a
  project whose first `tsc` or `next build` failed, in a file the CLI had just
  told the user not to hand-edit. The consolidated `Encryption` factory enforces
  the non-empty schema requirement.

  The scaffold now declares a single sentinel table, `__stash_placeholder__`, so
  the file typechecks as written. Every command that reads the encryption client
  — `stash db validate` and `stash encrypt backfill` — refuses to run while that
  table is still the only one declared, and names it, rather than failing later
  with a confusing "table not found". (`stash encrypt drop` does not read the
  client file at all; it resolves against the database.)

  Nothing in the repo compiled this output before: `packages/cli` has no
  typecheck step, the codegen tests only string-match fragments of the template,
  and the step test stubs the generator out entirely. Both templates are now
  committed as fixtures that CI typechecks, pinned byte-for-byte to the generator
  so they cannot drift.

- 46dde37: Fix two defects in the Drizzle migration generator used by `stash eql install --drizzle` (EQL v2):

  - **`--name` is now validated and no longer reaches a shell.** The migration name was interpolated into a shell command string, so a name containing shell metacharacters (e.g. `--name 'x; rm -rf ~'`) was executed. `--name` is now restricted to letters, numbers, dashes, and underscores, and drizzle-kit is invoked with an argv array instead of a shell string.
  - **`--out` is now actually passed to drizzle-kit.** The flag was used to search for the generated migration but never handed to `drizzle-kit generate`, so any project whose `drizzle.config.ts` writes migrations outside `drizzle/` had the file written in one place and searched for in another, failing with "migration file not found".
  - **drizzle-kit now runs project-locally.** The generator invoked drizzle-kit through the download-and-run form (`pnpm dlx` / `npx <pkg>` / `bunx`), which could fetch a different drizzle-kit major into a temp store and resolve a different `drizzle.config.ts`/schema than the project's. It now uses the project-local form (`pnpm exec` / `npx --no-install`), so it resolves the project's own drizzle-kit and config and fails loudly if drizzle-kit isn't installed rather than surprise-downloading it. The "run your migrations" hint matches. This aligns v2 with the v3 generator's behaviour.

  `stash eql migration --drizzle` (EQL v3) already had all three fixes and is unchanged.

- 1b8cac2: Add `columnExists(client, tableName, columnName)` — a case-exact "does this
  column exist at all?" catalog probe, distinct from `detectColumnEqlVersion`'s
  "and is it an EQL column?".

  Callers need that difference to tell a STALE column reference (it is gone) from
  a live one the domain classifier simply does not recognise — most often a legacy
  `eql_v2_encrypted` counterpart.

  `stash encrypt drop` had a private copy of this probe built on a bare
  `to_regclass($1)`. That form _parses_ its argument and case-folds unquoted
  identifiers, so on a Prisma-style `"User"` table it resolved `user`, reported the
  column missing, and treated a valid recorded pairing as stale — silently skipping
  the fail-closed that stops the command acting on a guessed encrypted column.
  The shared implementation quotes with `format('%I')` first, like every other
  catalog probe in this package, so the lookup is case-exact while still honouring
  `search_path` for unqualified names.

- a5fab3c: Correct shipped documentation that claimed the tooling detects a column's EQL
  **v2** generation. It does not, and has not since `classifyEqlDomain` dropped v2:
  detection is one-sided — a `public.eql_v3_*` Postgres domain classifies as **v3**,
  and anything else (a plaintext column, or a legacy `eql_v2_encrypted` one)
  classifies as _unknown_ and falls through to the **v2** lifecycle. The v2 path is
  reached by fallback, not by detection, and a v2 column records no `eqlVersion` in
  `.cipherstash/migrations.json`, so `stash encrypt status` reports no version for
  it.

  - `skills/stash-supabase/SKILL.md` said the CLI "still auto-detects a v2 column"
    (twice, once inside the "Stay on v2 for now" bullet — exactly the case it got
    wrong) and that `stash encrypt drop` picks its target from a version the CLI
    "auto-detects". All three now describe the one-sided rule, matching the correct
    wording already in the same file's EQL version note. This skill is copied into
    customer repos by `stash init`, so the wrong version of it was being installed
    as guidance.
  - `packages/migrate/README.md` documented `detectColumnEqlVersion(client, table,
column)` as returning `2`, `3`, or `null`. It cannot return `2` — the return
    type is now stated as `3` or `null`, with what a `null` means for the caller.
    The lifecycle intro no longer presents the v2 ladder as a detection result.
  - `packages/stack/README.md`'s Supabase example imported and called
    `encryptedSupabaseV3`, the `@deprecated` alias, contradicting the same file's
    package table and v3-only note. It now uses `encryptedSupabase`.

  Documentation only — no behaviour change.

- d6bc9e9: `stash plan` now reports the outcome that actually occurred instead of unconditionally printing `Plan drafted at .cipherstash/plan.md` and exiting 0 (#738). The plan file is written by the handed-off agent, so the command verifies it on disk after the handoff: "Plan drafted" appears only when the file exists; if a launched agent (Claude Code, Codex, or the wizard) exits without writing it, `plan` errors and exits non-zero so automation never proceeds against a plan that was never created; deferred handoffs (`--target agents-md`, or a CLI target that isn't installed) end with an honest "No plan drafted yet" hint; and a pre-existing plan the run didn't modify is reported as left unchanged rather than drafted. An unexpected filesystem error while reading the plan path (a locked or malformed `.cipherstash/`) now exits non-zero with a clear message rather than an opaque crash.
- b7fa61f: Upgrade the Prisma Next integration to Prisma Next 0.16.

  All `@prisma-next/*` dependencies move from `0.14.0` to `0.16.0`, in lockstep. The
  CipherStash encryption surface is unchanged — column types, envelopes, the `eql*`
  operators, `cipherstashFromStack`, and every subpath export behave exactly as before.

  **Action required in your `prisma-next.config.ts`:** Prisma Next 0.15 stopped
  materialising a placeholder namespace, so authoring a SQL contract now requires the
  target's namespace factory. Add `createNamespace` to your `prismaContract(...)` call:

  ```typescript
  import { postgresCreateNamespace } from '@prisma-next/target-postgres/types'

  contract: prismaContract('./prisma/schema.prisma', {
    output: 'src/prisma/contract.json',
    target: postgresPack,
    createNamespace: postgresCreateNamespace,
  }),
  ```

  Without it, `prisma-next contract emit` fails at runtime with `createNamespace is
not a function`. The bundled `stash-prisma` skill documents this too.

  The bundled EQL v3 baseline migration is re-emitted so its label and hash reflect
  the pinned `@cipherstash/eql` 3.0.2 (the committed artifact still said 3.0.0).

  Re-run `prisma-next contract emit` after upgrading. The regenerated
  `contract.{json,d.ts}` picks up the 0.15/0.16 shape changes — the namespace
  discriminator becomes the target-specific `'postgres-schema'` (was
  `'sql-namespace'`), emit adds the `StorageColumnTypes` / `StorageColumnInputTypes`
  maps and the `scalarList` capability marker, and foreign keys and their backing
  indexes become discrete contract entities. Your contract's `storageHash` is
  unaffected by the upgrade itself.

- 4923c0a: **Breaking (v3 authoring surface):** the EQL v3 PSL column constructors drop
  the `Encrypted` prefix to line up with the stack / Drizzle `types.*` catalog —
  the `cipherstash.` namespace already disambiguates. So
  `cipherstash.EncryptedTextSearch()` → `cipherstash.TextSearch()`,
  `cipherstash.EncryptedDoubleOrd()` → `cipherstash.DoubleOrd()`,
  `cipherstash.EncryptedBoolean()` → `cipherstash.Boolean()`, etc.

  The v3 one-call setup function is renamed `cipherstashFromStackV3` →
  `cipherstashFromStack`, the package's sole setup path.

  The camelCase TS-authoring factory exports move in lockstep:
  `encryptedTextSearch` → `textSearch`, `encryptedDoubleOrd` → `doubleOrd`, etc.
  (a property test enforces the PSL and TS names agree modulo first-letter case).

  Unchanged: the runtime value envelopes (`EncryptedString`, `EncryptedNumber`,
  `EncryptedBoolean`, …), the generated `contract.json` / codec ids, and the
  `eql*` query operators. The legacy v2 constructors are removed elsewhere in
  this release.

  The `stash-prisma` skill is updated to the new names (skills ship in the
  `stash` tarball).

- 90a0200: Make `stash encrypt` work in Prisma Next projects.

  `stash encrypt backfill` could not run against a Prisma Next project for two independent reasons, both now fixed:

  - **No encryption client file.** Prisma Next integrations deliberately have none — encrypted columns are declared in the PSL contract. Loading the encryption context hard-failed on the missing file. It now falls back (mirroring the existing Drizzle auto-derive) to detecting the project, locating the emitted `contract.json`, and deriving the v3 schemas with the adapter's own `deriveStackSchemasV3` + `Encryption`. Both `@cipherstash/stack-prisma` and `@cipherstash/stack` are resolved from the user's project, so the CLI's schema view always matches the application's.
  - **`cipherstash.cs_migrations` never existed.** That schema is created by `stash eql install`, which the Prisma Next flow skips (EQL installs through the `prisma-next` migration graph, which doesn't carry the tracking schema). The first checkpoint write then failed with an opaque relation-does-not-exist error. `backfill` now bootstraps it via the existing idempotent `installMigrationsSchema` before any event is written.

  `skills/stash-cli` documents both, including that the `client` config option is not required in Prisma Next projects.

- b7fa61f: Fix the wrong `prisma-next migration apply` command name in the Prisma Next
  guidance. Prisma Next has no `migration apply` subcommand — the apply verb is the
  top-level `prisma-next migrate` (`migration` only has `plan`/`new`/`show`/
  `status`/`log`/`list`/`graph`/`check`). The stale name appeared in the
  `stash-prisma` and `stash-cli` skills, the `@cipherstash/stack-prisma`
  README, and — user-visibly — in `stash init --prisma-next`'s printed next-steps,
  the `stash init` flag help, and the `stash eql install` Prisma-Next refusal
  message, all of which now say `prisma-next migrate`. Surfaced by the rc.4
  skilltester run (found independently at Prisma Next 0.14.0, confirmed at 0.16.0).
- 8817cfb: Correct the `stash-prisma` skill against the current adapter, and fix a
  stale constructor name in `stash init --prisma-next`'s next steps.

  The skill was verified line-by-line against `@cipherstash/stack-prisma` on
  main (constructors, domains, operators, `rawSql` shape, EQL function names,
  CLI commands — all confirmed current). Two real errors fixed:

  - The config example imported `defineConfig` from `'prisma-next'` — no such
    package exists; it comes from `@prisma-next/cli/config-types`.
  - The bundling section suggested `@cipherstash/stack/wasm-inline` for edge
    runtimes — the Prisma Next adapter is native-only (`cipherstashFromStack`
    constructs the native stack client; there is no WASM variant), so the
    advice was a dead end. It now says so.

  The column-type section now carries the **complete 31-constructor catalog**
  (plaintext TS type × capability tier) instead of a six-row sample presented
  as the whole surface (#756): every family (`Text*`, `Integer*`, `Smallint*`,
  `BigInt*`, `Numeric*`, `Real*`, `Double*`, `Date*`, `Timestamp*`, `Boolean`,
  `Json`) with its plaintext type — the column that distinguishes
  `IntegerOrd` (JS `number`) from `BigIntOrd` (JS `bigint`) and would have
  prevented the integer-cents trap the issue reports. Also states that `*Ord`
  includes equality, `TextMatch` is free-text only, and the `*OrdOre` variants
  are deliberately unexposed.

  Also documented the `column-types` subpath (camelCase factories for
  TS-authored contracts), and fixed `stash init --prisma-next`'s next-steps
  message, which still told users to declare columns with the old
  `cipherstash.Encrypted*()` constructor names (current: `cipherstash.TextSearch()`,
  `cipherstash.DateOrd()`, …).

- cf2c57c: Upgrade Stack to `@cipherstash/protect-ffi` 0.30 and EQL 3.0.2.

  Prisma Next includes a versioned EQL 3.0.2 upgrade migration, so databases
  that have already recorded the original EQL v3 baseline still install the new
  domains and functions.

  Encrypted JSON now uses the `public.eql_v3_json_search` storage domain and
  `eql_v3.query_json` query domain. Drizzle selector equality uses exact,
  GIN-indexable value-selector containment, while selector range comparisons use
  a ciphertext-free path selector plus string/number query term. Prisma Next gains
  the equivalent `eqlJsonPathEq`, `eqlJsonPathNeq`, `eqlJsonPathGt`,
  `eqlJsonPathGte`, `eqlJsonPathLt`, and `eqlJsonPathLte` operators. Selector
  Selector-based `ORDER BY` is available as
  `ops.selector(column, path).asc()/desc()` in Drizzle
  and `eqlJsonPathAsc(column, path)` / `eqlJsonPathDesc(column, path)` in Prisma
  Next; both lower to `ORDER BY eql_v3.ord_term` over the selected entry.

  If you call `encryptQuery` with an explicit `queryType`, note that `steVecTerm`
  now produces a scalar JSON ordering term. It no longer means structural
  containment; use the JSON containment query type with an object or array, or
  `steVecValueSelector` with
  `{ path, value }` for exact equality at a path.

  The FFI now rejects free-text needles shorter than the configured n-gram size
  at the core query-encryption boundary, including callers that bypass adapter
  guards.

  This EQL release changes the SteVec storage format. Existing EQL v3 encrypted
  JSON rows must be re-encrypted before they can be queried with the new domain.
  The former EQL v2 JSON schema shape is not accepted by the public client because
  the old selector envelope can no longer be emitted; migrate to the v3
  `types.Json` domain. Native decrypt compatibility for stored v2 payloads is
  unchanged.

  EQL 3.0.2 requires typed query-domain operands for encrypted free-text and JSON
  operators. PostgREST cannot express those casts, so Supabase v3 fails fast for
  `matches()`, encrypted `contains()`, and `selectorEq()`/`selectorNe()` instead
  of placing a decryptable storage envelope in a GET query string that the new
  SQL surface will reject. Use the Drizzle or Prisma Next adapter, or a carefully
  scoped direct SQL/RPC path.

- 04f7ac7: Document the `Date` reconstruction boundary on `decrypt` / `bulkDecrypt`, and correct the reason given for it.

  A `types.Date` / `types.Timestamp` column comes back as a `Date` from `decryptModel(row, table)` and as the string it was stored as from `decrypt(payload)` / `bulkDecrypt(payloads)`. Reconstruction is driven by the table's `cast_as`, and only the model path is handed a table. That split is intentional — the raw methods resolve to the FFI plaintext union, which excludes `Date`, so reconstructing without widening the return type would make the declared type wrong — but it was undocumented, and the JSDoc explained it with a reason that does not hold: that a lone ciphertext "carries no column identity". Every stored payload carries `i: { t, c }`, so the identity is present and simply unused. The real constraint is static typing (TypeScript cannot know which column a runtime payload came from), not a missing capability at runtime.

  No behaviour change. What changed:

  - `decrypt` and the new `bulkDecrypt` JSDoc state the boundary, its consequence, and the actual reason, on both the native and `wasm-inline` entries.
  - The one-arg `decryptModel(row)` / `bulkDecryptModels(rows)` overloads had the same wrong justification ("there is no `cast_as` to reconstruct from"); corrected to name the real one — the `table` argument is what selects reconstruction, and `Decrypted<T>` types those fields `string` to match.
  - `skills/stash-encryption` and the `@cipherstash/stack` README now call out the `Date`-vs-string consequence and point at the model helpers. Both also stop calling `bulkEncrypt` untyped: its plaintexts are pinned to the column's domain via `{ table, column }`, exactly like `encrypt` — it is `bulkDecrypt`, which takes the payloads alone, that resolves to the untyped plaintext union.
  - `bulkDecrypt` was the one path with no test either way; it is now pinned, using a payload whose `i: { t, c }` names a registered date-like column, so a future change of heart is a deliberate decision rather than a silent drift.
  - The boundary is pinned at the type layer too, which is the layer it is argued from: the raw paths resolve to the FFI plaintext union with no `Date` arm, the table-taking model path resolves to `Date`, and the table-less one to `string`. If `JsPlaintext` ever gains a `Date` arm upstream, the justification for the split expires — and the type tests fail rather than the docs quietly going stale.

  Resolves #779.

- d803914: Two guards for the release-train version embed (#661 follow-up):

  **Direction-aware version skew.** `stash init` now distinguishes an installed
  package that is _behind_ this CLI release (offered alignment / the pinned
  install command, as before) from one that is _newer_ than the release expects.
  A newer install no longer produces a downgrade command — init prints the exact
  `stash` update command instead (release-train lockstep guarantees that version
  exists), and when missing packages are about to be installed alongside newer
  ones it says the pairing may not match and to update `stash` first. Unreadable
  or malformed manifest versions always count as behind (a broken install should
  be offered the reinstall fix, never "looks newer, leave it").

  **Version lockstep.** The release-train packages (`stash`,
  `@cipherstash/stack`, `@cipherstash/stack-drizzle`,
  `@cipherstash/stack-supabase`, `@cipherstash/stack-prisma`,
  `@cipherstash/wizard`) are now a Changesets `fixed` group: a release of any of
  them republishes all of them at the same version, so the CLI's embedded
  version map can never go stale against the packages it pins (previously a
  runtime-package-only release would have left the published CLI embedding —
  and recommending — outdated versions). A test now asserts the fixed group
  stays exactly equal to the release train.

- c516b34: Follow the `@cipherstash/stack-drizzle` package-root collapse in the packages that
  document it.

  - **`stash`:** `stash init --drizzle` emits the package-root
    `extractEncryptionSchema` import, and the bundled `stash-drizzle` and
    `stash-encryption` skills match.
  - **`@cipherstash/stack`:** README only — its Drizzle section documents the
    package-root exports.

- b2f9d7a: Use the consolidated v3 client name in generated code and shipped guidance.

  `stash init` now scaffolds `Encryption` from `@cipherstash/stack/v3`, so a v3
  schema and its client come from one import specifier. The former suffixed client
  alias has been removed from the public API.

  Corrects the bundled agent skills and package docs, which described
  `encryptedSupabase` as the legacy EQL v2 wrapper. It is the EQL v3 factory;
  the v2 wrapper was removed. Also drops the stale "DynamoDB still requires v2"
  note from the `@cipherstash/stack` README — DynamoDB writes EQL v3 and reads
  existing v2 items.

- e0dea47: Update the bundled `stash-supabase` agent skill for the EQL v2 removal (#707):
  `encryptedSupabase` is now the connect-time-introspecting EQL v3 factory (with
  `encryptedSupabaseV3` kept as a type-identical `@deprecated` alias), and the
  legacy v2 `encryptedSupabase({ encryptionClient, supabaseClient })` authoring
  wrapper has been removed. The skill's examples, exported-type list, and migration/cutover
  guidance are corrected accordingly. Skills ship inside the `stash` tarball, so
  the stale v2 guidance would otherwise land in a user's project.
- 413ca39: The legacy `@cipherstash/drizzle` package (the `@cipherstash/protect`-based
  Drizzle integration) is removed from the repository and the release train —
  `@cipherstash/protect` is sunsetting at Stack 1.0, and the package's successor
  is `@cipherstash/stack-drizzle`. Already-published versions remain installable
  from npm (deprecated, pointing here); the git history preserves the source for
  any emergency maintenance. The `stash-drizzle` skill and the
  `@cipherstash/stack-drizzle` README now state the deprecation explicitly so
  nobody (human or agent) installs the legacy package by mistake.
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

- d84ebac: Close three correctness follow-ups in the Drizzle EQL migration rewriter, all of
  which previously exited 0 while leaving the user in a wrong state.

  **Dollar-quoted DDL no longer bypasses the already-encrypted guard.** DDL inside
  `DO $$ … END $$;` is executed SQL, but the corpus index skipped those bodies
  whole, so an encrypted `ADD COLUMN` there never registered as encrypted. The
  column fell through as "plaintext by residue" and the sweep staged an empty
  `<column>_encrypted` twin beside the real ciphertext, reporting success. The
  index now reads dollar-quoted bodies for the _encrypted_ side, so these are
  flagged for staged re-encryption instead. A plaintext declaration inside such a
  block still does not count as declaring the column — the block may be
  conditional — so those statements remain flagged rather than rewritten.
  `target-exists` also now recognises a twin that exists only inside a
  dollar-quoted body, which previously produced a duplicate `ADD COLUMN` that
  failed at migrate time.

  **A successful sweep now reports the artefact divergence it leaves behind.** The
  rewrite repairs SQL only, so afterwards the database has both `email` (still
  plaintext) and `email_encrypted`, while `schema.ts` and drizzle-kit's snapshot
  both still declare `email` as the encrypted domain and know nothing about the
  twin. `drizzle-kit generate` cannot surface this — it diffs the schema against
  its snapshot and reads neither the `.sql` nor the database — so the divergence
  was entirely silent: reads of the source column hand plaintext to a decrypt path
  expecting an EQL envelope, and writes store an EQL envelope in a plaintext
  column and succeed. `stash eql migration --drizzle` and the wizard now print the
  divergence per column, naming the table, both columns, the domain and the
  migration the twin was staged in, followed by the reconciliation: set the source
  column back to its plaintext type, declare the twin under its own name, then run
  `drizzle-kit generate` and delete the `ADD COLUMN` it regenerates for the twin.
  That last step is load-bearing — the snapshot can only learn about the twin from
  a `generate` that also emits SQL to create it, and the swept migration already
  added that column, so leaving both fails with `column already exists`. The
  `skills/stash-cli` and `skills/stash-drizzle` guides carry the same sequence.

  Twins are reported only once the migration file they were written into has been
  saved, so a sweep that fails mid-write no longer names a column that never
  reached disk.

  The new body scan is a single forward pass, so sweep time is unchanged on a real
  drizzle output directory — which contains the ~2.6 MB EQL install migration, and
  that file is itself thousands of `$$` PL/pgSQL bodies.

  **The wizard's per-directory sweep reporting no longer breaks on a non-`Error`
  throw.** It read its partial result off an unchecked cast, so a `throw null`
  raised a `TypeError` inside the very `catch` meant to report the failure —
  skipping the error result and abandoning the remaining directories. It now
  narrows, matching the CLI.

- 6c70e29: Fix a data-loss bug in the Drizzle migration rewriter: a **commented-out**
  `ALTER … SET DATA TYPE` was rewritten into executable SQL. The matcher was
  comment-blind and the replacement is multi-line, so the author's `-- ` survived
  on the first line only — the `DROP COLUMN` on the next line emitted live and
  dropped a populated column.

  A statement is now left exactly as written whenever it is inert — inside a `--`
  line comment, inside a `/* … */` block, or inside a single-quoted string
  literal, where an `ALTER` is data rather than SQL. (Rewriting one splices
  `--> statement-breakpoint` markers _inside_ the literal, so splitting the file
  the way drizzle's migrator does yields a bare, live `DROP COLUMN` as a chunk of
  its own.) Quoting is tokenised properly in the process: a `--` inside a string
  no longer opens a comment, an apostrophe inside a quoted identifier such as
  `"o'brien_data"` no longer opens a phantom string literal, a doubled `''` or
  `""` reads as an escape rather than a delimiter, and an unterminated quote of
  either kind makes the rest of the file inert rather than live.

  The sweep also refuses to rewrite a column the migration corpus already gives an
  encrypted type, so changing a column's encrypted domain no longer drops a column
  full of ciphertext. Skipped statements report why they were left alone. This
  recognises the encrypted forms drizzle-kit emits, a domain installed into a
  non-`public` schema, and an array of a domain — so a corpus that shows a column
  as encrypted in any of those shapes is flagged, not rewritten.

  The sweep is now fail-closed about the columns it does not recognise at all.
  Previously a column missing from the corpus index was assumed to be plaintext
  and rewritten; absence is not evidence, and the declaration can simply live in a
  migration directory the sweep never reads — the wizard ships scanning three of
  them and indexes each separately. Such a statement is now reported for review
  rather than rewritten, so the ADD+DROP+RENAME no longer drops a column that the
  migration corpus itself shows already holds ciphertext. That is a guarantee
  about what the corpus says, not about the database: the sweep reasons entirely
  from migration files, and a database that has drifted from its migration
  history is outside what it can see: a column encrypted by hand via psql or the
  Supabase dashboard is still described as plaintext by the corpus. If your migration history is squashed, the column's
  `CREATE TABLE` lives outside the directory being swept, or the database has
  simply drifted from what the migrations describe, you will see the statement
  flagged instead of repaired: check the column's current type in the database
  and either apply the rewrite by hand on an empty table, or use the staged
  `stash encrypt` lifecycle.

  An unreadable migration directory (`EACCES`) is reported rather than silently
  treated as empty, and the wizard's `Run the migration now?` prompt defaults to No
  whenever the sweep rewrote anything, flagged anything, or could not check a
  directory at all — naming the directories that went unchecked, and making no
  claim about data destruction for a directory nothing is known about.

  Four further ways the sweep could still reach a ciphertext column are closed:

  - **Chained conversions.** The corpus index read `CREATE TABLE`, `ADD COLUMN`
    and `RENAME`, but never the sweep's own target. A directory where an earlier
    migration already ran `SET DATA TYPE eql_v2_encrypted` — generated by a stack
    version predating this sweep — left the column looking plaintext, so a later
    domain change dropped its ciphertext. Conversions are now recorded as the
    sweep walks the corpus in order, so the first conversion still applies and
    only the ones after it are flagged.
  - **Schema qualification.** `"users"` and `"public"."users"` are the same table
    — Postgres resolves the unqualified name through `search_path` — but they were
    indexed under different keys. drizzle-kit emits unqualified while hand-written
    SQL and this sweep's own output are qualified, so a corpus mixing the two hid
    an encrypted column from the guard. A non-`public` schema stays distinct.
  - **Quote parity.** A `$$ … $$` body containing an odd number of apostrophes, or
    an `E'a\'b'` literal, ended a string literal earlier than Postgres does. Every
    token after it was then misread — including a commented-out `ALTER`, which
    read as live and was rewritten into a live `DROP COLUMN`. Dollar-quoted bodies
    are skipped whole and `E''` backslash escapes are honoured.
  - **Truncated `CREATE TABLE` bodies.** The body was matched up to the first
    `);`, which can sit inside a `--` comment or a string `DEFAULT`. Columns
    declared after that point vanished from the index entirely. The closing paren
    is now located by skipping candidates that are inside a comment or literal.

  The two copies of this rewriter — one in `stash`, one in `@cipherstash/wizard` —
  are now compared by a repo test, so a fix can no longer land in one and silently
  miss the other.

  **The wizard now sweeps only drizzle-kit output directories.** It cannot
  discover a project's configured `out`, so it tries `drizzle/`, `migrations/` and
  `src/db/migrations/` — but the last two are generic names that Knex,
  node-pg-migrate, Flyway and hand-rolled psql also use. A project whose drizzle
  `out` is `drizzle/` and which also keeps a hand-maintained `migrations/` had
  that second directory rewritten into ADD+DROP+RENAME, in a directory the wizard
  was never pointed at. The fail-closed rule is no defence there: a real migration
  history declares its own columns, so the rewrite proceeds. A candidate is now
  swept only if it carries the `meta/_journal.json` drizzle-kit maintains. A
  directory that holds `.sql` files but no journal is reported rather than passed
  over in silence, so a genuine drizzle output whose `meta/` went missing is
  visible instead of looking clean. `stash eql migration` and `stash eql install`
  are unaffected — both already take a single explicit `--out`.

- f78fd7a: `stash schema build` now picks a concrete EQL v3 domain per column
  (`TextSearch`, `IntegerOrd`, `TextEq`, …) instead of the legacy v2
  "searchable capabilities" toggle. Boolean columns are assigned the
  storage-only `types.Boolean` domain automatically, while JSON columns are
  assigned the queryable `types.Json` domain, with encrypted containment and
  selector queries. Other columns default to the widest searchable domain,
  matching the previous behaviour. The internal `SearchOp` capability tuple
  and the `v3DomainFactory` translation shim are removed, unblocking EQL v2
  removal (#707, #751).
- 46f4b34: Correct the EQL v2 callout in the shipped `stash-encryption` skill.

  The skill opened by pointing at an older EQL v2 schema surface "with chainable
  capability builders" that "still exists for existing deployments". The v2 schema
  builders and the `@cipherstash/stack/client` subpath were removed; v2 is a
  read-compatibility path for stored payloads only, which is what the same file
  already said two sections later. The opening callout now says so — it is the
  first thing an agent reads in a customer's repo, and `SKILL_MAP.drizzle` installs
  this skill into every Drizzle project.

- 8d32ba6: Fix telemetry stack traces printing to the terminal when the telemetry endpoint is unreachable or returns an error. The PostHog SDK logs flush failures to the console internally (bypassing the CLI's own error swallowing), so a machine with telemetry enabled and a failing network printed two full stack-trace blocks per command. The CLI now supplies the SDK with a fetch wrapper that absorbs network and HTTP errors, so a failed send is silently dropped — matching the documented fire-and-forget behaviour. Command output, including `stash manifest --json` stdout, was never corrupted; the noise went to stderr.
- 3a0a0dc: Correct `types.TOrd` in the `stash-indexing` skill, which named a factory that
  does not exist. The ordering factories are `types.<N>Ord` (over the numeric and
  time domains) and `types.TextOrd` — as the table directly above that line
  already showed. An agent following the skill would have written a schema that
  does not compile.
- 310bb19: `skills/stash-encryption` now documents how to name the client's type
  (`EncryptionClient<S>`) and states that `schemas` accepts any non-empty array of
  v3 tables rather than only an array literal.
- 524903c: Correct stale EQL v3 guidance in the bundled agent skills.

  `@cipherstash/migrate` and the `stash encrypt *` commands gained EQL v3 support
  (cipherstash/stack#648, now closed), but the shipped skills still told readers the
  rollout tooling was v2-only. Since these skills are copied into customer repos, the
  stale text steered users away from v3 and toward workarounds they no longer need.

  - **`stash-drizzle`, `stash-supabase`** — replaced the "v3 not supported end-to-end"
    callouts with an accurate EQL version note: the tooling classifies a column from
    its Postgres domain type, and the documented lifecycle is
    `backfill → switch the app to the encrypted column by name → drop` — there is no
    cut-over rename.
  - **`stash-supabase`** — removed the "Interim path until #648: the v2 encrypted twin"
    section; a v2 twin is no longer needed to get CLI-managed backfill.
  - **`stash-drizzle`, `stash-supabase`** — the drop step now documents that
    `stash encrypt drop` targets the _original_ column (there is no
    `<col>_plaintext`, since nothing is renamed).
  - **`stash-cli`** — corrected the documented `EQLInstaller` default (EQL v3) and
    removed the v2 cut-over known-gap note, which cited cipherstash/stack#585 as open
    tracking when it was resolved by making v3 the default.

- 40ab142: Docs: stop teaching the deprecated `LockContext.identify()` as the primary
  identity-aware-encryption path (#591). The `stash-encryption` and `stash-supabase`
  skills and the `@cipherstash/stack` README now lead with the current pattern —
  authenticate the client with `OidcFederationStrategy`, then bind the claim per
  operation with `.withLockContext({ identityClaim })` — and demote
  `LockContext.identify()` to a clearly-marked deprecated note (per-operation CTS
  tokens were removed in protect-ffi 0.25). Skills ship in the `stash` tarball, so
  this keeps the bundled guidance correct for the 1.0 surface.
- 8817cfb: Correct the keyset/credential model in five shipped skills to match the new
  canonical sources.

  `stash-edge`, `stash-cli`, `stash-postgres`, and `stash-supabase` all carried
  a "credential-identity rule": EQL index terms deriving from the ZeroKMS
  client key, so rows written under one credential would "decrypt correctly
  but never match a query — silently". That model is wrong. Index terms come
  from a per-**keyset** key, so every client **bound** to the same keyset
  derives the same terms — credential strings never matter. The keyset can
  still miss silently, though: encrypt and query use the client's bound
  keyset while decrypt follows each payload's keyset subject to grants, so a
  reader granted the writer's keyset but bound to a different one decrypts
  fine while its searches return zero rows. The old _credential_ diagnostic
  could never fire; the _keyset-binding_ check replaces it, alongside the
  other real causes of zero-row queries (operand casts, predicate forms,
  missing indexes).

  All five sites now state the keyset model and defer to `stash-zerokms`
  (keysets/grants) and `stash-auth` (credentials/lock context) as canonical.
  `stash-deployment`'s backfill-keyset guidance gets the same pass: bound
  keyset (not a mere grant) is what routes the backfill's writes, the failure
  table and troubleshooting rows distinguish the no-grant case (decrypt fails)
  from the granted-but-differently-bound case (decrypt works, search silently
  misses), and `stash-cli`'s backfill precondition now names the credential
  _resolution_ order — `CS_*` variables when present, else the local
  `~/.cipherstash` profile via native auto auth.
  `stash-encryption` also drops its claim that identity-bound encryption on
  the edge is "configured via `config.authStrategy`" (an auth strategy decides
  who the client is; a lock context gates retrieval of a value's data key —
  the edge entry simply lacks lock context, #797), and its auth, lock-context,
  and keysets sections now point at the canonical skills.

- c516b34: The bundled skills pin `1.0.0`, not a release candidate (#791).

  `skills/stash-edge` hardcoded `@cipherstash/stack@1.0.0-rc.4` in its Deno `npm:`
  import and its `deno.json` import map, and `skills/stash-cli` pinned the
  bare-project `npx --package=stash@…` one-shot the same way. Nothing in the build
  rewrites those literals — `tsup.config.ts` copies `skills/` verbatim, and the
  `__STASH_RUNTIME_VERSIONS__` embed only reaches compiled CLI code — so the
  published skill would have told Deno and Supabase Edge Function users to pin a
  release candidate in production, in their own repo, indefinitely.

  The prerelease-semver paragraph that explained why `@^1.0.0` does not match
  `1.0.0-rc.4` is gone with the rc pin; "pin exactly, Deno caches by specifier"
  stands on its own. The `supabase-worker` example pins the same way.

  A test now guards every `skills/*/SKILL.md`: an exact pin of a release-train
  package must name a stable version on the current major, so a stale rc pin fails
  on the version-bump PR instead of shipping.

- 5d304ec: Fixed: a change to `skills/` could ship a stale copy of that skill.

  Both CLIs copy the repo-root `skills/` into their bundle at build time
  (`dist/skills`), which `stash init` then installs into a customer's
  `.claude/skills/` or `.codex/skills/`. That directory sits outside the package,
  so it was not part of the build's declared inputs — a skills-only edit did not
  invalidate the cached build. Once the build began declaring its output
  directory, a cache hit stopped being merely stale and started actively restoring
  the previous `dist/skills` over the tree, so an edited skill could be published
  with the pre-edit text while the source file on disk was correct and CI green.

  The two builds now declare the skills directory as an input, and a test pins
  that coupling so it cannot come undone.

- 8832d35: Skills refresh for the EQL v3 collapse (ships in the `stash` tarball):

  - `stash-dynamodb`: audited decrypt now works on the typed client —
    `client.decryptModel(item, table).audit({ … })` — so the old "use
    a separate nominal client for audited decrypts" caveat is removed.
    Encrypt/write is EQL v3 only; legacy DynamoDB reads pass a v3 table with
    `{ storedEqlVersion: 2 }`.
  - `stash-encryption`: canonical examples use `Encryption` and the generic
    `EncryptionClient<S>` type; the DynamoDB notes state encrypt is v3-only while
    native decrypt still reads stored v2 payloads.

- 6ee68fd: The Drizzle migration rewriter now preserves the source column and adds a staged
  encrypted twin instead of emitting destructive drop/rename SQL. When the sweep
  cannot prove a source column's type or the encrypted twin already exists, the
  CLI and wizard fail closed with a non-zero exit so the migration directory must
  be reviewed before applying it.
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
    deprecated aliases that warn and forward; `db validate`, `db test-connection`, and
    `db migrate` remain in the `db` group.
  - Adds the missing `--database-url`, `--prisma-next`, and `--region` flags; corrects
    six programmatic API signatures; fixes the README's claim
    that `stash init` ends in an agent-handoff menu (that belongs to `stash plan` / `stash impl`);
    and marks `stash env` as the non-functional stub it currently is.

- 161f17b: Correct the `stash-drizzle` skill: `inArray` / `notInArray` now encrypt the whole
  list in a single `encryptQuery` batch crossing (the `bulkEncrypt`/concurrency
  fallback was removed when v3 query operands moved to `encryptQuery` — #622). The
  skill ships inside the `stash` tarball, so this keeps the bundled guidance in step
  with the adapter's behaviour.
- 2e6f032: Update the bundled `stash-prisma` skill for the EQL v3-only
  `@cipherstash/stack-prisma`: drop the stale references to the removed EQL v2
  surface (`cipherstashFromStackV2`, the `cipherstash*` operators, the "legacy v2"
  subpath note) so the guidance copied into customer repos matches the package.
- e40c3da: Update the `stash-drizzle` and `stash-supabase` skills for the EQL v3
  `contains()` → `matches()` rename (#617): the encrypted free-text operator is now
  `matches()` (fuzzy bloom token matching), `contains()` is reserved for exact
  containment, and Supabase `like()`/`ilike()` on encrypted columns are documented
  as an approximate compatibility shim delegating to `matches()`. Skills ship inside
  the `stash` tarball, so they must track the adapter surface.
- 58d7439: Correct the bundled `stash-supabase` agent skill: encrypted free-text search
  matches substrings. The skill previously carried the reverse — that it matched
  only exact values because the query's bloom filter appended the whole search term
  as an extra token. That was never true: `include_original` is inert in
  protect-ffi (the match bloom is trigram-only either way), so any substring of at
  least the tokenizer's `token_length` (3 characters) matches, and shorter terms are
  rejected rather than silently matching every row. The skills directory ships
  inside the `stash` tarball and is copied into the user's `.claude/skills/` /
  `.codex/skills/` (or inlined into `AGENTS.md`) at handoff time, so the stale
  sentence was shipping wrong guidance into customer repos.
- 8d31708: Diagnose a legacy EQL v2 table shape by name instead of crashing with a raw
  `TypeError`.

  A table created by the former v2 API is structurally similar to a v3 one. Old
  compiled code or untyped JavaScript could therefore pass that shape to
  `encryptedSupabase({ schemas })` and fail deep inside verification, naming an
  internal method rather than the version mismatch that caused it.

  Both paths now fail closed with the table named and the fix stated. The check
  routes through `hasBuildColumnKeyMap`, the canonical v2/v3 discriminator, rather
  than a second hand-written spelling of it.

  First-party adapters share an internal discriminator through
  `@cipherstash/stack/adapter-kit`; it is adapter plumbing rather than an
  end-user schema-authoring API.

- 5fe9a2f: Encrypted-JSON querying on the v3 Supabase surface (#650). A `types.Json`
  column now supports exact encrypted containment — `contains(col, subDocument)`
  (ste_vec `@>` via PostgREST `cs`, with the sub-document storage-encrypted
  against the column) — and JSONPath selector predicates: `selectorEq(col, path,
value)` and `selectorNe(col, path, value)` (dot-notation paths; `ne` includes
  rows where the path is absent, mirroring the Drizzle selector's semantics).
  Raw `.filter(col, 'cs', subDocument)` and `not(col, 'contains', …)` route
  through the same encrypted path. Selector ordering is not expressible over
  PostgREST yet (needs an EQL-bundle overload — see
  cipherstash/encrypt-query-language#407); the Drizzle integration's
  `ops.selector()` covers ordering today.

  In core, `QueryTypesForColumn` gains the `searchableJson` arm (a `types.Json`
  column no longer resolves to `never`, so typed adapter key sets can include
  it), and the JSONPath selector-path helpers the Drizzle adapter introduced in
  #651 moved to `@cipherstash/stack/adapter-kit` so both adapters share one
  validation surface (`@cipherstash/stack-drizzle` re-exports them unchanged).

  The bundled `stash-supabase` and `stash-encryption` skills are updated to
  document the new querying surface (including the array-leaf and SQL-NULL
  semantics, and the operand-exposure caveat) — skills ship inside the `stash`
  tarball, hence the patch.

- f5ee73f: Update the `stash-supply-chain-security` skill: npm OIDC trusted publishing and provenance are live in `release.yml`, not deferred. Documents the constraints that keep them working (`id-token: write`, GitHub-hosted runner, no `NPM_TOKEN`, npm >= 11.5.1, no Actions cache) and adds a runbook for claiming a package name on npm for the first time — a trusted publisher can only be attached to a package that already exists, so a new name needs a manual placeholder publish before the release workflow can publish it.
- 62df494: Type `extractEncryptionSchema` precisely: a Drizzle-extracted schema now preserves each column's concrete EQL v3 domain instead of widening to `AnyV3Table` (#589).

  `extractEncryptionSchema` is generic over the Drizzle table (`<T extends PgTable>(table: T)`) and returns `EncryptedTable<Cols> & Cols`, the same shape a hand-written `encryptedTable({...})` returns, when concrete column brands are available. Each column's builder is carried through `pgTable()` on a phantom brand and recovered by a mapped type, which also filters out the table's non-encrypted columns. Tables widened to `PgTable`, and tables containing ordinary `customType` columns recovered from their EQL SQL domain, retain the safe `AnyV3Table` fallback instead of incorrectly becoming an empty or partial schema type.

  What this fixes, along the documented flow `extractEncryptionSchema(table)` → `Encryption({ schemas })` → `bulkEncryptModels`:

  - `InferPlaintext<typeof schema>` is a precise per-column plaintext map (`{ email: string; age: number }`) rather than an index signature.
  - `encryptModel` / `bulkEncryptModels` check each schema field against its own domain's plaintext — a `string` written to an `IntegerOrd` column is now a compile error instead of an encrypt-time failure — and pass plain helper columns (`id`, a plain `text()`) through with their own types rather than typing them as encrypted.
  - `schema.email` addresses the column at its concrete type, so `encrypt` / `encryptQuery` pin the value to that column's plaintext.

  **Runtime behaviour is unchanged** — the runtime already recovered each column's builder correctly, so this is a type-level fix only. It is `minor` rather than `patch` because code that previously compiled against the widened types can now fail to compile: a model field typed against the wrong domain, or a schema-derived type that relied on the old index signature. Rows whose shape is only known at runtime (a dynamically built table) should name their model type explicitly — `client.bulkEncryptModels<typeof schema, MyRow>(rows, schema)` — rather than being cast back to `AnyV3Table`.

  `skills/stash-drizzle` documents the preserved typing and warns against casting an extracted schema to `AnyV3Table` to make an insert compile. A matching update to the separately maintained CipherStash documentation site is required so its Drizzle schema-extraction guidance explains the precise branded typing and the widened fallback for incomplete runtime-recovered column maps.

- ade9707: Close the gaps found reviewing the v3-only change against #815's acceptance
  criteria.

  `config.eqlVersion` is now rejected by the type system as well as at runtime, on
  both entries. `ClientConfig.eqlVersion` and `WasmClientConfig.eqlVersion` are
  declared `?: never` rather than omitted: every other property on those types is
  optional, so excess-property checking was the only thing catching a leftover
  `eqlVersion` — and that fires on fresh object literals alone. A shared config
  const, which is the shape a v2 → v3 migration actually holds, type-checked clean
  and then threw at `Encryption()`. It is now a compile error. Both entries keep
  their runtime guard, since JS and JSON callers bypass types entirely.

  `@cipherstash/stack/wasm-inline` now rejects `config.eqlVersion` at runtime too,
  with the same message as the native entry. Previously the native factory threw
  and the WASM one accepted the field silently — the entry disagreement #815 exists
  to remove.

  The WASM entry's non-v3-table error no longer refers the reader to the native
  entry for EQL v2 authoring. Authoring v2 has been removed everywhere, so that
  referral only bought a second rejection; the message now says so and points at
  what v2 payloads are still good for — decryption, which is unchanged.

  The `Encryption` signature sketch in the `@cipherstash/stack` README carried
  `schemas: AnyV3Table[]`, understating what is accepted; it now shows both real
  overloads, including the `readonly` and non-literal array forms. The bundled
  `stash-encryption` skill regained the `./encryption` and `./adapter-kit` subpath
  rows, both of which still ship. `cipherstashFromStack`'s `encryptionConfig`
  JSDoc described `config.eqlVersion` as an escape hatch that throws over an
  all-v3 schema set; it is rejected unconditionally, and the doc now says that.

  The `stash-dynamodb` skill documented the v3 descriptor a legacy read takes but
  not that it must also be one of the tables passed to `Encryption({ schemas })`.
  The adapter forwards that descriptor to the client, which rejects a table it was
  not initialized with, so reading v2 rows for a table your current schema no
  longer declares fails. That requirement is now stated where the legacy-read
  signature is.

- 3aff6cb: Make `Encryption` and schema authoring EQL v3-only. The client now always writes
  EQL v3, exposes the single generic `EncryptionClient<S>` type, and removes the
  legacy v2 builders, client aliases, `config.eqlVersion`, and `./client` subpath.

  Native decrypt operations continue to read stored EQL v2 payloads. DynamoDB
  legacy reads now use a v3 table descriptor with `{ storedEqlVersion: 2 }`.
  Update the Supabase and Prisma Next integrations and the bundled agent skills
  for the consolidated API.

- 508f1d5: **Breaking (`@cipherstash/stack/wasm-inline`):** every fallible method now returns a `Result` — `{ data } | { failure }` — instead of throwing. And `bulkEncrypt` / `bulkDecrypt` are added, so a list of encrypted rows costs **one** ZeroKMS round trip instead of one per row.

  ### Result alignment

  `encrypt`, `decrypt`, `encryptQuery` and `encryptQueryBulk` previously threw on failure, and returned bare values on success. They now return `{ data } | { failure }`, with `failure.type` drawn from `EncryptionErrorTypes` (`EncryptionError` for encrypt-side operations, `DecryptionError` for decrypt-side) and `failure.code` carrying the FFI error code where there is one.

  ```typescript
  // before
  const encrypted = await client.encrypt(plaintext, {
    table: users,
    column: users.email,
  });

  // after
  const result = await client.encrypt(plaintext, {
    table: users,
    column: users.email,
  });
  if (result.failure) throw new Error(result.failure.message);
  const encrypted = result.data;
  ```

  This is the contract the native entry has always honoured, and the one `AGENTS.md` states outright: _"Operations return `{ data }` or `{ failure }`. Preserve this shape and error `type` values in `EncryptionErrorTypes`."_ The WASM entry never followed it. That was drift rather than a design decision — nothing about WASM prevents it (`@byteslice/result` is already bundled into `dist/wasm-inline.js`), and it meant edge code had to be written in a different shape from every other surface, with failures that were easy to miss.

  Fixed now because it is a breaking change and 1.0.0 has not shipped: `@cipherstash/stack@latest` is still `0.19.0`, so this surface has only ever been published under the `rc` tag. After GA it would have had to wait for a major.

  `isEncrypted` is unchanged — a pure predicate with nothing to fail at, exactly as on the native entry.

  ### Bulk operations

  ```typescript
  // Write: several columns across many rows, one round trip
  const encrypted = await client.bulkEncrypt([
    { plaintext: "alice@example.com", table: users, column: users.email },
    { plaintext: "hello", table: users, column: users.bio },
  ]);

  // Read: a whole page in one call
  const emails = await client.bulkDecrypt(rows.map((r) => r.email));
  ```

  The WASM entry previously exposed no bulk operations at all, so rendering an N-row list on Deno, Cloudflare Workers, or Supabase Edge Functions meant N sequential ZeroKMS calls. Combined with the WASM cold start, that made list endpoints impractical on the edge.

  Both are index-aligned with their input, and `null` / `undefined` entries yield `null` at the same index without reaching ZeroKMS (an all-null batch makes no call at all). Because each entry names its own table and column, a single `bulkEncrypt` can cover several columns across many rows — which is what makes the saving real, since a single-column batch would still cost one round trip per column.

  `bulkDecrypt` builds on the fallible FFI primitive, so when items fail the `failure.message` names **every** failing index with its reason, rather than surfacing the first and discarding the rest.

  The model helpers (`encryptModel` / `decryptModel` and their bulk forms) remain Node-only: the WASM entry has no single-model operation to build them on, so those need their own port.

- d25d100: `@cipherstash/stack/wasm-inline` now has the model helpers: `encryptModel` / `decryptModel` and `bulkEncryptModels` / `bulkDecryptModels` (#742). They run the same schema traversal as the native entry (shared code, so the two entries cannot drift on which fields get encrypted): declared columns are encrypted — matched by JS property name, nested fields via the column's dotted path — everything else passes through, and `null`/`undefined` fields are preserved without reaching ZeroKMS. A call that encrypts (or decrypts) at least one field is one ZeroKMS round trip regardless of how many fields or models it covers; a `null`/empty batch, or one whose models carry no schema fields, returns without contacting ZeroKMS at all. `types.Date`/`types.Timestamp` columns round-trip `Date` → `Date` (ISO strings on the wire), and failures follow this entry's `{ data } | { failure }` Result contract, with decrypt failures naming every failing field by its model path. Edge code no longer needs the hand-written `bulkEncrypt` field mapping whose failure mode was a schema column silently persisted in plaintext.

  The shared model traversal is also hardened: it no longer mutates the caller's model (previously a nested-column decrypt wrote decrypted plaintext back into the caller's input, and encrypt overwrote it with ciphertext); a literal flat dotted key, a `__proto__`-shaped key, or a non-object model element is handled safely instead of crashing, leaking plaintext, or reaching `Object.prototype`; an already-encrypted field is passed through rather than re-encrypted; and an invalid `Date` is rejected per field. On the WASM entry, model ops now validate the table against the client's schemas, `Date` values are normalized at every encrypt/query crossing (not just the model path), and a `null`/empty model batch returns `{ data: [] }`. The skills update ships in the `stash` tarball, hence the `stash` patch.

- f628463: Fix invalid DDL when a Drizzle column changes to an EQL v3 domain.

  `drizzle-kit generate` emits an in-place `ALTER TABLE … ALTER COLUMN … SET DATA TYPE`
  when a plaintext column is changed to an encrypted one, which Postgres rejects — there
  is no cast from `text`/`numeric` to an EQL type, and on drizzle-kit 0.31.0+ the emitted
  type name is additionally mangled to `"undefined"."eql_v3_<name>"`. The migration
  rewriter only recognised the EQL v2 type, so a v3 user was left with an un-runnable
  migration and nothing to repair it.

  The rewriter now matches the whole `eql_v3_*` domain family alongside `eql_v2_encrypted`,
  across every mangled form observed from drizzle-kit 0.24 through 0.31, and emits the
  matched domain in the replacement instead of a hardcoded v2 type. `stash eql migration
--drizzle` — the EQL v3 migration-first path — now runs the same sweep that `eql install
--drizzle` has always run, so the repair actually reaches v3 projects.

  The rewrite's guidance comment now also warns that it drops the plaintext column in the
  same migration, and points at the staged `stash encrypt` path (add → backfill → cutover →
  drop) for populated production tables.

- Updated dependencies [1b8cac2]
- Updated dependencies [3a86939]
- Updated dependencies [a5fab3c]
- Updated dependencies [19cff11]
- Updated dependencies [4471471]
  - @cipherstash/migrate@1.0.0

## 1.0.0-rc.4

### Patch Changes

- 98156ac: Fix the Codex handoff installing zero skills — and losing `AGENTS.md` and `.cipherstash/` with them — when `.codex/` is not writable.

  Codex sandboxes deny writes under `.codex/`. `installSkills` created its destination with an unguarded `mkdirSync`, sitting directly above a per-skill copy loop that _was_ guarded — so the failure threw past that fallback and past the caller, aborting the whole handoff step. Because the skills install runs first, nothing after it ran either: no `AGENTS.md`, no `.cipherstash/context.json`, no `.cipherstash/setup-prompt.md`. All five Codex runs of the rc.3 skilltester matrix landed here, and it was identified in that report as the primary driver of the Claude→Codex quality gap.

  The fix, hardened by a follow-up review of the first cut:

  - **`installSkills` never throws, and reports what happened.** It returns `{ copied, failed }` instead of a flat list, so callers can tell "unwritable destination" from "stripped build" from "partial copy" without re-deriving it — every filesystem failure degrades to a warning plus a `failed` entry.
  - **The Codex handoff inlines exactly the skills that failed.** Whatever could not be copied into `.codex/skills/` — all of them under a sandbox, or a subset after a partial failure — has its body inlined into `AGENTS.md` via the same `doctrine-plus-skills` path the editor-agent handoff uses. The launch prompt points at wherever each skill actually ended up, including both locations after a partial copy. A stripped build that ships no skills stays `doctrine-only` and says nothing.
  - **The doctrine now ships where the published CLI can find it.** The bundled AGENTS.md doctrine was copied to `dist/commands/init/doctrine`, but the compiled resolver probes ancestor directories of the chunk in `dist/bin/` — so every published build silently wrote the minimal `AGENTS.md` stub instead of the doctrine (and the inline fallback would have inlined nothing). It now lands at `dist/doctrine`, like the skills bundle. `buildAgentsMdBody` also honours `doctrine-plus-skills` even when the doctrine fragment is missing, so inlined skills are never dropped with it.
  - **The generated artifacts describe the fallback honestly.** `context.json` gains an `inlinedSkills` field, and `setup-prompt.md` distinguishes installed / inlined / failed skills instead of mislabelling an unwritable destination as a "stripped build". The Claude handoff now warns when skills exist but could not be installed, and the AGENTS.md handoff records what it inlined.
  - **The rest of the handoff is guarded too.** The `AGENTS.md` upsert (which refuses malformed sentinel pairs) and the bundled-file reads degrade to warnings instead of aborting the step before `.cipherstash/` is written.

  `@cipherstash/wizard` carries its own copy of `installSkills` with the same unguarded `mkdirSync` above the same guarded copy loop. It targets `.claude/skills` rather than `.codex/skills`, so the Codex sandbox case does not apply, but an unwritable destination crashed it identically — now guarded the same way, with a confirmed-then-failed install recorded in the wizard changelog instead of vanishing with the terminal output.

- 0e2ce93: Fix `stash impl` and `stash init` hanging on CI runners that allocate a TTY.

  Four prompts decided whether to run interactively without going through the
  shared TTY helper, so on a CI runner with an allocated TTY they rendered a clack
  prompt and blocked forever on `/dev/tty` — a silent hang with no error and no
  timeout:

  - `stash impl` gated on an inline `process.env.CI !== 'true'`, which only
    recognised the exact lowercase spelling. Runners that set `CI=1` or `CI=TRUE`
    blocked on the plan-summary confirmation or the agent-target picker.
  - `stash init`'s offer to chain into `stash plan`, and its Proxy-vs-SDK
    question, gated on `process.stdout.isTTY` and did not consult `CI` at all —
    so they hung on any CI runner with a TTY, whatever the spelling. Gating on
    stdout was also the wrong stream: a redirected stdin still hangs a prompt.
  - `stash impl --continue-without-plan` confirmed the flag with a second prompt
    that was not gated at all, so a CI run with no plan on disk blocked there even
    though the flag had already granted consent. The flag is now taken as consent
    in non-interactive runs and only re-confirmed interactively.

  All four now use the shared `isInteractive()` helper (stdin is a TTY and `CI`
  is not set to `1`/`true` in any case), matching `stash plan`. Non-interactive
  runs take the path they always should have: `stash init` skips the chain offer
  and prints the `plan --target` hint, the Proxy-vs-SDK question defaults to
  SDK-only, and `stash impl` proceeds without prompting.

- c8726cd: `stash init --drizzle` now installs EQL v3 instead of v2.

  The Drizzle init flow pinned `--eql-version 2`, because `stash eql install
--drizzle` (the only migration-generating install path at the time) was
  v2-only. That made `stash init --drizzle` the single flow that provisioned a v2
  database — a bare `stash eql install`, and init for every other integration,
  already defaulted to v3. It also contradicted the `stash-drizzle` skill init
  copies into the same project, which documents the v3 `@cipherstash/stack-drizzle/v3`
  surface (`types.*` domains, `EncryptionV3`) and would have the user's agent
  author v3 code against a v2 database.

  Init's Drizzle flow now routes through `stash eql migration --drizzle`, so it
  stays migration-first (the install lands in your Drizzle migration history and
  ships to every environment via `drizzle-kit migrate`) while emitting v3 SQL.
  The generated migration also carries the `cs_migrations` tracking schema, so one
  `drizzle-kit migrate` covers everything `stash encrypt …` needs. If `drizzle-kit`
  isn't installed or configured, init now reports EQL as not installed and points
  at `stash eql migration --drizzle` rather than aborting the run.

  The v2 Drizzle path remains available for existing deployments via an explicit
  `stash eql install --drizzle --eql-version 2`; that command's error message now
  points at the v3 alternative instead of only suggesting `--eql-version 2`.

- 04f5a13: `stash init` now scaffolds an EQL **v3** encryption client, matching the EQL v3
  database it installs.

  The placeholder client (`DRIZZLE_PLACEHOLDER` / `GENERIC_PLACEHOLDER`) and the
  introspection-driven client generator previously emitted EQL v2 authoring
  patterns — `Encryption({ schemas })`, `encryptedColumn(...).equality().freeTextSearch()`,
  and `encryptedType<T>('x', { equality: true })`. Since init installs a v3
  database, this handed the customer's coding agent v2 guidance against a v3
  schema (follow-up to #732 / #705).

  Scaffolds now teach the v3 surface: `EncryptionV3` from `@cipherstash/stack/v3`,
  the concrete-domain `types.*` factories (`types.TextSearch`, `types.IntegerOrd`,
  `types.Text`, `types.Json`, …), and the `@cipherstash/stack-drizzle/v3` entry
  (`extractEncryptionSchemaV3`) for Drizzle. The `encryptionClient` export shape
  and the empty-schema "no schemas yet" error path are unchanged.

- 46dde37: Fix two defects in the Drizzle migration generator used by `stash eql install --drizzle` (EQL v2):

  - **`--name` is now validated and no longer reaches a shell.** The migration name was interpolated into a shell command string, so a name containing shell metacharacters (e.g. `--name 'x; rm -rf ~'`) was executed. `--name` is now restricted to letters, numbers, dashes, and underscores, and drizzle-kit is invoked with an argv array instead of a shell string.
  - **`--out` is now actually passed to drizzle-kit.** The flag was used to search for the generated migration but never handed to `drizzle-kit generate`, so any project whose `drizzle.config.ts` writes migrations outside `drizzle/` had the file written in one place and searched for in another, failing with "migration file not found".
  - **drizzle-kit now runs project-locally.** The generator invoked drizzle-kit through the download-and-run form (`pnpm dlx` / `npx <pkg>` / `bunx`), which could fetch a different drizzle-kit major into a temp store and resolve a different `drizzle.config.ts`/schema than the project's. It now uses the project-local form (`pnpm exec` / `npx --no-install`), so it resolves the project's own drizzle-kit and config and fails loudly if drizzle-kit isn't installed rather than surprise-downloading it. The "run your migrations" hint matches. This aligns v2 with the v3 generator's behaviour.

  `stash eql migration --drizzle` (EQL v3) already had all three fixes and is unchanged.

- cf2c57c: Upgrade Stack to `@cipherstash/protect-ffi` 0.30 and EQL 3.0.2.

  Prisma Next includes a versioned EQL 3.0.2 upgrade migration, so databases
  that have already recorded the original EQL v3 baseline still install the new
  domains and functions.

  Encrypted JSON now uses the `public.eql_v3_json_search` storage domain and
  `eql_v3.query_json` query domain. Drizzle selector equality uses exact,
  GIN-indexable value-selector containment, while selector range comparisons use
  a ciphertext-free path selector plus string/number query term. Prisma Next gains
  the equivalent `eqlJsonPathEq`, `eqlJsonPathNeq`, `eqlJsonPathGt`,
  `eqlJsonPathGte`, `eqlJsonPathLt`, and `eqlJsonPathLte` operators. Selector
  Selector-based `ORDER BY` is available as
  `ops.selector(column, path).asc()/desc()` in Drizzle
  and `eqlJsonPathAsc(column, path)` / `eqlJsonPathDesc(column, path)` in Prisma
  Next; both lower to `ORDER BY eql_v3.ord_term` over the selected entry.

  If you call `encryptQuery` with an explicit `queryType`, note that
  `steVecTerm` now produces a scalar JSON ordering term. It no longer means
  structural containment; use the recommended `searchableJson` query type with
  an object or array for containment, or `steVecValueSelector` with
  `{ path, value }` for exact equality at a path.

  The FFI now rejects free-text needles shorter than the configured n-gram size
  at the core query-encryption boundary, including callers that bypass adapter
  guards.

  This EQL release changes the SteVec storage format. Existing EQL v3 encrypted
  JSON rows must be re-encrypted before they can be queried with the new domain.
  Legacy EQL v2 `searchableJson()` schemas are rejected during client setup
  because the old selector envelope can no longer be emitted; migrate them to the
  v3 `types.Json` domain.

  EQL 3.0.2 requires typed query-domain operands for encrypted free-text and JSON
  operators. PostgREST cannot express those casts, so Supabase v3 fails fast for
  `matches()`, encrypted `contains()`, and `selectorEq()`/`selectorNe()` instead
  of placing a decryptable storage envelope in a GET query string that the new
  SQL surface will reject. Use the Drizzle or Prisma Next adapter, or a carefully
  scoped direct SQL/RPC path.

- 524903c: Correct stale EQL v3 guidance in the bundled agent skills.

  `@cipherstash/migrate` and the `stash encrypt *` commands gained EQL v3 support
  (cipherstash/stack#648, now closed), but the shipped skills still told readers the
  rollout tooling was v2-only. Since these skills are copied into customer repos, the
  stale text steered users away from v3 and toward workarounds they no longer need.

  - **`stash-drizzle`, `stash-supabase`** — replaced the "v3 not supported end-to-end"
    callouts with an accurate EQL version note: the tooling auto-detects a column's
    generation from its Postgres domain type, and the two lifecycles differ at the end.
    v3 is `backfill → switch the app to the encrypted column by name → drop` with no
    cut-over rename; v2 keeps the `stash encrypt cutover` rename plus config promotion.
  - **`stash-supabase`** — removed the "Interim path until #648: the v2 encrypted twin"
    section; a v2 twin is no longer needed to get CLI-managed backfill.
  - **`stash-drizzle`, `stash-supabase`** — the drop step now documents that
    `stash encrypt drop` targets the _original_ column under v3 (there is no
    `<col>_plaintext`, since nothing was renamed) and `<col>_plaintext` under v2.
  - **`stash-cli`** — corrected the documented `EQLInstaller` default: `eqlVersion`
    defaults to `3`, not `2`, matching the `--eql-version` CLI default. Also reworded
    the v2 cut-over known-gap note, which cited cipherstash/stack#585 as open tracking
    when it was resolved by making v3 the default.

- 2e6f032: Update the bundled `stash-prisma-next` skill for the EQL v3-only
  `@cipherstash/prisma-next`: drop the stale references to the removed EQL v2
  surface (`cipherstashFromStackV2`, the `cipherstash*` operators, the "legacy v2"
  subpath note) so the guidance copied into customer repos matches the package.
- 508f1d5: **Breaking (`@cipherstash/stack/wasm-inline`):** every fallible method now returns a `Result` — `{ data } | { failure }` — instead of throwing. And `bulkEncrypt` / `bulkDecrypt` are added, so a list of encrypted rows costs **one** ZeroKMS round trip instead of one per row.

  ### Result alignment

  `encrypt`, `decrypt`, `encryptQuery` and `encryptQueryBulk` previously threw on failure, and returned bare values on success. They now return `{ data } | { failure }`, with `failure.type` drawn from `EncryptionErrorTypes` (`EncryptionError` for encrypt-side operations, `DecryptionError` for decrypt-side) and `failure.code` carrying the FFI error code where there is one.

  ```typescript
  // before
  const encrypted = await client.encrypt(plaintext, {
    table: users,
    column: users.email,
  });

  // after
  const result = await client.encrypt(plaintext, {
    table: users,
    column: users.email,
  });
  if (result.failure) throw new Error(result.failure.message);
  const encrypted = result.data;
  ```

  This is the contract the native entry has always honoured, and the one `AGENTS.md` states outright: _"Operations return `{ data }` or `{ failure }`. Preserve this shape and error `type` values in `EncryptionErrorTypes`."_ The WASM entry never followed it. That was drift rather than a design decision — nothing about WASM prevents it (`@byteslice/result` is already bundled into `dist/wasm-inline.js`), and it meant edge code had to be written in a different shape from every other surface, with failures that were easy to miss.

  Fixed now because it is a breaking change and 1.0.0 has not shipped: `@cipherstash/stack@latest` is still `0.19.0`, so this surface has only ever been published under the `rc` tag. After GA it would have had to wait for a major.

  `isEncrypted` is unchanged — a pure predicate with nothing to fail at, exactly as on the native entry.

  ### Bulk operations

  ```typescript
  // Write: several columns across many rows, one round trip
  const encrypted = await client.bulkEncrypt([
    { plaintext: "alice@example.com", table: users, column: users.email },
    { plaintext: "hello", table: users, column: users.bio },
  ]);

  // Read: a whole page in one call
  const emails = await client.bulkDecrypt(rows.map((r) => r.email));
  ```

  The WASM entry previously exposed no bulk operations at all, so rendering an N-row list on Deno, Cloudflare Workers, or Supabase Edge Functions meant N sequential ZeroKMS calls. Combined with the WASM cold start, that made list endpoints impractical on the edge.

  Both are index-aligned with their input, and `null` / `undefined` entries yield `null` at the same index without reaching ZeroKMS (an all-null batch makes no call at all). Because each entry names its own table and column, a single `bulkEncrypt` can cover several columns across many rows — which is what makes the saving real, since a single-column batch would still cost one round trip per column.

  `bulkDecrypt` builds on the fallible FFI primitive, so when items fail the `failure.message` names **every** failing index with its reason, rather than surfacing the first and discarding the rest.

  The model helpers (`encryptModel` / `decryptModel` and their bulk forms) remain Node-only: the WASM entry has no single-model operation to build them on, so those need their own port.

  - @cipherstash/migrate@1.0.0-rc.1

## 1.0.0-rc.3

### Minor Changes

- 0811330: Add `stash eql migration` — generate an EQL **v3** install migration for your ORM
  instead of running the SQL directly against the database (`stash eql install`).
  Migration-first is the preferred path: the install lands in your migration history
  and ships to every environment through the ORM's own migrate step.

  ```bash
  stash eql migration --drizzle              # Drizzle custom migration
  stash eql migration --drizzle --supabase   # also grants eql_v3 to anon/authenticated/service_role
  ```

  The migration carries the CLI's bundled v3 install SQL (one source of truth) plus
  the `cs_migrations` tracking schema, so a single `drizzle-kit migrate` covers
  everything `stash encrypt …` needs. `--supabase` appends the `eql_v3` +
  `eql_v3_internal` role grants for PostgREST/RLS access.

  `--prisma` is registered but not available yet — the Prisma Next migration
  emitter is a follow-up (tracked in cipherstash/stack#690) that will let
  prisma-next drop its baked install baseline. It fails with a pointer for now.

- d20e48a: `stash init` is honest non-interactively — it no longer reports success for a
  setup that didn't fully complete.

  - **Fails on version skew.** A non-interactive run can't reconcile an
    already-installed `@cipherstash/*` package that's _older_ than this CLI
    expects (it won't mutate an install without consent), so instead of warning
    and proceeding — scaffolding against mismatched packages and then claiming
    success — it now refuses with a non-zero exit and the exact align command.
    Interactive runs still offer to align. A _newer_ install stays a warn (the
    install is likely fine; update the CLI instead).
  - **No false "Setup complete".** If the EQL extension isn't installed at the
    end — and the integration isn't one that installs it out-of-band — the
    summary reads "Setup incomplete" and init exits non-zero, pointing at
    `stash eql install`. Integrations that install EQL via a migration are
    reported honestly rather than as failures: Prisma Next (installs it via
    `migration apply`) and the Drizzle flow, which _generates_ an EQL migration
    and now says "EQL migration generated — apply it with `drizzle-kit migrate`"
    instead of claiming the extension is already installed.
  - **Honest checkmarks.** The summary no longer claims "Database connection
    verified" (init resolves a URL but doesn't open a connection) — it now says
    "Database URL resolved" — and only shows "Encryption client scaffolded" when
    a client was actually written (skipped for Prisma Next).
  - **No false "skills loaded".** The agent handoff prompt only points at the
    skills directory when skills were actually copied (a stripped build installs
    none), instead of telling the agent to read files that aren't there.

- 3a86939: EQL v3 support for the encryption rollout lifecycle (#648). The `stash
encrypt *` commands (and `@cipherstash/migrate` underneath) now resolve a
  column's EQL version and its encrypted counterpart from the **Postgres domain
  types** — the EQL v3 types are self-describing, so the `<col>_encrypted`
  naming is a convention only, never enforced or relied upon — and follow the
  right lifecycle, no new flags:

  - **`encrypt backfill`** works on v3 columns unchanged (the engine was always
    version-agnostic; pass an `EncryptionV3` client and real v3 envelopes land
    in the concrete `eql_v3_*` domain column — verified live against a real
    database, including the domain CHECK and a decrypt round-trip). The
    manifest records the detected version, the encrypted column's name, and the
    v3 target phase, and the command prints v3-appropriate next steps.
  - **`encrypt cutover`** on a backfilled v3 column reports "not applicable"
    (exit 0) with guidance: v3 has no rename cut-over — the application
    switches to the encrypted column by name. Before backfill completes it
    exits 1 and says to finish the backfill instead of instructing the switch.
    On a database with no `eql_v2_configuration` table (a v3-only install) the
    v2 path now explains that instead of surfacing a raw Postgres error.
  - **`encrypt drop`** is version-aware: v3 runs from the `backfilled` phase,
    **verifies live coverage** (refuses to generate the migration while any row
    still has the plaintext set and the encrypted column NULL — the
    `countUnencrypted` check), and drops the ORIGINAL plaintext column (there
    is no `<col>_plaintext` under v3); v2 behaviour is unchanged. The generated
    v3 migration **re-verifies coverage at apply time** — it locks the table,
    re-counts, and aborts without dropping if plaintext-only rows appeared
    after generation. And because dropping is the one irreversible step, it
    requires a positively asserted plaintext↔ciphertext pairing (the
    manifest's recorded `encryptedColumn` or the naming convention): a match
    found only by being the table's sole EQL column is refused with
    instructions, and an ambiguous table (several EQL columns, none
    identifiable) fails closed listing the candidates — as does `cutover`.
  - **`encrypt status`** classifies each column from the observed domain type
    (manifest as fallback), shows `v3` in the EQL column, and no longer raises
    the v2-only `not-registered` / `plaintext-col-missing` drift flags for v3
    columns. `stash status`'s quest ladder and the `stash init` agent handoff
    prompt teach the version-appropriate next step (no more "run cutover" on
    v3 columns).
  - New `@cipherstash/migrate` exports: `classifyEqlDomain`,
    `resolveEncryptedColumn`, `pickEncryptedColumn`, `listEncryptedColumns`
    (domain-type resolution — case-exact for quoted/mixed-case table names),
    `countEncrypted` / `countUnencrypted` (coverage counts), and manifest
    `eqlVersion` + `encryptedColumn` fields. `EqlVersion` is numeric (`2 | 3`),
    matching the manifest and the installer. Resolved columns carry `via:
'hint' | 'convention' | 'sole'` so callers can tell a positively asserted
    pairing from a by-elimination guess.
  - Fixed: `encrypt cutover`/`encrypt drop` precondition failures now actually
    exit 1 — the early-return guards previously skipped the exit-code path
    entirely, so failed preconditions exited 0. (This also applies to v2
    preconditions: scripted pipelines that relied on the erroneous exit 0 will
    now see the documented exit 1.)

  The `stash-cli` and `stash-encryption` skills and the `@cipherstash/migrate`
  README document the two lifecycles (v2: backfill → cutover → drop;
  v3: backfill → switch-by-name → drop).

- b0634df: `stash plan --complete-rollout` is now automatable and has an honest exit code.
  It skips the production-deploy gate, so it needs explicit consent — previously
  that was an interactive prompt with no bypass, so a non-interactive run
  auto-cancelled (default-no) and exited **0** without drafting a plan, leaving
  automation to assume a plan existed.

  - New `--yes` flag confirms the gate-skip without a prompt (for CI/agents).
  - Without `--yes`, a non-interactive `--complete-rollout` run now **refuses
    with a non-zero exit** and points at `--yes`, instead of silently succeeding.
  - Interactive behaviour is unchanged (default-no confirm).

- f188c7a: `stash env` now works: it mints deployment credentials from your device-code
  session and prints them as env vars — no dashboard copy-paste. The command
  creates a fresh ZeroKMS client and a member-role CipherStash access key (named
  via `--name`; the role is pinned in the request and verified on the response —
  the CLI deliberately cannot mint admin keys), then emits `CS_WORKSPACE_CRN`,
  `CS_CLIENT_ID`, `CS_CLIENT_KEY`, and `CS_CLIENT_ACCESS_KEY`.

  Output goes to stdout by default — and stdout is pipe-clean (progress UI is on
  stderr), so `stash env --name x > prod.env` and pipes into secret stores are
  safe. `--write [path]` writes a file instead (default `.env.production.local`,
  enforced mode 0600 even when overwriting), confirming before overwriting and
  refusing non-interactively — always _before_ anything is minted, so a refusal
  never discards the shown-exactly-once access key. `--json` emits NDJSON; with
  `--write` the confirmation event is deliberately secret-free. API responses
  are schema-validated so a service change can never print `undefined` into a
  credentials file. Creating access keys requires the admin role in the
  workspace.

  This is also the supported credential path for WASM/edge local development
  (Supabase Edge Functions, Cloudflare Workers, Deno), where the runtime cannot
  read the `~/.cipherstash` device profile: mint a key and feed it via
  `supabase functions serve --env-file` or the platform's secret store.

  The `STASH_EXPERIMENTAL_ENV_CMD` gate is removed.

- 8872d1e: `stash init`, `stash plan`, and `stash impl` no longer crash on a Prisma Next
  project. `SKILL_MAP` was missing a `prisma-next` entry, so the skills-install
  and AGENTS.md-builder steps hit `SKILL_MAP[integration]` → `undefined` and threw
  "not iterable" for any repo the CLI detected as Prisma Next. The entry is added
  and both consumers now resolve skills through a `skillsFor()` helper that
  degrades an unmapped integration to the base skill set instead of crashing
  (`tsup` ships without type-checking, so the `Record<Integration>` type alone
  didn't protect the build).

  Ships a new **`stash-prisma-next`** agent skill documenting the EQL v3 Prisma
  Next surface — the domain-named encrypted column types (`EncryptedTextSearch`,
  `EncryptedDoubleOrd`, …), `cipherstashFromStackV3` wiring, the runtime value
  envelopes, the `eql*` query operators, and EQL installation via
  `prisma-next migration apply`. It is installed for Prisma Next projects and
  inlined into `AGENTS.md` for editor agents.

  `stash eql install` now refuses to run in a Prisma Next project (pointing you
  at `prisma-next migration apply`, which owns EQL installation) unless you pass
  `--force` — closing the manual-invocation hole that `stash init --prisma-next`
  already avoided.

### Patch Changes

- 8b2551a: Fix "Failed to load native binding" on project-local installs of the CLI/SDK
  (npm). `@cipherstash/auth` was pinned at 0.41.0 while the six
  `@cipherstash/auth-*` platform bindings declared in stack/stash/wizard's
  optionalDependencies were pinned at 0.42.0. Because auth pins its bindings as
  exact-version optional peer dependencies, the skew made npm nest per-consumer
  binding copies that the hoisted `auth` package could not resolve — any command
  or import touching auth then died at startup. All seven packages now move in
  lockstep at 0.42.0, Dependabot is barred from bumping any of them
  independently, and a supply-chain CI test fails on any future skew.
- b8cb599: Fix invalid DDL from `drizzle-kit generate`/`push` for EQL v3 encrypted columns.
  A v3 column declared its SQL type as the schema-qualified domain
  (`public.eql_v3_text_search`), but drizzle-kit wraps a custom type's whole name
  in a single pair of double quotes — emitting `"public.eql_v3_text_search"`, which
  Postgres reads as one dotted identifier and rejects with `type
"public.eql_v3_text_search" does not exist`. Generated migrations had to be
  hand-repaired.

  The v3 column now emits the **unqualified** domain (`eql_v3_text_search`), which
  drizzle-kit renders as the valid `"eql_v3_text_search"` and which resolves via the
  search path (the domains live in `public`). This matches how the v2
  `encryptedType` surface already declares its type, and how drizzle-kit reads the
  type back during a `push` introspection diff, so the two sides no longer disagree.
  Builder recovery still yields the canonical `public.eql_v3_*` identity, so
  operators and schema extraction are unchanged.

  The bundled `stash-drizzle` skill is updated to describe the unqualified generated
  type and the search-path requirement (hence the `stash` bump — the skill ships in
  its tarball).

- 175eeb7: The EQL **v3** install SQL is now read from the `@cipherstash/eql` package at
  runtime instead of a copy vendored into this repo. `@cipherstash/eql` becomes a
  runtime dependency of `stash`, and a version bump now flows straight through — no
  re-vendor step, no drift between the pin and the shipped bundle.

  This removes ~44k lines of generated plpgsql from the repository (which had made
  GitHub classify the whole repo as plpgsql — CIP-3518) along with the
  `gen:eql-v3-sql` vendor script and its CI drift-check.

  No behaviour change: v3 installs the same one-artifact bundle (which self-adapts to
  non-superuser environments like Supabase), and the v2 path is unchanged.

- 4923c0a: **Breaking (v3 authoring surface):** the EQL v3 PSL column constructors drop
  the `Encrypted` prefix to line up with the stack / Drizzle `types.*` catalog —
  the `cipherstash.` namespace already disambiguates. So
  `cipherstash.EncryptedTextSearch()` → `cipherstash.TextSearch()`,
  `cipherstash.EncryptedDoubleOrd()` → `cipherstash.DoubleOrd()`,
  `cipherstash.EncryptedBoolean()` → `cipherstash.Boolean()`, etc.

  The v3 one-call setup function is renamed `cipherstashFromStackV3` →
  `cipherstashFromStack` (v3 is the default), and the existing v2 setup function
  becomes `cipherstashFromStackV2`.

  The camelCase TS-authoring factory exports move in lockstep:
  `encryptedTextSearch` → `textSearch`, `encryptedDoubleOrd` → `doubleOrd`, etc.
  (a property test enforces the PSL and TS names agree modulo first-letter case).

  Unchanged: the runtime value envelopes (`EncryptedString`, `EncryptedNumber`,
  `EncryptedBoolean`, …), the `cipherstash.*V2` legacy column constructors, the
  generated `contract.json` / codec ids, and the `eql*` query operators.

  The `stash-prisma-next` skill is updated to the new names (skills ship in the
  `stash` tarball).

- Updated dependencies [3a86939]
  - @cipherstash/migrate@1.0.0-rc.1

## 1.0.0-rc.2

### Patch Changes

- 6fcb967: `stash init` now pins the packages it installs (`@cipherstash/stack`, the
  integration adapter, and `stash` itself) to the exact versions this CLI
  release was built alongside, instead of installing bare package names that
  resolve through npm dist-tags (#661). During a pre-release window dist-tags
  lag or point at placeholders, so an unpinned `init` could silently deliver a
  different release than the CLI driving the setup — stale `@cipherstash/stack`,
  or an empty placeholder adapter — breaking `/v3` imports out of the box. The
  versions are embedded at build time from the release train itself
  (`src/release-train.ts`, the single source both the build and the runtime
  check against), so they can never disagree with what was published together.

  Init also now surfaces **version skew** on already-installed packages —
  unconditionally, before any prompt or early exit, including when the install
  is declined or partially fails. Interactively it offers to align the skewed
  packages in the same confirm as the missing installs (keeping `stash` a dev
  dependency); non-interactively it never mutates an existing install — it
  warns and prints the exact align commands. A package whose manifest exists
  but can't be read (an aborted install) is reported as skew, not treated as
  matching. All other install guidance is pinned the same way: the
  missing-package hints, `.cipherstash/context.json`'s `installCommand`, the
  `install-eql` manual note, the native-module recovery hint (previously
  `stash@latest`), and the `stash wizard` one-shot spawn (previously an
  unpinned `npx @cipherstash/wizard`). The `stash-cli` skill documents the
  behaviour, and the other bundled skills' manual install commands now carry a
  verify-what-resolved note.

- d803914: Two guards for the release-train version embed (#661 follow-up):

  **Direction-aware version skew.** `stash init` now distinguishes an installed
  package that is _behind_ this CLI release (offered alignment / the pinned
  install command, as before) from one that is _newer_ than the release expects.
  A newer install no longer produces a downgrade command — init prints the exact
  `stash` update command instead (release-train lockstep guarantees that version
  exists), and when missing packages are about to be installed alongside newer
  ones it says the pairing may not match and to update `stash` first. Unreadable
  or malformed manifest versions always count as behind (a broken install should
  be offered the reinstall fix, never "looks newer, leave it").

  **Version lockstep.** The release-train packages (`stash`,
  `@cipherstash/stack`, `@cipherstash/stack-drizzle`,
  `@cipherstash/stack-supabase`, `@cipherstash/prisma-next`,
  `@cipherstash/wizard`) are now a Changesets `fixed` group: a release of any of
  them republishes all of them at the same version, so the CLI's embedded
  version map can never go stale against the packages it pins (previously a
  runtime-package-only release would have left the published CLI embedding —
  and recommending — outdated versions). A test now asserts the fixed group
  stays exactly equal to the release train.

- 413ca39: The legacy `@cipherstash/drizzle` package (the `@cipherstash/protect`-based
  Drizzle integration) is removed from the repository and the release train —
  `@cipherstash/protect` is sunsetting at Stack 1.0, and the package's successor
  is `@cipherstash/stack-drizzle`. Already-published versions remain installable
  from npm (deprecated, pointing here); the git history preserves the source for
  any emergency maintenance. The `stash-drizzle` skill and the
  `@cipherstash/stack-drizzle` README now state the deprecation explicitly so
  nobody (human or agent) installs the legacy package by mistake.
  - @cipherstash/migrate@1.0.0-rc.0

## 1.0.0-rc.1

### Minor Changes

- 134fd43: Add anonymous, opt-out usage analytics to the `stash` CLI, plus a
  `stash telemetry [status|enable|disable]` command to manage it.

  Only coarse events are collected — command name, CLI version, OS/arch, Node
  version, success/failure, duration, and a coarse caller class (e.g.
  `claude-code`, `cursor`, `interactive`) derived from environment markers so we
  can gauge agent- vs human-driven usage. Events carry a random install
  identifier (a locally generated UUID, not derived from any machine or user
  attribute) used only to de-duplicate events in aggregate. Plaintext, schema,
  table/column names,
  connection strings, argument values, and any session/trace identifier are never
  collected — enforced by a property-key allowlist at the emitter boundary plus
  closed-vocabulary coercion of every argv- or error-derived value (unrecognised
  commands, subcommands, and error class names all collapse to `<other>`). A
  one-time notice is shown on first run, and nothing is sent on that run.

  Telemetry is off by default in CI and can be disabled with `DO_NOT_TRACK=1`
  (the cross-tool standard), `STASH_TELEMETRY_DISABLED=1`, or
  `stash telemetry disable` (persisted to `~/.cipherstash/telemetry.json`).

  Events are sent via a first-party proxy and never block or slow the CLI. The
  feature ships dormant — no events are sent until a PostHog project key is
  embedded at release. Updates the `stash-cli` skill to document the command and
  opt-out controls.

### Patch Changes

- 59b994e: Add EQL v3 JSON **selector-with-constraint** querying to the Drizzle integration
  (#623). `ops.selector(col, '$.path')` returns comparison methods bound to a
  JSONPath into a `types.Json` column — `eq`/`ne`/`gt`/`gte`/`lt`/`lte` — emitting
  `col->'<selector>' <op> <value>` over the encrypted document. Its unique power
  over `contains` is **ordering at a path** (`col->'$.age' > 21`), which
  containment cannot express.

  Complements the existing `contains` (JSONB `@>`) containment operator. Core
  `@cipherstash/stack` needs no change — the selector hash and comparison entry are
  produced by `encryptQuery`/`encrypt` on the existing `types.Json` surface. v1
  supports dot-notation object paths; array-index/wildcard paths are rejected with
  a clear error. The Supabase adapter is tracked separately.

  The right-hand comparison operand is currently a storage-encrypted needle (its
  ste_vec entry carries the ordering term), pending a ciphertext-free ordering
  query needle from protect-ffi (cipherstash/protectjs-ffi#137); until then the
  value's ciphertext appears in the WHERE clause.

  The bundled `stash-encryption` and `stash-drizzle` skills document the new
  `ops.selector(...)` surface (they previously said JSONPath selector queries were
  not yet implemented).

- e297f64: Docs: EQL v3 is now the sole documented approach. The `stash-encryption`,
  `stash-drizzle`, and `stash-supabase` skills and the `@cipherstash/stack`
  README teach only the v3 typed surface (`EncryptionV3`, `types.*` concrete
  domains, `@cipherstash/stack-drizzle/v3`, `encryptedSupabaseV3`); EQL v2
  shrinks to one short Legacy section per document. Two explicit exceptions are
  called out: DynamoDB still requires the v2 schema surface (#657), and the
  encrypt rollout tooling (`stash encrypt backfill`/`cutover`,
  `@cipherstash/migrate`) currently targets v2 columns (#648) — its guidance is
  kept under a version callout. Also corrects the legacy `@cipherstash/drizzle`
  README's pointer to the removed `@cipherstash/stack/drizzle` subpath (now the
  separate `@cipherstash/stack-drizzle` package).
- 40ab142: Docs: stop teaching the deprecated `LockContext.identify()` as the primary
  identity-aware-encryption path (#591). The `stash-encryption` and `stash-supabase`
  skills and the `@cipherstash/stack` README now lead with the current pattern —
  authenticate the client with `OidcFederationStrategy`, then bind the claim per
  operation with `.withLockContext({ identityClaim })` — and demote
  `LockContext.identify()` to a clearly-marked deprecated note (per-operation CTS
  tokens were removed in protect-ffi 0.25). Skills ship in the `stash` tarball, so
  this keeps the bundled guidance correct for the 1.0 surface.
- 5fe9a2f: Encrypted-JSON querying on the v3 Supabase surface (#650). A `types.Json`
  column now supports exact encrypted containment — `contains(col, subDocument)`
  (ste_vec `@>` via PostgREST `cs`, with the sub-document storage-encrypted
  against the column) — and JSONPath selector predicates: `selectorEq(col, path,
value)` and `selectorNe(col, path, value)` (dot-notation paths; `ne` includes
  rows where the path is absent, mirroring the Drizzle selector's semantics).
  Raw `.filter(col, 'cs', subDocument)` and `not(col, 'contains', …)` route
  through the same encrypted path. Selector ordering is not expressible over
  PostgREST yet (needs an EQL-bundle overload — see
  cipherstash/encrypt-query-language#407); the Drizzle integration's
  `ops.selector()` covers ordering today.

  In core, `QueryTypesForColumn` gains the `searchableJson` arm (a `types.Json`
  column no longer resolves to `never`, so typed adapter key sets can include
  it), and the JSONPath selector-path helpers the Drizzle adapter introduced in
  #651 moved to `@cipherstash/stack/adapter-kit` so both adapters share one
  validation surface (`@cipherstash/stack-drizzle` re-exports them unchanged).

  The bundled `stash-supabase` and `stash-encryption` skills are updated to
  document the new querying surface (including the array-leaf and SQL-NULL
  semantics, and the operand-exposure caveat) — skills ship inside the `stash`
  tarball, hence the patch.

  - @cipherstash/migrate@1.0.0-rc.0

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
