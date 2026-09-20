# @cipherstash/wizard

## 1.2.0

### Patch Changes

- e36f1a0: Stop telling customers the Supabase wrapper cannot run in a Worker.

  `@cipherstash/stack-supabase` has shipped two entry points since #912. The
  package root introspects your database and runs on Node; the `wasm-inline`
  entry carries the WASM engine, takes declared `schemas` instead of
  introspecting, and runs on Deno, Supabase Edge Functions and Cloudflare
  Workers. Introspection was the only thing that needed a Postgres socket, and
  that entry does not do it.

  Two shipping documents were never updated and still described the state before
  that change:

  - `packages/stack-supabase/README.md` said "the factory cannot run in an edge
    Worker or the browser" and did not mention the `wasm-inline` entry anywhere
    in the file. This is the npm package page.
  - `skills/stash-supabase/SKILL.md` said the same thing in its setup section.
    The skill ships inside the `stash` tarball, and `stash init` copies it into
    the customer's own repository, where their coding agent reads it as
    instruction. The one correct mention of the edge entry was in a callout near
    the top that the setup steps never pointed at, so a reader following the
    setup never learned the second entry existed.

  The population this misled hardest is the one that needs the edge entry most:
  server code on Lovable, v0, Bolt and Replit runs on an edge runtime, which is
  exactly the case `wasm-inline` was built for and exactly the case these
  documents called impossible.

  Both files now describe both entries. The README gains an "Edge runtimes"
  section with the call shape; the skill gains a fifth setup step with the same,
  and the introspection paragraph now scopes its restriction to the native entry
  and points there. Both name the four ways the edge entry differs: `schemas` is
  required, `config` is required, `databaseUrl` is refused, and
  `.withLockContext()` / `.audit()` throw rather than silently dropping an
  identity claim (#797).

  The **browser** half of the old sentence was correct and is kept, with the
  reason now given: the WASM client requires a workspace `clientKey` on every
  authentication path, so a browser build would ship the key with it (#804).

  Four claims that were wrong in the same neighbourhood are corrected while we
  are here, three of them pre-dating this change:

  - **`skills/stash-managed-platforms/SKILL.md` shipped a snippet that does not
    compile.** It authored the `schemas` object from `@cipherstash/stack/wasm-inline`
    and handed it to `encryptedSupabase` from `@cipherstash/stack-supabase/wasm-inline`.
    The adapter types `schemas` from `@cipherstash/stack/eql/v3`, and the two
    entries ship independent declarations of the column classes whose private
    `columnName` field TypeScript compares nominally — so `tsc` rejects it while
    the code runs perfectly, which is why nobody noticed. The schema import now
    comes from `eql/v3`, and a new guard
    (`scripts/__tests__/skills-supabase-edge-schema-entry.test.mjs`) fails if any
    shipped document pairs the two again.
  - **`skills/stash-edge/SKILL.md` is what produced that snippet.** Its "Schema
    Modules Do Not Cross Entries" section told edge projects to author schemas
    from `@cipherstash/stack/wasm-inline` with no carve-out. The rule is really
    "author against the entry whose _client type_ consumes the schema": a raw
    `Encryption` client from `wasm-inline` wants `wasm-inline` tables, but the
    Supabase adapter wants `eql/v3` tables on both of its entries, WASM engine or
    not. The section now says so, and the "The Supabase adapter has its own edge
    entry" note points at it.
  - **`skills/stash-supabase/SKILL.md` described the wrong failure mode for a
    missing declaration.** Omitting `schemas` on the edge entry cannot produce a
    no-column client — it is non-optional on the type and throws at construction —
    and an undeclared _table_ throws rather than passing through unencrypted. The
    hazard is an undeclared **column** on a declared table, which is treated as
    plaintext; the bullet now says that, along with the one thing that limits it
    (a plaintext write to an `eql_v3_*` column fails the domain CHECK, though a
    NULL still passes) and the fact that the native entry's warning about
    unverified declarations is gated on the introspector and so never fires
    there. Reads get no equivalent backstop, and the bullet now says so: the
    `select('*')` refusal looks like one, but a query awaited with no
    `.select()` at all takes the raw-`*` branch in `query-builder.ts` and
    returns every column undecrypted.
  - **"Undeclared tables behave exactly as with no `schemas` at all" was false on
    the native entry too.** Introspection is gated on a resolved database URL,
    not on the absence of `schemas`, and an ambient `DATABASE_URL` is
    deliberately ignored once tables are declared. The statement holds only when
    `databaseUrl` is passed _alongside_ `schemas`, which is what it now says.

  `config` is corrected everywhere that called all four `CS_*` values mandatory:
  the README, `skills/stash-supabase/SKILL.md`, and — in `skills/stash-edge/SKILL.md`
  — its frontmatter description, its Credentials section, its troubleshooting
  advice, and the native-vs-WASM comparison table. That skill already contradicted
  itself, since its own `config.authStrategy` example passes two values, not four.
  The same sentence in the `EncryptedSupabaseWasmOptions` doc comment
  (`packages/stack-supabase/src/wasm-inline.ts`) is fixed too, comment-only. Only
  `clientId` and `clientKey` are always required. Beyond them the config is a union — the
  access-key path adds `workspaceCrn` + `accessKey`, and the strategy path takes
  a pre-built `config.authStrategy` and makes `workspaceCrn` optional, because a
  built strategy already carries the CRN. `OidcFederationStrategy` is re-exported
  from `@cipherstash/stack/wasm-inline`, so authenticating as the end user works
  on the edge; what does not work is binding data to that user, which stays
  called out in its own `.withLockContext()` bullet.

  Tests now anchor the corrected claims against the code rather than against
  prose. `packages/stack-supabase/__tests__/supabase-wasm-config.test-d.ts` asserts
  at the type level that the edge `config` accepts both the access-key arm and a
  strategy-only arm without `workspaceCrn`, and rejects `clientId` + `clientKey`
  alone. `supabase-declared-mode.test.ts` gains a case pinning the real hazard: an
  undeclared column on a declared table reaches PostgREST as plaintext on insert,
  update and filter, and is absent from the decrypt call.

  Review found four more, one of them a change to a published type:

  - **`databaseUrl` was only refused for callers who wrote the options inline.**
    `EncryptedSupabaseWasmOptions` left the field out, and omission is policed by
    excess-property checking, which fires on fresh object literals alone. An
    options object assembled as a `const` and passed by variable — which is what
    a Node-to-edge port actually holds — type-checked clean and reached the
    construction-time throw instead, from documents saying the type checker
    enforced it. The field is now declared `databaseUrl?: never`, mirroring
    `WasmClientConfig.eqlVersion?: never` in `@cipherstash/stack`, which exists
    for the identical reason one package along. The runtime throw stays as the
    backstop for plain JS. New type tests cover the inline and by-variable
    shapes on both call forms, plus a positive control that the same options
    object still compiles once `databaseUrl` is dropped.
  - **The `select('*')` correction had landed in only one of its two shipped
    copies.** `skills/stash-supabase/SKILL.md` carried it;
    `skills/stash-managed-platforms/SKILL.md`, edited in the same change, still
    framed declared mode as giving things up "loudly rather than silently" over a
    bullet naming the refusal — precisely the inference the correction exists to
    kill. That skill is read as instruction by an agent on Lovable, v0, Bolt or
    Replit, and the failure it mispromised is silent: raw EQL payloads returned
    as `data`, no error. The wording is carried across, and a new guard
    (`scripts/__tests__/skills-select-star-not-a-read-backstop.test.mjs`) fails
    if any shipped document states the refusal without the caveat in the same
    section. Two copies of one fact drift the moment one of them is edited, and
    no reviewer diff shows the copy nobody touched.
  - **"Everything after construction is the same wrapper" was false in the first
    way a reader hits it.** Both `packages/stack-supabase/README.md` and
    `skills/stash-supabase/SKILL.md` said `from()`, the filters and the response
    shape are identical across the two entries — the README saying so twenty-five
    lines under a paragraph telling the same reader `select('*')` just works. The
    edge entry is always in declared mode, where `select('*')` is refused and
    `from()` on an undeclared table throws. Both sentences now name the two
    exceptions, so the quick-start snippet the section tells you to port no
    longer arrives with a promise it breaks.
  - **The ambient-`DATABASE_URL` warning cannot fire on the edge entry.**
    `skills/stash-managed-platforms/SKILL.md` said an ambient `DATABASE_URL` is
    ignored when `schemas` are passed, "with a warning that the declaration is
    unverified" — in a section whose subject is `wasm-inline`. Both the ambient
    read and the warning are gated on the introspector, which that build does not
    have, so nothing there ever tells you a declaration is incomplete. Now scoped
    to Node, with the edge case stated. The sentence immediately above it had the
    same fault and is fixed with it: the ⚠️ callout on undeclared columns offered
    "pass `databaseUrl` so introspection fills the gaps" as the remedy, inside a
    section about the entry that refuses `databaseUrl` — and it is the remedy a
    Lovable or Replit agent, which has only the edge entry, would have reached
    for. It now says introspection is unavailable there and what to do instead.

  `@cipherstash/wizard` is bumped alongside `stash` because `skills/` ships in
  both tarballs — `packages/wizard/tsup.config.ts` copies it into `dist/skills`
  and `package.json` lists that under `files`. Without the bump the published
  wizard keeps shipping the old text until some unrelated change moves its
  version.

  One more wording correction, of the kind #952 fixed in this package's `.d.ts`:
  `packages/stack-supabase/README.md` and `skills/stash-supabase/SKILL.md` both
  derived "runs on Node only" from introspection — "introspection needs a direct
  Postgres connection, **so** … this entry runs on Node only". Introspection is
  not the cause. The entry binds the native engine, so it is Node-only whether or
  not you declare `schemas`; a reader who took the stated cause at face value
  would conclude that declaring tables makes the root entry edge-capable, which is
  the exact wrong turn the `wasm-inline` entry exists to prevent. Both sentences
  now attribute the restriction to the engine and say that declaring `schemas`
  does not move it. Both files are enrolled in #952's
  `scripts/__tests__/supabase-runtime-claims.test.mjs`, which is what its own
  comment said to do once this branch stopped rewriting the same lines — the
  README and this skill are the two copies that reach a customer, and the guard
  now fails if either grows the claim back. `skills/stash-managed-platforms/SKILL.md`
  stays out, with the reason written down: its causal claims are correct, but
  rewording the unqualified "Worker" in its frontmatter `description` changes
  what the skill matches on, which is not a rider on a documentation fix.

  No runtime behaviour changes. The one non-documentation change is the
  `databaseUrl?: never` field on `EncryptedSupabaseWasmOptions`, which is
  type-level: it rejects at compile time a call that already threw at
  construction.

## 1.1.1

## 1.1.0

### Minor Changes

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

## 1.0.0

### Minor Changes

- 0b9b192: Rename `stash db install` to `stash eql install`. The command scaffolds
  `stash.config.ts` and installs the EQL extensions, so it now lives under a
  dedicated `eql` command group. `stash db install` keeps working as a
  deprecated alias that prints a warning pointing at the new name. All help
  text, hints, generated migration headers, and wizard steps now reference
  `stash eql install`.
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

- 8cbe007: Teach the wizard's post-agent Drizzle step to repair EQL **v3** migrations, not
  just legacy EQL v2.

  The wizard now scaffolds EQL v3 columns, so `drizzle-kit generate` emits
  `ALTER TABLE … ALTER COLUMN … SET DATA TYPE eql_v3_<name>` — which Postgres
  rejects (there is no cast from `text`/`numeric` to an EQL domain). The migration
  rewriter previously matched only the single `eql_v2_encrypted` type, so those v3
  statements slipped through unrepaired and failed at migrate time.

  The rewriter is ported to match the whole EQL v3 concrete-domain family
  (`eql_v3_text_search`, `eql_v3_integer_ord`, …) alongside legacy
  `eql_v2_encrypted`, across every mangled form drizzle-kit emits (including the
  `"undefined".` prefix from 0.31.0+ and schema-qualified `pgSchema()` tables). It
  now also flags near-miss `SET DATA TYPE … USING …` statements it cannot safely
  repair instead of leaving broken SQL, and each rewritten file carries a clearer
  warning that the ADD+DROP+RENAME is data-destroying and safe only on an empty
  table — a populated table must use the staged `stash encrypt` flow. This
  re-converges the rewriter with the sibling copy in the `stash` CLI.

  The post-agent step now sweeps **every** candidate migration directory
  (`drizzle/`, `migrations/`, `src/db/migrations/`) rather than stopping at the
  first one that exists. Previously an empty or already-rewritten `drizzle/`
  sitting next to a project's real `migrations/` caused those migrations to be
  skipped entirely, so they still failed at migrate time. A directory that can't
  be read is reported and the remaining candidates are still swept. Reported
  near-miss statements are also trimmed of any preceding comment block, so the
  statement quoted back to the user is the offending statement alone.

  Database introspection also recognises v3 encrypted columns: `isEqlEncrypted`
  now reports both `eql_v2_encrypted` and the `eql_v3_*` family as already
  encrypted, so the agent won't scaffold over existing encrypted data of either
  generation.

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

- 8b2551a: Fix "Failed to load native binding" on project-local installs of the CLI/SDK
  (npm). `@cipherstash/auth` was pinned at 0.41.0 while the six
  `@cipherstash/auth-*` platform bindings declared in stack/stash/wizard's
  optionalDependencies were pinned at 0.42.0. Because auth pins its bindings as
  exact-version optional peer dependencies, the skew made npm nest per-consumer
  binding copies that the hoisted `auth` package could not resolve — any command
  or import touching auth then died at startup. All seven packages now move in
  lockstep at 0.42.0, Dependabot is barred from bumping any of them
  independently, and a supply-chain CI test fails on any future skew.
- 98156ac: Fix the Codex handoff installing zero skills — and losing `AGENTS.md` and `.cipherstash/` with them — when `.codex/` is not writable.

  Codex sandboxes deny writes under `.codex/`. `installSkills` created its destination with an unguarded `mkdirSync`, sitting directly above a per-skill copy loop that _was_ guarded — so the failure threw past that fallback and past the caller, aborting the whole handoff step. Because the skills install runs first, nothing after it ran either: no `AGENTS.md`, no `.cipherstash/context.json`, no `.cipherstash/setup-prompt.md`. All five Codex runs of the rc.3 skilltester matrix landed here, and it was identified in that report as the primary driver of the Claude→Codex quality gap.

  The fix, hardened by a follow-up review of the first cut:

  - **`installSkills` never throws, and reports what happened.** It returns `{ copied, failed }` instead of a flat list, so callers can tell "unwritable destination" from "stripped build" from "partial copy" without re-deriving it — every filesystem failure degrades to a warning plus a `failed` entry.
  - **The Codex handoff inlines exactly the skills that failed.** Whatever could not be copied into `.codex/skills/` — all of them under a sandbox, or a subset after a partial failure — has its body inlined into `AGENTS.md` via the same `doctrine-plus-skills` path the editor-agent handoff uses. The launch prompt points at wherever each skill actually ended up, including both locations after a partial copy. A stripped build that ships no skills stays `doctrine-only` and says nothing.
  - **The doctrine now ships where the published CLI can find it.** The bundled AGENTS.md doctrine was copied to `dist/commands/init/doctrine`, but the compiled resolver probes ancestor directories of the chunk in `dist/bin/` — so every published build silently wrote the minimal `AGENTS.md` stub instead of the doctrine (and the inline fallback would have inlined nothing). It now lands at `dist/doctrine`, like the skills bundle. `buildAgentsMdBody` also honours `doctrine-plus-skills` even when the doctrine fragment is missing, so inlined skills are never dropped with it.
  - **The generated artifacts describe the fallback honestly.** `context.json` gains an `inlinedSkills` field, and `setup-prompt.md` distinguishes installed / inlined / failed skills instead of mislabelling an unwritable destination as a "stripped build". The Claude handoff now warns when skills exist but could not be installed, and the AGENTS.md handoff records what it inlined.
  - **The rest of the handoff is guarded too.** The `AGENTS.md` upsert (which refuses malformed sentinel pairs) and the bundled-file reads degrade to warnings instead of aborting the step before `.cipherstash/` is written.

  `@cipherstash/wizard` carries its own copy of `installSkills` with the same unguarded `mkdirSync` above the same guarded copy loop. It targets `.claude/skills` rather than `.codex/skills`, so the Codex sandbox case does not apply, but an unwritable destination crashed it identically — now guarded the same way, with a confirmed-then-failed install recorded in the wizard changelog instead of vanishing with the terminal output.

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

- 6ee68fd: The Drizzle migration rewriter now preserves the source column and adds a staged
  encrypted twin instead of emitting destructive drop/rename SQL. When the sweep
  cannot prove a source column's type or the encrypted twin already exists, the
  CLI and wizard fail closed with a non-zero exit so the migration directory must
  be reviewed before applying it.
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

- 9c673bb: Stop the agent guard from blocking `.env.example`.

  `SENSITIVE_FILE_PATTERNS` matched `/\.env($|\.)/`, which tests true against
  `.env.example`. Because the guard covers `Edit` and `Write` as well as `Read`,
  the wizard's agent was blocked from creating or editing the very file the
  CipherStash doctrine tells it to write ("New env keys go in `.env.example` with
  placeholders"). Committed env templates carry placeholder key names, not values.

  `.env.example`, `.env.sample` and `.env.template` are now readable and writable.
  Everything else is unchanged: `.env`, `.env.local`, `.env.production`, and
  value-bearing files that merely start with a template name
  (`.env.example.local`, `.env.example.bak`) stay blocked, as do `auth.json`,
  `secretkey.json` and credential files. Bash access to any env file — including
  the templates — remains blocked; `Read`/`Write` is the sanctioned path.

- d8e0c1d: Align the wizard's analytics with the `stash` CLI's telemetry privacy contract.
  The wizard now honors `DO_NOT_TRACK`, `STASH_TELEMETRY_DISABLED`, and CI
  auto-detection; uses a random per-session identifier instead of one derived
  from username@hostname; disables IP→geo resolution; and reports error events as
  fixed labels / error class names instead of raw messages (which could embed
  schema names or connection details). Analytics remain dormant unless a PostHog
  key is configured at build time.
- 46f4b34: Drop the last `stash db push` references from the wizard's output, and name the
  migration files a failed sweep rewrote before it stopped.

  - The "Post-agent steps complete" changelog line claimed `db push` had run.
    `stash db push` was retired with the CipherStash Proxy lifecycle and
    `runPostAgentSteps` never invoked it; the line now reports what the step
    actually does (package install, `eql install`, migrations). The `--plan` help
    text no longer promises "no db pushes" either, and the package README — which
    ships in the tarball — no longer lists `db push` as a prerequisite or a
    post-agent step.
  - When a candidate directory's ALTER COLUMN sweep threw, the wizard reported the
    failure but skipped the per-directory report, so files it had already rewritten
    on disk — and statements it had flagged — went unnamed. It now lists them
    ("Rewrote N migration file(s) in drizzle/ before the sweep stopped", followed by
    the flagged statements and their reasons), matching
    `stash eql migration --drizzle`.
  - The cross-directory summary ("Rewrote N migration file(s) in the drizzle output
    to add staged encrypted columns while preserving the source columns") is now
    suppressed when any directory failed to sweep. It is built from a total that
    counts clean and partially-swept directories alike, so on that path it restated
    the reassuring framing the per-directory report deliberately drops. A _flagged_
    statement still prints the summary — there the sweep finished and the count is
    accurate.

  Both are reporting-only: the rewritten SQL is additive and the wizard still
  throws before the migrate prompt, so this changes what the user is told, not what
  runs.

- daa25b8: `@cipherstash/wizard` now versions in lockstep with the Stack release train
  (`stash`, `@cipherstash/stack`, and the adapters) via a Changesets `fixed`
  group — the `stash` CLI executes the wizard by exact version, so the two must
  always release together. This moves the package from its previous `0.5.x`
  line onto the shared train version; no API changes.

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

## 1.0.0-rc.3

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

## 1.0.0-rc.2

### Patch Changes

- daa25b8: `@cipherstash/wizard` now versions in lockstep with the Stack release train
  (`stash`, `@cipherstash/stack`, and the adapters) via a Changesets `fixed`
  group — the `stash` CLI executes the wizard by exact version, so the two must
  always release together. This moves the package from its previous `0.5.x`
  line onto the shared train version; no API changes.

## 0.5.0-rc.1

### Patch Changes

- d8e0c1d: Align the wizard's analytics with the `stash` CLI's telemetry privacy contract.
  The wizard now honors `DO_NOT_TRACK`, `STASH_TELEMETRY_DISABLED`, and CI
  auto-detection; uses a random per-session identifier instead of one derived
  from username@hostname; disables IP→geo resolution; and reports error events as
  fixed labels / error class names instead of raw messages (which could embed
  schema names or connection details). Analytics remain dormant unless a PostHog
  key is configured at build time.

## 0.5.0-rc.0

### Minor Changes

- 0b9b192: Rename `stash db install` to `stash eql install`. The command scaffolds
  `stash.config.ts` and installs the EQL extensions, so it now lives under a
  dedicated `eql` command group. `stash db install` keeps working as a
  deprecated alias that prints a warning pointing at the new name. All help
  text, hints, generated migration headers, and wizard steps now reference
  `stash eql install`.

### Patch Changes

- 9c673bb: Stop the agent guard from blocking `.env.example`.

  `SENSITIVE_FILE_PATTERNS` matched `/\.env($|\.)/`, which tests true against
  `.env.example`. Because the guard covers `Edit` and `Write` as well as `Read`,
  the wizard's agent was blocked from creating or editing the very file the
  CipherStash doctrine tells it to write ("New env keys go in `.env.example` with
  placeholders"). Committed env templates carry placeholder key names, not values.

  `.env.example`, `.env.sample` and `.env.template` are now readable and writable.
  Everything else is unchanged: `.env`, `.env.local`, `.env.production`, and
  value-bearing files that merely start with a template name
  (`.env.example.local`, `.env.example.bak`) stay blocked, as do `auth.json`,
  `secretkey.json` and credential files. Bash access to any env file — including
  the templates — remains blocked; `Read`/`Write` is the sanctioned path.

## 0.4.0

### Minor Changes

- 64fdeb2: Rename `stash db install`, `stash db upgrade`, and `stash db status` to
  `stash eql install`, `stash eql upgrade`, and `stash eql status`. These
  commands manage the EQL extension itself, so they now live under a dedicated
  `eql` command group. The old `db` spellings keep working as deprecated
  aliases that print a warning pointing at the new names. All help text,
  hints, generated migration headers, and wizard steps now reference the
  `eql` commands.

### Patch Changes

- a5f5422: Bump `@cipherstash/auth` (and its per-platform native bindings) from `0.40.0` to `0.41.0`, and migrate to its new `Result`-returning API.

  **What changed in `@cipherstash/auth` `0.41`.** Every fallible auth operation now returns a `@byteslice/result` `Result<T, AuthFailure>` (`{ data }` on success, `{ failure }` on error) instead of throwing. This covers strategy construction (`AccessKeyStrategy.create`, `OidcFederationStrategy.create`, `AutoStrategy.detect`, `DeviceSessionStrategy.fromProfile`), `getToken()`, and the device-code flow (`beginDeviceCodeFlow`, `pollForToken`, `openInBrowser`, `bindClientDevice`). Consumers now write `if (result.failure) …` and read `result.data` rather than `try/catch`. The `AuthError` type was renamed to **`AuthFailure`** — a discriminated union keyed by `type` (`"NOT_AUTHENTICATED"`, `"WORKSPACE_MISMATCH"`, …), replacing the old `error.code` string.

  **`@cipherstash/stack` (breaking type surface).**

  - **`AuthError` is renamed to `AuthFailure`** in the public re-exports from `@cipherstash/stack`. `AuthErrorCode` and `TokenResult` are unchanged. Anyone importing `AuthError` from `@cipherstash/stack` must switch to `AuthFailure`.
  - The WASM-inline access-key path (`resolveStrategy`, used by `@cipherstash/stack/wasm-inline`'s `Encryption()`) now unwraps the `Result` from `AccessKeyStrategy.create`. A construction failure (e.g. an invalid CRN or access key) throws a descriptive `[encryption]` error naming the `AuthFailure.type` instead of surfacing the raw auth error.
  - Bump `@cipherstash/protect-ffi` from `0.27.0` to `0.28.0`. auth `0.41`'s `getToken()` returns the token inside a `Result` envelope; protect-ffi `0.28` unwraps it (`.data.token`) inside its WASM `newClient`, whereas `0.27` read `.token` off the envelope and got `undefined` — which failed the WASM encrypt/decrypt round-trip with `token field is not a string`. `0.28` is the floor for the WASM path under auth `0.41`.

  **`stash` (CLI) and `@cipherstash/wizard`.** Internal auth call sites (`stash auth login`, device binding, `init` auth check, and the wizard's token acquisition / prerequisite check) were updated to unwrap `Result` and branch on `failure.type`. Behaviour is preserved — auth failures still surface the same way to end users; no CLI/wizard API changed.

- 17f4745: Add `@anthropic-ai/sdk` `^0.106.0` as a direct dependency so the
  auto-installed peer of `@anthropic-ai/claude-agent-sdk` resolves to a release
  patched against GHSA-p7fg-763f-g4gf, instead of the vulnerable 0.81.0 the
  peer range alone would select. The wizard never imports the SDK directly —
  this is a peer-resolution pin only; no behaviour change.

## 0.3.0

### Minor Changes

- bb9764d: `stash db push` is no longer included by default in `stash plan` / `stash impl` agent prompts or the wizard's post-agent step. SDK users (Drizzle, Supabase, plain PostgreSQL) no longer see `stash db push` baked into their rollout/cutover walkthroughs — the encryption config lives in app code, so the database doesn't need a copy.

  Pass `--proxy` to `stash init` (or answer the new interactive prompt) if you query encrypted data via [CipherStash Proxy](https://github.com/cipherstash/proxy). The choice is persisted to `.cipherstash/context.json` as `usesProxy` and is honoured by `stash plan`, `stash impl`, and the wizard's post-agent step. Existing `.cipherstash/context.json` files without the field default to SDK-only.

  Known gap: `stash encrypt cutover` currently requires a pending EQL config registered via `stash db push`, so SDK-only users running the migrate-existing-column flow will hit a "No pending EQL configuration" error from cutover. Workaround: run `stash db push` once before `stash encrypt cutover`. Decoupling cutover from EQL config for SDK-only users is tracked as a follow-up to [#447](https://github.com/cipherstash/stack/issues/447).

## 0.2.0

### Minor Changes

- 1a97d40: Add plan-mode support to the wizard so `stash plan` can hand off to the CipherStash Agent. The wizard now accepts `--mode <plan|implement>` (default `implement` for back-compat). In plan mode it skips the column-selection TUI, forwards `mode: 'plan'` to the gateway (which returns a planning prompt whose deliverable is `.cipherstash/plan.md`), and skips the post-agent install/push/migrate and call-site-scan steps. Implement mode is unchanged.

  `stash plan`'s handoff picker now offers all four targets (Claude Code, Codex, AGENTS.md, CipherStash Agent) — the wizard is no longer gated out of plan mode. `stash impl`'s picker is unchanged.

## 0.1.3

### Patch Changes

- a8dbb65: Render every user-facing CLI string and execute every shell-out under the detected package manager (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`), completing the work started in #379. Affected surfaces: `@cipherstash/cli` top-level + `auth` + `env` help, `db install` Drizzle migration steps, `db migrate` not-implemented warning, the Supabase migration SQL header, the Supabase status fallback exec, the `@cipherstash/protect` `stash` Stricli help (set/get/list/delete), the `@cipherstash/wizard` usage line and agent command allowlist, and the `@cipherstash/drizzle` `generate-eql-migration` help + drizzle-kit invocation. A new `pnpm run lint:runners` lint runs in CI and fails on any reintroduction of a hardcoded runner literal.

## 0.1.2

### Patch Changes

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

## 0.1.1

### Patch Changes

- f34fe9d: Show and execute commands using the detected package manager's runner (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`) instead of always emitting `npx`. A user who runs `bunx @cipherstash/cli init` now sees a "Next Steps" panel that suggests `bunx @cipherstash/cli db install` and `bunx @cipherstash/wizard`, and the wizard's post-agent step both displays and shells out to `bunx @cipherstash/cli db push` (was: `Failed: npx @cipherstash/cli db push`). Wizard prerequisite messages and AI-agent error hints (e.g. on a 401, `Run: bunx @cipherstash/cli auth login`) follow the same rule. Detection sources are unchanged: `npm_config_user_agent` first, then lockfile, then `npx` fallback.

## 0.1.0

### Minor Changes

- 5d3eb13: Initial release of `@cipherstash/wizard` — AI-powered encryption setup for CipherStash, extracted from `@cipherstash/cli`.

  Run it once per project, after `stash init`:

  ```bash
  npx @cipherstash/wizard
  pnpm dlx @cipherstash/wizard
  yarn dlx @cipherstash/wizard
  bunx @cipherstash/wizard
  ```

  The wizard reads your codebase, asks which columns to encrypt, hands a surgical prompt to the Claude Agent SDK against the CipherStash-hosted LLM gateway, and runs deterministic post-agent steps (package install, `db install`, `db push`, framework migrations). Same behavior as the previous `stash wizard` command — just shipped as its own package so it doesn't bloat the cli's dependency tree.
