---
'@cipherstash/stack-supabase': patch
'stash': patch
'@cipherstash/wizard': patch
---

Stop telling customers the Supabase wrapper cannot run in a Worker.

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
  "author against the entry whose *client type* consumes the schema": a raw
  `Encryption` client from `wasm-inline` wants `wasm-inline` tables, but the
  Supabase adapter wants `eql/v3` tables on both of its entries, WASM engine or
  not. The section now says so, and the "The Supabase adapter has its own edge
  entry" note points at it.
- **`skills/stash-supabase/SKILL.md` described the wrong failure mode for a
  missing declaration.** Omitting `schemas` on the edge entry cannot produce a
  no-column client — it is non-optional on the type and throws at construction —
  and an undeclared *table* throws rather than passing through unencrypted. The
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
  `databaseUrl` is passed *alongside* `schemas`, which is what it now says.

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
  to Node, with the edge case stated.

`@cipherstash/wizard` is bumped alongside `stash` because `skills/` ships in
both tarballs — `packages/wizard/tsup.config.ts` copies it into `dist/skills`
and `package.json` lists that under `files`. Without the bump the published
wizard keeps shipping the old text until some unrelated change moves its
version.

No runtime behaviour changes. The one non-documentation change is the
`databaseUrl?: never` field on `EncryptedSupabaseWasmOptions`, which is
type-level: it rejects at compile time a call that already threw at
construction.
