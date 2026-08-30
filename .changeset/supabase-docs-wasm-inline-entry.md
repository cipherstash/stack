---
'@cipherstash/stack-supabase': patch
'stash': patch
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
  plaintext; the bullet now says that, along with the two things that limit it
  (`select('*')` is refused in declared mode, and a plaintext write to an
  `eql_v3_*` column fails the domain CHECK) and the fact that the native
  entry's warning about unverified declarations is gated on the introspector
  and so never fires there.
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

Two tests now anchor the corrected claims against the code rather than against
prose. `packages/stack-supabase/__tests__/supabase-wasm-config.test-d.ts` asserts
at the type level that the edge `config` accepts both the access-key arm and a
strategy-only arm without `workspaceCrn`, and rejects `clientId` + `clientKey`
alone. `supabase-declared-mode.test.ts` gains a case pinning the real hazard: an
undeclared column on a declared table reaches PostgREST as plaintext on insert,
update and filter, and is absent from the decrypt call.

Documentation and tests only — no runtime behaviour changes.
