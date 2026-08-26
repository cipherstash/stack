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
required, `config` is required and must carry all four `CS_*` values,
`databaseUrl` is refused, and `.withLockContext()` / `.audit()` throw rather
than silently dropping an identity claim (#797).

The **browser** half of the old sentence was correct and is kept, with the
reason now given: the WASM client requires a workspace `clientKey` on every
authentication path, so a browser build would ship the key with it (#804).

Documentation only — no runtime behaviour changes.
