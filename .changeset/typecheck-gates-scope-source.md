---
'@cipherstash/stack': patch
---

The declaration gate now covers all three emitted type artifacts, not just one.

`packages/stack/dist-types` typechecks what `tsc` emits rather than what the
source says — the gap that let typed `encryptQuery` ship uncallable for every
column through the whole rc series. It resolved `../dist/*.js` by relative path
under bundler resolution, which never consults the `exports` map, so it only ever
exercised the ESM `.d.ts` set. `tsup` emits the CJS `.d.cts` set in a separate
pass and `wasm-inline.d.ts` in a third, each with its own inlined copy of the
column class whose domain parameter the bug was about.

A second suite now resolves `@cipherstash/stack/*` **by package name** under
`moduleResolution: node16`, with the file extension selecting the condition
(`.cts` → `require` → `.d.cts`, `.mts` → `import` → `.d.ts`), plus a probe for
the `wasm-inline` entry — the documented target for Workers, Deno, Bun and
Supabase Edge, and previously the one artifact nothing typechecked. Removing the
phantom domain carrier makes all three fail, so none of them passes vacuously.
