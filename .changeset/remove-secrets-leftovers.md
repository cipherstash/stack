---
"@cipherstash/stack": patch
"stash": patch
---

Remove the leftovers from the secrets removal (`1929c8fe`), which deleted
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
