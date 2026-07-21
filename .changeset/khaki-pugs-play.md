---
'stash': patch
---

Fix two defects in the Drizzle migration generator used by `stash eql install --drizzle` (EQL v2):

- **`--name` is now validated and no longer reaches a shell.** The migration name was interpolated into a shell command string, so a name containing shell metacharacters (e.g. `--name 'x; rm -rf ~'`) was executed. `--name` is now restricted to letters, numbers, dashes, and underscores, and drizzle-kit is invoked with an argv array instead of a shell string.
- **`--out` is now actually passed to drizzle-kit.** The flag was used to search for the generated migration but never handed to `drizzle-kit generate`, so any project whose `drizzle.config.ts` writes migrations outside `drizzle/` had the file written in one place and searched for in another, failing with "migration file not found".
- **drizzle-kit now runs project-locally.** The generator invoked drizzle-kit through the download-and-run form (`pnpm dlx` / `npx <pkg>` / `bunx`), which could fetch a different drizzle-kit major into a temp store and resolve a different `drizzle.config.ts`/schema than the project's. It now uses the project-local form (`pnpm exec` / `npx --no-install`), so it resolves the project's own drizzle-kit and config and fails loudly if drizzle-kit isn't installed rather than surprise-downloading it. The "run your migrations" hint matches. This aligns v2 with the v3 generator's behaviour.

`stash eql migration --drizzle` (EQL v3) already had all three fixes and is unchanged.
