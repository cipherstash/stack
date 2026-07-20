---
'stash': patch
---

Fix two defects in the Drizzle migration generator used by `stash eql install --drizzle` (EQL v2):

- **`--name` is now validated and no longer reaches a shell.** The migration name was interpolated into a shell command string, so a name containing shell metacharacters (e.g. `--name 'x; rm -rf ~'`) was executed. `--name` is now restricted to letters, numbers, dashes, and underscores, and drizzle-kit is invoked with an argv array instead of a shell string.
- **`--out` is now actually passed to drizzle-kit.** The flag was used to search for the generated migration but never handed to `drizzle-kit generate`, so any project whose `drizzle.config.ts` writes migrations outside `drizzle/` had the file written in one place and searched for in another, failing with "migration file not found".

`stash eql migration --drizzle` (EQL v3) already had both fixes and is unchanged.
