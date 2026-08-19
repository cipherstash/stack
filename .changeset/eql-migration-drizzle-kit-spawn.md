---
'stash': patch
---

Fix `stash eql migration --drizzle`, which aborted for every project with a `drizzle.config.ts` (#924).

- **Stop passing `--out` to `drizzle-kit generate`.** drizzle-kit reads its config file *or* its command-line options, never both: any of `--schema`/`--out`/`--dialect` switches it into CLI mode, where it then aborts demanding the two we cannot supply (`Please provide required params: [x] schema [x] dialect`). Verified against drizzle-kit 0.28.5, 0.30.6 and 0.31.4 — this was never version-specific. Your `drizzle.config.ts` now decides the output directory and stash follows the path drizzle-kit reports, warning when it differs from a `--out` you passed. `--out` remains the fallback directory to search.
- **Pass the resolved `DATABASE_URL` into the drizzle-kit child process.** A `drizzle.config.ts` that reads `process.env.DATABASE_URL` (and often throws when it is missing) previously saw nothing, because the project's usual `dotenv -e .env.local -- drizzle-kit …` wrapper never runs when stash invokes drizzle-kit directly. stash already loads `.env`/`.env.local` at startup; it now also threads down a URL only the CLI can find, such as a running local Supabase.
- **Report the actual failure.** drizzle-kit writes its errors to stdout, not stderr, so the abort printed nothing but "Make sure drizzle-kit is installed and configured" — the one thing that was never wrong. Both streams are now surfaced, and a config that could not read `DATABASE_URL` gets a follow-up naming that instead.
