/**
 * User-facing message handles for strings that E2E tests assert on.
 *
 * Production code imports these instead of inlining literals so that copy
 * tweaks (rename, rephrase, capitalisation) only need to land in one place
 * and tests stay green automatically.
 *
 * Scope: only strings the E2E suite asserts on. Inline strings that no test
 * depends on stay inline — premature extraction is worse than copy-paste
 * here. See `packages/cli/AGENTS.md` for guidance on what to add.
 */
export const messages = {
  cli: {
    versionBannerPrefix: 'CipherStash CLI v',
    /**
     * Stable leader of the usage line. The runner-and-package portion
     * (e.g. `npx stash` or `bunx stash`) is appended at render time by
     * the bin so the help text matches how the user invoked the CLI.
     * Tests assert on this leader plus `'stash'` separately to stay
     * runner-agnostic.
     */
    usagePrefix: 'Usage: ',
    unknownCommand: 'Unknown command',
  },
  doctor: {
    title: 'stash doctor',
    /** Leader of the platform check line; the `<platform>-<arch>` is appended. */
    platformLabel: 'Platform',
    allChecksPassed: 'All checks passed.',
  },
  auth: {
    /** Same shape as `cli.usagePrefix` — leader only. */
    usagePrefix: 'Usage: ',
    unknownSubcommand: 'Unknown auth command',
    selectRegion: 'Select a region',
    cancelled: 'Cancelled.',
    /**
     * Shown when `--region` / `STASH_REGION` names a region that isn't in
     * the known list. `Unknown region` is the stable leader tests assert on;
     * the offending value and the valid slugs are appended for the human.
     */
    regionInvalid: (value: string, validSlugs: readonly string[]) =>
      `Unknown region: ${value}. Valid regions: ${validSlugs.join(', ')}.`,
    /**
     * Shown when no region can be resolved and we're not in an interactive
     * TTY (agent / CI / piped stdin, or `--json`). Naming both the flag and
     * the env var lets automation discover the escape hatch instead of
     * hanging on the picker.
     */
    regionMissingNonInteractive:
      'Cannot resolve a region without a prompt. Pass --region <slug> or set STASH_REGION (e.g. STASH_REGION=us-east-1).',
    /**
     * Shown when `--region` is passed with no value (arg parsing turns a
     * valueless flag into a boolean). Distinguishes "you forgot the value"
     * from "no region anywhere" so the fix is obvious.
     */
    regionFlagNeedsValue:
      'The --region flag needs a value, e.g. --region us-east-1. Run `stash auth regions` to list valid slugs.',
  },
  eql: {
    unknownSubcommand: 'Unknown eql subcommand',
    /**
     * Stable leader of the guard shown when `stash eql install` runs in a
     * Prisma Next project — Prisma Next owns EQL installation via its own
     * migration system, so the standalone installer is the wrong tool. The
     * actionable command + `--force` note are appended at the call site.
     */
    prismaNextDetected: 'This looks like a Prisma Next project',
    /** `stash eql migration` with no `--drizzle`/`--supabase`/`--prisma` target. */
    migrationNeedsTarget:
      'Specify a target: `stash eql migration --drizzle` for a Drizzle project, or `stash eql migration --supabase` to write into supabase/migrations/ (or `--prisma`).',
    /**
     * `--drizzle --prisma`. Note that `--drizzle --supabase` is NOT this error:
     * there, `--supabase` is the role-grants modifier, not a second target.
     */
    migrationOneTarget:
      'Pass exactly one target: `--drizzle` or `--prisma`, not both. (`--supabase` is a target on its own, and the role-grants modifier when combined with `--drizzle`.)',
    /**
     * `--prisma` is registered only to route people to the right mechanism:
     * Prisma Next installs the EQL bundle through its own migration framework
     * (the `migrations/cipherstash/` contract space), so there is no emitter
     * here and never needs to be. Fail with a pointer rather than a silent
     * no-op.
     */
    migrationPrismaNotNeeded:
      'Prisma Next does not need `stash eql migration` — its extension pack installs the EQL bundle through its own migration framework (the `migrations/cipherstash/` contract space). Run `prisma-next migration plan` and `prisma-next migrate` instead.',
    /** `--name` carried characters outside `[A-Za-z0-9_-]`. */
    migrationBadName:
      'Migration name must contain only letters, numbers, dashes, and underscores.',
    /**
     * `--name` with `--supabase`. The Supabase filename is fixed because
     * duplicate detection matches on the `_cipherstash_eql.sql` suffix, so the
     * flag cannot be honoured — warn rather than rename nothing silently.
     */
    migrationNameDrizzleOnly:
      '`--name` applies to `--drizzle` only and is ignored here — the Supabase migration is always named `<timestamp>_cipherstash_eql.sql`, which is how a duplicate install is detected.',
    /**
     * `--out` with a bare `--supabase`, pointing anywhere other than
     * `<cwd>/supabase/migrations`.
     *
     * The Supabase CLI's migrations directory is NOT configurable. In the Go
     * implementation it is `filepath.Join(SupabaseDirPath, "migrations")` with
     * `SupabaseDirPath = "supabase"`, and the path builder that derives it from
     * a `--config` path still carries a literal `// TODO: make base path
     * configurable from toml`; the TypeScript CLI hard-codes
     * `path.join(workdir, "supabase", "migrations")` in both the `db reset` and
     * `db push` handlers. `--workdir` / `SUPABASE_WORKDIR` moves the whole
     * project root, not this subdirectory, and `config.toml` has no key for it
     * (supabase/supabase#33257 is the open request to add one).
     *
     * So a file written elsewhere is exactly the failure this command exists to
     * fix — EQL missing from the directory a reset replays — just relocated.
     * A warning rather than a hard error, because the user may well have their
     * own apply step for that directory; what they cannot be allowed to assume
     * is that `supabase db reset` will pick it up.
     */
    migrationSupabaseOutNotReplayed: (migrationsDir: string) =>
      `--out points at ${migrationsDir}, but the Supabase CLI only ever replays <project>/supabase/migrations — that path is hard-coded, with no config.toml key to move it (--workdir relocates the whole supabase/ directory, not this one). \`supabase db reset\` and \`supabase db push\` will not apply this file, so EQL will still be missing after the next reset. Drop --out to write into supabase/migrations/, unless you have your own step that applies this directory.`,
    /**
     * `--supabase --force` replaced an install migration in place.
     *
     * Two things the user cannot see from the success line. First, `supabase db
     * push` will NOT pick the new bundle up: `FindPendingMigrations`
     * (`pkg/migration/apply.go`) computes the pending set positionally —
     * `pending := localMigrations[len(remoteMigrations):]` — with no content
     * hash and no statement diff. (Seed files DO carry a `Hash`/`Dirty` pair and
     * re-run on change; migrations do not.) Equal counts mean an empty pending
     * set, so push prints "Remote database is up to date." and applies nothing.
     * Telling people to `db push` here leaves them believing a remote was
     * updated when it was not.
     *
     * Second, re-applying is not free. The EQL bundle opens with `DROP SCHEMA IF
     * EXISTS eql_v3 CASCADE;` / `DROP SCHEMA IF EXISTS eql_v3_internal
     * CASCADE;`, so it takes every dependent index, constraint, and RLS policy
     * with it. On a fresh `supabase db reset` that is a no-op on an empty
     * database; on a populated remote it is destructive.
     */
    migrationSupabaseForceReplaced:
      'Replaced the EQL install migration in place, keeping its version. A database that already applied that version still has the OLD bundle, and `supabase db push` will not re-apply it — the Supabase CLI decides what is pending by version, not by content, so a version already in the ledger is never re-run (push just reports "Remote database is up to date."). Re-applying is not free either: the EQL bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE` (and `eql_v3_internal`), which also drops every index, constraint, and RLS policy that references those schemas. Harmless against a fresh `supabase db reset`; destructive against a populated remote.',
    /**
     * The re-apply recipe for a replaced install migration, in place of the
     * plain "Apply it" note. `migration repair --status reverted` deletes the
     * ledger row and nothing else — Supabase's docs are explicit that it updates
     * the tracking table without applying or reverting any SQL — which puts the
     * version back in the pending set. `--include-all` is then required because
     * that version is now a gap in the middle of remote history, which
     * `FindPendingMigrations` rejects with `ErrMissingRemote` before applying
     * anything.
     */
    migrationSupabaseReapply: (version: string | null) =>
      `Re-apply the replaced migration.\n\nLocal:\n\n  supabase db reset\n\nRemote — clear the ledger row first, or the push is a no-op:\n\n  supabase migration repair --status reverted ${version ?? '<version>'}\n  supabase db push --include-all\n\n\`migration repair\` updates the tracking table only; it applies no SQL. \`--include-all\` is required because the reverted version is now a gap in the middle of remote history, which \`db push\` otherwise refuses to step over. Read the CASCADE warning above before doing this to a populated database.`,
    /**
     * Migrations already in the directory that reference EQL and sort BEFORE the
     * install this command writes.
     *
     * The brownfield case: `stash eql install` applied EQL straight to the
     * database, encrypted-column migrations were written against it, and only
     * then did the project move to the migration-first install. A current
     * timestamp sorts LAST, so those migrations replay before EQL exists and
     * `supabase db reset` dies on the first `eql_v3_*` reference.
     *
     * Detection and a warning, not a fix: back-dating the install, renaming the
     * user's migrations, or squashing the lot are all their call, and a
     * back-dated file has its own remote consequence that they have to be the
     * ones to accept.
     *
     * That consequence is split by the remote's state, and getting it wrong is
     * destructive. This warning only ever fires on a project that already ran
     * `stash eql install` — that is what put EQL in the database ahead of the
     * migration history — so the remote typically HAS the bundle and is missing
     * only the ledger row. `migration repair --status applied` is the answer
     * there: it writes the row and runs no SQL. Pushing the file instead re-runs
     * a bundle that opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`, dropping
     * every index, constraint, and RLS policy that references those schemas.
     * `--include-all` stays for the other case — a remote that genuinely has not
     * had the SQL applied — where the back-dated version is a gap in the middle
     * of history that `db push` otherwise refuses to step over.
     */
    migrationSupabaseEqlBeforeInstall: (
      migrationsDir: string,
      files: string[],
    ) =>
      `Migrations in ${migrationsDir} reference EQL and sort BEFORE the EQL install migration:\n\n  ${files.join('\n  ')}\n\n\`supabase db reset\` replays the directory in version order, with no dependency awareness, so each of those runs before EQL is installed and the reset fails (\`type "eql_v3_text_search" does not exist\`). Rename the install migration to a version below ${files[0]} so it replays first.\n\nHow that back-dated version reaches a remote depends on the remote. If \`stash eql install\` has already run there, EQL is present and only the ledger row is missing — mark it applied, which writes the ledger row and runs no SQL:\n\n  supabase migration repair --status applied <version>\n\nDo NOT push the file to that remote instead: the bundle opens with \`DROP SCHEMA IF EXISTS eql_v3 CASCADE\` (and \`eql_v3_internal\`), so re-applying it drops every index, constraint, and RLS policy that references those schemas. A remote that genuinely still needs the SQL applied takes \`supabase db push --include-all\`, because the back-dated version lands as a gap in the middle of that history.`,
    /** `stash eql repair` with no `--drizzle` target. */
    repairNeedsTarget: 'Specify a target: `stash eql repair --drizzle`.',
    /** `--out` (or its `drizzle` default) points at a directory that isn't there. */
    repairOutMissing: (outDir: string) =>
      `Drizzle output directory not found: ${outDir}\nPass --out <dir> so it matches your drizzle.config.ts.`,
    /**
     * The sweep left statements it could not rewrite. Fail closed, exactly as
     * `eql migration --drizzle` does: the remaining SQL still fails at migrate
     * time, so a zero exit would tell CI the repair had succeeded.
     */
    repairSweepIncomplete: (outDir: string) =>
      `The ALTER COLUMN sweep found unsafe or unverified SQL in ${outDir}. Review the statements above and use the staged stash encrypt lifecycle before running drizzle-kit migrate.`,
    /**
     * The dry-run stand-in for `describeStagedReconciliation`, which is written
     * in the past tense and would otherwise claim a column exists that no
     * migration has added yet.
     */
    repairDryRunStaged: (count: number) =>
      `Would stage ${count} encrypted column(s). Re-run without --dry-run to apply the repair — the reconciliation your Drizzle schema and drizzle-kit snapshot then need is printed at that point.`,
    /**
     * Lead line for migrations left alone because the database has already run
     * them. A distinct outcome from the sweep's `skipped` near-misses: those
     * are statements the rewriter could not understand, this is one it
     * understood perfectly and must not act on.
     */
    repairAppliedRefused: (count: number) =>
      `Left ${count} ALREADY APPLIED migration(s) untouched. They carry ALTER-to-encrypted statements, but rewriting an applied migration is not a repair:`,
    /**
     * Why an applied migration is refused, and what to do instead. Named
     * separately so the e2e/unit assertions pin the hazard, not the phrasing
     * around it.
     */
    repairAppliedHazard:
      'the database already has whatever this migration did, so rewriting its .sql leaves the file describing a shape that database never got from it — a fresh CI or staging database replaying the rewritten file would silently diverge from this one. Reconcile the environments by hand instead, and move the column onto the encrypted twin through the staged `stash encrypt` lifecycle.',
    /**
     * The applied-state probe could not run. Fail closed: the user asked to be
     * protected from rewriting applied migrations, and a silent fallback to
     * "nothing is applied" would hand them the drift they were avoiding.
     */
    repairAppliedCheckFailed: (detail: string) =>
      `Could not check which migrations have been applied: ${detail}\nNothing was rewritten. Fix the connection and re-run, or re-run without --database-url to repair unverified (see the warning that prints in that mode).`,
    /**
     * `--migrations-table` is not a plain `[schema.]table`. Rejected before
     * connecting: the value is quoted before it reaches SQL, so it cannot break
     * out, but a malformed one would query a relation that cannot exist and the
     * resulting `undefined_table` would be read as an absent ledger — silently
     * downgrading the check the flag was passed to get.
     */
    repairMigrationsTableInvalid: (value: string) =>
      `--migrations-table must be a table name, optionally schema-qualified (e.g. \`my_migrations\` or \`audit.my_migrations\`). Got: ${value}`,
    /**
     * The ledger relation is not there. Ambiguous, and deliberately NOT the
     * confident `repairNothingApplied`: either `drizzle-kit migrate` never ran
     * against this database, or the project overrode `migrations.table` /
     * `migrations.schema` in drizzle.config.ts and the probe queried the wrong
     * relation. Claiming "nothing applied" for the second case would rewrite
     * applied migrations while reporting the check as clean.
     */
    repairLedgerMissing: (relation: string) =>
      `Could not verify which migrations have been applied: ${relation} does not exist. Either drizzle-kit migrate has never run against this database — in which case there is nothing applied and this repair is safe — or your drizzle.config.ts sets migrations.table / migrations.schema, and the check looked in the wrong place. If it does, re-run with --migrations-table <[schema.]table> naming your ledger. Repairing anyway.`,
    /** Nothing in `drizzle.__drizzle_migrations` — every migration is fair game. */
    repairNothingApplied:
      'No applied migrations found in drizzle.__drizzle_migrations — every migration in this directory can be repaired.',
    /** How many of the journal's migrations the database has already run. */
    repairAppliedCount: (count: number) =>
      `${count} migration(s) already applied to this database; they will not be rewritten.`,
    /**
     * No database URL, so the applied-state check did not run.
     *
     * The default is to proceed. The journal proves a migration EXISTS, not
     * that it ran, and refusing everything on that ambiguity would make the
     * command useless in exactly the flow it exists for — a broken migration
     * that failed on apply, in a project whose database may not be reachable
     * from where the repair is being run. So: warn loudly, name the one case
     * that is genuinely unsafe, and tell the user how to get the check.
     */
    repairAppliedUnverified:
      'Could not verify which migrations have been applied: no --database-url and no DATABASE_URL. The journal shows that a migration EXISTS, not that it ran. Almost every ALTER-to-encrypted statement is un-runnable and so cannot have been applied — the exception is a jsonb column changed to an EQL domain on an empty table, which applies successfully. If you have run drizzle-kit migrate since generating these migrations, re-run with --database-url so applied migrations are left alone.',
    /** A clean sweep — said out loud so silence never reads as "did not run". */
    repairNothingToDo:
      'Nothing to repair: no unsafe ALTER-to-encrypted statements found.',
    /**
     * The drizzle journal is missing or unparseable. `detail` names the file and
     * the underlying reason. Fail closed: the journal is the only offline record
     * of which migrations exist and when each was generated, so without it the
     * applied-state check cannot run and a rewrite would be blind.
     */
    repairJournalUnreadable: (detail: string) =>
      `${detail}\nstash eql repair needs drizzle-kit's meta/_journal.json to tell which migrations have already been applied. Check that --out points at your drizzle-kit output directory.`,
  },
  db: {
    unknownSubcommand: 'Unknown db subcommand',
    /** Warning shown when a deprecated `db <sub>` alias for `eql <sub>` is used. */
    aliasDeprecated: (stashRef: string, sub: string) =>
      `"${stashRef} db ${sub}" is deprecated — use "${stashRef} eql ${sub}" instead.`,
    migrateNotImplemented: (stashRef: string) =>
      `"${stashRef} db migrate" is not yet implemented.`,
    /** Source labels surfaced after DATABASE_URL resolution. */
    urlResolvedFromFlag: 'Using DATABASE_URL from --database-url flag',
    urlResolvedFromSupabase: 'Using DATABASE_URL from supabase status',
    urlResolvedFromPrompt: 'Using DATABASE_URL from prompt',
    urlPromptMessage: 'Paste your DATABASE_URL',
    /**
     * Shown immediately before the URL prompt to surface alternatives.
     * `dotenvFile` is the first existing dotenv file in the project (or
     * `.env` as the default) so the suggestion matches the user's setup.
     */
    urlPromptTip: (dotenvFile: string) =>
      `Tip: you can also pass --database-url <url> on the command line, or set DATABASE_URL in your environment / ${dotenvFile} file.`,
    /**
     * Shown when a connection attempt fails — points the user at where
     * to fix the URL. Same dotenv detection as `urlPromptTip` so the
     * suggestion matches their setup.
     */
    urlConnectionFailedHint: (dotenvFile: string) =>
      `Check that DATABASE_URL is correct. You can pass --database-url <url> on the command line, set DATABASE_URL in your environment, or write it to ${dotenvFile}.`,
    urlInvalid: 'Not a valid URL',
    urlFlagMalformed:
      'Invalid --database-url: not a parseable connection string',
    urlMissingCi:
      'Cannot resolve DATABASE_URL in CI. Pass --database-url or set DATABASE_URL.',
    urlMissingInteractive:
      'Cannot resolve DATABASE_URL. Pass --database-url, set DATABASE_URL in your environment, or run `supabase start` if this is a Supabase project.',
    /** Nudge shown after a prompt-sourced run completes. */
    urlHint: (file: string) =>
      `Set DATABASE_URL in ${file} to skip this prompt next time.`,
    /**
     * Shown when a `stash.config.ts` (or the encryption client it points at)
     * can't load because a CipherStash package isn't installed. `installCommands`
     * is the newline-joined install invocation and `stash` the runner-aware
     * `stash` prefix (e.g. `npx stash`).
     */
    missingCipherStashPackage: (
      pkg: string,
      installCommands: string,
      stash: string,
    ) =>
      `\`${pkg}\` is not installed in this project.\n\nInstall the CipherStash packages, then re-run:\n  ${installCommands}\n\nOr run \`${stash} init\` to set everything up.`,
  },
  env: {
    /**
     * Stable leaders of the pre-mint argv errors. The e2e suite asserts on
     * these; the runner-aware hints are appended at the call sites. All
     * three fire BEFORE any profile or network access.
     */
    missingName: 'A credential name is required in non-interactive mode',
    nameRequiresValue: '--name requires a value',
    unexpectedArgument: 'Unexpected argument',
  },
  plan: {
    /**
     * Stable leader of the refusal shown when `plan --complete-rollout` runs
     * non-interactively without `--yes`. The e2e suite asserts on it; the
     * `--yes` hint is appended at the call site. Exits non-zero — the plan
     * was NOT drafted, so automation must not read exit 0 as success.
     */
    completeRolloutNeedsYes:
      '`--complete-rollout` skips the production-deploy gate and needs explicit confirmation',
    /** Shown when `--yes` confirms the gate-skip (bypasses the prompt). */
    completeRolloutConfirmed:
      'Proceeding with --yes: the production-deploy gate is skipped',
    /**
     * Outcome honesty (#738): the plan file is written by the handed-off
     * agent, not by the CLI, so `stash plan` verifies it on disk after the
     * handoff and reports what actually happened. These are the stable
     * leaders the e2e suite asserts on; the path and next-step hints are
     * appended at the call sites.
     */
    drafted: 'Plan drafted at',
    /** A pre-existing plan the run did not modify — usable, but not "drafted". */
    unchanged: 'left unchanged by this run',
    /** An agent was launched and told to write the plan, but the file is
     *  absent. Exits non-zero — automation must not read this as success. */
    notWritten: 'The agent handoff finished but no plan was written',
    /** Deferred handoff (AGENTS.md target, or a CLI target that isn't
     *  installed): the plan is written later, when the user drives their
     *  agent. Exit 0, but never claim the plan exists. */
    noPlanYet: 'No plan drafted yet',
  },
  init: {
    /**
     * Honest non-interactive init. These exit non-zero so automation never
     * reads a false success — the e2e suite asserts on the leaders.
     */
    setupIncomplete: 'Setup incomplete',
    eqlNotInstalled: 'EQL is not installed — encryption queries will fail.',
    /** Shown when a non-interactive run hits version skew it won't reconcile. */
    skewNonInteractive:
      'Version skew on already-installed packages — refusing to proceed non-interactively. Align the packages (below) and re-run, or run init interactively.',
  },
  telemetry: {
    /**
     * The one-time first-run notice. Printed to stderr so it never pollutes
     * piped or `--json` stdout. Nothing is sent on the run that shows it.
     * `stashRef` is the runner-aware invocation (e.g. `npx stash`) so the
     * opt-out command is actionable even before `stash` is on PATH.
     */
    notice: (stashRef: string) =>
      [
        'CipherStash collects anonymous CLI usage analytics to improve the tool.',
        'No plaintext, schema, table/column names, or connection details are ever collected.',
        `We honor the DO_NOT_TRACK standard. Opt out any time: set DO_NOT_TRACK=1, or run \`${stashRef} telemetry disable\`.`,
        'Learn more: https://cipherstash.com/docs/reference/cli',
      ].join('\n'),
    enabled: 'Telemetry enabled.',
    disabled: 'Telemetry disabled.',
    unknownSubcommand: 'Unknown telemetry command',
  },
} as const
