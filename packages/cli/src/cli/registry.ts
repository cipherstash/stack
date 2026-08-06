/**
 * The command-descriptor registry — one descriptor per `stash` command, grouped
 * for display. It is the single source of truth for command metadata: it backs
 * both `stash manifest --json` (via `cli/manifest.ts`) and per-command
 * `stash <command> --help` (via `cli/help.ts`). A flag/summary/example edit here
 * flows into both automatically.
 *
 * ⚠️ The one remaining hand-maintained surface is the global `HELP` banner in
 * `bin/main.ts` (bare `stash` / `stash --help`) — it duplicates only the
 * command *list* (names + summaries), not their flags. A new command, or a
 * summary edit, still belongs in both places or the banner and `stash manifest`
 * will diverge. See `docs/plans/cli-help-and-manifest.md`.
 */

/** A single flag/option on a command. */
export interface Flag {
  /** Long form including dashes, e.g. `--supabase`. */
  name: string
  /** Value placeholder for value-taking flags, e.g. `<slug>`; omit for booleans. */
  value?: string
  description: string
  /** Default value, when the flag has one worth surfacing. */
  default?: string
  /** Env var that also sets this, e.g. `DATABASE_URL`. */
  env?: string
}

/** A command's metadata. `name` is the full path, e.g. `"auth login"`. */
export interface CommandDescriptor {
  /** Full command path without the `stash` prefix, e.g. `"eql install"`. */
  name: string
  /** One-line summary (the `Commands:` text in `--help`). */
  summary: string
  /** Rich multi-paragraph help (cobra `Long`). */
  long?: string
  /** Curated per-command examples, each WITHOUT the runner prefix, e.g. `"auth login"`. */
  examples?: string[]
  flags?: Flag[]
  /** Deprecated aliases / commands hidden from help + manifest (e.g. old `db install`). */
  hidden?: boolean
}

/** A display group of related commands. */
export interface CommandGroup {
  title: string
  commands: CommandDescriptor[]
}

/**
 * Shared `--database-url` flag — every db/eql/schema command accepts it, so it's
 * declared once and referenced, not copy-pasted.
 */
const DATABASE_URL_FLAG: Flag = {
  name: '--database-url',
  value: '<url>',
  description:
    'Database URL for this run only — never written to disk. Highest precedence in the resolution order: --database-url flag → DATABASE_URL env → supabase status → interactive prompt. A stash.config.ts is not a separate tier (its default databaseUrl re-runs this same chain); a hand-set literal databaseUrl in the config bypasses the resolver and wins over all of these.',
  env: 'DATABASE_URL',
}

const REGION_FLAG: Flag = {
  name: '--region',
  value: '<slug>',
  description:
    'Region to authenticate against (e.g. us-east-1). Skips the interactive region picker.',
  env: 'STASH_REGION',
}

// Flags shared verbatim across several commands — declared once so a description
// edit lands in one place and can't drift. (`--supabase` only shares the
// "compatible mode" spelling; `init`/`auth` use different wording, kept inline.)
const DRY_RUN_FLAG: Flag = {
  name: '--dry-run',
  description: 'Show what would happen without making changes.',
}
const EXCLUDE_OPERATOR_FAMILY_FLAG: Flag = {
  name: '--exclude-operator-family',
  description: 'Skip operator family creation.',
}
const SUPABASE_COMPAT_FLAG: Flag = {
  name: '--supabase',
  description: 'Use Supabase-compatible mode.',
}
const TABLE_FLAG: Flag = {
  name: '--table',
  value: '<name>',
  description: 'Target table.',
}
const COLUMN_FLAG: Flag = {
  name: '--column',
  value: '<name>',
  description: 'Target column.',
}

/**
 * The registry. Ordered as it should render in help. Populated from the existing
 * `HELP` surface in `bin/main.ts` plus the per-command flag parsing in the
 * command modules, so it is authoritative for the current CLI.
 */
export const registry: CommandGroup[] = [
  {
    title: 'Setup & workflow',
    commands: [
      {
        name: 'init',
        summary: 'Initialize CipherStash for your project',
        long: [
          'Set up CipherStash end-to-end: authenticate, introspect your database,',
          'install dependencies, install EQL, and hand off the rest to your local',
          'coding agent. Every prompt has a non-interactive escape hatch, so init',
          'never blocks waiting on a TTY (CI, agents, pipes).',
        ].join('\n'),
        examples: [
          'init',
          'init --supabase',
          'init --prisma',
          'init --region us-east-1',
        ],
        flags: [
          {
            name: '--supabase',
            description: 'Use Supabase-specific setup flow.',
          },
          {
            name: '--drizzle',
            description: 'Use Drizzle-specific setup flow.',
          },
          {
            name: '--prisma',
            description:
              'Use Prisma Next-specific setup flow (EQL bundle installed via prisma-next migrate).',
          },
          {
            ...REGION_FLAG,
            description:
              'Region to authenticate against (e.g. us-east-1). Skips the interactive region picker. Required for non-interactive init when not already logged in.',
          },
        ],
      },
      {
        name: 'plan',
        summary: 'Draft a reviewable encryption plan at .cipherstash/plan.md',
        examples: [
          'plan',
          'plan --target claude-code',
          'plan --complete-rollout --yes --target claude-code',
        ],
        flags: [
          {
            name: '--complete-rollout',
            description:
              'Plan the entire encryption lifecycle (schema-add through drop) in one document. Skips the production-deploy gate; only safe when this database is not backing a deployed application. Needs confirmation — an interactive prompt, or --yes non-interactively (else it exits non-zero without drafting).',
          },
          {
            name: '--yes',
            description:
              "Confirm --complete-rollout's gate-skip without a prompt (for automation / CI). No effect without --complete-rollout.",
          },
          {
            name: '--target',
            value: '<name>',
            description:
              'Skip the agent-target picker and hand off directly to one of claude-code | codex | agents-md | wizard. Safe in non-TTY contexts.',
          },
        ],
      },
      {
        name: 'impl',
        summary: 'Execute the plan with a local agent',
        examples: [
          'impl',
          'impl --continue-without-plan',
          'impl --target claude-code',
        ],
        flags: [
          {
            name: '--continue-without-plan',
            description:
              'Skip planning and go straight to implementation (interactively confirms before proceeding).',
          },
          {
            name: '--target',
            value: '<name>',
            description:
              'Skip the agent-target picker and hand off directly to one of claude-code | codex | agents-md | wizard. Safe in non-TTY contexts.',
          },
        ],
      },
      {
        name: 'status',
        summary: 'Displays implementation status',
        flags: [
          {
            name: '--quest',
            description:
              'Force the quest-log output (emoji + progress bars) even in non-TTY contexts.',
          },
          {
            name: '--plain',
            description: 'Force the plain-text output even in TTY contexts.',
          },
          {
            name: '--json',
            description: 'Emit a structured JSON document instead.',
          },
        ],
      },
      {
        name: 'wizard',
        summary: 'AI-guided encryption setup (reads your codebase)',
      },
      {
        name: 'doctor',
        summary: 'Diagnose install problems (native binaries, runtime)',
      },
      {
        name: 'manifest',
        summary: 'Print the structured, versioned command surface',
        long: [
          'Emit the CLI command surface as data. `--json` produces the machine-',
          'readable manifest the docs generator and agents consume; without it a',
          'grouped command list is printed. The manifest is stamped with the CLI',
          'version, so a page generated from it always names the version it describes.',
        ].join('\n'),
        examples: ['manifest --json', 'manifest'],
        flags: [
          {
            name: '--json',
            description:
              'Emit the structured JSON manifest instead of a text list.',
          },
        ],
      },
      {
        name: 'telemetry',
        summary: 'Manage anonymous usage analytics',
        long: [
          'Manage the anonymous, opt-out usage analytics the CLI collects to',
          'improve the tool. `status` (the default) reports whether telemetry is',
          'on and which setting governs it; `enable` / `disable` write your saved',
          'preference. Telemetry is also disabled by the DO_NOT_TRACK or',
          'STASH_TELEMETRY_DISABLED environment variables and automatically in CI.',
          'No plaintext, schema, table/column names, or connection details are',
          'ever collected. See https://cipherstash.com/docs/reference/cli.',
        ].join('\n'),
        examples: ['telemetry status', 'telemetry disable', 'telemetry enable'],
      },
    ],
  },
  {
    title: 'Auth',
    commands: [
      {
        name: 'auth login',
        summary: 'Authenticate with CipherStash',
        long: [
          'Runs the OAuth 2.0 device authorization flow:',
          '1. Pick a region for your workspace.',
          '2. Approve in the browser — the URL is printed, so it works over SSH/headless.',
          '3. The CLI polls until you approve, then stores a short-lived token.',
          "4. Your device is bound to the workspace's default keyset, so later",
          '   commands authenticate without a fresh login.',
        ].join('\n'),
        examples: [
          'auth login',
          'auth login --region us-east-1',
          'auth login --supabase',
          'auth login --region us-east-1 --json',
        ],
        flags: [
          REGION_FLAG,
          {
            name: '--json',
            description:
              'Emit newline-delimited JSON events instead of prose. The first event (authorization_required) carries the device verification URL for a human to open. Implies no prompt and no browser auto-open.',
          },
          {
            name: '--no-open',
            description:
              "Don't auto-open the verification URL in a browser (already implied by --json).",
          },
          {
            name: '--supabase',
            description: 'Track Supabase as the referrer.',
          },
          { name: '--drizzle', description: 'Track Drizzle as the referrer.' },
          { name: '--prisma', description: 'Track Prisma as the referrer.' },
        ],
      },
      {
        name: 'auth regions',
        summary: 'List the regions you can authenticate against',
        examples: ['auth regions', 'auth regions --json'],
        flags: [
          {
            name: '--json',
            description:
              'Emit machine-readable [{ slug, label }] instead of a text list.',
          },
        ],
      },
    ],
  },
  {
    title: 'EQL',
    commands: [
      {
        name: 'eql install',
        summary:
          'Scaffold stash.config.ts (if missing) and install EQL extensions',
        flags: [
          {
            name: '--force',
            description: 'Reinstall / overwrite even if already installed.',
          },
          DRY_RUN_FLAG,
          {
            name: '--supabase',
            description:
              'Use Supabase-compatible mode (auto-detected from DATABASE_URL).',
          },
          DATABASE_URL_FLAG,
        ],
      },
      {
        name: 'eql migration',
        summary:
          'Generate an EQL v3 install migration (Drizzle, or supabase/migrations/; Prisma Next installs EQL through its own migrations)',
        long: [
          'Migration-first is the preferred way to install EQL: it lands in your',
          'migration history and ships to every environment through the same',
          'migrate step as the rest of your schema. On Supabase it is the only',
          'durable way — `supabase db reset` replays the migrations directory, so',
          'a direct `eql install` is wiped by the next reset.',
        ].join('\n'),
        examples: [
          'eql migration --drizzle',
          'eql migration --drizzle --supabase',
          'eql migration --supabase',
          // Deliberately no `--out` here. The Supabase CLI reads
          // `supabase/migrations` and nothing else, so an example pointing the
          // install elsewhere would teach the exact "EQL isn't in the replayed
          // directory" failure this command exists to fix. `--force` is what
          // needed demonstrating; it works fine on its own.
          'eql migration --supabase --force',
        ],
        flags: [
          {
            name: '--drizzle',
            description:
              'Emit a Drizzle custom migration containing the EQL v3 install SQL.',
          },
          {
            name: '--prisma',
            description:
              'Not needed: Prisma Next installs EQL through its own migration framework — run `prisma-next migrate` instead.',
          },
          {
            name: '--supabase',
            description:
              'On its own, write the install into supabase/migrations/ so it survives `supabase db reset`. With --drizzle, instead append the Supabase role grants (eql_v3 + eql_v3_internal for anon/authenticated/service_role) to the Drizzle migration.',
          },
          {
            name: '--name',
            value: '<name>',
            description:
              'Name for the generated migration (Drizzle). Letters, numbers, dashes, underscores only. Defaults to `install-eql`.',
          },
          {
            name: '--out',
            value: '<path>',
            description:
              'Where the migration is written. Drizzle: passed to `drizzle-kit generate --out`, defaults to `drizzle` — set it to match your drizzle.config.ts. Supabase: leave it alone. The Supabase CLI replays `supabase/migrations` and has no setting to move it, so pointing elsewhere means `supabase db reset` / `db push` never apply the install; the command warns when you do.',
          },
          {
            name: '--force',
            description:
              'Write a Supabase install migration even though one already exists. Not needed for --drizzle (drizzle-kit numbers each generated migration).',
          },
          DRY_RUN_FLAG,
        ],
      },
      {
        name: 'eql repair',
        summary:
          'Repair migrations drizzle-kit generated with an un-runnable ALTER COLUMN to an encrypted type',
        long: [
          'Sweep an existing Drizzle output directory for in-place',
          '`ALTER COLUMN ... SET DATA TYPE <eql domain>` statements — which cannot run,',
          'because Postgres has no cast from text/numeric to an EQL domain — and rewrite',
          'each into an additive encrypted column that preserves the source column.',
          '',
          'This is the same sweep `eql migration --drizzle` runs, without having to',
          'generate an EQL install migration you do not want just to trigger it.',
          '',
          'Migrations the database has already applied are reported and left alone:',
          'rewriting one would leave its .sql describing a shape that database never got',
          'from it, so a fresh CI or staging database replaying the file would silently',
          'diverge. Pass --database-url so that check can run; without it the repair',
          'proceeds and warns that applied state could not be verified. If your',
          'drizzle.config.ts overrides `migrations.table` / `migrations.schema`, name',
          'the ledger with --migrations-table — otherwise the check queries the default',
          'relation, finds nothing, and reports applied state as unverified.',
        ].join('\n'),
        examples: [
          'eql repair --drizzle',
          'eql repair --drizzle --dry-run',
          'eql repair --drizzle --out db/migrations --database-url postgres://…',
        ],
        flags: [
          {
            name: '--drizzle',
            description: 'Repair a Drizzle migration directory.',
          },
          {
            name: '--out',
            value: '<path>',
            description:
              'Directory holding the migrations to sweep. Defaults to `drizzle`; set it to match your drizzle.config.ts.',
          },
          {
            name: '--migrations-table',
            value: '<[schema.]table>',
            description:
              "Drizzle's migration ledger, when drizzle.config.ts overrides `migrations.table` / `migrations.schema`. Defaults to `drizzle.__drizzle_migrations`. Only read with --database-url.",
          },
          DRY_RUN_FLAG,
          DATABASE_URL_FLAG,
        ],
      },
      {
        name: 'eql upgrade',
        summary: 'Upgrade EQL extensions to the latest version',
        flags: [DRY_RUN_FLAG, SUPABASE_COMPAT_FLAG, DATABASE_URL_FLAG],
      },
      {
        name: 'eql status',
        summary: 'Show EQL installation status',
        flags: [DATABASE_URL_FLAG],
      },
    ],
  },
  {
    title: 'Database',
    commands: [
      {
        name: 'db validate',
        summary: 'Validate encryption schema',
        flags: [
          SUPABASE_COMPAT_FLAG,
          EXCLUDE_OPERATOR_FAMILY_FLAG,
          DATABASE_URL_FLAG,
        ],
      },
      {
        // Dispatch currently only prints a "not yet implemented" warning and
        // reads no flags — describe that rather than advertising a working
        // command with a --database-url override it never consumes.
        name: 'db migrate',
        summary: 'Run pending encrypt config migrations (not yet implemented)',
      },
      {
        name: 'db test-connection',
        summary: 'Test database connectivity',
        flags: [DATABASE_URL_FLAG],
      },
    ],
  },
  {
    title: 'Schema',
    commands: [
      {
        name: 'schema build',
        summary: 'Build an encryption schema from your database',
        flags: [SUPABASE_COMPAT_FLAG, DATABASE_URL_FLAG],
      },
    ],
  },
  {
    title: 'Encrypt',
    commands: [
      {
        // `encrypt status` / `encrypt plan` dispatch to zero-arg commands
        // (main.ts calls statusCommand()/planCommand() with no values), so they
        // take no flags — don't advertise --table/--column the CLI ignores.
        name: 'encrypt status',
        summary: 'Show per-column migration status (phase, progress, drift)',
      },
      {
        name: 'encrypt plan',
        summary: 'Diff intent (.cipherstash/migrations.json) vs observed state',
      },
      {
        name: 'encrypt backfill',
        summary: 'Resumably encrypt plaintext into the encrypted column',
        flags: [
          TABLE_FLAG,
          COLUMN_FLAG,
          {
            name: '--pk-column',
            value: '<name>',
            description: 'Primary-key column used to page through rows.',
          },
          {
            name: '--chunk-size',
            value: '<n>',
            description: 'Rows encrypted per batch.',
          },
          {
            name: '--encrypted-column',
            value: '<name>',
            description: 'Destination encrypted column.',
          },
          {
            name: '--schema-column-key',
            value: '<key>',
            description: 'Schema key identifying the column config.',
          },
          {
            name: '--confirm-dual-writes-deployed',
            description:
              'Assert the app is dual-writing before backfilling (safety gate).',
          },
          {
            name: '--force',
            description: 'Proceed past non-fatal safety checks.',
          },
        ],
      },
      {
        name: 'encrypt drop',
        summary: 'Generate a migration to drop the plaintext column',
        flags: [
          TABLE_FLAG,
          COLUMN_FLAG,
          {
            name: '--migrations-dir',
            value: '<path>',
            description: 'Directory to write the drop migration into.',
          },
        ],
      },
    ],
  },
  {
    title: 'Deployment',
    commands: [
      {
        name: 'env',
        summary: 'Mint deployment credentials and print them as env vars',
        long: [
          'Mints a fresh ZeroKMS client and a CipherStash access key from your',
          'device-code session (`stash auth login`), then prints the four env',
          'vars a deployed app needs: CS_WORKSPACE_CRN, CS_CLIENT_ID,',
          'CS_CLIENT_KEY, CS_CLIENT_ACCESS_KEY.',
          '',
          'The access key is created with the member role (the CLI never mints',
          'admin keys) and is shown exactly once — pipe the output into your',
          'deployment secret store. Creating access keys requires your user to',
          'have the admin role in the workspace.',
          '',
          'Stdout carries only the dotenv block (or the --json events);',
          'progress UI goes to stderr, so `stash env --name x > prod.env`',
          'and pipes into secret stores are safe.',
        ].join('\n'),
        examples: [
          'env --name my-app-prod',
          'env --name my-app-prod --write',
          'env --name staging --write .env.staging.local',
          'env --name edge-dev --json',
        ],
        flags: [
          {
            name: '--name',
            value: '<name>',
            description:
              'Name for the minted access key and ZeroKMS client. Prompted for interactively; required in non-interactive runs.',
          },
          {
            name: '--write',
            value: '[path]',
            description:
              'Write the vars to a file (default .env.production.local, mode 0600) instead of printing them. An existing file prompts before overwriting — and is refused non-interactively — before anything is minted.',
          },
          {
            name: '--json',
            description:
              'Emit machine-readable NDJSON (a { status: "minted" } object, or { status: "written" } with --write — deliberately secret-free since the secrets are in the file; failures are { status: "error" }). Implies no prompts.',
          },
        ],
      },
    ],
  },
]
