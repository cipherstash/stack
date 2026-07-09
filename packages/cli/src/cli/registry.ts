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
          'init --prisma-next',
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
            name: '--prisma-next',
            description:
              'Use Prisma Next-specific setup flow (EQL bundle installed via prisma-next migration apply).',
          },
          {
            name: '--proxy',
            description: 'Query encrypted data via CipherStash Proxy.',
          },
          {
            name: '--no-proxy',
            description: 'Query encrypted data directly via the SDK.',
            default: 'true',
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
        examples: ['plan', 'plan --target claude-code'],
        flags: [
          {
            name: '--complete-rollout',
            description:
              'Plan the entire encryption lifecycle (schema-add through drop) in one document. Skips the production-deploy gate; only safe when this database is not backing a deployed application.',
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
          {
            name: '--drizzle',
            description:
              'Generate a Drizzle migration instead of direct install (auto-detected from project).',
          },
          {
            name: '--migration',
            description:
              'Write a Supabase migration file instead of running SQL directly (requires --supabase).',
          },
          {
            name: '--direct',
            description:
              'Run the SQL directly against the database (requires --supabase; mutually exclusive with --migration).',
          },
          {
            name: '--migrations-dir',
            value: '<path>',
            description:
              'Override the Supabase migrations directory (requires --supabase).',
            default: 'supabase/migrations',
          },
          EXCLUDE_OPERATOR_FAMILY_FLAG,
          {
            name: '--eql-version',
            value: '<2|3>',
            description:
              'EQL generation to target. v3 is the native eql_v3.* domain schema (direct install only for now).',
            default: '2',
          },
          {
            name: '--latest',
            description: 'Fetch the latest EQL from GitHub (v2 only).',
          },
          {
            name: '--name',
            value: '<name>',
            description:
              'With --drizzle: name for the generated migration (defaults to a scaffold name).',
          },
          {
            name: '--out',
            value: '<path>',
            description:
              'With --drizzle: directory to write the generated migration into.',
          },
          DATABASE_URL_FLAG,
        ],
      },
      {
        name: 'eql upgrade',
        summary: 'Upgrade EQL extensions to the latest version',
        flags: [
          DRY_RUN_FLAG,
          SUPABASE_COMPAT_FLAG,
          EXCLUDE_OPERATOR_FAMILY_FLAG,
          {
            name: '--eql-version',
            value: '<2|3>',
            description: 'EQL generation to target.',
            default: '2',
          },
          {
            name: '--latest',
            description: 'Fetch the latest EQL from GitHub (v2 only).',
          },
          DATABASE_URL_FLAG,
        ],
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
        name: 'db push',
        summary:
          'Push encryption schema (writes pending if active config already exists)',
        flags: [DRY_RUN_FLAG, DATABASE_URL_FLAG],
      },
      {
        name: 'db activate',
        summary:
          'Promote pending → active without renames (use after additive db push)',
        flags: [DATABASE_URL_FLAG],
      },
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
        name: 'encrypt cutover',
        summary: 'Rename swap encrypted → primary column',
        flags: [
          TABLE_FLAG,
          COLUMN_FLAG,
          {
            name: '--proxy-url',
            value: '<url>',
            description: 'Proxy URL to verify against.',
          },
          {
            name: '--migrations-dir',
            value: '<path>',
            description: 'Directory to write the rename migration into.',
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
    title: 'Experimental',
    commands: [
      {
        name: 'env',
        summary: '(experimental) Print production env vars for deployment',
        flags: [
          {
            name: '--write',
            description: 'Write the vars to a file instead of printing them.',
          },
        ],
      },
    ],
  },
]
