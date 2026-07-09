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
  },
  eql: {
    unknownSubcommand: 'Unknown eql subcommand',
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
} as const
