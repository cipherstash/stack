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
  },
  db: {
    unknownSubcommand: 'Unknown db subcommand',
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
  },
} as const
