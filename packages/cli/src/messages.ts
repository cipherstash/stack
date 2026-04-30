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
    usagePrefix: 'Usage: npx @cipherstash/cli',
    unknownCommand: 'Unknown command',
  },
  auth: {
    usagePrefix: 'Usage: npx @cipherstash/cli auth',
    unknownSubcommand: 'Unknown auth command',
    selectRegion: 'Select a region',
    cancelled: 'Cancelled.',
  },
  db: {
    unknownSubcommand: 'Unknown db subcommand',
    migrateNotImplemented:
      '"npx @cipherstash/cli db migrate" is not yet implemented.',
    /** Source labels surfaced after DATABASE_URL resolution. */
    urlResolvedFromFlag: 'Using DATABASE_URL from --database-url flag',
    urlResolvedFromSupabase: 'Using DATABASE_URL from supabase status',
    urlResolvedFromPrompt: 'Using DATABASE_URL from prompt',
    urlPromptMessage: 'Paste your DATABASE_URL',
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
