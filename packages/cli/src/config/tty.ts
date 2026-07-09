/**
 * Non-interactive context detection, shared so every resolver gates the same
 * way instead of each re-deriving it.
 */

/**
 * True when `CI` is set to a common truthy spelling (`true`/`1`,
 * case-insensitive) — not every CI provider sets `CI=true` exactly. Shared by
 * the region resolver (`commands/auth/region.ts`) and the DATABASE_URL resolver
 * (`config/database-url.ts`) so their non-interactive gating stays identical.
 */
export function isCiEnv(): boolean {
  const ciVar = process.env.CI?.trim()
  return ciVar !== undefined && /^(1|true)$/i.test(ciVar)
}

/**
 * True when it's safe to show an interactive clack prompt: stdin is a TTY and
 * we're not in CI. Every prompt gate (the DATABASE_URL resolver, the config
 * scaffolder, the Supabase install-mode selector) must decide this the same
 * way, so they all call here rather than re-deriving `isTTY && !CI` inline and
 * drifting apart.
 */
export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY) && !isCiEnv()
}
