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
