/**
 * Region selection — the one interactive prompt that every auth flow (and,
 * transitively, `stash init`) hits before any network I/O.
 *
 * This module deliberately imports **no** native code (`@cipherstash/auth`).
 * The pure helpers (`normalizeRegion`, `regionSlugs`) and the resolution
 * policy (`resolveRegion`) can therefore be unit-tested under the fast
 * `vitest.config.ts` suite without loading a platform binary. `login.ts`
 * re-exports everything here so existing `import … from '../auth/login.js'`
 * call sites keep working unchanged.
 */
import * as p from '@clack/prompts'
import { messages } from '../../messages.js'

/** Env var an agent / CI job can set to skip the interactive region picker. */
export const REGION_ENV_VAR = 'STASH_REGION'

// TODO: pull from the CTS API. `value` is the canonical `<slug>.aws` form the
// auth server expects; `label` is the human-facing picker entry.
export const regions = [
  { value: 'us-east-1.aws', label: 'us-east-1 (Virginia, USA)' },
  { value: 'us-east-2.aws', label: 'us-east-2 (Ohio, USA)' },
  { value: 'us-west-1.aws', label: 'us-west-1 (California, USA)' },
  { value: 'us-west-2.aws', label: 'us-west-2 (Oregon, USA)' },
  { value: 'ap-southeast-2.aws', label: 'ap-southeast-2 (Sydney, Australia)' },
  { value: 'eu-central-1.aws', label: 'eu-central-1 (Frankfurt, Germany)' },
  { value: 'eu-west-1.aws', label: 'eu-west-1 (Dublin, Ireland)' },
]

/** The short slugs (`us-east-1`, …) — what a human types and what we echo. */
export function regionSlugs(): string[] {
  return regions.map((r) => r.value.replace(/\.aws$/, ''))
}

export interface RegionInfo {
  /** The value passed to `--region` / `STASH_REGION` (e.g. `us-east-1`). */
  slug: string
  /** Human-friendly label, including the location (e.g. `us-east-1 (Virginia, USA)`). */
  label: string
}

/**
 * The full region list as structured data. Backs `stash auth regions` — a
 * first-contact affordance so an agent (or human) can discover valid
 * `--region` values instead of learning them reactively from an error.
 */
export function regionList(): RegionInfo[] {
  return regions.map((r) => ({
    slug: r.value.replace(/\.aws$/, ''),
    label: r.label,
  }))
}

/**
 * Normalize a user-supplied region to the canonical `<slug>.aws` value the
 * auth server expects, or return `null` when it isn't a known region.
 *
 * Accepts both the short slug (`us-east-1`) and the canonical form
 * (`us-east-1.aws`), case-insensitively and whitespace-trimmed, so a value
 * copied from the picker label or an env var both resolve.
 */
export function normalizeRegion(input: string): string | null {
  const trimmed = input.trim().toLowerCase()
  if (!trimmed) return null
  const candidate = trimmed.endsWith('.aws') ? trimmed : `${trimmed}.aws`
  return regions.some((r) => r.value === candidate) ? candidate : null
}

/** True when `CI` is set to a truthy spelling. Mirrors the DATABASE_URL resolver. */
function isCiEnv(): boolean {
  const ciVar = process.env.CI?.trim()
  return ciVar !== undefined && /^(1|true)$/i.test(ciVar)
}

/**
 * The interactive region picker. Unchanged behaviour — kept as its own
 * export because the E2E cancel test targets this prompt (it runs before
 * any network I/O, so it's a deterministic assertion point).
 */
export async function selectRegion(): Promise<string> {
  const region = await p.select({
    message: messages.auth.selectRegion,
    options: regions,
  })

  if (p.isCancel(region)) {
    p.cancel(messages.auth.cancelled)
    process.exit(0)
  }

  return region
}

export interface ResolveRegionOptions {
  /** Value of `--region <slug>` if the user passed one. */
  regionFlag?: string
  /**
   * Machine-readable mode. When true we never prompt (a picker would corrupt
   * the JSON stream) and errors are emitted as a single JSON object rather
   * than pretty clack output.
   */
  json?: boolean
}

/** Report a region resolution failure as JSON or human copy, then the caller exits. */
function reportRegionError(json: boolean, code: string, message: string): void {
  if (json) {
    console.log(JSON.stringify({ status: 'error', code, message }))
  } else {
    p.log.error(message)
  }
}

/**
 * Resolve the auth region without forcing an interactive prompt.
 *
 * Precedence:
 *   1. `--region <slug>` flag (explicit override).
 *   2. `STASH_REGION` env var.
 *   3. Interactive picker — only when we have a real TTY, aren't in CI, and
 *      aren't in `--json` mode.
 *   4. Clean `exit(1)` with an actionable message (never a hang).
 *
 * An explicit-but-unknown region is a hard error (exit 1) in every mode.
 */
export async function resolveRegion(
  opts: ResolveRegionOptions = {},
): Promise<string> {
  const json = opts.json ?? false
  const explicit = (opts.regionFlag ?? process.env[REGION_ENV_VAR])?.trim()

  if (explicit) {
    const normalized = normalizeRegion(explicit)
    if (normalized) return normalized
    reportRegionError(
      json,
      'region_invalid',
      messages.auth.regionInvalid(explicit, regionSlugs()),
    )
    process.exit(1)
  }

  const isInteractive = !json && Boolean(process.stdin.isTTY) && !isCiEnv()
  if (isInteractive) return selectRegion()

  reportRegionError(
    json,
    'region_required',
    messages.auth.regionMissingNonInteractive,
  )
  process.exit(1)
}
