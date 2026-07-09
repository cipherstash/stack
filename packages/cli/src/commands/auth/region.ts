/**
 * Region selection — the one interactive prompt that every auth flow (and,
 * transitively, `stash init`) hits before any network I/O.
 *
 * This module deliberately imports **no** native code (`@cipherstash/auth`).
 * The pure helpers (`normalizeRegion`, `regionSlugs`) and the resolution
 * policy (`resolveRegion`) can therefore be unit-tested under the fast
 * `vitest.config.ts` suite without loading a platform binary. Auth call sites
 * (`auth/index.ts`, the init authenticate step) import directly from here.
 */
import * as p from '@clack/prompts'
import { isCiEnv } from '../../config/tty.js'
import { messages } from '../../messages.js'
import { emitJsonError } from './events.js'

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
  return regionList().map((r) => r.slug)
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

/** Report a region resolution failure as JSON or human copy, then exit non-zero. */
export function failRegion(
  json: boolean,
  code: string,
  message: string,
): never {
  if (json) {
    emitJsonError(code, message)
  } else {
    p.log.error(message)
  }
  process.exit(1)
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
  // Treat an empty / whitespace `--region` as "not provided" so the
  // STASH_REGION fallback still applies — matches the `if (values.region)`
  // guard `init` uses, so both entry points agree.
  const flag = opts.regionFlag?.trim()
  const explicit = flag || process.env[REGION_ENV_VAR]?.trim()

  if (explicit) {
    const normalized = normalizeRegion(explicit)
    if (normalized) return normalized
    failRegion(
      json,
      'region_invalid',
      messages.auth.regionInvalid(explicit, regionSlugs()),
    )
  }

  const isInteractive = !json && Boolean(process.stdin.isTTY) && !isCiEnv()
  if (isInteractive) return selectRegion()

  failRegion(json, 'region_required', messages.auth.regionMissingNonInteractive)
}
