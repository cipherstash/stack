/**
 * The exact versions of the CipherStash runtime packages this CLI release was
 * built alongside, embedded at build time.
 *
 * Why this exists (#661): `stash init` used to install runtime packages
 * unpinned (`npm install @cipherstash/stack`), which resolves whatever the
 * `latest` dist-tag points at. During a pre-release window dist-tags lag or
 * point at placeholders (`@cipherstash/stack-drizzle@latest` was the empty
 * `0.0.0`; `@cipherstash/stack@latest` a stale `0.19.0`), so `init` silently
 * delivered a *different release than the CLI running it* — broken `/v3`
 * imports, and eval/agent runs that thought they were testing an rc while
 * exercising the old stable. Pinning to the versions from this CLI's own
 * release train (see `src/release-train.ts`) makes `init` deterministic
 * regardless of dist-tag state.
 *
 * The embed mirrors `__STASH_POSTHOG_KEY__` (see `src/telemetry/index.ts`):
 * `tsup.config.ts` reads each release-train package's `package.json` at
 * build time and defines `__STASH_RUNTIME_VERSIONS__` as a JSON string. Every
 * tsup build gets it (it needs no env var, unlike the PostHog key); only
 * source-mode runs (unit tests, direct `tsx` execution) leave the identifier
 * undefined, in which case {@link pinnedSpec} degrades to the bare package
 * name — today's behaviour, and irrelevant to shipped artifacts.
 *
 * Failure policy: an ABSENT embed is legitimate (source mode) and yields an
 * empty map. A PRESENT-but-malformed embed is a build defect and THROWS —
 * degrading it silently to `{}` would quietly reintroduce unpinned installs,
 * the exact regression this module exists to prevent, with no signal anywhere.
 */
declare const __STASH_RUNTIME_VERSIONS__: string | undefined

/**
 * Parse the build-time embed. `undefined` (source mode — no embed) → empty
 * map. A present but malformed value (unparseable, wrong shape, non-string
 * versions) is a build defect: throw loudly instead of degrading to unpinned
 * installs. Exported for direct unit testing.
 */
export function parseEmbeddedVersions(
  raw: string | undefined,
): Record<string, string> {
  if (raw === undefined) return {}
  const fail = (why: string): never => {
    throw new Error(
      `stash build defect: __STASH_RUNTIME_VERSIONS__ is ${why}. ` +
        'This binary cannot know which package versions to pin and will not ' +
        'fall back to unpinned installs (#661) — rebuild the CLI.',
    )
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return fail('not valid JSON')
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
    return fail('not a plain object')
  for (const [pkg, version] of Object.entries(parsed)) {
    if (typeof version !== 'string' || version.length === 0)
      return fail(`missing a usable version for "${pkg}"`)
  }
  return parsed as Record<string, string>
}

/** Package name → exact version from this CLI release's build. */
export const RUNTIME_PACKAGE_VERSIONS: Readonly<Record<string, string>> =
  parseEmbeddedVersions(
    typeof __STASH_RUNTIME_VERSIONS__ === 'string'
      ? __STASH_RUNTIME_VERSIONS__
      : undefined,
  )

/**
 * The version of `pkg` this CLI release expects, or `undefined` when the
 * package isn't part of the release train (or the build embed is absent).
 */
export function expectedVersion(
  pkg: string,
  versions: Readonly<Record<string, string>> = RUNTIME_PACKAGE_VERSIONS,
): string | undefined {
  return versions[pkg]
}

/**
 * The install specifier for `pkg`, pinned to this release's version when
 * known: `@cipherstash/stack` → `@cipherstash/stack@1.0.0-rc.2`. Falls back
 * to the bare name when no version is embedded, preserving the old behaviour
 * for source-mode runs.
 */
export function pinnedSpec(
  pkg: string,
  versions: Readonly<Record<string, string>> = RUNTIME_PACKAGE_VERSIONS,
): string {
  const version = expectedVersion(pkg, versions)
  return version ? `${pkg}@${version}` : pkg
}

/**
 * Compare two release-train version strings per semver precedence (§11):
 * numeric core compared numerically, then prerelease identifiers dot-by-dot
 * (numeric < alphanumeric; a release outranks any of its prereleases).
 * Returns -1 / 0 / 1 for a < b / a == b / a > b.
 *
 * Deliberately NOT a full semver implementation — no ranges, no build
 * metadata — just enough to order the versions this repo publishes
 * (`x.y.z` and `x.y.z-rc.n`), so the skew warning can tell "behind" from
 * "ahead" without adding a dependency to the CLI.
 *
 * A version that isn't strictly `digits.digits.digits` with an optional
 * well-formed prerelease (`v1.0.0`, `1.0.x`, `1.0`, `1.0.0-`, `1.0.0beta`,
 * `1.0.0-rc.2+sha` — build metadata deliberately rejected, and any other
 * garbage from a corrupt manifest) is NOT COMPARABLE: return `0` rather
 * than a partially-parsed order. Callers classify non-ahead as behind, so
 * an unparseable installed version gets the safe treatment (align/reinstall
 * guidance) instead of being silently promoted to "newer, leave it".
 */
/** Exactly three numeric core segments, optional dot-separated prerelease
 * identifiers (each non-empty alphanumeric/hyphen). No build metadata: `+`
 * fails the shape and the version is treated as not comparable — the safe
 * direction — rather than mis-ordered by an identifier like `2+sha`. */
const VERSION_SHAPE = /^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/

export function compareVersions(a: string, b: string): -1 | 0 | 1 {
  if (!VERSION_SHAPE.test(a) || !VERSION_SHAPE.test(b)) return 0
  const parse = (v: string) => {
    const [core, ...pre] = v.split('-')
    return {
      core: core.split('.').map((n) => Number.parseInt(n, 10)),
      pre: pre.join('-'), // prerelease may itself contain '-'
    }
  }
  const pa = parse(a)
  const pb = parse(b)
  for (let i = 0; i < 3; i++) {
    // The shape gate guarantees exactly three numeric segments.
    const da = pa.core[i] as number
    const db = pb.core[i] as number
    if (da !== db) return da < db ? -1 : 1
  }
  // Same core: a release (no prerelease) outranks any prerelease of it.
  if (!pa.pre && !pb.pre) return 0
  if (!pa.pre) return 1
  if (!pb.pre) return -1
  const ia = pa.pre.split('.')
  const ib = pb.pre.split('.')
  for (let i = 0; i < Math.max(ia.length, ib.length); i++) {
    const xa = ia[i]
    const xb = ib[i]
    // Fewer identifiers sorts lower when all preceding ones are equal.
    if (xa === undefined) return -1
    if (xb === undefined) return 1
    const na = /^\d+$/.test(xa) ? Number.parseInt(xa, 10) : undefined
    const nb = /^\d+$/.test(xb) ? Number.parseInt(xb, 10) : undefined
    if (na !== undefined && nb !== undefined) {
      if (na !== nb) return na < nb ? -1 : 1
    } else if (na !== undefined) {
      return -1 // numeric identifiers sort below alphanumeric ones
    } else if (nb !== undefined) {
      return 1
    } else if (xa !== xb) {
      return xa < xb ? -1 : 1
    }
  }
  return 0
}
