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
 * release train makes `init` deterministic regardless of dist-tag state.
 *
 * The embed mirrors `__STASH_POSTHOG_KEY__` (see `src/telemetry/index.ts`):
 * `tsup.config.ts` reads each sibling workspace package's `package.json` at
 * build time and defines `__STASH_RUNTIME_VERSIONS__` as a JSON string. Every
 * tsup build gets it (it needs no env var, unlike the PostHog key); only
 * source-mode runs (unit tests, direct `tsx` execution) leave the identifier
 * undefined, in which case {@link pinnedSpec} degrades to the bare package
 * name — today's behaviour, and irrelevant to shipped artifacts.
 */
declare const __STASH_RUNTIME_VERSIONS__: string | undefined

/** Parse and validate the build-time embed; empty map when absent/malformed. */
function embeddedVersions(): Record<string, string> {
  if (typeof __STASH_RUNTIME_VERSIONS__ !== 'string') return {}
  try {
    const parsed: unknown = JSON.parse(__STASH_RUNTIME_VERSIONS__)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
      return {}
    const map: Record<string, string> = {}
    for (const [pkg, version] of Object.entries(parsed)) {
      if (typeof version === 'string' && version.length > 0) map[pkg] = version
    }
    return map
  } catch {
    return {}
  }
}

/** Package name → exact version from this CLI release's build. */
export const RUNTIME_PACKAGE_VERSIONS: Readonly<Record<string, string>> =
  embeddedVersions()

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
