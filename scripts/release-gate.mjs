/**
 * Decide what a push to `main` still has to publish.
 *
 * THE GATE IS REGISTRY STATE, NOT CHANGESET ANALYSIS. "No unconsumed
 * `.changeset/*.md`" is also true for an ordinary docs commit and for the very
 * next commit after a release, so gating on it would fire the sixteen-minute
 * native matrix routinely. Asking npm what is actually missing is exact, and it
 * is the same question `changeset publish` asks itself, per package.
 *
 * THIS IS LOAD-BEARING, not a cost control, and an earlier draft of the plan had
 * that backwards. A false negative — reporting `ffi=false` while those versions
 * are in fact unpublished — skips the artifact build and the FFI publish, and
 * `changeset publish` then finds the same versions unpublished and packs the six
 * platform workspaces FROM THE WORKSPACE, where `index.node` is a build output
 * nobody produced. Six binary-less tarballs go to npm and every consumer's
 * install resolves a wrapper whose binding cannot load.
 *
 * So every failure mode here fails loudly: a lookup that errors for any reason
 * other than a 404 throws rather than being read as "already published".
 */
import { execFileSync } from 'node:child_process'
import { appendFileSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../..')

/**
 * The wrapper and its six platform packages all start with this, so one prefix
 * separates the two publisher branches.
 */
export const FFI_PREFIX = '@cipherstash/protect-ffi'

/**
 * Names whose committed version is absent from the registry.
 *
 * `lookup(name)` returns the published versions, or `null` when the package
 * does not exist at all (a 404 — a first publish). Anything else it throws
 * propagates: see the header.
 */
export function unpublished(manifests, lookup) {
  const missing = []
  for (const { name, version, private: isPrivate } of manifests) {
    // Before the lookup, not after: a private package has no registry entry, so
    // asking costs a round trip to be told 404 and then ignored.
    if (isPrivate) continue
    const published = lookup(name)
    if (published === null || !published.includes(version)) missing.push(name)
  }
  return missing
}

/** Which publisher branches the unpublished set requires. */
export function classify(names) {
  return {
    ffi: names.some((name) => name.startsWith(FFI_PREFIX)),
    js: names.some((name) => !name.startsWith(FFI_PREFIX)),
  }
}

/**
 * Every workspace manifest, read from disk.
 *
 * `pnpm ls -r` enumerates the workspace rather than this file listing it, so a
 * package added tomorrow is gated the day it lands. The root manifest is
 * dropped: it is private and publishes nothing.
 */
export function workspaceManifests() {
  const entries = JSON.parse(
    execFileSync('pnpm', ['ls', '-r', '--depth', '-1', '--json'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
    }),
  )
  return entries
    .filter((entry) => entry.path !== REPO_ROOT)
    .map((entry) =>
      JSON.parse(readFileSync(join(entry.path, 'package.json'), 'utf8')),
    )
    .map(({ name, version, private: isPrivate }) => ({
      name,
      version,
      private: Boolean(isPrivate),
    }))
}

/**
 * Registry lookup. `null` on a 404 so a first publish is not mistaken for
 * "published"; everything else throws.
 */
export function npmVersions(name) {
  try {
    return JSON.parse(
      execFileSync('npm', ['view', name, 'versions', '--json'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    )
  } catch (err) {
    const text = `${err.stdout ?? ''}${err.stderr ?? ''}`
    if (text.includes('E404')) return null
    throw new Error(`npm view ${name} failed: ${text.trim() || err.message}`)
  }
}

function main() {
  const manifests = workspaceManifests()
  const missing = unpublished(manifests, npmVersions)
  const { ffi, js } = classify(missing)

  console.log(
    missing.length
      ? `unpublished: ${missing.join(', ')}`
      : 'nothing to publish — every committed version is on the registry',
  )
  console.log(`ffi=${ffi} js=${js}`)

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `ffi=${ffi}\njs=${js}\nunpublished=${missing.join(' ')}\n`,
    )
  }
}

// Importable without running: the unit tests exercise the two pure functions
// above, and neither the workspace scan nor the registry lookups may fire on
// import.
if (process.argv[1] === fileURLToPath(import.meta.url)) main()
