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
import { appendFileSync, globSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(import.meta.dirname, '..')

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
 * The `packages:` globs from `pnpm-workspace.yaml`, parsed without a YAML
 * library.
 *
 * NODE BUILTINS ONLY, DELIBERATELY. This script needs nothing installed, and
 * that is the whole cost of the job it runs in: the gate fires on EVERY push to
 * main, and one `import yaml from 'js-yaml'` obliges that job to do a cold
 * full-workspace install (no caching is permitted in a publishing workflow)
 * before it can answer a question that is sitting in the tree. An earlier
 * draft argued exactly that against `pnpm ls -r` and then paid the same cost
 * for the parse.
 *
 * The block is a flat sequence of scalars, so the parse is a block scan rather
 * than a YAML implementation — and `release-gate.test.mjs` pins the result
 * against `js-yaml` reading the same file, so a `pnpm-workspace.yaml` written
 * in a shape this does not handle fails a unit test on the pull request rather
 * than silently narrowing the gate.
 *
 * Narrowing is the failure that matters: a pattern dropped here is a package
 * never looked up, reported as "nothing to publish", and then published
 * binary-less by `changeset publish`. So an empty result throws.
 */
export function workspacePackagePatterns(source) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => /^packages:\s*(#.*)?$/.test(line))
  if (start === -1)
    throw new Error('pnpm-workspace.yaml has no `packages:` key')

  const patterns = []
  for (const line of lines.slice(start + 1)) {
    if (/^\s*(#.*)?$/.test(line)) continue
    // A non-indented line ends the block: the next top-level key.
    if (!/^\s/.test(line)) break
    const item = line.match(/^\s+-\s+(['"]?)(.+?)\1\s*(?:#.*)?$/)
    if (!item) {
      throw new Error(
        `unparsable \`packages:\` entry in pnpm-workspace.yaml: ${line}`,
      )
    }
    patterns.push(item[2])
  }

  if (patterns.length === 0) {
    throw new Error('pnpm-workspace.yaml lists no `packages:` patterns')
  }
  return patterns
}

/**
 * Every workspace manifest, read from disk.
 *
 * Resolved from `pnpm-workspace.yaml`'s own globs rather than by listing
 * packages here, so a package added tomorrow is gated the day it lands — and
 * read directly rather than through `pnpm ls -r`, which needs an installed
 * `node_modules` to answer.
 */
export function workspaceManifests() {
  const patterns = workspacePackagePatterns(
    readFileSync(join(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8'),
  ).map((pattern) => `${pattern}/package.json`)

  const manifests = globSync(patterns, { cwd: REPO_ROOT })
    .sort()
    .map((relative) =>
      JSON.parse(readFileSync(join(REPO_ROOT, relative), 'utf8')),
    )
    .map(({ name, version, private: isPrivate }) => ({
      name,
      version,
      private: Boolean(isPrivate),
    }))

  // Same reasoning as the empty-pattern throw: no manifests is indistinguishable
  // from "everything is published" downstream, and it is the reading that skips
  // the artifact build.
  if (manifests.length === 0) {
    throw new Error(
      `no workspace manifests matched ${patterns.join(', ')} under ${REPO_ROOT}`,
    )
  }
  return manifests
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

  // `ffi` and `js` only: the unpublished list was written here too and no job
  // ever declared it as an output, so it was reachable by nothing. The
  // `console.log` above is where that list is actually read, in the job log.
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `ffi=${ffi}\njs=${js}\n`)
  }
}

// Importable without running: the unit tests exercise the two pure functions
// above, and neither the workspace scan nor the registry lookups may fire on
// import.
if (process.argv[1] === fileURLToPath(import.meta.url)) main()
