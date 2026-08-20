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
 *
 * ## The second half: what must NOT be published
 *
 * The gate above answers "what is missing from npm". `publishBlockers` answers
 * the question that arrives with it — whether publishing that set produces
 * something installable — and it EXITS NON-ZERO, which is what stops the
 * release. `release.yml`'s `release` job requires `needs.gate.result ==
 * 'success'`, so a blocker here means `changeset publish` is never reached.
 *
 * It exists because `changeset publish` has no idea. In the installed 2.31.0 it
 * filters `packages.filter(pkg => !pkg.packageJson.private)`, asks npm which of
 * those versions are missing, and publishes them with `Promise.all` — no
 * dependency ordering — while `publishAPackage` RETURNS a failure rather than
 * throwing it. So a package that cannot publish does not abort the release; it
 * simply does not arrive, and every sibling that depends on it ships anyway,
 * pointing at a version nobody can install.
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

/** pnpm's in-workspace dependency protocol. */
const WORKSPACE_PROTOCOL = 'workspace:'

/** Every table a `workspace:` specifier can appear in. */
const DEPENDENCY_TABLES = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
]

/**
 * The tables a CONSUMER of the published tarball installs from.
 *
 * `devDependencies` is deliberately absent. pnpm rewrites the `workspace:`
 * specifier there too, and the rewritten range does ship inside the packed
 * `package.json` — but nothing installing the package ever resolves it, so an
 * unsatisfiable one breaks nobody. That asymmetry is live in this tree:
 * `packages/stack` declares `"@cipherstash/eql": "workspace:^"` under
 * devDependencies and is not a finding — a caret there is harmless, which is
 * why it is still written that way, while `packages/cli` and
 * `packages/stack-prisma` carry the same dependency under `dependencies` and
 * pin it with `workspace:*` so the packed range is exact.
 */
const INSTALLED_TABLES = new Set([
  'dependencies',
  'optionalDependencies',
  'peerDependencies',
])

/**
 * Packages that live in this repository but are NOT published from it, each
 * with the reason.
 *
 * WHY THIS CANNOT BE DERIVED. npm trusted publishing binds a package to a
 * repository and a workflow filename, and the registry exposes no way to ask
 * "would a publish from here be accepted?" — the provenance attestation on the
 * LAST release names the repository that made it, which is evidence about the
 * past, not permission for the next one. So the fact has to be written down,
 * and the cost of it being wrong is a release that half-publishes. Hence: one
 * entry per package, with the reason a later reader needs in order to decide
 * whether it is still true, in the shape of `EXEMPT_DECLARATIONS` in
 * `scripts/lint-no-eql-registry-pins.mjs`.
 *
 * Each entry is DELETED by the cutover that repoints its publisher — for
 * `@cipherstash/eql` that is the Phase-5 release cutover.
 *
 * DELETE IT IN THAT PR, not afterwards. An entry left behind does not fail on
 * the day it goes wrong, it fails on the next release: while the package sits
 * at a version already on npm the frozen check keeps passing, so nothing
 * notices, and the FIRST bump after the cutover blocks a release that would
 * have worked. The seven protect-ffi packages spent a cutover in exactly that
 * state — their trusted publishing moved to this repository and their entries
 * stayed here, arming this gate against the very release the move enabled.
 * `release-gate.test.mjs` now asserts their absence, so the map has a test for
 * what is NOT in it as well as what is.
 */
export const FROZEN_PUBLISHERS = new Map([
  [
    '@cipherstash/eql',
    'Still published from cipherstash/encrypt-query-language — the npm provenance on ' +
      '3.0.5 names that repository and `release.yml` here carries no NPM_TOKEN. Repointing ' +
      'is Phase 5 of docs/plans/2026-08-13-eql-monorepo-absorption.md.',
  ],
])

/**
 * The range pnpm writes into the packed `package.json` for a `workspace:`
 * specifier.
 *
 * `workspace:*` is the one worth reading twice: it becomes the dependency's
 * EXACT version, not a wildcard. That is what makes an unpublished workspace
 * dependency unsatisfiable rather than merely loose.
 *
 * Returns `null` for anything that is not the workspace protocol — a registry
 * range is npm's problem, not this gate's.
 */
export function packedRange(spec, version) {
  if (typeof spec !== 'string' || !spec.startsWith(WORKSPACE_PROTOCOL)) {
    return null
  }
  const rest = spec.slice(WORKSPACE_PROTOCOL.length)
  if (rest === '*') return version
  if (rest === '^' || rest === '~') return `${rest}${version}`
  if (rest === '') {
    throw new Error(`\`${spec}\` names no version and no alias`)
  }
  return rest
}

const VERSION =
  /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/

function parseVersion(text) {
  const match = VERSION.exec(String(text).trim())
  if (!match) return null
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    pre: match[4] ?? null,
  }
}

/** semver precedence for the prerelease field. A release outranks its prereleases. */
function comparePrerelease(a, b) {
  if (a === b) return 0
  if (a === null) return 1
  if (b === null) return -1
  const left = a.split('.')
  const right = b.split('.')
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const x = left[i]
    const y = right[i]
    if (x === undefined) return -1
    if (y === undefined) return 1
    const xNumeric = /^\d+$/.test(x)
    const yNumeric = /^\d+$/.test(y)
    if (xNumeric && yNumeric) {
      if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1
      continue
    }
    if (xNumeric !== yNumeric) return xNumeric ? -1 : 1
    if (x !== y) return x < y ? -1 : 1
  }
  return 0
}

function compareVersions(a, b) {
  for (const field of ['major', 'minor', 'patch']) {
    if (a[field] !== b[field]) return a[field] < b[field] ? -1 : 1
  }
  return comparePrerelease(a.pre, b.pre)
}

/** The exclusive upper bound of `^v` — the 0.x and 0.0.x narrowings included. */
function caretBound({ major, minor, patch }) {
  if (major > 0) return { major: major + 1, minor: 0, patch: 0, pre: null }
  if (minor > 0) return { major: 0, minor: minor + 1, patch: 0, pre: null }
  return { major: 0, minor: 0, patch: patch + 1, pre: null }
}

const RANGE =
  /^(\^|~)?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/

/**
 * Whether `version` satisfies `range`, for the range shapes `packedRange` can
 * produce.
 *
 * WRITTEN OUT RATHER THAN DEPENDED ON, for the reason in the `NODE BUILTINS
 * ONLY` note below: this file runs in a job with no `node_modules`, and adding
 * `semver` to it would oblige a cold full-workspace install on every push to
 * main just to compare two version strings.
 *
 * The scope is exactly what pnpm writes — an exact pin, `^`, `~`, and `*` —
 * and ANYTHING ELSE THROWS. A general range parser written by hand is how a
 * gate quietly starts answering the wrong question; a range this cannot read is
 * a release that stops until someone extends it, which is the safe direction.
 *
 * The prerelease rule is not decoration. npm carries `@cipherstash/eql`
 * prereleases (`3.0.0-alpha.2`, `3.0.1-alpha.0`, …), and under a naive
 * comparison some of them fall inside `^3.0.5`'s window — which would report
 * that range as satisfiable and wave the entire defect through. Per semver, a
 * prerelease satisfies a range only when the range's own bound is a prerelease
 * of the same major.minor.patch.
 */
export function satisfies(version, range) {
  const text = String(range).trim()
  const parsed = parseVersion(version)
  if (parsed === null) {
    throw new Error(`unparsable version \`${version}\``)
  }
  if (text === '*') return parsed.pre === null

  const match = RANGE.exec(text)
  if (!match) {
    throw new Error(
      `unsupported version range \`${range}\` — this gate reads exact, \`^\`, \`~\` and ` +
        '`*` only, which is everything pnpm writes for a `workspace:` specifier. Extend ' +
        '`satisfies` rather than loosening it.',
    )
  }
  const [, operator, bound] = match
  const lower = parseVersion(bound)

  if (
    parsed.pre !== null &&
    !(
      lower.pre !== null &&
      parsed.major === lower.major &&
      parsed.minor === lower.minor &&
      parsed.patch === lower.patch
    )
  ) {
    return false
  }

  if (!operator) return compareVersions(parsed, lower) === 0
  if (compareVersions(parsed, lower) < 0) return false
  const upper =
    operator === '^'
      ? caretBound(lower)
      : { major: lower.major, minor: lower.minor + 1, patch: 0, pre: null }
  return compareVersions(parsed, upper) < 0
}

/**
 * Everything that must not be published, as data.
 *
 * Two checks, one pass. `lookup` is the same injected registry reader
 * `unpublished` takes, so a failure propagates rather than reading as "nothing
 * blocks" — the header's rule, applied here too.
 *
 * CHECK A — a FROZEN package whose committed version is absent from npm.
 * `changeset publish` will attempt it (it publishes on registry state alone)
 * and the attempt is rejected, without stopping anything else.
 *
 * CHECK B — a published package's runtime `workspace:` range that no version on
 * npm satisfies. Three verdicts, and the middle one is what makes this usable:
 *
 *   * the dependency is PRIVATE, or the range cannot be satisfied even by the
 *     workspace's own version (a hand-written `workspace:^2.0.0` on a 1.x
 *     member) — a blocker either way, since no publish will ever fix it;
 *   * the dependency is FROZEN — a blocker, because the version that would
 *     satisfy the range is precisely the one that cannot be published;
 *   * otherwise the dependency is simply being published in this same release,
 *     which is EVERY ordinary release of this repo. `@cipherstash/stack-drizzle`
 *     depends on `@cipherstash/stack` at `workspace:*`, they share a fixed
 *     group, and at gate time neither is on npm yet. Blocking that would freeze
 *     the repository permanently while catching nothing.
 *
 * THE THIRD VERDICT IS NOT SAFE, IT IS MERELY NOT WORSE. Changesets publishes
 * with `Promise.all`, so within one release a dependent can reach npm before
 * its dependency, and for that window an install resolves a range whose target
 * is not there yet. Nothing here can close it: the gate has no ordering to
 * check, and refusing the case outright is the freeze above. What it CAN do is
 * separate the transient window from the permanent hole — a dependency that
 * cannot publish at all — which is the whole difference between the two, and
 * the only one either side of it gets wrong in the same direction.
 */
export function publishBlockers({
  manifests,
  lookup,
  frozen = FROZEN_PUBLISHERS,
}) {
  const cache = new Map()
  const versionsOf = (name) => {
    if (!cache.has(name)) cache.set(name, lookup(name))
    return cache.get(name) ?? []
  }
  const byName = new Map(manifests.map((manifest) => [manifest.name, manifest]))
  const published = manifests.filter((manifest) => !manifest.private)
  const blockers = []

  for (const { name, version } of published) {
    if (frozen.has(name) && !versionsOf(name).includes(version)) {
      blockers.push({
        kind: 'frozen-publisher',
        package: name,
        version,
        reason: frozen.get(name),
      })
    }
  }

  for (const manifest of published) {
    for (const dep of manifest.workspaceDeps ?? []) {
      if (!INSTALLED_TABLES.has(dep.table)) continue

      const target = byName.get(dep.name)
      if (!target) {
        // pnpm cannot resolve this at pack time either, but it is worth a
        // verdict of its own rather than an unhandled throw below.
        blockers.push({
          kind: 'unknown-workspace-dependency',
          package: manifest.name,
          dependency: dep.name,
          table: dep.table,
        })
        continue
      }

      const range = packedRange(dep.spec, target.version)
      const finding = {
        package: manifest.name,
        dependency: dep.name,
        table: dep.table,
        range,
      }

      if (!satisfies(target.version, range)) {
        blockers.push({ ...finding, kind: 'unsatisfiable-range' })
        continue
      }
      // BEFORE the registry, not after. Privacy is a fact about this tree and
      // no registry answer revises it: the dependency will not be packed by
      // this release or any later one. A package that was published and then
      // marked private keeps every version npm ever accepted, so the lookup
      // goes on answering — and read first, that answer disarms the check.
      if (target.private) {
        blockers.push({ ...finding, kind: 'private-dependency' })
        continue
      }
      if (
        versionsOf(dep.name).some((candidate) => satisfies(candidate, range))
      ) {
        continue
      }
      if (frozen.has(dep.name)) {
        blockers.push({
          ...finding,
          kind: 'frozen-dependency',
          reason: frozen.get(dep.name),
        })
      }
    }
  }

  return blockers
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
    .map((manifest) => ({
      name: manifest.name,
      version: manifest.version,
      private: Boolean(manifest.private),
      // Carried alongside, not looked up later: `publishBlockers` has to answer
      // questions about a manifest it was not handed the path to, and the four
      // tables are read here once rather than re-globbed per dependency.
      // devDependencies are INCLUDED — `INSTALLED_TABLES` is what narrows them,
      // and keeping the raw set means the narrowing is a decision the tests can
      // see rather than an absence they cannot.
      workspaceDeps: DEPENDENCY_TABLES.flatMap((table) =>
        Object.entries(manifest[table] ?? {})
          .filter(
            ([, spec]) =>
              typeof spec === 'string' && spec.startsWith(WORKSPACE_PROTOCOL),
          )
          .map(([name, spec]) => ({ table, name, spec })),
      ),
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

/**
 * A blocker list, turned into the text that explains it.
 *
 * Separate and exported so the message itself is testable — it is the entire
 * product of a failing gate, and a release stopped by a message nobody can act
 * on is a release stopped twice.
 */
export function reportBlockers(blockers) {
  const lines = blockers.map((blocker) => {
    switch (blocker.kind) {
      case 'frozen-publisher':
        return (
          `  ${blocker.package}@${blocker.version} is not on npm, and cannot be published ` +
          `from this repository.\n      ${blocker.reason}`
        )
      case 'frozen-dependency':
        return (
          `  ${blocker.package} depends on ${blocker.dependency}@${blocker.range} ` +
          `[${blocker.table}], which no published version satisfies.\n` +
          `      ${blocker.reason}`
        )
      case 'private-dependency':
        return (
          `  ${blocker.package} depends on ${blocker.dependency}@${blocker.range} ` +
          `[${blocker.table}], and that package is private — it has no registry entry at all.`
        )
      case 'unsatisfiable-range':
        return (
          `  ${blocker.package} declares ${blocker.dependency}@${blocker.range} ` +
          `[${blocker.table}], which the workspace's own version does not satisfy.`
        )
      default:
        return (
          `  ${blocker.package} declares a \`workspace:\` dependency on ` +
          `${blocker.dependency} [${blocker.table}], which is not a workspace member.`
        )
    }
  })

  // The version to publish is READ OFF THE FINDINGS, never written down here.
  // The text used to name 3.0.5 outright: true when drafted, false one release
  // later, and latent in between because this function runs only when
  // something is blocked — so the wrong instruction would print for the first
  // time to whoever was already stuck.
  const publisher = blockers.find((b) => b.kind === 'frozen-publisher')
  const dependency = blockers.find((b) => b.kind === 'frozen-dependency')
  const target = publisher
    ? `${publisher.package}@${publisher.version}`
    : dependency
      ? `${dependency.dependency}@${dependency.range}`
      : null

  // No frozen finding means publishing nothing fixes this — a private or
  // unsatisfiable dependency is a manifest to change, not a release to make —
  // so the first way out names no version rather than an irrelevant one.
  const publishStep = target
    ? '  1. Publish the frozen package. For @cipherstash/eql that is the Phase 5\n' +
      '     cutover in docs/plans/2026-08-13-eql-monorepo-absorption.md: repoint\n' +
      '     npm trusted publishing to cipherstash/stack and release the version\n' +
      `     above — ${target}.\n` +
      '     Every finding then clears on its own, with no further change here.\n'
    : '  1. Publish the frozen package. Nothing above is frozen, so this way out\n' +
      '     is not available: the findings are manifests to fix, not a release to\n' +
      '     make.\n'

  return (
    '\nThis release would publish packages that cannot be installed:\n\n' +
    `${lines.join('\n')}\n\n` +
    '`changeset publish` will not catch any of this. It publishes every public\n' +
    'workspace package whose version is absent from npm — changeset or no\n' +
    'changeset — with no dependency ordering, and a failed publish returns a\n' +
    'result rather than throwing, so it does not stop the packages that depend\n' +
    'on it. The tarballs would go out and the failure would surface in a\n' +
    "consumer's `npm install`.\n\n" +
    'There are exactly two ways past this, and neither is editing this gate:\n\n' +
    publishStep +
    '  2. Do not release. Reverting the workspace version to the one already on\n' +
    '     npm also clears it, at the cost of the bump.\n\n' +
    'Weakening the check is not a third option — the ranges above are what ends\n' +
    'up in a published tarball either way.\n'
  )
}

function main() {
  const manifests = workspaceManifests()
  // One cache across both questions: `unpublished` and `publishBlockers` ask
  // the registry about overlapping sets, and `npm view` is a network round trip
  // per package in a job that may not cache anything.
  const cache = new Map()
  const lookup = (name) => {
    if (!cache.has(name)) cache.set(name, npmVersions(name))
    return cache.get(name)
  }

  const missing = unpublished(manifests, lookup)
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

  // AFTER the outputs are written, and before anything acts on them. The
  // outputs are diagnostic — the job log should still say what was missing even
  // on the run that refuses to publish it — while the exit code is what
  // actually stops the release: `release.yml`'s `release` job requires
  // `needs.gate.result == 'success'`, so a non-zero exit here skips the job
  // that runs `changeset publish` (and, through the same `needs`, the FFI
  // matrix). Asserted by scripts/__tests__/release-gate.test.mjs.
  const blockers = publishBlockers({ manifests, lookup })
  if (blockers.length > 0) {
    console.error(reportBlockers(blockers))
    process.exit(1)
  }
}

// Importable without running: the unit tests exercise the two pure functions
// above, and neither the workspace scan nor the registry lookups may fire on
// import.
if (process.argv[1] === fileURLToPath(import.meta.url)) main()
