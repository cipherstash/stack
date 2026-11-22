// Run a command (in practice `changeset version`) with each changesets `fixed`
// group's own `workspace:` peer dependencies hidden, and put them back after.
//
//   node scripts/with-lockstep-peers-hidden.mjs changeset version
//
// Why this exists. `@cipherstash/auth` declares its six platform packages as
// optional `peerDependencies` at `workspace:*`, deliberately: Deno's resolver
// (and Supabase Edge Runtime) treats a missing `optionalDependencies` platform
// package as a fatal graph error, so they are peers, and `pnpm pack` rewrites
// `workspace:*` to the exact version so the wrapper and its binaries stay
// paired. All seven version together as one changesets `fixed` group.
//
// Changesets has a rule for peers: when a peer dependency gets a minor or
// major bump that leaves the dependent's declared range, the DEPENDENT gets a
// MAJOR bump. It reads `workspace:*` as "exactly the current version", so any
// minor of a platform package is out of range — and the fixed group gives the
// platform packages a minor whenever the wrapper has one. A `minor` changeset
// on `@cipherstash/auth` therefore planned 0.44.1 -> 1.0.0 for all seven
// packages, with no changeset anywhere asking for a major. A patch is exempt
// from the rule, which is how 0.44.1 itself went out unnoticed.
//
// Inside a fixed group that rule is a false positive. The range and the
// version move together by construction: the group is versioned as one, and
// the `workspace:` range is rewritten from that same version at pack time.
// The peer can never be out of range in what is published.
//
// Changesets has no switch for this (`onlyUpdatePeerDependentsWhenOutOfRange`
// is already on, and is what makes `workspace:*` "out of range"). So the peers
// are taken out of the manifest for the duration of the command and restored
// afterwards, including when the command fails or is interrupted. Nothing
// about the manifest that is committed, packed or published changes; only what
// Changesets sees while it computes the plan.
//
// Only a fixed group's peers on its OWN members, at a `workspace:` range, are
// hidden. A peer on anything else (`@tanstack/react-start`, say) is left
// alone, and so is a peer between packages that do not version together —
// there the rule is doing its job.

import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
// Changesets' own modules, so this sees the workspace and the `fixed` groups
// exactly as `changeset version` will. They are dependencies of the CLI, not
// of this repo, hence the second resolver.
const changesetsRequire = createRequire(
  require.resolve('@changesets/cli/package.json'),
)

/**
 * The peers of `manifest` to hide: those naming another member of its fixed
 * group at a `workspace:` range.
 *
 * @param {{ name?: string, peerDependencies?: Record<string, string> }} manifest
 * @param {ReadonlyArray<ReadonlyArray<string>>} fixedGroups
 * @returns {string[]}
 */
export function lockstepPeers(manifest, fixedGroups) {
  const group = fixedGroups.find((names) => names.includes(manifest.name))
  if (!group) return []
  return Object.entries(manifest.peerDependencies ?? {})
    .filter(
      ([name, range]) =>
        name !== manifest.name &&
        group.includes(name) &&
        typeof range === 'string' &&
        range.startsWith('workspace:'),
    )
    .map(([name]) => name)
}

/** Serialise `manifest` the way `text` was written: same indent, same ending. */
function serialise(manifest, text) {
  const indent = /^([ \t]+)\S/m.exec(text)?.[1] ?? 2
  return (
    JSON.stringify(manifest, null, indent) + (text.endsWith('\n') ? '\n' : '')
  )
}

/**
 * `text` (a package.json) without the peers in `names`. The `peerDependencies`
 * key itself stays, even when empty, so it keeps its place in the file.
 *
 * @param {string} text
 * @param {ReadonlyArray<string>} names
 * @returns {string}
 */
export function withoutPeers(text, names) {
  const manifest = JSON.parse(text)
  for (const name of names) delete manifest.peerDependencies[name]
  return serialise(manifest, text)
}

/**
 * `current` (the package.json as the command left it) with the peers in
 * `names` put back from `original`, in their original order. Everything else
 * `current` holds is kept: the version the command wrote, and any range it
 * rewrote on a peer that was not hidden.
 *
 * @param {string} current
 * @param {string} original
 * @param {ReadonlyArray<string>} names
 * @returns {string}
 */
export function withPeersRestored(current, original, names) {
  const manifest = JSON.parse(current)
  const before = JSON.parse(original).peerDependencies ?? {}
  const now = manifest.peerDependencies ?? {}
  const restored = {}
  for (const [name, range] of Object.entries(before)) {
    restored[name] = names.includes(name) ? range : (now[name] ?? range)
  }
  for (const [name, range] of Object.entries(now)) {
    if (!(name in restored)) restored[name] = range
  }
  manifest.peerDependencies = restored
  return serialise(manifest, current)
}

/**
 * Hide the lockstep peers of every package under `root`. Returns what was
 * hidden, for {@link restoreLockstepPeers}.
 *
 * @param {string} root  The workspace root (where `.changeset/` lives).
 * @returns {Promise<Array<{ manifestPath: string, original: string, names: string[] }>>}
 */
export async function hideLockstepPeers(root) {
  const { getPackagesSync } = changesetsRequire('@manypkg/get-packages')
  const { read } = changesetsRequire('@changesets/config')
  const packages = getPackagesSync(root)
  const { fixed } = await read(root, packages)

  const hidden = []
  for (const { dir, packageJson } of packages.packages) {
    const names = lockstepPeers(packageJson, fixed)
    if (names.length === 0) continue
    const manifestPath = join(dir, 'package.json')
    const original = readFileSync(manifestPath, 'utf8')
    writeFileSync(manifestPath, withoutPeers(original, names))
    hidden.push({ manifestPath, original, names })
  }
  return hidden
}

/**
 * Put back what {@link hideLockstepPeers} hid, and check that it is back.
 *
 * @param {Array<{ manifestPath: string, original: string, names: string[] }>} hidden
 */
export function restoreLockstepPeers(hidden) {
  for (const { manifestPath, original, names } of hidden) {
    const current = readFileSync(manifestPath, 'utf8')
    writeFileSync(manifestPath, withPeersRestored(current, original, names))

    const peers = JSON.parse(
      readFileSync(manifestPath, 'utf8'),
    ).peerDependencies
    const before = JSON.parse(original).peerDependencies
    const missing = names.filter((name) => peers?.[name] !== before[name])
    if (missing.length > 0) {
      throw new Error(
        `${manifestPath}: could not restore the peer dependencies ${missing.join(', ')}. ` +
          'Do not commit this file as it is: the published package would lose the exact-version ' +
          'peers that pair it with its platform binaries.',
      )
    }
  }
}

async function main() {
  const argv = process.argv.slice(2)
  if (argv[0] === '--') argv.shift()
  const [command, ...args] = argv
  if (!command) {
    console.error(
      'usage: node scripts/with-lockstep-peers-hidden.mjs <command> [args...]',
    )
    process.exit(2)
  }

  const root = process.cwd()
  const hidden = await hideLockstepPeers(root)
  for (const { manifestPath, names } of hidden) {
    const file = relative(root, manifestPath).split(sep).join('/')
    console.log(
      `hiding ${names.length} lockstep peer(s) of ${file} while \`${command} ${args.join(' ')}\` runs`,
    )
  }

  let restored = false
  const restore = () => {
    if (restored) return
    restored = true
    restoreLockstepPeers(hidden)
  }
  // With no handler, a signal ends this process without running `finally`,
  // and leaves the manifests without their peers. With one, Node defers it
  // until the synchronous child below has returned.
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(signal, () => {
      restore()
      process.exit(1)
    })
  }

  let result
  try {
    result = spawnSync(command, args, { cwd: root, stdio: 'inherit' })
  } finally {
    restore()
  }
  if (hidden.length > 0) console.log('restored the lockstep peers')
  if (result.error) throw result.error
  process.exit(result.status ?? 1)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main()
