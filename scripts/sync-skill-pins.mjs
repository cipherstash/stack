/**
 * Move the release-train version pins in `skills/` to the versions in the tree.
 *
 * `skills/` ships inside the `stash` tarball verbatim, and no build step
 * rewrites a version inside it, so a pin such as `npx --package=stash@1.2.0`
 * keeps telling customers to install the previous release.
 * `release-train.test.ts` fails a tree whose `stash-cli` pin is not the
 * `stash` version. People moved the pins by hand in each Version Packages PR:
 * #928 and #938 did, and #1020 did not, because no CI ran on it.
 *
 * This runs from the root `version` script, right after `changeset version`,
 * so the Version Packages PR carries the pins with the versions they name.
 *
 * The packages are the changesets `fixed` group that holds `stash`: the ones
 * `changeset version` moves together. A test holds that group to the CLI's
 * `RELEASE_TRAIN_MANIFESTS`, which is the set `release-train.test.ts` checks.
 * A pin takes the STABLE version, because a prerelease must not be pinned in a
 * customer's repo; that is the test's rule too.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, relative, resolve, sep } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(import.meta.dirname, '..')

export const SKILLS_DIR = 'skills'
export const PACKAGES_DIR = 'languages/typescript/packages'

/**
 * `release-train.test.ts`'s pin form: an exact `name@X.Y.Z[-pre]`, optionally
 * `npm:`-prefixed. A range such as `^1.0.0` is not a pin. The lookbehind stops
 * `stash` matching inside a longer name.
 */
const PIN =
  /(?<![\w-])((?:npm:)?)(stash|@cipherstash\/[a-z0-9-]+)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/g

export const stableVersion = (version) => version.split('-')[0]

/** The names in the changesets `fixed` group that holds `stash`. */
export function releaseTrain(changesetConfig) {
  const group = (changesetConfig.fixed ?? []).find((names) =>
    names.includes('stash'),
  )
  if (!group) {
    throw new Error(
      'no `fixed` group in .changeset/config.json holds `stash`, so there is no ' +
        'release train to pin the skills to',
    )
  }
  return [...group]
}

/** name -> version for each `names` entry, from the package manifests. */
export function trainVersions(root, names) {
  const found = new Map()
  const dir = join(root, PACKAGES_DIR)
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    let manifest
    try {
      manifest = JSON.parse(
        readFileSync(join(dir, entry.name, 'package.json'), 'utf8'),
      )
    } catch (err) {
      if (err.code === 'ENOENT') continue
      throw err
    }
    if (names.includes(manifest.name))
      found.set(manifest.name, manifest.version)
  }
  const missing = names.filter((name) => !found.has(name))
  if (missing.length > 0) {
    throw new Error(
      `no manifest under ${PACKAGES_DIR}/ names ${missing.join(', ')}, so their skill ` +
        'pins cannot be moved',
    )
  }
  return found
}

/** Rewrite each train pin in `text` to its stable version. */
export function syncPins(text, versions) {
  const changes = []
  const out = text.replace(PIN, (whole, prefix, pkg, pinned) => {
    if (!versions.has(pkg)) return whole
    const to = stableVersion(versions.get(pkg))
    if (pinned === to) return whole
    changes.push({ pkg, from: pinned, to })
    return `${prefix}${pkg}@${to}`
  })
  return { text: out, changes }
}

function markdownFiles(dir) {
  return readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.md'))
    .map((entry) => join(entry.parentPath, entry.name))
    .sort()
}

/** Every changed file, repo-relative, with its changes. Writes unless `write` is false. */
export function syncSkillPins({ root = REPO_ROOT, write = true } = {}) {
  const config = JSON.parse(
    readFileSync(join(root, '.changeset/config.json'), 'utf8'),
  )
  const versions = trainVersions(root, releaseTrain(config))
  const changed = []
  for (const file of markdownFiles(join(root, SKILLS_DIR))) {
    const before = readFileSync(file, 'utf8')
    const { text, changes } = syncPins(before, versions)
    if (changes.length === 0) continue
    if (write) writeFileSync(file, text)
    changed.push({ file: relative(root, file).split(sep).join('/'), changes })
  }
  return changed
}

function main() {
  const changed = syncSkillPins()
  for (const { file, changes } of changed) {
    for (const { pkg, from, to } of changes) {
      console.log(`${file}: ${pkg}@${from} -> ${pkg}@${to}`)
    }
  }
  console.log(
    changed.length === 0
      ? 'skill pins already name the release-train versions'
      : `moved the release-train pins in ${changed.length} skill file(s)`,
  )
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
