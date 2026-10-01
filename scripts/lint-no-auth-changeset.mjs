/**
 * Fail if any pending changeset names one of the seven `@cipherstash/auth`
 * packages.
 *
 * TEMPORARY. Delete this script, its self-test and its `lint:auth-changeset`
 * entry in the arming PR of the stack-* crates import (PR E), when npm trusted
 * publishing for the seven packages moves from `cipherstash/cipherstash-suite`
 * to `cipherstash/stack` and their `FROZEN_PUBLISHERS` entries are deleted.
 *
 * The release gate's CHECK A already refuses to publish a frozen package at a
 * version npm does not carry, but it fires on `main` after the Version
 * Packages PR merges, and then it blocks every release until the bump is
 * reverted. This stops the changeset on the pull request instead.
 *
 * There is nowhere to park the changeset: the `.md.deferred` convention the
 * retired protect-ffi guard used is forbidden by `no-parked-changesets`.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

const REPO_ROOT = resolve(import.meta.dirname, '..')

const GUARDED = new Set([
  '@cipherstash/auth',
  '@cipherstash/auth-darwin-arm64',
  '@cipherstash/auth-darwin-x64',
  '@cipherstash/auth-linux-arm64-gnu',
  '@cipherstash/auth-linux-x64-gnu',
  '@cipherstash/auth-linux-x64-musl',
  '@cipherstash/auth-win32-x64-msvc',
])

const changesetDir = process.argv[2]
  ? resolve(process.argv[2])
  : join(REPO_ROOT, '.changeset')

// Only the first fenced block is frontmatter: prose below it may quote a
// package name, and `---` rules in markdown would otherwise reopen the block.
function packagesIn(source) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(source)
  if (!match) return []
  return match[1]
    .split(/\r?\n/)
    .map((line) => /^\s*['"]?(@?[^'":]+?)['"]?\s*:/.exec(line))
    .filter(Boolean)
    .map((m) => m[1].trim())
}

const offenders = []
for (const entry of readdirSync(changesetDir)) {
  if (!entry.endsWith('.md') || entry === 'README.md') continue
  const named = packagesIn(readFileSync(join(changesetDir, entry), 'utf8'))
  const guarded = named.filter((name) => GUARDED.has(name))
  if (guarded.length) offenders.push({ file: entry, packages: guarded })
}

if (offenders.length === 0) {
  console.log('No pending changeset names an @cipherstash/auth package.')
  process.exit(0)
}

console.error('\nA pending changeset names an @cipherstash/auth package:\n')
for (const { file, packages } of offenders) {
  console.error(`  ${relative(REPO_ROOT, join(changesetDir, file))}`)
  for (const name of packages) console.error(`      ${name}`)
}
console.error(
  '\nThese seven packages live in this repo but are still PUBLISHED from\n' +
    'cipherstash/cipherstash-suite — npm trusted publishing has not been\n' +
    'repointed yet, so `release.yml` here cannot publish them. Releasing a\n' +
    'bumped version from here is blocked by `release:gate`, and that block\n' +
    'stops every other release with it.\n\n' +
    'Remove the changeset. Merges that touch the auth packages are paused\n' +
    'until the arming PR (PR E of the stack-* crates import), which repoints\n' +
    'trusted publishing, deletes this script and writes the changesets. If a\n' +
    'change must land before then, put its release note in the pull request.\n',
)
process.exit(1)
