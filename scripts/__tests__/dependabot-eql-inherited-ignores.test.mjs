import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import yaml from 'js-yaml'
import { beforeAll, describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The `/packages/eql` Dependabot entry must ignore every crate the root
 * workspace's entry ignores, for as long as the EQL workspace depends by path
 * on root-workspace crates.
 *
 * The EQL workspace is a separate Cargo workspace, but not an independent one:
 * `tests/encryption` depends by path on `stack-kms` and `stack-encrypt`, and
 * `eql-bindings` on `stack-encrypt` (behind its optional `stack-encrypt`
 * feature). Those crates declare `recipher`, `cllw-ore` and `vitaminc-*` as
 * `{ workspace = true }`. Built inside the EQL workspace, those requirements
 * still come from the ROOT `Cargo.toml`. The root entry ignores these crates
 * because they move by hand with cipherstash-suite: the root manifest pins
 * `recipher` and `cllw-ore` with `=`, and so does the Go guest. With no
 * matching ignore, the EQL entry's monthly PR bumped them in the EQL lock and,
 * to satisfy the exact pins, edited the root `Cargo.toml` without updating the
 * root `Cargo.lock` or the guest's pin (#1205). Every root `--locked` build and
 * the Go guest failed (#1207).
 *
 * Two defences:
 * - the EQL entry is `versioning-strategy: lockfile-only`, so it can never
 *   edit a manifest, the root one included. That one is held, for every cargo
 *   entry a path dependency crosses into or out of, by
 *   dependabot-cargo-cross-workspace.test.mjs;
 * - held here: it ignores every crate the root entry moves by hand, so its lockfile does
 *   not move those crates apart from the root's. The two ignore lists are
 *   hand-written copies, so this compares them.
 */

const DEPENDABOT = join(REPO_ROOT, '.github/dependabot.yml')
const EQL_DIR = '/packages/eql'
const ROOT_DIR = '/'

/**
 * Crates the root entry ignores that the EQL entry need not, each with the
 * reason. An entry naming a crate the root entry no longer ignores is stale
 * and fails.
 */
const EXEMPT = new Map([
  // ['crate-name', 'why the EQL workspace cannot resolve it through a path dependency'],
])

/**
 * The crates `rootIgnored` names that `eqlIgnored` does not, less those
 * `exempt` excuses. Only a written reason excuses one: an exemption whose
 * reason is empty is no exemption.
 */
function unexempted(rootIgnored, eqlIgnored, exempt) {
  return [...rootIgnored].filter(
    (name) => !eqlIgnored.has(name) && !exempt.get(name)?.trim(),
  )
}

/** The `cargo` entry covering `dir`, from `directory:` or `directories:`. */
function cargoEntry(config, dir) {
  const matches = config.updates.filter(
    (u) =>
      u['package-ecosystem'] === 'cargo' &&
      (u.directory === dir || (u.directories ?? []).includes(dir)),
  )
  expect(matches, `exactly one cargo entry covers ${dir}`).toHaveLength(1)
  return matches[0]
}

/**
 * The crate names an entry ignores outright. An ignore that carries
 * `update-types` (the semver-major rule) only narrows which updates are
 * proposed, so it is not an ignore of the crate.
 */
function ignoredCrates(entry) {
  return new Set(
    (entry.ignore ?? [])
      .filter((rule) => !rule['update-types'])
      .map((rule) => rule['dependency-name']),
  )
}

/** The root workspace's member directories, repo-relative. */
function rootMembers() {
  const manifest = readFileSync(join(REPO_ROOT, 'Cargo.toml'), 'utf8')
  const block = manifest.match(/^members\s*=\s*\[([\s\S]*?)\]/m)
  expect(
    block,
    'the root Cargo.toml lists its workspace members',
  ).not.toBeNull()
  return [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
}

/**
 * Every root-workspace member an EQL-workspace manifest depends on by path,
 * as `{ manifest, member }` pairs. Read from the tracked manifests so a new
 * path dependency is covered the day it lands.
 */
function eqlPathDependenciesIntoRoot() {
  const members = new Set(rootMembers())
  const manifests = execFileSync(
    'git',
    ['ls-files', '--', 'packages/eql/**/Cargo.toml', 'packages/eql/Cargo.toml'],
    { cwd: REPO_ROOT, encoding: 'utf8' },
  )
    .split('\n')
    .filter(Boolean)
  const found = []
  for (const manifest of manifests) {
    const text = readFileSync(join(REPO_ROOT, manifest), 'utf8')
    for (const [, path] of text.matchAll(/\bpath\s*=\s*"([^"]+)"/g)) {
      // Repo-relative with `/`, the separator Cargo.toml's `members` uses.
      const member = relative(
        REPO_ROOT,
        resolve(REPO_ROOT, dirname(manifest), path),
      )
        .split(sep)
        .join('/')
      if (members.has(member)) found.push({ manifest, member })
    }
  }
  return found
}

describe('the /packages/eql Dependabot entry ignores what it inherits from the root workspace', () => {
  let eqlEntry
  let rootIgnored
  let eqlIgnored
  let pathDeps

  // In beforeAll, not at module scope, so a config-shape failure (say, two
  // entries covering one directory) is reported against a named test.
  beforeAll(() => {
    const config = yaml.load(readFileSync(DEPENDABOT, 'utf8'))
    eqlEntry = cargoEntry(config, EQL_DIR)
    rootIgnored = ignoredCrates(cargoEntry(config, ROOT_DIR))
    eqlIgnored = ignoredCrates(eqlEntry)
    pathDeps = eqlPathDependenciesIntoRoot()
  })

  it('finds the root ignore list it compares against', () => {
    expect(rootIgnored.size).toBeGreaterThan(0)
  })

  it('finds the EQL path dependencies into root-workspace crates', () => {
    // If these go away the EQL workspace stops inheriting root requirements,
    // and this whole file can be retired rather than left vacuously green.
    expect(
      pathDeps.map((d) => d.member),
      'the EQL workspace depends by path on root-workspace crates',
    ).not.toHaveLength(0)
  })

  it('ignores every crate the root entry ignores, unless exempted with a reason', () => {
    const missing = unexempted(rootIgnored, eqlIgnored, EXEMPT)
    expect(
      missing,
      `the root cargo entry ignores these but the ${EQL_DIR} entry does not. The EQL workspace ` +
        `inherits root requirements through path dependencies on ` +
        `${[...new Set(pathDeps.map((d) => d.member))].join(', ')}, so an EQL Dependabot PR ` +
        `would edit the root workspace's pins. Add them to the ${EQL_DIR} entry's ignore list, ` +
        `or exempt one with a reason here if the EQL workspace provably cannot resolve it.`,
    ).toEqual([])
  })

  it('counts an exemption only when it gives a reason', () => {
    const root = new Set(['recipher', 'cllw-ore', 'vitaminc*'])
    const eql = new Set()
    const exempt = new Map([
      ['recipher', 'the EQL workspace resolves no crate that requires it'],
      ['cllw-ore', ''],
      ['vitaminc*', '   '],
    ])
    expect(unexempted(root, eql, exempt)).toEqual(['cllw-ore', 'vitaminc*'])
  })

  it('carries no stale exemption', () => {
    const stale = [...EXEMPT.keys()].filter(
      (name) => !rootIgnored.has(name) || eqlIgnored.has(name),
    )
    expect(
      stale,
      'exempt crates the root entry no longer ignores, or that the EQL entry ignores anyway',
    ).toEqual([])
  })
})
