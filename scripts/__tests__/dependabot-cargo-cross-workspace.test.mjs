import { existsSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve, sep } from 'node:path'
import yaml from 'js-yaml'
import { beforeAll, describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * Every cargo Dependabot entry whose workspaces share crates with another
 * workspace by path must be `versioning-strategy: lockfile-only`.
 *
 * Each cargo `directory:` is one Cargo workspace with its own Cargo.lock, and
 * a Dependabot PR updates exactly that one lockfile. A path dependency crosses
 * that line in both directions:
 * - OUTWARD: a workspace that depends by path on another workspace's crate
 *   resolves that crate's requirements, including any `{ workspace = true }`
 *   ones from the other workspace's root Cargo.toml. To satisfy a bump it may
 *   edit those manifests, outside its own workspace, and leave the other
 *   workspace's Cargo.lock behind. That is #1205: the EQL entry rewrote the
 *   root Cargo.toml, and every root `--locked` build failed (#1207).
 * - INWARD: a workspace whose crate another workspace depends on by path can
 *   raise a requirement in its own manifest and update its own lockfile, and
 *   the depending workspace's Cargo.lock is then stale under `--locked`.
 *
 * `lockfile-only` stops both: the entry never edits a manifest. An update that
 * needs one is dropped and made by hand, across every affected lockfile.
 *
 * The edges are read from the tracked manifests, so a new path dependency is
 * covered the day it lands.
 */

const DEPENDABOT = join(REPO_ROOT, '.github/dependabot.yml')

/** Repo-relative, `/`-separated, no leading slash: the form Cargo uses. */
function repoRel(abs) {
  return relative(REPO_ROOT, abs).split(sep).join('/')
}

function readManifest(dir) {
  return readFileSync(join(REPO_ROOT, dir, 'Cargo.toml'), 'utf8')
}

/**
 * The crate directories of the workspace rooted at `dir`: its `members`, plus
 * the root itself when it is also a package (a detached single-crate
 * workspace, such as a fuzz crate or a Go guest).
 */
function workspaceCrates(dir, manifest) {
  const crates = []
  if (/^\[package\]/m.test(manifest)) crates.push(dir)
  const block = manifest.match(/^members\s*=\s*\[([\s\S]*?)\]/m)
  if (block) {
    for (const [, member] of block[1].matchAll(/"([^"]+)"/g)) {
      expect(
        member,
        `${dir}/Cargo.toml: glob members are not expanded here`,
      ).not.toMatch(/[*?[]/)
      crates.push(repoRel(resolve(REPO_ROOT, dir, member)))
    }
  }
  return crates
}

/**
 * The crates a manifest depends on by path, repo-relative. A `path =` that
 * names a file (`[lib]`, `[[bin]]`) is not a dependency and is skipped.
 */
function pathDependencies(crateDir, manifest) {
  const deps = []
  for (const [, path] of manifest.matchAll(/\bpath\s*=\s*"([^"]+)"/g)) {
    const abs = resolve(REPO_ROOT, crateDir, path)
    if (!existsSync(abs) || !statSync(abs).isDirectory()) continue
    if (!existsSync(join(abs, 'Cargo.toml'))) continue
    deps.push(repoRel(abs))
  }
  return deps
}

/**
 * Every cross-workspace path dependency, as
 * `{ from, to, fromDir, toDir }`: crate `from` in the workspace at `fromDir`
 * depends on crate `to` in the workspace at `toDir`. `toDir` is null when no
 * Dependabot cargo directory covers `to`.
 */
function crossWorkspaceEdges(workspaces) {
  const owner = new Map()
  for (const [dir, crates] of workspaces) {
    for (const crate of crates) owner.set(crate, dir)
  }
  const edges = []
  for (const [dir, crates] of workspaces) {
    for (const crate of crates) {
      for (const to of pathDependencies(crate, readManifest(crate))) {
        const toDir = owner.get(to) ?? null
        const seen = edges.some((e) => e.from === crate && e.to === to)
        if (toDir !== dir && !seen) {
          edges.push({ from: crate, to, fromDir: dir, toDir })
        }
      }
    }
  }
  return edges
}

/** The directories of a Dependabot entry, without the leading `/`. */
function entryDirs(entry) {
  const dirs = entry.directories ?? [entry.directory]
  return dirs.map((d) => d.replace(/^\/+/, '').replace(/\/+$/, ''))
}

describe('cargo Dependabot entries that share crates across workspaces never edit a manifest', () => {
  let entries
  let edges

  beforeAll(() => {
    const config = yaml.load(readFileSync(DEPENDABOT, 'utf8'))
    entries = config.updates.filter((u) => u['package-ecosystem'] === 'cargo')
    const workspaces = new Map()
    for (const entry of entries) {
      for (const dir of entryDirs(entry)) {
        workspaces.set(dir, workspaceCrates(dir, readManifest(dir)))
      }
    }
    edges = crossWorkspaceEdges(workspaces)
  })

  it('finds cross-workspace path dependencies', () => {
    // If these all go away the rule below has nothing to hold, and this file
    // can be retired rather than left vacuously green.
    expect(edges).not.toHaveLength(0)
  })

  it('covers every crate a path dependency reaches', () => {
    const uncovered = edges.filter((e) => e.toDir === null)
    expect(
      uncovered.map((e) => `${e.from} -> ${e.to}`),
      'path dependencies on crates no cargo Dependabot directory covers',
    ).toEqual([])
  })

  it('makes every entry on either end of one lockfile-only', () => {
    const involved = new Set(edges.flatMap((e) => [e.fromDir, e.toDir]))
    const offenders = entries
      .filter((entry) => entryDirs(entry).some((d) => involved.has(d)))
      .filter((entry) => entry['versioning-strategy'] !== 'lockfile-only')
      .map((entry) => {
        const dirs = new Set(entryDirs(entry))
        const why = edges
          .filter((e) => dirs.has(e.fromDir) || dirs.has(e.toDir))
          .map((e) => `${e.from} -> ${e.to}`)
        return `${(entry.directories ?? [entry.directory]).join(', ')}: ${why.join('; ')}`
      })
    expect(
      offenders,
      'these cargo entries share crates by path with another workspace, so a manifest ' +
        "edit can leave the other workspace's Cargo.lock behind. Set " +
        '`versioning-strategy: lockfile-only` on each.',
    ).toEqual([])
  })
})
