import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { pathPackageNames } from './lib/cargo-lock.mjs'
import { filterCovers, negationRemovesAll } from './lib/paths-filter.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import {
  compiledCrateFiles,
  includes,
  moduleDeclarations,
} from './lib/rust-compiled-files.mjs'
import { readWorkflow, triggers } from './lib/workflows.mjs'

/**
 * `fuzz.yml`'s `pull_request` filter is held to the crates its fuzz targets
 * compile, read from each fuzz crate's own `Cargo.lock`.
 *
 * The regression job is the only thing that builds a harness on a pull
 * request. A change to a crate a harness compiles, and the filter does not
 * name, can break the harness with no job to notice. Each fuzz crate is a
 * detached workspace, so its `Cargo.lock` lists every crate it compiles from
 * this tree as a package with no `source`. A new path dependency appears
 * there, and this file fails until the filter follows.
 *
 * The fuzz crates are the campaign matrix's `dir` values, each with `/fuzz`.
 * The files each crate compiles come from `compiledCrateFiles`, which
 * follows `mod`, `#[path]` and `include_str!` with comments stripped, with
 * every feature counted as on. `python-ci.test.mjs` holds `tests-python.yml`
 * to the Python workspace the same way.
 */

const WORKFLOW = '.github/workflows/fuzz.yml'

const read = (rel) => readFileSync(join(REPO_ROOT, rel), 'utf8')

/** The fuzz crates, from the campaign matrix. */
function fuzzCrates() {
  const job = readWorkflow(WORKFLOW).jobs['fuzz-campaign']
  return [
    ...new Set(job.strategy.matrix.include.map((row) => `${row.dir}/fuzz`)),
  ].sort()
}

/** Where a path package of this tree lives, checked against its manifest. */
function crateDir(name) {
  const candidates = [
    `packages/${name}`,
    `packages/eql/crates/${name}`,
    `languages/python/crates/${name.replace(/^stackencrypt-/, '')}`,
  ]
  const dir = candidates.find((d) => {
    const manifest = join(REPO_ROOT, d, 'Cargo.toml')
    return (
      existsSync(manifest) &&
      new RegExp(`^name = "${name}"$`, 'm').test(read(`${d}/Cargo.toml`))
    )
  })
  if (!dir) {
    throw new Error(
      `a fuzz Cargo.lock lists ${name} as a path dependency, and none of ${candidates.join(', ')} holds its Cargo.toml; teach this test where it lives`,
    )
  }
  return dir
}

/** The directories of the path packages a fuzz crate compiles. */
function pathDependencyTrees(fuzzCrate) {
  return pathPackageNames(read(`${fuzzCrate}/Cargo.lock`))
    .filter((name) => !name.endsWith('-fuzz'))
    .map(crateDir)
}

/** Every feature counted as on: a module behind any feature is kept. */
const EVERY_FEATURE = { has: () => true }

/** The files a path package compiles, `#[path]` and include files among them. */
function compiledFiles(crate) {
  const { files, unresolved } = compiledCrateFiles(
    REPO_ROOT,
    crate,
    EVERY_FEATURE,
  )
  if (unresolved.length > 0) {
    throw new Error(
      `${crate}: compiledCrateFiles could not follow:\n${unresolved.join('\n')}`,
    )
  }
  return files
}

/**
 * The files a fuzz crate's targets name by `#[path]` or an include. A target
 * is a crate root that `compiledCrateFiles` does not walk, since it walks a
 * library. Its plain `mod` files sit in the fuzz crate's own folder.
 */
function fuzzTargetFiles(fuzzCrate) {
  const dir = `${fuzzCrate}/fuzz_targets`
  const rel = (abs) => relative(REPO_ROOT, abs).replaceAll('\\', '/')
  return readdirSync(join(REPO_ROOT, dir))
    .filter((name) => name.endsWith('.rs'))
    .flatMap((name) => {
      const file = join(REPO_ROOT, dir, name)
      const text = readFileSync(file, 'utf8')
      return [
        rel(file),
        ...moduleDeclarations(text)
          .filter((decl) => decl.path !== undefined)
          .map((decl) => rel(resolve(dirname(file), decl.path))),
        ...includes(text)
          .filter((include) => include.literal !== undefined)
          .map((include) => rel(resolve(dirname(file), include.literal))),
      ]
    })
}

const coversTree = (pattern, file) =>
  pattern.endsWith('/**') && file.startsWith(pattern.slice(0, -2))

const covers = (pattern, file) => pattern === file || coversTree(pattern, file)

describe('fuzz.yml', () => {
  const paths = triggers(readWorkflow(WORKFLOW)).pull_request?.paths ?? []
  // `!**.md` and `!**.example` drop documents only, not a whole tree.
  const selected = (file) =>
    filterCovers(paths, file, covers, negationRemovesAll)

  it('finds every fuzz crate, the Python one included', () => {
    expect(fuzzCrates()).toEqual([
      'languages/python/crates/core/fuzz',
      'packages/stack-auth/fuzz',
      'packages/stack-encrypt/fuzz',
      'packages/stack-kms/fuzz',
    ])
  })

  it('runs on pull requests touching every crate a fuzz target compiles', () => {
    const trees = [...new Set(fuzzCrates().flatMap(pathDependencyTrees))]
    expect(trees).toContain('packages/eql/crates/eql-bindings')
    const missing = trees.filter((dir) => !selected(`${dir}/Cargo.toml`))
    expect(
      missing,
      `pull_request.paths does not select these crates, which a fuzz target compiles:\n${missing.join('\n')}`,
    ).toEqual([])
  })

  it('runs on pull requests touching every file those crates and the targets compile', () => {
    const trees = [...new Set(fuzzCrates().flatMap(pathDependencyTrees))]
    const files = [
      ...trees.flatMap(compiledFiles),
      ...fuzzCrates().flatMap(fuzzTargetFiles),
    ]
    // The Go guest's resolver, which the Python core crate compiles by #[path].
    expect(files).toContain('languages/golang/encrypt/guest/src/targets.rs')
    const missing = [...new Set(files.filter((file) => !selected(file)))]
    expect(
      missing,
      `pull_request.paths does not select these files, which a fuzz target compiles:\n${missing.join('\n')}`,
    ).toEqual([])
  })
})
