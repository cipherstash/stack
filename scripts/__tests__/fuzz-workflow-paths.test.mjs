import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, posix } from 'node:path'
import { describe, expect, it } from 'vitest'
import { filterCovers, negationRemovesAll } from './lib/paths-filter.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
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
 * `python-ci.test.mjs` holds `tests-python.yml` to the Python workspace the
 * same way.
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
  const trees = []
  for (const block of read(`${fuzzCrate}/Cargo.lock`)
    .split('[[package]]')
    .slice(1)) {
    if (/^source = /m.test(block)) continue
    const name = /^name = "([^"]+)"/m.exec(block)?.[1]
    if (!name) throw new Error(`${fuzzCrate}/Cargo.lock: a package with no name`)
    if (name.endsWith('-fuzz')) continue
    trees.push(crateDir(name))
  }
  return trees
}

/** The files a crate compiles through `#[path = "..."]`, from its `src/`. */
function pathModuleFiles(crate) {
  const files = []
  const walk = (dir) => {
    if (!existsSync(join(REPO_ROOT, dir))) return
    for (const entry of readdirSync(join(REPO_ROOT, dir), {
      withFileTypes: true,
    })) {
      const rel = `${dir}/${entry.name}`
      if (entry.isDirectory()) walk(rel)
      else if (entry.name.endsWith('.rs')) {
        const attribute = /#\[\s*path\s*=\s*"([^"]+)"\s*\]/g
        for (const match of read(rel).matchAll(attribute)) {
          files.push(posix.normalize(`${dir}/${match[1]}`))
        }
      }
    }
  }
  walk(`${crate}/src`)
  return files
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
    const missing = trees.filter((dir) => !selected(`${dir}/src/lib.rs`))
    expect(
      missing,
      `pull_request.paths does not select these crates, which a fuzz target compiles:\n${missing.join('\n')}`,
    ).toEqual([])
  })

  it('runs on pull requests touching a file those crates compile by #[path]', () => {
    const trees = [...new Set(fuzzCrates().flatMap(pathDependencyTrees))]
    const files = trees.flatMap(pathModuleFiles)
    expect(files).toContain('languages/golang/encrypt/guest/src/targets.rs')
    const missing = files.filter((file) => !selected(file))
    expect(
      missing,
      `pull_request.paths does not select these files, which a fuzzed crate compiles by #[path]:\n${missing.join('\n')}`,
    ).toEqual([])
  })
})
