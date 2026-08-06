import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'

/**
 * An integration workflow only runs when its `paths:` filter matches the diff.
 * So a source directory that the selected suites import, but that no `paths:`
 * entry covers, is live coverage that silently does not run: edit only that
 * directory and the job the code depends on never starts.
 *
 * `packages/stack/src/dynamodb/**` was exactly that (#815 review). The only
 * live EQL v2 read coverage in the repo lives in
 * `integration/shared/v2-decrypt-compat.integration.test.ts`, which exercises
 * the DynamoDB legacy read path — and `grep -rn dynamodb .github/` returned
 * nothing at all, so a change to that path (or a `protect-ffi` bump that broke
 * v2 deserialization) would not have run it.
 *
 * Rather than hardcode "dynamodb must be listed", this derives the requirement:
 * whatever the selected suites import via the `@/` alias must be covered. A new
 * import in an integration suite therefore fails here until the filter follows.
 *
 * The same argument applies to what the suites import from OUTSIDE the repo.
 * Those v2 suites mint their fixtures with `@cipherstash/protect-ffi` directly,
 * and a bump of that native module edits only a dependency manifest — no source
 * directory — so it too must appear in the filter. `importedDependencyManifests`
 * derives which manifest that is (package manifest for exact pins,
 * `pnpm-workspace.yaml` for `catalog:` ones).
 *
 * Finally, GitHub Actions has no YAML anchors, so every filter is written twice.
 * A one-sided edit disables the job on pull requests while leaving it green on
 * `main` — the exact inversion of what you want — so the two copies are
 * compared directly.
 */

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')
const STACK_SRC = 'packages/stack/src'
const STACK_MANIFEST = 'packages/stack/package.json'
const CATALOG_MANIFEST = 'pnpm-workspace.yaml'

/** Both trigger events, in the order GitHub evaluates them. */
const TRIGGER_EVENTS = ['push', 'pull_request']

function readWorkflow(relPath) {
  return yaml.load(readFileSync(join(REPO_ROOT, relPath), 'utf8'))
}

/**
 * The integration workflows, discovered rather than listed: any workflow whose
 * `CS_IT_SUITE` globs select suites out of `packages/stack/` is in scope. A
 * fourth integration job added later is therefore held to the same bar without
 * anyone remembering to add it here.
 */
function discoverWorkflows() {
  const dir = join(REPO_ROOT, '.github/workflows')
  return readdirSync(dir)
    .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
    .map((name) => `.github/workflows/${name}`)
    .filter(
      (relPath) => suiteFiles(suiteGlobs(readWorkflow(relPath))).length > 0,
    )
    .sort()
}

/**
 * `on:` parses as the boolean `true` under YAML 1.1 (the "Norway problem"),
 * which is why this reads both keys rather than `wf.on`.
 */
function triggerFilters(wf) {
  const on = wf.on ?? wf[true]
  return Object.fromEntries(
    TRIGGER_EVENTS.map((event) => [event, on?.[event]?.paths]),
  )
}

function triggerBlocks(wf) {
  const on = wf.on ?? wf[true]
  return TRIGGER_EVENTS.map((event) => on?.[event]).filter(
    (block) => block && Array.isArray(block.paths),
  )
}

/** Every `CS_IT_SUITE` glob set declared anywhere in the workflow. */
function suiteGlobs(wf) {
  const globs = []
  for (const job of Object.values(wf.jobs ?? {})) {
    const raw = job.env?.CS_IT_SUITE
    if (!raw) continue
    globs.push(
      ...String(raw)
        .split(',')
        .map((g) => g.trim())
        .filter(Boolean),
    )
  }
  return globs
}

/** Test files under `packages/stack/` matching a `CS_IT_SUITE` glob. */
function suiteFiles(globs) {
  const files = []
  const walk = (dir) => {
    if (!existsSync(dir)) return
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry)
      if (statSync(full).isDirectory()) walk(full)
      else if (full.endsWith('.integration.test.ts')) files.push(full)
    }
  }
  for (const glob of globs) {
    // Walk the literal prefix; the glob tail only ever narrows to
    // `*.integration.test.ts`, which the walk already filters on.
    const prefix = glob.split('/').slice(0, 2).join('/')
    walk(join(REPO_ROOT, 'packages/stack', prefix))
  }
  return [...new Set(files)]
}

/**
 * Resolve the `@/`-aliased imports of a suite to the source paths a `paths:`
 * filter would have to cover. `@/eql/v3` is a directory; `@/types` is a file.
 */
function importedSourcePaths(file) {
  const source = readFileSync(file, 'utf8')
  const targets = new Set()
  for (const match of source.matchAll(/from '@\/([^']+)'/g)) {
    const specifier = match[1]
    const asDir = join(REPO_ROOT, STACK_SRC, specifier)
    if (existsSync(asDir) && statSync(asDir).isDirectory()) {
      targets.add(`${STACK_SRC}/${specifier}/`)
      continue
    }
    // A module file (`@/types`, `@/encryption/v3`). Its own directory is what a
    // `paths:` glob would cover, so record the file and let `isCovered` match
    // either the file itself or an ancestor glob.
    targets.add(`${STACK_SRC}/${specifier}.ts`)
  }
  return targets
}

/** `packages/stack`'s dependency declarations, specifier -> version range. */
function stackDependencies() {
  const manifest = JSON.parse(
    readFileSync(join(REPO_ROOT, STACK_MANIFEST), 'utf8'),
  )
  return {
    ...manifest.dependencies,
    ...manifest.devDependencies,
    ...manifest.peerDependencies,
    ...manifest.optionalDependencies,
  }
}

/**
 * The manifests that PIN the versions of the third-party packages a suite
 * imports directly — the files a dependency bump actually edits.
 *
 * This is the second half of the same argument as `importedSourcePaths`. That
 * one covers first-party source; this one covers the native/WASM modules the
 * suites are proving the behaviour of. `integration/shared/v2-decrypt-compat`
 * and its `integration/wasm/` twin are the repo's only live EQL v2 read
 * coverage, and both mint their fixtures by importing `@cipherstash/protect-ffi`
 * directly — so a protect-ffi bump is precisely the change most able to break
 * them, and precisely the change that touches no source directory at all.
 *
 * Specifiers with no entry in `packages/stack/package.json` (e.g.
 * `@cipherstash/test-kit`, resolved through tsconfig `paths` to a workspace
 * package) are skipped: `importedSourcePaths`' sibling globs already cover them.
 */
function importedDependencyManifests(file, deps) {
  const source = readFileSync(file, 'utf8')
  const targets = new Set()
  for (const match of source.matchAll(/from '([^'@.][^']*|@[^/']+\/[^']+)'/g)) {
    const specifier = match[1]
    const parts = specifier.split('/')
    const pkg = specifier.startsWith('@')
      ? parts.slice(0, 2).join('/')
      : parts[0]
    const range = deps[pkg]
    if (!range) continue
    targets.add(STACK_MANIFEST)
    // A `catalog:` specifier carries no version — the number lives in
    // `pnpm-workspace.yaml`, so that is the file a bump edits.
    if (String(range).startsWith('catalog:')) targets.add(CATALOG_MANIFEST)
  }
  return targets
}

/** Does any `paths:` entry match this source path? */
function isCovered(target, paths) {
  return paths.some((entry) => {
    const literal = entry.replace(/\*\*$/, '').replace(/\/$/, '')
    return target.startsWith(`${literal}/`) || target === literal
  })
}

const WORKFLOWS = discoverWorkflows()

describe('integration workflow paths filters', () => {
  it('finds the integration workflows to check', () => {
    expect(WORKFLOWS.length).toBeGreaterThan(0)
  })

  for (const relPath of WORKFLOWS) {
    /**
     * GitHub Actions has no YAML anchors, so each filter is written out twice.
     * A one-sided edit is silent: the workflow keeps running on `push` to main
     * and stops running on the PR that introduced the break, which is the only
     * time it matters. Compare the two lists rather than trusting the comment.
     */
    it(`${relPath} repeats an identical paths filter under push and pull_request`, () => {
      const filters = triggerFilters(readWorkflow(relPath))
      for (const event of TRIGGER_EVENTS) {
        expect(Array.isArray(filters[event])).toBe(true)
      }
      expect(filters.pull_request).toEqual(filters.push)
    })

    it(`${relPath} triggers on the manifests pinning its suites' dependencies`, () => {
      const wf = readWorkflow(relPath)
      const blocks = triggerBlocks(wf)
      expect(blocks.length).toBe(TRIGGER_EVENTS.length)

      const deps = stackDependencies()
      const files = suiteFiles(suiteGlobs(wf))
      expect(files.length).toBeGreaterThan(0)

      const required = new Set()
      for (const file of files) {
        for (const target of importedDependencyManifests(file, deps)) {
          required.add(target)
        }
      }
      expect(required.size).toBeGreaterThan(0)

      for (const block of blocks) {
        const uncovered = [...required].filter(
          (target) => !isCovered(target, block.paths),
        )
        expect(uncovered).toEqual([])
      }
    })

    it(`${relPath} triggers on every source path its suites import`, () => {
      const wf = readWorkflow(relPath)
      const blocks = triggerBlocks(wf)
      expect(blocks.length).toBeGreaterThan(0)

      const files = suiteFiles(suiteGlobs(wf))
      expect(files.length).toBeGreaterThan(0)

      const required = new Set()
      for (const file of files) {
        for (const target of importedSourcePaths(file)) required.add(target)
      }

      // The requirement is DERIVED from `@/`-aliased imports, so "no suite
      // uses that alias" and "every import is covered" are the same green.
      // Mutation-tested: rewriting the suites' `from '@/…'` to the public
      // `@cipherstash/stack/…` entry — an ordinary "test the built package,
      // not internals" refactor — empties this set, and the check then passed
      // with `packages/stack/src/dynamodb/**` deleted from the filter, which
      // is verbatim the #815 gap described at the top of this file. The
      // sibling manifest check above already asserts its own premise; this one
      // has to as well.
      expect(
        required.size,
        `No @/-aliased import was resolved from ${files.length} suite file(s) in ${relPath}, so this check has nothing to verify and would pass no matter what the paths filter said. If the suites moved off the @/ alias, teach importedSourcePaths the new form.`,
      ).toBeGreaterThan(0)

      for (const block of blocks) {
        const uncovered = [...required].filter(
          (target) => !isCovered(target, block.paths),
        )
        expect(uncovered).toEqual([])
      }
    })
  }
})
