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
 */

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')
const STACK_SRC = 'packages/stack/src'

/** The integration workflows and the package their `CS_IT_SUITE` globs select from. */
const WORKFLOWS = [
  '.github/workflows/integration-drizzle.yml',
  '.github/workflows/integration-supabase.yml',
]

function readWorkflow(relPath) {
  return yaml.load(readFileSync(join(REPO_ROOT, relPath), 'utf8'))
}

/**
 * `on:` parses as the boolean `true` under YAML 1.1 (the "Norway problem"),
 * which is why this reads both keys rather than `wf.on`.
 */
function triggerBlocks(wf) {
  const on = wf.on ?? wf[true]
  return ['push', 'pull_request']
    .map((event) => on?.[event])
    .filter((block) => block && Array.isArray(block.paths))
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

/** Does any `paths:` entry match this source path? */
function isCovered(target, paths) {
  return paths.some((entry) => {
    const literal = entry.replace(/\*\*$/, '').replace(/\/$/, '')
    return target.startsWith(`${literal}/`) || target === literal
  })
}

describe('integration workflow paths filters', () => {
  for (const relPath of WORKFLOWS) {
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

      for (const block of blocks) {
        const uncovered = [...required].filter(
          (target) => !isCovered(target, block.paths),
        )
        expect(uncovered).toEqual([])
      }
    })
  }
})
