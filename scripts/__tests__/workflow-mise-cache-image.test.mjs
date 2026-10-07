import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * Every cached `jdx/mise-action` step keys its cache by runner image.
 *
 * mise-action's default key is `mise-v1-<os>-<arch>-<mise version>-<env>-<hash
 * of the mise config>`. It names Linux, not the distro, so a job on
 * `blacksmith-*-ubuntu-2404` (glibc 2.39) and one on `…-ubuntu-2204` (glibc
 * 2.35) read and write the same entry. The `cargo:` tools in `mise.test.toml`
 * are built where they are installed, so whichever job saves the key first
 * decides what glibc every other job's `cargo-nextest` and `cargo-llvm-cov`
 * need. When a 2404 job (fuzz, udeps) wins, every 2204 job dies with
 * "GLIBC_2.38 not found" before any test runs.
 *
 * It surfaces only when the config hash changes, because that is the only time
 * a key is new and up for grabs: on `main` the entry was saved long ago by a
 * 2204 job and stays good. PR #1094 changed `mise.toml`, its fuzz and udeps jobs
 * saved the new key first, and four crate jobs failed with nothing wrong in the
 * code. A re-run hits the same entry.
 *
 * So each cached step sets `cache_key_prefix: mise-v1-<image>`, where `<image>`
 * is the `ubuntu-NNNN` its job's `runs-on` names (`ubuntu-24.04` counts as
 * `ubuntu-2404`). A job whose `runs-on` names no image (a matrix,
 * `ubuntu-latest`) must turn the cache off. No step sets `cache_key`, which
 * mise-action prefers over the prefix and so would bring the shared key back.
 * A step with the cache off sets no prefix: it would read as a cache in use,
 * on paths `scripts/lint-no-workflow-caching.mjs` keeps cache-free.
 *
 * Composite actions under `.github/actions` cannot know their caller's
 * `runs-on`, so they keep the default key, and may cache only tools that run
 * on any glibc (`IMAGE_INDEPENDENT_TOOLS`); the last test holds them to it.
 */

const isMise = (step) =>
  typeof step?.uses === 'string' &&
  step.uses.split('@')[0].toLowerCase() === 'jdx/mise-action'

/** mise-action caches unless told not to. */
const caches = (step) => {
  const value = step.with?.cache
  return !(value === false || value === 'false')
}

function miseSteps() {
  const found = []
  for (const file of workflowFiles()) {
    for (const [job, def] of Object.entries(readWorkflow(file)?.jobs ?? {})) {
      for (const step of def?.steps ?? []) {
        if (isMise(step))
          found.push({ file, job, runsOn: def['runs-on'], step })
      }
    }
  }
  return found
}

/** Static binaries: one cache entry serves every image. */
const IMAGE_INDEPENDENT_TOOLS = new Set(['aqua:wasm-bindgen/wasm-pack'])

/** The `ubuntu-NNNN` a runs-on label names, or undefined. */
function imageOf(runsOn) {
  const m = /ubuntu-(\d{2})\.?(\d{2})/.exec(String(runsOn))
  return m ? `ubuntu-${m[1]}${m[2]}` : undefined
}

/** The finding for one mise step, or null when the step is correct. */
function cacheKeyFinding({ file, job, runsOn, step }) {
  const where = `${file} ${job}`
  const prefix = step.with?.cache_key_prefix
  if (step.with?.cache_key !== undefined)
    return `${where}: sets cache_key, which overrides cache_key_prefix and names no image; remove it`
  if (!caches(step))
    return prefix === undefined
      ? null
      : `${where}: the cache is off, so cache_key_prefix ${prefix} does nothing; remove it`
  const image = imageOf(runsOn)
  if (!image)
    return `${where}: runs-on ${runsOn} names no ubuntu-NNNN image, so the mise cache must be off (cache: false)`
  const want = `mise-v1-${image}`
  return prefix === want
    ? null
    : `${where}: cache_key_prefix is ${prefix ?? 'unset'}, want ${want}`
}

describe('mise-action cache keys', () => {
  const steps = miseSteps()

  it('finds the mise steps it checks', () => {
    // A discovery test that finds nothing passes having checked nothing.
    expect(steps.filter(({ step }) => caches(step)).length).toBeGreaterThan(10)
  })

  it('keys every cached step by its runner image', () => {
    expect(steps.map(cacheKeyFinding).filter(Boolean)).toEqual([])
  })

  // Every step in the tree is correct, so the test above runs none of the
  // branches that report a wrong one. These do.
  it('reports the steps it exists to report', () => {
    const check = (runsOn, input) =>
      cacheKeyFinding({
        file: 'w.yml',
        job: 'j',
        runsOn,
        step: { uses: 'jdx/mise-action@sha', with: input },
      })
    // PR #1094: a 2404 job that writes the 2204 entry.
    expect(
      check('blacksmith-4vcpu-ubuntu-2404', {
        cache_key_prefix: 'mise-v1-ubuntu-2204',
      }),
    ).toMatch(/want mise-v1-ubuntu-2404/)
    expect(check('blacksmith-16vcpu-ubuntu-2204', { cache: true })).toMatch(
      /is unset/,
    )
    expect(check('ubuntu-latest', {})).toMatch(/cache: false/)
    expect(
      check('blacksmith-16vcpu-ubuntu-2204', {
        cache_key_prefix: 'mise-v1-ubuntu-2204',
        cache_key: 'mise-shared',
      }),
    ).toMatch(/sets cache_key/)
    expect(
      check('blacksmith-16vcpu-ubuntu-2204', {
        cache: false,
        cache_key_prefix: 'mise-v1-ubuntu-2204',
      }),
    ).toMatch(/cache is off/)
    expect(
      check('ubuntu-24.04', { cache_key_prefix: 'mise-v1-ubuntu-2404' }),
    ).toBeNull()
    expect(check('ubuntu-latest', { cache: 'false' })).toBeNull()
    expect(
      check('blacksmith-16vcpu-ubuntu-2204', {
        cache_key_prefix: 'mise-v1-ubuntu-2204',
      }),
    ).toBeNull()
  })

  it('reads both forms of an image label', () => {
    expect(imageOf('blacksmith-4vcpu-ubuntu-2404')).toBe('ubuntu-2404')
    expect(imageOf('ubuntu-22.04')).toBe('ubuntu-2204')
    expect(imageOf('ubuntu-24.04-arm')).toBe('ubuntu-2404')
    expect(imageOf('ubuntu-latest')).toBeUndefined()
    expect(imageOf(undefined)).toBeUndefined()
  })

  it('lets a composite action cache only image-independent tools', () => {
    const checked = []
    const wrong = []
    for (const name of readdirSync(join(REPO_ROOT, '.github/actions'))) {
      const rel = `.github/actions/${name}/action.yml`
      if (!existsSync(join(REPO_ROOT, rel))) continue
      for (const step of readWorkflow(rel)?.runs?.steps ?? []) {
        if (!isMise(step) || !caches(step)) continue
        checked.push(rel)
        if (step.with?.cache_key !== undefined)
          wrong.push(`${rel}: sets cache_key`)
        const tools = String(step.with?.install_args ?? '')
          .split(/\s+/)
          .filter(Boolean)
        // No install_args installs every tool in the mise config.
        if (
          tools.length === 0 ||
          tools.some((t) => !IMAGE_INDEPENDENT_TOOLS.has(t))
        )
          wrong.push(
            `${rel}: caches install_args ${step.with?.install_args ?? '(unset: every configured tool)'}, and only ${[...IMAGE_INDEPENDENT_TOOLS].join(', ')} runs on every image`,
          )
      }
    }
    expect(checked.length).toBeGreaterThan(0)
    expect(wrong).toEqual([])
  })
})
