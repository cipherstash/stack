import { describe, expect, it } from 'vitest'
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
 * is the `ubuntu-NNNN` its job's `runs-on` names. A job whose `runs-on` names
 * no image (a matrix, `ubuntu-latest`) must turn the cache off.
 *
 * Composite actions under `.github/actions` are not checked. Their only mise
 * steps install the musl-static wasm-pack from aqua, which runs on any glibc,
 * and they cannot know their caller's `runs-on`.
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

describe('mise-action cache keys', () => {
  const steps = miseSteps()

  it('finds the mise steps it checks', () => {
    // A discovery test that finds nothing passes having checked nothing.
    expect(steps.filter(({ step }) => caches(step)).length).toBeGreaterThan(10)
  })

  it('keys every cached step by its runner image', () => {
    const wrong = []
    for (const { file, job, runsOn, step } of steps) {
      if (!caches(step)) continue
      const image = /ubuntu-\d{4}/.exec(String(runsOn))?.[0]
      const want = image ? `mise-v1-${image}` : null
      const got = step.with?.cache_key_prefix
      if (!want) {
        wrong.push(
          `${file} ${job}: runs-on ${runsOn} names no ubuntu-NNNN image, so the mise cache must be off (cache: false)`,
        )
      } else if (got !== want) {
        wrong.push(
          `${file} ${job}: cache_key_prefix is ${got ?? 'unset'}, want ${want}`,
        )
      }
    }
    expect(wrong).toEqual([])
  })
})
