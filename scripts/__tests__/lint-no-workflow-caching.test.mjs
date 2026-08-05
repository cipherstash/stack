import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'

// Workflows the supply-chain gate is responsible for.
const TARGET_WORKFLOWS = [
  '.github/workflows/release.yml',
  '.github/workflows/tests-supply-chain.yml',
]

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-workflow-caching.mjs',
)
const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')

function run(...targets) {
  try {
    execFileSync('node', [SCRIPT, ...targets], { encoding: 'utf8' })
    return { exitCode: 0, output: '' }
  } catch (err) {
    return {
      exitCode: err.status,
      output: String(err.stdout) + String(err.stderr),
    }
  }
}

describe('lint-no-workflow-caching', () => {
  const fx = (name) =>
    resolve(
      fileURLToPath(import.meta.url),
      `../fixtures/lint-no-workflow-caching/${name}`,
    )

  it('defaults to checking release.yml and tests-supply-chain.yml', () => {
    expect(run().exitCode).toBe(0)
  })

  it('passes on a workflow with no caching', () => {
    expect(run(fx('clean.yml')).exitCode).toBe(0)
  })

  it('fails on `cache:` under a setup-node step', () => {
    const r = run(fx('setup-node-cache.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/with\.cache/)
  })

  it('fails on an `actions/cache` step', () => {
    const r = run(fx('actions-cache.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/actions\/cache@/)
  })

  it('fails on an `actions/cache/restore` step', () => {
    const r = run(fx('actions-cache-restore.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/actions\/cache\/restore@/)
  })

  it('fails on an `actions/cache/save` step', () => {
    const r = run(fx('actions-cache-save.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/actions\/cache\/save@/)
  })

  it('passes when `actions/cache` appears only as prose, not a step', () => {
    expect(run(fx('no-actions-cache.yml')).exitCode).toBe(0)
  })

  it('fails when caching is not disabled explicitly', () => {
    const r = run(fx('missing-explicit-false.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/\bcache\b/)
    expect(r.output).toMatch(/package-manager-cache/)
  })

  it('keeps release.yml free of GitHub Actions caching', () => {
    expect(
      run(resolve(REPO_ROOT, '.github/workflows/release.yml')).exitCode,
    ).toBe(0)
  })

  it('keeps tests-supply-chain.yml free of GitHub Actions caching', () => {
    expect(
      run(resolve(REPO_ROOT, '.github/workflows/tests-supply-chain.yml'))
        .exitCode,
    ).toBe(0)
  })

  // The gate read a step's own `uses:` and stopped there, so a workflow could
  // reach `actions/cache` through one indirection — `uses: ./.github/actions/x`
  // — and stay green. Verified against a copy of release.yml with
  // `.github/actions/build-ffi-binding` spliced in: exit 0, no output, while
  // the composite it never opened restores two caches.
  describe('local composite actions', () => {
    const cfx = (name) =>
      resolve(
        fileURLToPath(import.meta.url),
        `../fixtures/lint-no-workflow-caching/composites/.github/workflows/${name}`,
      )

    it('follows a local composite into its `actions/cache` step', () => {
      const r = run(cfx('composite-cache.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/actions\/cache@/)
    })

    // A message naming only the workflow step sends the reader to a file with
    // no `actions/cache` anywhere in it. Both ends of the indirection, or the
    // finding costs more to act on than it saves.
    it('names the workflow step and the offending composite step', () => {
      const r = run(cfx('composite-cache.yml'))
      expect(r.output).toMatch(/step "Build the protect-ffi binding"/)
      expect(r.output).toMatch(
        /\.github\/actions\/cachey\/action\.yml step "Restore the compiled binding"/,
      )
    })

    it('follows a local composite into `actions/cache/restore`', () => {
      const r = run(cfx('composite-cache-restore.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/actions\/cache\/restore@/)
    })

    it('follows a local composite into `actions/cache/save`', () => {
      const r = run(cfx('composite-cache-save.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/actions\/cache\/save@/)
    })

    it('passes on a composite that disables caching explicitly', () => {
      expect(run(cfx('composite-clean.yml')).exitCode).toBe(0)
    })

    it('flags a truthy `with.cache` inside a composite', () => {
      const r = run(cfx('composite-setup-node-cache.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/with\.cache/)
    })

    // The explicit-`false` rules apply through the indirection too: the action
    // executes in the same job, with the same credentials, and defaults the
    // same way. Exempting composites would make "move the step into a
    // composite" a silent way out of the rule — the bug this whole block fixes.
    it('applies the explicit-`false` rules inside a composite', () => {
      const r = run(cfx('composite-missing-explicit-false.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/pnpm\/action-setup/)
      expect(r.output).toMatch(/package-manager-cache/)
    })

    it('recurses into a composite reached from a composite', () => {
      const r = run(cfx('composite-nested.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/actions\/cache@/)
      // The whole chain, not just its ends — otherwise the reader has to guess
      // which of `outer`'s steps led to the cache.
      expect(r.output).toMatch(
        /step "Build the protect-ffi binding".*outer\/action\.yml step "Delegate to the inner composite".*cachey\/action\.yml step "Restore the compiled binding"/,
      )
    })

    // `execFileSync` has no timeout here, so an unguarded cycle hangs the suite
    // rather than failing it. The offender count is the real assertion: a
    // visited set that is per-branch rather than per-run terminates but reports
    // `loop-b` once per path into it.
    it('terminates on a cyclic composite reference, reporting once', () => {
      const r = run(cfx('composite-cyclic.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/Found 1 caching issue/)
    })

    it('reads `action.yaml` as well as `action.yml`', () => {
      const r = run(cfx('composite-yaml-ext.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/actions\/cache@/)
    })

    // Marketplace and `docker://` references have no `action.yml` on this
    // filesystem. Exit 0 is the assertion that the traversal never tried.
    it('skips `uses:` values that are not local paths', () => {
      expect(run(cfx('third-party-uses.yml')).exitCode).toBe(0)
    })

    // Exit 2, not 1: nothing was found to be caching, the linter simply could
    // not look — the same contract lint-no-hardcoded-runners.mjs uses for a
    // target that does not exist. Silently skipping would turn a typo'd path
    // into a permanent exemption.
    it('exits 2 when a local `uses:` resolves to no action file', () => {
      const r = run(cfx('composite-unresolvable.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(/no-such-action/)
    })

    // A live citation, not a fixture: `.github/actions/build-ffi-binding` is
    // the composite whose header says publishing workflows must not use it.
    // The first assertion is what keeps the second honest — drop the caching
    // from that action and this fails, which is the prompt to fix the header
    // too, rather than leaving a test that passes because it now proves
    // nothing.
    it('flags a publishing workflow that uses .github/actions/build-ffi-binding', () => {
      const action = yaml.load(
        readFileSync(
          resolve(REPO_ROOT, '.github/actions/build-ffi-binding/action.yml'),
          'utf8',
        ),
      )
      expect(
        action?.runs?.steps?.filter((s) =>
          /^actions\/cache(\/(restore|save))?@/.test(s?.uses ?? ''),
        ),
      ).not.toHaveLength(0)

      const r = run(fx('uses-build-ffi-binding.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/build-ffi-binding\/action\.yml/)
      expect(r.output).toMatch(/actions\/cache@/)
    })
  })

  it('the target workflows contain no `actions/cache` step', () => {
    for (const target of TARGET_WORKFLOWS) {
      const doc = yaml.load(readFileSync(resolve(REPO_ROOT, target), 'utf8'))
      for (const [jobName, job] of Object.entries(doc?.jobs ?? {})) {
        for (const step of job?.steps ?? []) {
          if (typeof step?.uses === 'string') {
            expect(
              step.uses,
              `${target} job "${jobName}" must not use actions/cache`,
            ).not.toMatch(/^actions\/cache(\/(restore|save))?@/)
          }
        }
      }
    }
  })
})
