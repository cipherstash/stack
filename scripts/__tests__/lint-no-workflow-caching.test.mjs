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
  // — and stay green. Verified against a copy of release.yml with a
  // cache-restoring composite spliced in: exit 0, no output, while the
  // composite it never opened restores two caches.
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
    // filesystem, and the traversal must not try to open them — a traversal
    // that treats every `uses:` as a path fails here rather than on the
    // composite fixtures.
    //
    // The assertion used to be exit 0. It is no longer, because the allowlist
    // below reports each of these as unaudited; what is asserted instead is the
    // property this test was written for, and more directly than exit 0 did:
    // no message says the path could not be opened. Exit 1, not 2, is the other
    // half — the gate reached a verdict on every step, it did not fail to look.
    it('never tries to open a `uses:` that is not a local path', () => {
      const r = run(cfx('third-party-uses.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).not.toMatch(/no action\.yml or action\.yaml there/)
      expect(r.output).toMatch(/docker:\/\/alpine:3\.19/)
    })

    // GitHub trims a `uses:` before resolving it. Untrimmed, `" ./x"` fails the
    // `^\.{1,2}/` test, so the composite was never opened — and nothing was
    // reported either, making this the one unfollowable local reference shape
    // that exited 0 instead of 2. Trimming makes it followable, which is the
    // right outcome: this is a valid reference GitHub runs.
    it('follows a local composite whose `uses:` has leading whitespace', () => {
      const r = run(cfx('composite-leading-space.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/actions\/cache@/)
      expect(r.output).toMatch(
        /\.github\/actions\/cachey\/action\.yml step "Restore the compiled binding"/,
      )
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
  })

  // The second indirection the composite traversal left open. A job that calls
  // a reusable workflow has no `steps:` — it is `jobs.<id>.uses` plus `with:` /
  // `secrets:` — so `Array.isArray(job?.steps) ? job.steps : []` yielded an
  // empty list and skipped the job whole. Verified before the fix against a
  // caller whose job was `uses: ./.github/workflows/reusable.yml` with
  // `secrets: inherit`, the called workflow holding an `actions/cache@v4` step:
  // exit 0, `OK`, nothing scanned.
  describe('reusable workflows', () => {
    const rfx = (name) =>
      resolve(
        fileURLToPath(import.meta.url),
        `../fixtures/lint-no-workflow-caching/reusable/.github/workflows/${name}`,
      )

    it('follows a job-level `uses:` into the called workflow', () => {
      const r = run(rfx('reusable-cache.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/actions\/cache@/)
    })

    // The called workflow adds a job of its own between the caller's job and
    // the step, so a message that names only the caller job sends the reader to
    // a file with no `actions/cache` in it — and, worse, no `steps:` either.
    it('names the caller job, the called workflow, and its job and step', () => {
      const r = run(rfx('reusable-cache.yml'))
      expect(r.output).toMatch(
        /job "publish" -> \.github\/workflows\/called-cache\.yml job "release" step "Restore the compiled binding"/,
      )
    })

    // The case that proves the two traversals compose rather than each handling
    // only its own shape: the workflow hop lands on a job whose step hands off
    // to a local composite, and the cache is inside that.
    it('composes with the composite traversal: workflow -> composite -> cache', () => {
      const r = run(rfx('reusable-composite.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(
        /job "publish" -> \.github\/workflows\/called-composite\.yml job "build" step "Build the protect-ffi binding" -> \.github\/actions\/cachey\/action\.yml step "Restore the compiled binding"/,
      )
    })

    it('follows a called workflow that itself calls a called workflow', () => {
      const r = run(rfx('reusable-nested.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(
        /job "publish" -> \.github\/workflows\/called-outer\.yml job "forward" -> \.github\/workflows\/called-cache\.yml job "release" step "Restore the compiled binding"/,
      )
    })

    // Same reasoning 402af3f3 recorded for composites: the called workflow's
    // steps default the same way, so exempting them would make "move the step
    // into a reusable workflow" a supported way out of the rule — one level up
    // from the way out that commit closed.
    it('applies the explicit-`false` rules inside a called workflow', () => {
      const r = run(rfx('reusable-missing-explicit-false.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/pnpm\/action-setup/)
      expect(r.output).toMatch(/package-manager-cache/)
    })

    it('passes on a called workflow that disables caching explicitly', () => {
      expect(run(rfx('reusable-clean.yml')).exitCode).toBe(0)
    })

    // A job-level `with:` is inputs to the called workflow, not `with:` on an
    // action step. Running the step rules over the job object would flag this
    // caller for passing `cache: true` to an input named `cache` — a finding
    // about nothing, in the file least able to act on it.
    it('does not read a called workflow`s inputs as step inputs', () => {
      expect(run(rfx('reusable-input-named-cache.yml')).exitCode).toBe(0)
    })

    // The verdict does not turn on how credentials reach the called workflow.
    // `secrets:` is not the only channel — `permissions:` is inherited
    // independently, and that is what mints the OIDC token npm trusted
    // publishing signs with, so a call passing no secrets at all can still
    // publish. A restore also does not need credentials in its own job to be
    // the attack: poisoned bytes landing in a build job that hands an artifact
    // to a publish job is the canonical shape. Conditioning on `secrets:` would
    // buy nothing and hand an attacker a phrasing that evades the gate.
    it('flags the cache however credentials are passed, or not passed', () => {
      for (const name of [
        'reusable-cache.yml', // secrets: inherit
        'reusable-explicit-secrets.yml', // secrets: {NPM_TOKEN: ...}
        'reusable-no-secrets.yml', // no secrets: key at all
      ]) {
        expect(run(rfx(name)).exitCode, name).toBe(1)
      }
    })

    // `execFileSync` has no timeout here, so an unguarded cycle hangs the suite
    // rather than failing it. The count is the real assertion — a visited set
    // that does not span the workflow hops terminates but re-reports the cache
    // once per path into it.
    it('terminates on a cyclic reusable reference, reporting once', () => {
      const r = run(rfx('reusable-cyclic.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/Found 1 caching issue/)
    })

    it('exits 2 when a job-level `uses:` resolves to no workflow file', () => {
      const r = run(rfx('reusable-unresolvable.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(/no-such-workflow/)
    })

    // A remote reusable workflow is reported, where a remote *step* action is
    // skipped, and the difference is coverage rather than depth. A marketplace
    // step sits inside a job whose step list the gate has read end to end; the
    // residual risk is bounded, and reporting every `actions/checkout@v6` would
    // make the gate exit 2 forever and mean nothing. A remote job-level `uses:`
    // is the whole job — the gate reads no steps, reaches no verdict, and
    // prints OK anyway. That is the exact failure this file exists to stop: a
    // check that never ran reads like a check that passed. It is also
    // actionable and rare (zero today), so the report is signal, not noise —
    // inline the job, or point it at a workflow in this checkout.
    it('reports a remote reusable workflow as un-auditable rather than passing it', () => {
      const r = run(rfx('reusable-remote.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(/osv-scanner-reusable\.yml@v2\.3\.8/)
      expect(r.output).toMatch(/not in this checkout/)
    })

    // Never reached on GitHub — the schema rejects `steps:` and `uses:` on one
    // job — but this gate runs on files GitHub has not validated yet. Treating
    // either key as authoritative would let an invalid file hide a cache behind
    // the key the gate chose to ignore and still report a pass, so both are
    // checked and both are counted.
    it('checks both halves of a job carrying `steps:` and `uses:`', () => {
      const r = run(rfx('reusable-both.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/Found 2 caching issue/)
      expect(r.output).toMatch(/step "Restore the toolchain"/)
      expect(r.output).toMatch(/called-cache\.yml job "release"/)
    })
  })

  // The gap both traversals ran straight past. `CACHE_ACTION` recognised only
  // GitHub's first-party cache action, and the `with.cache` rule only fires on
  // an action that takes a `cache:` input — so a third-party cache action with
  // neither was invisible to every rule in the file. Reproduced before the fix
  // against a composite reached from a targeted workflow holding
  // `useblacksmith/cache@v5` and `Swatinem/rust-cache@v2`: `OK`, exit 0.
  //
  // The fix is not two more names on a regex. See the ALLOWLIST RATIONALE in
  // the script: every remote `uses:` reachable from a targeted workflow must be
  // on `AUDITED_ACTIONS`, so the gate fails CLOSED on an action it has never
  // met — which is the only posture that survives the next vendor.
  describe('third-party cache actions and unaudited `uses:`', () => {
    const cfx = (name) =>
      resolve(
        fileURLToPath(import.meta.url),
        `../fixtures/lint-no-workflow-caching/composites/.github/workflows/${name}`,
      )
    const rfx = (name) =>
      resolve(
        fileURLToPath(import.meta.url),
        `../fixtures/lint-no-workflow-caching/reusable/.github/workflows/${name}`,
      )

    it('flags a third-party cache action at workflow level', () => {
      const r = run(fx('thirdparty-cache.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/useblacksmith\/cache@v5/)
      expect(r.output).toMatch(/Swatinem\/rust-cache@v2/)
    })

    // Two rules could fire on `useblacksmith/cache`: it is cache-shaped AND it
    // is unaudited. The cache-shaped message wins, because "this restores a
    // cache" is what the reader needs to act on — "this is not on a list"
    // invites adding it to the list.
    it('names a cache-shaped action as a cache, not merely as unaudited', () => {
      const r = run(fx('thirdparty-cache.yml'))
      expect(r.output).toMatch(
        /useblacksmith\/cache@v5` — a third-party cache action/,
      )
    })

    // `Swatinem/rust-cache` is the check the shape heuristic had to survive: a
    // segment-equality test (`owner/cache`) misses it, a substring test does
    // not. Verified, not assumed.
    it('flags a cache action whose name is not exactly `cache`', () => {
      const r = run(fx('cache-family.yml'))
      expect(r.exitCode).toBe(1)
      for (const name of [
        'buildjet/cache',
        'runs-on/cache',
        'tespkg/actions-cache',
      ]) {
        expect(r.output, name).toContain(name)
      }
    })

    // The case the allowlist exists for, and the argument against a denylist of
    // any kind. `gradle/actions/setup-gradle` caches by default, has no `cache:`
    // input, and has no "cache" in its name — so no enumeration of cache
    // actions can see it. The message must say unaudited, not cache: claiming
    // it caches would be a guess, and the finding is true either way.
    it('flags a caching setup action that no cache-name rule could see', () => {
      const r = run(fx('unaudited-setup.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/gradle\/actions\/setup-gradle@v4/)
      expect(r.output).toMatch(/AUDITED_ACTIONS/)
      expect(r.output).not.toMatch(/setup-gradle@v4` — a third-party cache/)
    })

    // Over-trigger guard. Every `uses:` here is allowlisted and none caches,
    // `changesets/action` most of all: it is third-party, it is real
    // (release.yml's publish step), and its name is nowhere near "cache". A
    // rule that fired here would fire on the live release workflow — which is
    // what the two live-target assertions above independently confirm.
    it('does not flag audited actions, including third-party ones', () => {
      expect(run(fx('audited-actions.yml')).exitCode).toBe(0)
    })

    it('flags a third-party cache action inside a local composite', () => {
      const r = run(cfx('composite-thirdparty-cache.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(
        /step "Build the protect-ffi binding" -> \.github\/actions\/thirdparty-cache\/action\.yml step "Restore the compiled binding"/,
      )
      expect(r.output).toMatch(/useblacksmith\/cache@v5/)
    })

    it('flags a third-party cache action inside a reusable workflow', () => {
      const r = run(rfx('reusable-thirdparty-cache.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(
        /job "publish" -> \.github\/workflows\/called-thirdparty-cache\.yml job "release" step "Restore the Cargo build"/,
      )
      expect(r.output).toMatch(/Swatinem\/rust-cache@v2/)
    })

    // A local `uses:` is exempt from the allowlist because this gate opens it
    // and reads every step — it is audited by construction, not trusted. Losing
    // that exemption would report `./.github/actions/cachey` as unaudited *as
    // well as* the `actions/cache@v4` inside it, burying the finding that
    // matters under one about the wrapper. The count is the assertion; grepping
    // the output for `AUDITED_ACTIONS` would only find the epilogue, which
    // names it unconditionally.
    it('does not report a local composite as unaudited', () => {
      const r = run(cfx('composite-cache.yml'))
      expect(r.output).toMatch(/Found 1 caching issue/)
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
