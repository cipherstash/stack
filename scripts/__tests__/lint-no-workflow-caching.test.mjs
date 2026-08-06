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

    // `execFileSync` has no timeout here, and does not need one: the script is
    // synchronous end to end, so it has no way to hang. Deleting the `visited`
    // guard was tried — the recursion blows the stack and the child exits in
    // well under a second, which a timeout would not improve on.
    //
    // The offender count is the real assertion, because that exit is a bare 1
    // and so is a genuine finding. A visited set that is per-branch rather than
    // per-run terminates too, but reports `loop-b` once per path into it.
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

    // The sibling asymmetry, and the bug in it. `resolveWorkflowFile` has
    // guarded `isFile` since it was written; `resolveActionFile` returned on a
    // bare `existsSync`, so a DIRECTORY named `action.yml` passed as the
    // manifest and `readFileSync` aborted the run with an unhandled EISDIR.
    // Guarded, the directory is skipped, `action.yaml` is tried, and this lands
    // on the report that already exists for a local `uses:` pointing at
    // nothing — the accurate message rather than a stack trace.
    it('skips a directory named `action.yml` rather than reading it', () => {
      const r = run(cfx('composite-dir-action-yml.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(/dir-action-yml/)
      expect(r.output).toMatch(/no action\.yml or action\.yaml there/)
    })
  })

  // The step-level twin of the false positive `reusable-input-named-cache`
  // pins one level up. `with:` on a step that hands off to a LOCAL action is
  // that action's declared inputs, and a composite is free to declare one
  // called `cache` — so the step rules reported ``with.cache: true` restores
  // the GitHub Actions cache` about an input that restores nothing.
  //
  // The exemption is narrow on purpose, because its justification is "the body
  // is audited instead", not "local is trusted". It applies only where this
  // gate actually opens the action and reads its steps — a resolved
  // `runs.using: composite`. A local `uses:` that resolves to nothing, or to a
  // JS or Docker action with no step list, keeps the heuristic, because there
  // the heuristic is the only signal the gate has: a local `uses:` is already
  // exempt from AUDITED_ACTIONS as well.
  describe('`with.cache` on a step that hands off to a local action', () => {
    const cfx = (name) =>
      resolve(
        fileURLToPath(import.meta.url),
        `../fixtures/lint-no-workflow-caching/composites/.github/workflows/${name}`,
      )

    it("does not read a composite's declared inputs as step inputs", () => {
      expect(run(cfx('composite-input-named-cache.yml')).exitCode).toBe(0)
    })

    // The guard that makes the exemption safe rather than a hole, and the
    // reason it may only apply where the body is read: a composite that
    // forwards its `cache` input into a step that caches is still a finding,
    // and the finding names the step doing the caching rather than the caller
    // that switched it on. One issue, not two — the caller is not a second
    // problem to fix.
    it('still flags a composite that forwards `cache` into a caching step', () => {
      const r = run(cfx('composite-cache-passthrough.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/Found 1 caching issue/)
      expect(r.output).toMatch(
        /cache-passthrough\/action\.yml step "Install Node\.js": `with\.cache/,
      )
      expect(r.output).not.toMatch(
        /step "Build the protect-ffi binding": `with\.cache/,
      )
    })

    // `runs.using: node20`, `main: index.js` — the gate opens the manifest,
    // finds no step list, and audits nothing. Since a local `uses:` is already
    // exempt from AUDITED_ACTIONS, the caller's `with:` is all that is left
    // standing here.
    it('keeps the `with.cache` rule on a local JavaScript action', () => {
      const r = run(cfx('local-js-action.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/with\.cache/)
    })

    // No manifest to open means no body to audit, so the heuristic stays on —
    // and its finding has to stay visible next to the exit-2 report rather
    // than being swallowed by it.
    it('keeps the `with.cache` rule on a local `uses:` resolving to nothing', () => {
      const r = run(cfx('composite-unresolvable-with-cache.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(/with\.cache/)
      expect(r.output).toMatch(/no action\.yml or action\.yaml there/)
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

  // Every `yaml.load` in the script was unguarded, so a file this gate cannot
  // parse — malformed YAML, EISDIR, EACCES — threw straight out of the run: a
  // stack trace instead of a finding, exit 1 (indistinguishable from "found a
  // caching issue"), and every remaining target never scanned at all.
  //
  // An unparseable file is the same problem as a missing one. It hands the
  // traversal no step list, so nothing below it is audited — which is exactly
  // what the un-auditable list, exit 2, and the "this gate could not look"
  // epilogue are for.
  describe('a file this gate cannot parse', () => {
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

    it('reports an unparseable target rather than crashing on it', () => {
      const r = run(fx('malformed.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(/Found 1 un-auditable reference/)
      expect(r.output).toMatch(
        /malformed\.yml — could not be read: bad indentation of a mapping entry \(\d+:\d+\)/,
      )
    })

    // js-yaml's message is a position line followed by a multi-line source
    // snippet — numbered lines and a caret ruler, carrying their own
    // indentation. Pasting all of it into a two-space bullet wrecks the report,
    // so the first line is kept and the snippet dropped. The position is the
    // half that lets someone fix the file.
    it('keeps the parse error’s position and drops its source snippet', () => {
      const r = run(fx('malformed.yml'))
      expect(r.output).toMatch(/\(\d+:\d+\)/)
      expect(r.output).not.toMatch(/-{4,}\^/)
      expect(r.output).not.toMatch(/^\s*\d+ \| /m)
    })

    // The target loop died on the first unparseable file, so a malformed
    // release.yml meant tests-supply-chain.yml was never scanned — the gate
    // silently stopped covering the workflow it could still read.
    it('keeps scanning the remaining targets after an unparseable one', () => {
      const r = run(fx('malformed.yml'), fx('actions-cache.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(/could not be read/)
      expect(r.output).toMatch(/Found 1 caching issue/)
      expect(r.output).toMatch(/actions\/cache@/)
    })

    // A manifest that does not parse is a NON-composite manifest, for the same
    // reason the unresolvable branch beside it is: no body was audited, so
    // every step rule stays on, `with.cache` included. The `actions/cache@v4`
    // inside the unreadable file must not be reported as found — this gate
    // never read it, and claiming otherwise would be a guess.
    it('keeps every step rule on a caller whose composite does not parse', () => {
      const r = run(cfx('composite-malformed.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(
        /\.github\/actions\/malformed\/action\.yml — could not be read:/,
      )
      expect(r.output).toMatch(/with\.cache/)
      expect(r.output).not.toMatch(/actions\/cache@v4/)
    })

    it('stops the workflow hop at a called workflow that does not parse', () => {
      const r = run(rfx('reusable-malformed.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(/Found 1 un-auditable reference/)
      expect(r.output).toMatch(
        /\.github\/workflows\/called-malformed\.yml — could not be read:/,
      )
      expect(r.output).not.toMatch(/actions\/cache@v4/)
    })
  })

  // `LOCAL_USES` was `^\.{1,2}/`, which accepted `../` while the comment
  // directly above it said GitHub requires the `./` prefix. GitHub does not
  // accept `../`, and reading one as local meant two wrong things at once:
  // exempt from `AUDITED_ACTIONS`, and handed to a resolver that `resolve()`s
  // it clean out of the workspace root — so a file OUTSIDE the checkout could
  // be opened and audited as though it were inside it.
  describe('a `../` reference', () => {
    const rfx = (name) =>
      resolve(
        fileURLToPath(import.meta.url),
        `../fixtures/lint-no-workflow-caching/reusable/.github/workflows/${name}`,
      )

    // Falling through to the unaudited branch is fail-closed, so the exit code
    // was never the problem — the wording was. "This gate cannot read a
    // published action's steps" sends the reader to audit a published action
    // that does not exist; the finding is that the reference itself is one
    // GitHub will not run and this gate will not follow.
    it('reports a step-level `../` instead of resolving it', () => {
      const r = run(fx('parent-uses-step.yml'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(
        /uses `\.\.\/outside-action` — a `\.\.\/` reference/,
      )
      expect(r.output).not.toMatch(
        /uses `\.\.\/outside-action` — not in AUDITED_ACTIONS/,
      )
      // Reported, never resolved: nothing outside the workspace root is opened.
      expect(r.output).not.toMatch(/no action\.yml or action\.yaml there/)
    })

    // Same at job level, where the fall-through called it "a remote reusable
    // workflow". Nothing here is remote — the reference is simply invalid.
    it('reports a job-level `../` instead of resolving it', () => {
      const r = run(rfx('reusable-parent-uses.yml'))
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(
        /`uses: \.\.\/outside-workflow\.yml` — a `\.\.\/` reference/,
      )
      expect(r.output).not.toMatch(
        /outside-workflow\.yml` — a remote reusable workflow/,
      )
      expect(r.output).not.toMatch(/no workflow file there/)
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

  // The un-auditable list printed and exited before the offender list was
  // reached, so a run collecting both showed only the reference the gate could
  // not open. The cache finding — the one with a step to delete — stayed
  // hidden until the path was fixed, then arrived on the next run looking new.
  // Both fail CI either way, so this is about what the failure tells you.
  describe('a run that collects both kinds of finding', () => {
    const cfx = (name) =>
      resolve(
        fileURLToPath(import.meta.url),
        `../fixtures/lint-no-workflow-caching/composites/.github/workflows/${name}`,
      )

    it('prints the cache offenders alongside the un-auditable references', () => {
      const r = run(cfx('mixed-unresolved-and-cache.yml'))
      // 2 beats 1 on a mixed run: something WAS found caching, but an
      // incomplete scan is the more severe verdict — the list of what was
      // found may be short.
      expect(r.exitCode).toBe(2)
      expect(r.output).toMatch(/Found 1 un-auditable reference/)
      expect(r.output).toMatch(/no-such-action/)
      expect(r.output).toMatch(/Found 1 caching issue/)
      expect(r.output).toMatch(/actions\/cache@v4/)
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
