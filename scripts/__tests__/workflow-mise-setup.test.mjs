import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A job whose command chain reaches `mise` must install mise, first.
 *
 * ## Why this fails open, and silently, without a test
 *
 * `mise` is NOT preinstalled on GitHub's ubuntu runner images. A job that needs
 * it and does not install it fails with `ENOENT: spawn mise` — which is loud
 * enough, once it runs. The problem is *when* it runs.
 *
 * `release.yml`'s `release` job passes `version: pnpm run version` to
 * `changesets/action`. That input is a shell command, and the chain behind it
 * is three hops deep and entirely invisible in the workflow file:
 *
 *     version: pnpm run version                       (release.yml)
 *       -> "changeset version && node scripts/sync-lockstep-versions.mjs"
 *                                                     (root package.json)
 *          -> execFileSync('mise', ['run', 'release:prepare_bindings_assets'…])
 *                                                     (that script)
 *
 * Nothing in `release.yml` says the word `mise`. The job installed pnpm, Node,
 * node-gyp and npm and looked complete. And the branch that runs the hook —
 * changesets taking its VERSION branch, which it does only when `.changeset/`
 * holds unconsumed changesets — is not the branch a release rehearsal
 * exercises, so the gap survived review of both the workflow and the script.
 *
 * The cost of finding out at run time is what makes this a test rather than a
 * comment: `changeset version` runs FIRST and rewrites every manifest and
 * changelog in the tree. The ENOENT lands after that, so the failure is a
 * half-applied version bump in a job holding `contents: write`, and the repair
 * is manual.
 *
 * ## What is checked
 *
 * The chain is RESOLVED, not pattern-matched, because the whole defect is that
 * the requirement is not visible at the call site. `pnpm run <script>` is
 * followed into the root `package.json`, `node <path>.mjs` into the file, and
 * `child_process` spawns inside those files are read for the binary they
 * launch. A job that reaches `mise` by any of those routes must carry a mise
 * setup step, at a lower step index than the step that needs it.
 *
 * ## Why `mise` and not also `cargo`
 *
 * The runner images DO ship a Rust toolchain, and this repo relies on that:
 * `.github/actions/build-ffi-binding` runs `cargo build --release` with no
 * toolchain step of its own. Requiring a Rust setup step wherever cargo is
 * reachable would report every one of those as a finding. mise is the tool that
 * is genuinely absent — and, for the EQL tasks, the thing that supplies cargo
 * anyway (`packages/eql/mise.toml` pins `rust` under `[tools]`).
 */

/**
 * Action inputs whose value is a shell command rather than data.
 *
 * Hand-listed because there is no way to tell from the outside: `version:` on
 * `changesets/action` is a command, `version:` on `jdx/mise-action` is a
 * version number. The floor below fails if an entry here matches no step, so a
 * renamed input cannot leave this silently covering nothing.
 */
const ACTION_COMMAND_INPUTS = new Map([
  ['changesets/action', ['version', 'publish']],
])

/** A `uses:` value reduced to its `owner/repo` half, lowercased. */
const actionPath = (uses) =>
  typeof uses === 'string' ? uses.trim().split('@')[0].toLowerCase() : null

/** Steps that put `mise` on PATH for everything after them. */
const isMiseSetup = (step) => actionPath(step?.uses) === 'jdx/mise-action'

/** Every shell command a step runs — its `run:`, plus any command-valued input. */
function stepCommands(step) {
  const commands = []
  if (typeof step?.run === 'string') commands.push(step.run)
  for (const input of ACTION_COMMAND_INPUTS.get(actionPath(step?.uses)) ?? []) {
    const value = step?.with?.[input]
    if (typeof value === 'string') commands.push(value)
  }
  return commands
}

const ROOT_SCRIPTS =
  JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')).scripts ??
  {}

/**
 * `pnpm run x` / `npm run x` / `pnpm x` / `yarn x`.
 *
 * A capture that is not a root script name resolves to nothing and is dropped,
 * which is what happens to `pnpm install`, `pnpm exec …` and the `--filter`
 * forms. Package-level scripts are deliberately not followed: no workflow input
 * reaches `mise` that way today, and resolving them would mean modelling
 * `--filter` selection.
 */
const RUN_SCRIPT =
  /(?:^|[\s;&|(])(?:pnpm|npm|yarn)(?:\s+run)?\s+([a-z0-9:_-]+)/gi

/** `node path/to/file.mjs`, with any `node` flags in between. */
const NODE_SCRIPT = /\bnode\s+(?:--?[^\s]+\s+)*([\w./-]+\.[cm]?js)\b/g

/**
 * The first argument of a `node:child_process` spawn, as a literal.
 *
 * Both shapes matter and they read differently: `execFileSync('mise', [...])`
 * names the binary alone, while `execSync('mise run build')` is a whole shell
 * line. `commandLaunchesMise` below accepts either.
 */
const CHILD_PROCESS_SPAWN =
  /\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn)\s*\(\s*(['"`])([^'"`]*)\1/g

/** Does this shell line invoke `mise` as a command? */
const invokesMise = (command) => /(?:^|[\s;&|(])mise(?:\s|$)/.test(command)

/**
 * Whether a shell command reaches `mise`, following package scripts and the
 * Node scripts they run.
 *
 * `seen` spans the whole walk so a script pair that references each other
 * terminates, and so a script reached twice is read once.
 */
function reachesMise(command, seen = new Set()) {
  if (typeof command !== 'string' || seen.has(command)) return false
  seen.add(command)
  if (invokesMise(command)) return true

  for (const [, name] of command.matchAll(RUN_SCRIPT)) {
    if (ROOT_SCRIPTS[name] && reachesMise(ROOT_SCRIPTS[name], seen)) return true
  }
  for (const [, relative] of command.matchAll(NODE_SCRIPT)) {
    if (fileReachesMise(relative, seen)) return true
  }
  return false
}

/** The same question, of a JavaScript file this repo owns. */
function fileReachesMise(relative, seen) {
  const file = join(REPO_ROOT, relative)
  if (seen.has(file) || !existsSync(file)) return false
  seen.add(file)

  const source = readFileSync(file, 'utf8')
  for (const [, , launched] of source.matchAll(CHILD_PROCESS_SPAWN)) {
    if (launched === 'mise' || invokesMise(launched)) return true
  }
  // A script that runs another script. Same walk, one level down.
  for (const [, nested] of source.matchAll(NODE_SCRIPT)) {
    if (fileReachesMise(nested, seen)) return true
  }
  return false
}

/** Every job in the workflow directory, with its steps. */
const JOBS = workflowFiles().flatMap((file) => {
  const doc = readWorkflow(file)
  return Object.entries(doc?.jobs ?? {}).map(([name, job]) => ({
    id: `${file} / ${name}`,
    steps: Array.isArray(job?.steps) ? job.steps : [],
  }))
})

/** `{ id, needsAt, setupAt }` for every job whose chain reaches mise. */
const MISE_JOBS = JOBS.map(({ id, steps }) => {
  const needsAt = steps.findIndex((step) =>
    stepCommands(step).some((command) => reachesMise(command)),
  )
  const setupAt = steps.findIndex(isMiseSetup)
  return { id, needsAt, setupAt }
}).filter(({ needsAt }) => needsAt !== -1)

describe('a job that reaches mise installs mise', () => {
  it('resolves the release hook’s chain, which names mise nowhere it is called', () => {
    // THE MECHANISM, pinned directly. Every assertion below is "for each job
    // whose chain reaches mise…", and a resolver that quietly stopped following
    // `pnpm run` or `node …` would make that set empty and every one of them
    // pass having checked nothing. This is the chain the defect lived in, so it
    // is the one worth pinning: three hops, no `mise` token at the call site.
    expect(reachesMise('pnpm run version')).toBe(true)
    // …and the resolver is not simply answering true. A root script with no
    // mise anywhere behind it must come back false.
    expect(reachesMise('pnpm run code:check')).toBe(false)
  })

  it('finds jobs to check', () => {
    // The floor. This whole file is a discovery scan, and a scan that matches
    // nothing exits green — the failure mode `lint-no-eql-registry-pins.mjs`
    // spends a page of its header on.
    expect(MISE_JOBS.length).toBeGreaterThan(0)
  })

  it('matches every command-valued action input against a real step', () => {
    // ACTION_COMMAND_INPUTS is hand-maintained, so it goes stale silently: an
    // input renamed upstream leaves an entry that reads as coverage and follows
    // nothing. Require each key to name an action a step actually uses.
    const used = new Set(
      JOBS.flatMap(({ steps }) => steps.map((step) => actionPath(step?.uses))),
    )
    expect(
      [...ACTION_COMMAND_INPUTS.keys()].filter((action) => !used.has(action)),
      'ACTION_COMMAND_INPUTS names an action no workflow step uses — its command inputs are followed nowhere.',
    ).toEqual([])
  })

  it('installs mise in every job that reaches it', () => {
    // The defect. `release.yml`'s `release` job runs the lockstep version hook
    // through `changesets/action`'s `version:` input and installed no mise, so
    // the first push to main with unconsumed changesets would rewrite every
    // manifest and then die on ENOENT.
    const offenders = MISE_JOBS.filter(({ setupAt }) => setupAt === -1).map(
      ({ id }) => id,
    )
    expect(
      offenders,
      'These jobs run a command whose chain shells out to `mise`, which is not preinstalled on ' +
        "GitHub's runner images. Add a `jdx/mise-action` step — with `working_directory:` set to " +
        'the directory holding the `mise.toml` the task needs, or mise will not trust it.',
    ).toEqual([])
  })

  it('installs mise before the step that needs it', () => {
    // PATH is set for SUBSEQUENT steps, so a setup step that lands after the
    // step needing it is the same failure with a passing existence check.
    const offenders = MISE_JOBS.filter(
      ({ needsAt, setupAt }) => setupAt !== -1 && setupAt > needsAt,
    ).map(
      ({ id, needsAt, setupAt }) =>
        `${id}: needs at ${needsAt}, installs at ${setupAt}`,
    )
    expect(offenders).toEqual([])
  })
})
