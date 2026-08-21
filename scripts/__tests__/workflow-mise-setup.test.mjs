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

/** The `node:child_process` functions that start a process. */
const SPAWN_FUNCTIONS = [
  'execSync',
  'exec',
  'execFileSync',
  'execFile',
  'spawnSync',
  'spawn',
]

/**
 * A local name bound to one of those by a DEFAULT PARAMETER —
 * `function f({ run = execFileSync })` — after which `run('mise', …)` spawns
 * mise exactly as much as the direct call did.
 *
 * This shape is used for injecting a fake spawner in unit tests, and
 * `scripts/sync-lockstep-versions.mjs` adopted it for precisely that reason
 * ("what matters is the argv, and asserting it must not require a Rust
 * toolchain"). The refactor is behaviour-preserving — the workflow passes no
 * override, so the default runs — but it moved the only `mise` spawn in the
 * release chain behind an identifier, and a scanner that matched the
 * `execFileSync(` spelling alone went from finding it to finding nothing. The
 * pin in the first test below is what reported that, which is the argument for
 * the pin.
 */
const INJECTED_SPAWNER = new RegExp(
  `\\b([A-Za-z_$][\\w$]*)\\s*=\\s*(?:${SPAWN_FUNCTIONS.join('|')})\\b`,
  'g',
)

/**
 * The first argument of every spawn in a source file, as a literal.
 *
 * Both shapes matter and they read differently: `execFileSync('mise', [...])`
 * names the binary alone, while `execSync('mise run build')` is a whole shell
 * line. `invokesMise` below accepts either.
 */
function spawnedLiterals(source) {
  const names = new Set(SPAWN_FUNCTIONS)
  for (const [, alias] of source.matchAll(INJECTED_SPAWNER)) names.add(alias)
  const spawn = new RegExp(
    `\\b(?:${[...names].join('|')})\\s*\\(\\s*(['"\`])([^'"\`]*)\\1`,
    'g',
  )
  return [...source.matchAll(spawn)].map(([, , literal]) => literal)
}

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
  for (const launched of spawnedLiterals(source)) {
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

// ---------------------------------------------------------------------------
// The INPUTS on that step, not just its presence.
//
// Everything above answers "is there a mise setup step, and is it early
// enough?". `release.yml`'s step carries five inputs and three of them are
// load-bearing in a way the value alone does not show — each one is a default
// that had to be overridden, so the failure mode is a copy-paste from
// `test-eql.yml` (where the defaults are correct) or a tidy-up that deletes an
// input for looking redundant. The comment block above the step explains all
// three at length; comments do not fail.
//
// `cache: false` is the fourth and is NOT asserted here — `pnpm run
// lint:workflow-cache` (scripts/lint-no-workflow-caching.mjs) already forbids a
// cache restore in any job that publishes, which is the stronger form of the
// same rule.

/** Where mise looks for config, relative to `working_directory`. */
const MISE_CONFIG_NAMES = [
  'mise.toml',
  '.mise.toml',
  'mise/config.toml',
  '.mise/config.toml',
  '.config/mise.toml',
]

/** Action inputs arrive as strings; YAML gives us booleans. Compare as text. */
const inputIs = (value, expected) => String(value) === expected

/** Every `jdx/mise-action` step in the workflow directory, with its job. */
const MISE_STEPS = workflowFiles().flatMap((file) => {
  const doc = readWorkflow(file)
  return Object.entries(doc?.jobs ?? {}).flatMap(([name, job]) =>
    (Array.isArray(job?.steps) ? job.steps : [])
      .filter(isMiseSetup)
      .map((step) => ({
        id: `${file} / ${name}`,
        inputs: step?.with ?? {},
        permissions: job?.permissions ?? {},
      })),
  )
})

/**
 * Jobs that publish to npm through OIDC trusted publishing.
 *
 * `id-token: write` is the marker because it is the thing OIDC cannot work
 * without — a publish job that loses it stops publishing, loudly, rather than
 * quietly ceasing to be covered by the checks below.
 */
const OIDC_MISE_STEPS = MISE_STEPS.filter(({ permissions }) =>
  inputIs(permissions?.['id-token'], 'write'),
)

describe('the mise setup step carries the inputs it depends on', () => {
  it('finds mise setup steps', () => {
    // The floor, again. Every check below iterates a discovered set.
    expect(MISE_STEPS.length).toBeGreaterThan(0)
  })

  it('points every mise setup step at a directory that has a mise config', () => {
    // THE TRUST ERROR. mise reads config from the current directory and its
    // PARENTS, and this repo has NO mise config at its root — the two that
    // exist are `packages/eql/mise.toml` and `packages/protect-ffi/mise.toml`.
    // So an action running at the default working directory finds nothing to
    // install and leaves the config untrusted, and the first `mise run` fails
    // with "Config files … are not trusted", which reads as a broken toolchain
    // rather than a wrong directory. In `release.yml` that file is also where
    // the Rust toolchain comes from (`[tools] rust`), so the same input is what
    // makes the step a cargo setup; there is deliberately no second one.
    const offenders = MISE_STEPS.filter(({ inputs }) => {
      const dir = inputs?.working_directory
      if (typeof dir !== 'string' || dir.trim() === '') return true
      return !MISE_CONFIG_NAMES.some((name) =>
        existsSync(join(REPO_ROOT, dir, name)),
      )
    }).map(
      ({ id, inputs }) =>
        `${id}: working_directory=${inputs?.working_directory ?? '(unset)'}`,
    )

    expect(
      offenders,
      'These `jdx/mise-action` steps do not name a directory containing a mise config. There is no mise config at the repo root, so mise installs nothing and marks the config untrusted — the first `mise run` then fails with a TRUST error that looks like a toolchain problem.',
    ).toEqual([])
  })

  it('finds a publishing job that installs mise', () => {
    // Anti-vacuity for the two checks below: they are scoped to jobs holding
    // `id-token: write`, and if that set empties they pass having checked
    // nothing. `release.yml`'s `release` job is the member today.
    expect(
      OIDC_MISE_STEPS.map(({ id }) => id),
      'No job holds `id-token: write` and installs mise, so the npm-version and env checks below cover nothing. If the publish job stopped installing mise, delete those checks; if it moved, this is the reminder to re-scope them.',
    ).not.toEqual([])
  })

  it('keeps mise shims off PATH in a publishing job', () => {
    // `add_shims_to_path` DEFAULTS TO TRUE, and the shim directory is PREPENDED
    // to PATH for every later step. `packages/eql/mise.toml` pins
    // `node = "22"`, so with the default, mise's Node shadows the one
    // `actions/setup-node` installed — and `changeset publish` shells out to
    // that Node's bundled npm 10.x instead of the `npm@^11.5.1` the job
    // installed. OIDC trusted publishing requires >= 11.5.1 and returns E404
    // below it, so the release fails at the publish call, after
    // `changeset version` has already rewritten every manifest.
    // `mise run` resolves its own toolchain internally and does not need shims.
    const offenders = OIDC_MISE_STEPS.filter(
      ({ inputs }) => !inputIs(inputs?.add_shims_to_path, 'false'),
    ).map(
      ({ id, inputs }) =>
        `${id}: add_shims_to_path=${inputs?.add_shims_to_path ?? '(default true)'}`,
    )

    expect(
      offenders,
      "A job that publishes to npm over OIDC installs mise with its shims on PATH. mise prepends them, so its pinned `node` shadows `actions/setup-node`, `changeset publish` gets that Node's npm 10.x, and OIDC trusted publishing fails with E404 (it needs npm >= 11.5.1). Set `add_shims_to_path: false` — a copy-paste of the `test-eql.yml` step will not carry it, because there the default is harmless.",
    ).toEqual([])
  })

  it('keeps the mise config’s env out of a publishing job', () => {
    // `env` DEFAULTS TO TRUE, which exports the config's `[env]` block into
    // GITHUB_ENV for every subsequent step. `packages/eql/mise.toml` sets
    // `DATABASE_URL`, `POSTGRES_PASSWORD`, `PGPORT` and friends, all pointed at
    // a Postgres this job does not run — injected into the one job that holds
    // the npm publishing credential, and into whatever `pnpm run release`
    // spawns from there.
    const offenders = OIDC_MISE_STEPS.filter(
      ({ inputs }) => !inputIs(inputs?.env, 'false'),
    ).map(({ id, inputs }) => `${id}: env=${inputs?.env ?? '(default true)'}`)

    expect(
      offenders,
      "A job that publishes to npm over OIDC lets `jdx/mise-action` export the mise config's `[env]` block into GITHUB_ENV. `packages/eql/mise.toml` points DATABASE_URL and the POSTGRES_* variables at a database that does not exist in this job. Set `env: false`.",
    ).toEqual([])
  })
})
