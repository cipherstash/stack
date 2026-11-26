import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { basename, dirname, join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import { expr } from './lib/expressions.mjs'
import {
  parseIncludes,
  parseStringArray,
  parseTomlTasks,
  stripCommentLines,
} from './lib/mise-tasks.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { isRunsOnJob } from './lib/runs-on.mjs'
import { readWorkflow, stepsOf, workflowFiles } from './lib/workflows.mjs'

/**
 * Every RunsOn job logs in to Docker Hub before it pulls an image.
 *
 * Docker Hub refuses pulls without a login after too many from one address.
 * RunsOn machines reach that limit: on #1419, Postgres shards failed with
 * `toomanyrequests` before a single test ran, and failed again on a re-run.
 * So a RunsOn job that may pull an image logs in first, with the
 * `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD` secrets.
 *
 * The login must do nothing when either secret is empty. That is the case on a
 * fork's pull request, and on Dependabot's, and the job must still run there.
 *
 * - A service or job container from Docker Hub sets `credentials` to one
 *   expression that reads both secrets and falls back to `fromJSON('{}')`.
 *   `username:` and `password:` keys do not work: GitHub rejects an empty
 *   value for either ("Unexpected value ''"), so the job fails at "Set up
 *   job". With `{}`, the runner pulls without a login.
 * - Any other pull needs a `run:` step before it that pipes the password to
 *   `docker login --password-stdin`, and exits early when either secret is
 *   empty.
 *
 * "May pull" is decided without knowing the registry, so it fails closed. A
 * step that starts or builds a container counts, whichever registry its image
 * comes from. That covers a `docker` command in the step, a `docker/` action
 * that pulls, a local composite action that does either, and a `mise run` of a
 * task that reaches either through its body, its `depends`, or a nested
 * `mise run`. A login a job did not need costs one step and nothing else.
 *
 * A job counts as RunsOn when its label starts with `runs-on=`. It also
 * counts when `MATRIX_RUNNERS` in `lib/runs-on.mjs` says its matrix gives it
 * RunsOn machines, because a matrix runner is an expression this file cannot
 * read. GitHub-hosted runners are not limited this way.
 *
 * In a called workflow, `secrets.*` is empty unless the caller passes it. A
 * login there would skip, and the job would pull anonymously with no error.
 * So every caller of a workflow whose RunsOn jobs log in passes both secrets.
 */

// ---------------------------------------------------------------------------
// What pulls an image
// ---------------------------------------------------------------------------

/** A command that starts or builds a container, so may pull an image. */
const PULLS = new RegExp(
  [
    String.raw`\bdocker(?:-compose|\s+compose)\b[^\n]*\b(?:up|pull|run|create)\b`,
    String.raw`\bdocker\s+(?:run|pull|create|build)\b`,
    String.raw`\bdocker\s+buildx\s+(?:build|bake)\b`,
    String.raw`\bdocker\s+container\s+(?:run|create)\b`,
    String.raw`\bdocker\s+image\s+(?:pull|build)\b`,
  ].join('|'),
)

/** Comment lines gone, and each `\`-continued command on one line. */
const commands = (script) =>
  stripCommentLines(script).replace(/\\\r?\n[ \t]*/g, ' ')

/**
 * `docker/` actions that pull: QEMU's binfmt image, the BuildKit image, and
 * the base images of a build. Logging in and computing tags pull nothing.
 */
const PULLING_ACTION = /^docker\/(?!login-action@|metadata-action@)[\w-]+@/

const DOCKER_HUB_HOSTS = new Set([
  'docker.io',
  'index.docker.io',
  'registry-1.docker.io',
])

/** Whether an image reference names Docker Hub, where a bare name resolves. */
export function onDockerHub(image) {
  const first = String(image).split('/')[0]
  const isHost =
    String(image).includes('/') &&
    (first.includes('.') || first.includes(':') || first === 'localhost')
  return !isHost || DOCKER_HUB_HOSTS.has(first)
}

// ---------------------------------------------------------------------------
// mise tasks
// ---------------------------------------------------------------------------

// Tracked files only. A walk of the working tree would read gitignored
// configs such as mise.local.toml, descend into .claude/worktrees, and fail on
// a broken symbolic link anywhere in an untracked folder.
function trackedFiles(relDir = '.') {
  return execFileSync('git', ['ls-files', '-z', '--', relDir], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
    .split('\0')
    .filter(Boolean)
}

/** Every `mise.toml` / `mise.<env>.toml`, repo-relative. */
const miseConfigs = () =>
  trackedFiles().filter((rel) =>
    /^\.?mise(\.[\w-]+)?\.toml$/.test(basename(rel)),
  )

/** File tasks: `tasks/test/splinter.sh` is the task `test:splinter`. */
function fileTasks(dir) {
  const relDir = relative(REPO_ROOT, dir)
  return trackedFiles(relDir)
    .filter((rel) => !rel.endsWith('.toml'))
    .map((rel) => ({
      name: relative(relDir, rel)
        .replace(/\.[^./]+$/, '')
        .split('/')
        .join(':'),
      block: readFileSync(join(REPO_ROOT, rel), 'utf8'),
    }))
}

/**
 * Task name -> bodies. Names repeat across configs (two packages can each
 * have a `setup`), so a name keeps every body, and pulls if any of them does.
 * That is the fail-closed direction.
 */
function taskIndex() {
  const index = new Map()
  const add = ({ name, block }) => {
    if (!index.has(name)) index.set(name, [])
    index.get(name).push(block)
  }
  for (const config of miseConfigs()) {
    const text = readFileSync(join(REPO_ROOT, config), 'utf8')
    for (const task of parseTomlTasks(text, { bareTables: false })) add(task)
    for (const include of parseIncludes(text)) {
      const path = join(REPO_ROOT, dirname(config), include)
      if (!existsSync(path)) continue
      if (statSync(path).isDirectory()) fileTasks(path).forEach(add)
      else
        parseTomlTasks(readFileSync(path, 'utf8'), {
          bareTables: true,
        }).forEach(add)
    }
  }
  return index
}

// A quote starts a command only at the start of a line, as in a TOML
// `run = [ "mise run …" ]` entry. Mid-line it is a message to the reader.
const COMMAND_START = String.raw`(?:^[ \t]*["']?|(?:&&|\|\||[;|(){}])[ \t]*)`

function invokes(text, taskName) {
  const escaped = taskName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(
    `${COMMAND_START}mise\\s+run\\s+[^\\n'"]*?(?<![\\w:.-])${escaped}(?![\\w:.-])`,
    'm',
  ).test(commands(text))
}

const dependsOf = (body) =>
  [...body.matchAll(/depends\s*=\s*\[([^\]]*)\]/g)].flatMap((m) =>
    parseStringArray(m[1]),
  )

/** The names of every task that may pull an image, directly or through others. */
function pullingTasks(index) {
  const pulling = new Set(
    [...index]
      .filter(([, bodies]) => bodies.some((body) => PULLS.test(commands(body))))
      .map(([name]) => name),
  )
  // Grow the set until nothing new reaches a member: a fixpoint, so a cycle
  // between tasks cannot loop.
  let grew = true
  while (grew) {
    grew = false
    for (const [name, bodies] of index) {
      if (pulling.has(name)) continue
      const reaches = bodies.some(
        (body) =>
          dependsOf(body).some((dep) => pulling.has(dep)) ||
          [...pulling].some((target) => invokes(body, target)),
      )
      if (reaches) {
        pulling.add(name)
        grew = true
      }
    }
  }
  return pulling
}

const PULLING_TASKS = pullingTasks(taskIndex())

// Pulls this file cannot find, because test code or a README the test runs
// starts the container. Each named step counts as a pull.
export const HIDDEN_PULLS = {
  '.github/workflows/prisma-example-readme-e2e.yml#walkthrough': [
    {
      step: 'Run README walkthrough e2e',
      reason:
        "e2e/tests/prisma-example-readme.e2e.test.ts runs the Prisma example's README, whose `docker compose up -d` pulls postgres:16.",
    },
  ],
  '.github/workflows/tests.yml#e2e-tests': [
    {
      step: 'Run E2E tests',
      reason: 'e2e/vitest.config.ts includes the same README walkthrough test.',
    },
    {
      step: 'Run the credentialed Migration Harness self-test',
      reason:
        'With HARNESS_LIVE=1, e2e/migration-harness runs postgres:17-alpine and node:22-bookworm-slim, and builds an image from node:22-bookworm-slim.',
    },
  ],
}

const isHiddenPull = (ref, step) =>
  (HIDDEN_PULLS[ref] ?? []).some((hidden) => hidden.step === step?.name)

// ---------------------------------------------------------------------------
// Steps and jobs
// ---------------------------------------------------------------------------

/** Whether one step, or the local composite action it uses, may pull an image. */
export function stepPulls(step) {
  return stepsOf(step).some((inner) => {
    const uses = typeof inner?.uses === 'string' ? inner.uses.trim() : ''
    if (PULLING_ACTION.test(uses)) return true
    const run = typeof inner?.run === 'string' ? commands(inner.run) : ''
    return (
      PULLS.test(run) || [...PULLING_TASKS].some((task) => invokes(run, task))
    )
  })
}

const USERNAME = expr('secrets.DOCKER_HUB_USERNAME')
const PASSWORD = expr('secrets.DOCKER_HUB_PASSWORD')

/** Whether a step logs in to Docker Hub, and does nothing without the secrets. */
export function loginFinding(step) {
  const run = typeof step?.run === 'string' ? step.run : ''
  if (!/\bdocker\s+login\b/.test(run)) return 'not a login'
  if (
    step.env?.DOCKER_HUB_USERNAME !== USERNAME ||
    step.env?.DOCKER_HUB_PASSWORD !== PASSWORD
  )
    return `does not read ${USERNAME} and ${PASSWORD} into DOCKER_HUB_USERNAME and DOCKER_HUB_PASSWORD`
  if (!/--password-stdin/.test(run))
    return 'does not pass the password on stdin'
  if (
    !/-z\s+"\$DOCKER_HUB_USERNAME"/.test(run) ||
    !/-z\s+"\$DOCKER_HUB_PASSWORD"/.test(run)
  )
    return 'does not skip the login when a secret is empty, so a fork pull request would fail'
  return null
}

/**
 * Whether a step logs out of Docker Hub even when an earlier step failed. The
 * login stores the password in the Docker config file, where every later
 * step's code can read it.
 */
export function logoutFinding(step) {
  const run = typeof step?.run === 'string' ? step.run : ''
  if (!/\bdocker\s+logout\b/.test(run)) return 'not a logout'
  if (!/\balways\(\)/.test(String(step.if ?? '')))
    return 'logs out of Docker Hub only when every earlier step passed; add always() to its if'
  return null
}

/** Whether a container's `credentials` log in, and still work without the secrets. */
export function credentialsFinding(credentials) {
  if (credentials === undefined) return 'sets no credentials'
  if (typeof credentials !== 'string')
    return "sets username and password keys, which fail at 'Set up job' when a secret is empty; use one expression with a fromJSON('{}') fallback"
  const flat = credentials.replace(/\s+/g, ' ')
  if (
    !flat.includes('secrets.DOCKER_HUB_USERNAME') ||
    !flat.includes('secrets.DOCKER_HUB_PASSWORD')
  )
    return 'does not read secrets.DOCKER_HUB_USERNAME and secrets.DOCKER_HUB_PASSWORD'
  if (!flat.includes("|| fromJSON('{}')"))
    return "has no || fromJSON('{}') fallback for when a secret is empty"
  return null
}

/** Every finding for one job, or [] when it is correct. */
export function jobFindings(where, job, ref) {
  if (!isRunsOnJob(job, ref)) return []
  const findings = []
  const containers = [
    ...Object.entries(job.services ?? {}).map(([name, svc]) => [
      `service ${name}`,
      svc,
    ]),
    ...(job.container ? [['container', job.container]] : []),
  ]
  for (const [what, def] of containers) {
    const image = typeof def === 'string' ? def : def?.image
    if (!image || !onDockerHub(image)) continue
    const finding = credentialsFinding(def?.credentials)
    if (finding)
      findings.push(
        `${where}: ${what} pulls ${image} from Docker Hub, and ${finding}`,
      )
  }
  const steps = job.steps ?? []
  const pulls = (step) => stepPulls(step) || isHiddenPull(ref, step)
  const firstPull = steps.findIndex(pulls)
  if (firstPull === -1) return findings
  const logins = steps
    .map((step, i) => ({ i, finding: loginFinding(step) }))
    .filter(({ finding }) => finding !== 'not a login')
  for (const { i, finding } of logins)
    if (finding) findings.push(`${where}: step ${i + 1} ${finding}`)
  const nameOf = (i) => steps[i].name ?? steps[i].uses ?? 'run'
  if (!logins.some(({ i }) => i < firstPull))
    findings.push(
      `${where}: step ${firstPull + 1} (${nameOf(firstPull)}) may pull an image, and no Docker Hub login comes before it`,
    )
  if (logins.length === 0) return findings
  const lastPull = steps.findLastIndex(pulls)
  const logouts = steps
    .map((step, i) => ({ i, finding: logoutFinding(step) }))
    .filter(({ finding }) => finding !== 'not a logout')
  for (const { i, finding } of logouts) {
    if (finding) findings.push(`${where}: step ${i + 1} ${finding}`)
    if (i < lastPull)
      findings.push(
        `${where}: step ${i + 1} logs out of Docker Hub before step ${lastPull + 1} (${nameOf(lastPull)}), which may pull an image`,
      )
  }
  if (!logouts.some(({ i, finding }) => i > lastPull && finding === null))
    findings.push(
      `${where}: no Docker Hub logout with if: always() comes after step ${lastPull + 1} (${nameOf(lastPull)}), the last step that may pull an image`,
    )
  return findings
}

function runsOnJobs() {
  return workflowFiles().flatMap((file) =>
    Object.entries(readWorkflow(file)?.jobs ?? {})
      .map(([name, job]) => ({
        where: `${file} ${name}`,
        ref: `${file}#${name}`,
        job,
      }))
      .filter(({ job, ref }) => isRunsOnJob(job, ref)),
  )
}

/** Whether a calling job passes both Docker Hub secrets to the workflow it calls. */
export function callerFinding(job) {
  if (job?.secrets === 'inherit') return null
  const passed = job?.secrets ?? {}
  const missing = [
    ['DOCKER_HUB_USERNAME', USERNAME],
    ['DOCKER_HUB_PASSWORD', PASSWORD],
  ]
    .filter(([name, value]) => passed[name] !== value)
    .map(([name]) => name)
  return missing.length
    ? `does not pass ${missing.join(' and ')} to the workflow it calls, so its login would skip`
    : null
}

/** Each local workflow call whose called RunsOn jobs log in, and what it lacks. */
function callerFindings() {
  return workflowFiles().flatMap((file) =>
    Object.entries(readWorkflow(file)?.jobs ?? {})
      .filter(([, job]) =>
        String(job?.uses ?? '').startsWith('./.github/workflows/'),
      )
      .flatMap(([name, job]) => {
        const called = job.uses.replace(/^\.\//, '').replace(/@.*$/, '')
        const logsIn = Object.entries(readWorkflow(called)?.jobs ?? {}).some(
          ([id, calledJob]) =>
            isRunsOnJob(calledJob, `${called}#${id}`) &&
            (calledJob.steps ?? []).some((step) => loginFinding(step) === null),
        )
        const finding = logsIn ? callerFinding(job) : null
        return finding ? [`${file}#${name}: ${finding}`] : []
      }),
  )
}

// ---------------------------------------------------------------------------

describe('Docker Hub login on RunsOn', () => {
  const jobs = runsOnJobs()

  it('finds the jobs it checks', () => {
    // A discovery test that finds nothing passes having checked nothing.
    expect(jobs.length).toBeGreaterThan(50)
    expect(
      jobs.filter(({ job }) => (job.steps ?? []).some((s) => stepPulls(s)))
        .length,
    ).toBeGreaterThan(8)
    expect(PULLING_TASKS).toContain('postgres:up')
    expect(PULLING_TASKS).toContain('setup')
  })

  it('logs in before every pull', () => {
    expect(
      jobs.flatMap(({ where, job, ref }) => jobFindings(where, job, ref)),
    ).toEqual([])
  })

  it('passes the Docker Hub secrets to every called workflow whose RunsOn jobs log in', () => {
    expect(callerFindings()).toEqual([])
  })

  it('names a RunsOn job and a real step for every hidden pull', () => {
    // A stale entry would stop guarding the pull it was written for.
    const stale = Object.entries(HIDDEN_PULLS).flatMap(([ref, hidden]) => {
      const entry = jobs.find((j) => j.ref === ref)
      return hidden
        .filter(
          ({ step }) => !(entry?.job.steps ?? []).some((s) => s?.name === step),
        )
        .map(({ step }) => `${ref} ${step}`)
    })
    expect(stale).toEqual([])
  })

  // Every job in the tree is correct, so the test above runs none of the
  // branches that report a wrong one. These do.
  const runsOn = 'runs-on=1/family=c8a+m8a/cpu=8'
  const login = {
    name: 'Log in to Docker Hub',
    env: { DOCKER_HUB_USERNAME: USERNAME, DOCKER_HUB_PASSWORD: PASSWORD },
    run: [
      'if [ -z "$DOCKER_HUB_USERNAME" ] || [ -z "$DOCKER_HUB_PASSWORD" ]; then',
      '  exit 0',
      'fi',
      'printf \'%s\' "$DOCKER_HUB_PASSWORD" |',
      '  docker login --username "$DOCKER_HUB_USERNAME" --password-stdin',
    ].join('\n'),
  }
  const up = { name: 'Start Postgres', run: 'mise run postgres:up' }
  const logout = {
    name: 'Log out of Docker Hub',
    if: 'always()',
    run: 'docker logout',
  }

  it('reports a pull with no login before it', () => {
    expect(jobFindings('w j', { 'runs-on': runsOn, steps: [up] })).toEqual([
      expect.stringMatching(/no Docker Hub login comes before it/),
    ])
    expect(
      jobFindings('w j', { 'runs-on': runsOn, steps: [up, login, logout] }),
    ).toEqual([expect.stringMatching(/no Docker Hub login comes before it/)])
    expect(
      jobFindings('w j', { 'runs-on': runsOn, steps: [login, up, logout] }),
    ).toEqual([])
    // Not RunsOn: out of scope.
    expect(
      jobFindings('w j', { 'runs-on': 'ubuntu-latest', steps: [up] }),
    ).toEqual([])
    // A matrix runner that MATRIX_RUNNERS marks as RunsOn is in scope.
    expect(
      jobFindings(
        'w j',
        // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, the literal `runs-on` value under test.
        { 'runs-on': '${{ matrix.cfg.os }}', steps: [up] },
        '.github/workflows/_build-ffi-artifacts.yml#binaries',
      ),
    ).toEqual([expect.stringMatching(/no Docker Hub login comes before it/)])
  })

  it('reports a login with no logout after the last pull', () => {
    const job = (...steps) => ({ 'runs-on': runsOn, steps })
    expect(jobFindings('w j', job(login, up))).toEqual([
      expect.stringMatching(
        /no Docker Hub logout with if: always\(\) comes after step 2 \(Start Postgres\)/,
      ),
    ])
    expect(
      jobFindings('w j', job(login, up, { ...logout, if: undefined })),
    ).toEqual([
      expect.stringMatching(/step 3 logs out .* add always\(\) to its if/),
      expect.stringMatching(/no Docker Hub logout with if: always\(\)/),
    ])
    expect(jobFindings('w j', job(login, up, logout, up))).toEqual([
      expect.stringMatching(/step 3 logs out of Docker Hub before step 4/),
      expect.stringMatching(/no Docker Hub logout .* after step 4/),
    ])
    // A matrix leg's own condition may sit beside always().
    expect(
      logoutFinding({
        ...logout,
        // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression under test.
        if: "${{ always() && startsWith(matrix.cfg.os, 'runs-on=') }}",
      }),
    ).toBeNull()
  })

  it('reports a call that does not pass both secrets', () => {
    const uses = './.github/workflows/x.yml'
    expect(callerFinding({ uses })).toMatch(/DOCKER_HUB_USERNAME/)
    expect(callerFinding({ uses, secrets: 'inherit' })).toBeNull()
    expect(
      callerFinding({
        uses,
        secrets: {
          DOCKER_HUB_USERNAME: USERNAME,
          DOCKER_HUB_PASSWORD: PASSWORD,
        },
      }),
    ).toBeNull()
    expect(
      callerFinding({ uses, secrets: { DOCKER_HUB_USERNAME: USERNAME } }),
    ).toMatch(/DOCKER_HUB_PASSWORD/)
  })

  it('reports a login that would fail on a fork pull request', () => {
    const noSkip = {
      ...login,
      run: 'printf \'%s\' "$DOCKER_HUB_PASSWORD" | docker login --username "$DOCKER_HUB_USERNAME" --password-stdin',
    }
    expect(loginFinding(noSkip)).toMatch(/fork pull request/)
    expect(loginFinding({ ...login, env: {} })).toMatch(/does not read/)
    expect(loginFinding(login)).toBeNull()
  })

  it('reports a Docker Hub service with no credentials', () => {
    const job = (credentials) => ({
      'runs-on': runsOn,
      services: { pg: { image: 'postgres:17', credentials } },
      steps: [],
    })
    expect(jobFindings('w j', job(undefined))).toEqual([
      expect.stringMatching(
        /service pg pulls postgres:17.*sets no credentials/,
      ),
    ])
    // The form GitHub rejects when a secret is empty.
    expect(
      jobFindings('w j', job({ username: USERNAME, password: PASSWORD })),
    ).toEqual([expect.stringMatching(/fail at 'Set up job'/)])
    const flat = `secrets.DOCKER_HUB_USERNAME != '' && secrets.DOCKER_HUB_PASSWORD != '' && fromJSON(format('{{"username":{0},"password":{1}}}', toJSON(secrets.DOCKER_HUB_USERNAME), toJSON(secrets.DOCKER_HUB_PASSWORD)))`
    expect(jobFindings('w j', job(expr(flat)))).toEqual([
      expect.stringMatching(/no \|\| fromJSON\('\{\}'\) fallback/),
    ])
    expect(jobFindings('w j', job(expr(`${flat} || fromJSON('{}')`)))).toEqual(
      [],
    )
    expect(
      jobFindings('w j', {
        'runs-on': runsOn,
        services: { pg: { image: 'ghcr.io/cipherstash/postgres-eql:17' } },
        steps: [],
      }),
    ).toEqual([])
  })

  it('recognises what may pull an image', () => {
    expect(
      stepPulls({ run: 'docker compose -p x -f y.yml up -d --wait' }),
    ).toBe(true)
    expect(stepPulls({ run: 'docker run --rm alpine true' })).toBe(true)
    expect(
      stepPulls({ run: 'mise run --output prefix postgres:up pg-17' }),
    ).toBe(true)
    expect(stepPulls({ uses: './.github/actions/integration-db' })).toBe(true)
    expect(stepPulls({ uses: 'docker/setup-qemu-action@abc' })).toBe(true)
    expect(stepPulls({ uses: 'docker/login-action@abc' })).toBe(false)
    for (const run of [
      'docker compose \\\n  -f x.yml \\\n  up -d',
      'docker compose -f x.yml pull',
      'docker compose run --rm app true',
      'docker compose create',
      'docker-compose run app true',
      'docker-compose pull',
      'docker buildx bake',
      'docker container run --rm alpine true',
      'docker container create alpine',
      'docker image pull alpine',
      'mise run \\\n  postgres:up',
    ])
      expect({ run, pulls: stepPulls({ run }) }).toEqual({ run, pulls: true })
    expect(stepPulls({ run: 'docker exec -i pg psql -f-' })).toBe(false)
    expect(stepPulls({ run: 'docker compose logs pg' })).toBe(false)
    expect(stepPulls({ run: 'docker compose down' })).toBe(false)
    expect(stepPulls({ run: '# docker run in a comment' })).toBe(false)
  })

  it('reads which registry an image names', () => {
    expect(onDockerHub('postgres:17')).toBe(true)
    expect(onDockerHub('supabase/postgres:17.4.1.048')).toBe(true)
    expect(onDockerHub('docker.io/library/postgres:17')).toBe(true)
    expect(onDockerHub('ghcr.io/cipherstash/postgres-eql:17')).toBe(false)
    expect(onDockerHub('public.ecr.aws/docker/library/postgres:17')).toBe(false)
    expect(onDockerHub('localhost:5000/pg')).toBe(false)
  })
})
