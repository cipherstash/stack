import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import { expr } from './lib/expressions.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

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
 * - A service or job container from Docker Hub sets `credentials` from the
 *   two secrets. The runner skips that login when either value is empty
 *   (`ContainerRegistryLogin` in actions/runner).
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
 * Only a literal `runs-on=` label counts as RunsOn. GitHub-hosted runners are
 * not limited this way, and Blacksmith jobs are leaving.
 */

// ---------------------------------------------------------------------------
// What pulls an image
// ---------------------------------------------------------------------------

/** A command that starts or builds a container, so may pull an image. */
const PULLS =
  /\bdocker(?:-compose\s+up\b|\s+(?:compose\b[^\n]*\bup\b|run\b|pull\b|create\b|build\b|buildx\s+build\b))/

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

const SKIP_DIRS = new Set(['node_modules', '.git', 'target', 'dist'])

/** Every tracked-looking `mise.toml` / `mise.<env>.toml`, repo-relative. */
function miseConfigs(dir = REPO_ROOT, found = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue
    const path = join(dir, name)
    if (statSync(path).isDirectory()) miseConfigs(path, found)
    else if (/^\.?mise(\.[\w-]+)?\.toml$/.test(name))
      found.push(relative(REPO_ROOT, path))
  }
  return found
}

const parseStringArray = (inner) =>
  [...inner.matchAll(/"([^"]+)"|'([^']+)'/g)].map((m) => m[1] ?? m[2])

function parseIncludes(text) {
  const section = /^\[task_config\][^\n]*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/m.exec(
    text,
  )
  const array = /^includes\s*=\s*\[([^\]]*)\]/m.exec(section?.[1] ?? '')
  return array ? parseStringArray(array[1]) : []
}

/**
 * Task blocks. A mise config writes `[tasks."name"]`; an included file makes
 * every top-level table a task, `["name"]`.
 */
function parseTomlTasks(text, { bareTables }) {
  const header = bareTables
    ? /^\[(?:"([^"]+)"|([\w:.-]+))\]/
    : /^\[tasks\.(?:"([^"]+)"|([\w:.-]+))\]/
  return text
    .split(/^(?=\[)/m)
    .map((block) => ({ match: header.exec(block), block }))
    .filter(({ match }) => match)
    .map(({ match, block }) => ({ name: match[1] ?? match[2], body: block }))
}

/** File tasks: `tasks/test/splinter.sh` is the task `test:splinter`. */
function fileTasks(dir, base = dir, found = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) fileTasks(path, base, found)
    else if (!name.endsWith('.toml'))
      found.push({
        name: relative(base, path)
          .replace(/\.[^./]+$/, '')
          .split('/')
          .join(':'),
        body: readFileSync(path, 'utf8'),
      })
  }
  return found
}

/**
 * Task name -> bodies. Names repeat across configs (two packages can each
 * have a `setup`), so a name keeps every body, and pulls if any of them does.
 * That is the fail-closed direction.
 */
function taskIndex() {
  const index = new Map()
  const add = ({ name, body }) => {
    if (!index.has(name)) index.set(name, [])
    index.get(name).push(body)
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

const stripCommentLines = (text) => text.replace(/^[ \t]*#(?!MISE).*$/gm, '')

// A quote starts a command only at the start of a line, as in a TOML
// `run = [ "mise run …" ]` entry. Mid-line it is a message to the reader.
const COMMAND_START = String.raw`(?:^[ \t]*["']?|(?:&&|\|\||[;|(){}])[ \t]*)`

function invokes(text, taskName) {
  const escaped = taskName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(
    `${COMMAND_START}mise\\s+run\\s+[^\\n'"]*?(?<![\\w:.-])${escaped}(?![\\w:.-])`,
    'm',
  ).test(stripCommentLines(text))
}

const dependsOf = (body) =>
  [...body.matchAll(/depends\s*=\s*\[([^\]]*)\]/g)].flatMap((m) =>
    parseStringArray(m[1]),
  )

/** The names of every task that may pull an image, directly or through others. */
function pullingTasks(index) {
  const pulling = new Set(
    [...index]
      .filter(([, bodies]) =>
        bodies.some((body) => PULLS.test(stripCommentLines(body))),
      )
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

// ---------------------------------------------------------------------------
// Steps and jobs
// ---------------------------------------------------------------------------

/** Whether one step may pull an image. `seen` guards composite-action cycles. */
export function stepPulls(step, seen = new Set()) {
  const uses = typeof step?.uses === 'string' ? step.uses.trim() : ''
  if (PULLING_ACTION.test(uses)) return true
  if (uses.startsWith('./')) {
    const dir = uses.replace(/^\.\//, '').replace(/\/$/, '')
    if (seen.has(dir)) return false
    seen.add(dir)
    for (const file of ['action.yml', 'action.yaml']) {
      const rel = `${dir}/${file}`
      if (!existsSync(join(REPO_ROOT, rel))) continue
      const steps = readWorkflow(rel)?.runs?.steps ?? []
      return steps.some((inner) => stepPulls(inner, seen))
    }
    return false
  }
  const run = typeof step?.run === 'string' ? stripCommentLines(step.run) : ''
  return (
    PULLS.test(run) || [...PULLING_TASKS].some((task) => invokes(run, task))
  )
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

const isRunsOn = (job) => String(job?.['runs-on'] ?? '').startsWith('runs-on=')

/** Every finding for one job, or [] when it is correct. */
export function jobFindings(where, job) {
  if (!isRunsOn(job)) return []
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
    if (
      def?.credentials?.username !== USERNAME ||
      def?.credentials?.password !== PASSWORD
    )
      findings.push(
        `${where}: ${what} pulls ${image} from Docker Hub without credentials: { username: ${USERNAME}, password: ${PASSWORD} }`,
      )
  }
  const steps = job.steps ?? []
  const firstPull = steps.findIndex((step) => stepPulls(step))
  if (firstPull === -1) return findings
  const logins = steps
    .map((step, i) => ({ i, finding: loginFinding(step) }))
    .filter(({ finding }) => finding !== 'not a login')
  for (const { i, finding } of logins)
    if (finding) findings.push(`${where}: step ${i + 1} ${finding}`)
  const pullName = steps[firstPull].name ?? steps[firstPull].uses ?? 'run'
  if (!logins.some(({ i }) => i < firstPull))
    findings.push(
      `${where}: step ${firstPull + 1} (${pullName}) may pull an image, and no Docker Hub login comes before it`,
    )
  return findings
}

function runsOnJobs() {
  return workflowFiles().flatMap((file) =>
    Object.entries(readWorkflow(file)?.jobs ?? {})
      .filter(([, job]) => isRunsOn(job))
      .map(([name, job]) => ({ where: `${file} ${name}`, job })),
  )
}

// ---------------------------------------------------------------------------

describe('Docker Hub login on RunsOn', () => {
  const jobs = runsOnJobs()

  it('finds the jobs it checks', () => {
    // A discovery test that finds nothing passes having checked nothing.
    expect(jobs.length).toBeGreaterThan(20)
    expect(
      jobs.filter(({ job }) => (job.steps ?? []).some((s) => stepPulls(s)))
        .length,
    ).toBeGreaterThan(8)
    expect(PULLING_TASKS).toContain('postgres:up')
    expect(PULLING_TASKS).toContain('setup')
  })

  it('logs in before every pull', () => {
    expect(jobs.flatMap(({ where, job }) => jobFindings(where, job))).toEqual(
      [],
    )
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

  it('reports a pull with no login before it', () => {
    expect(jobFindings('w j', { 'runs-on': runsOn, steps: [up] })).toEqual([
      expect.stringMatching(/no Docker Hub login comes before it/),
    ])
    expect(
      jobFindings('w j', { 'runs-on': runsOn, steps: [up, login] }),
    ).toEqual([expect.stringMatching(/no Docker Hub login comes before it/)])
    expect(
      jobFindings('w j', { 'runs-on': runsOn, steps: [login, up] }),
    ).toEqual([])
    // Not RunsOn: out of scope.
    expect(
      jobFindings('w j', { 'runs-on': 'ubuntu-latest', steps: [up] }),
    ).toEqual([])
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
      expect.stringMatching(/service pg pulls postgres:17/),
    ])
    expect(
      jobFindings('w j', job({ username: USERNAME, password: PASSWORD })),
    ).toEqual([])
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
    expect(stepPulls({ run: 'docker exec -i pg psql -f-' })).toBe(false)
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
