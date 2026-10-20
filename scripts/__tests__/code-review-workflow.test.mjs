import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { runsWhen } from './lib/expressions.mjs'
import { readWorkflow } from './lib/workflows.mjs'

const WORKFLOW = '.github/workflows/code-review.yml'
const gha = (expression) => `\${{ ${expression} }}`

const workflow = readWorkflow(WORKFLOW)
const triggers = workflow.on ?? workflow[true]
const request = workflow.jobs.request
const fire = request.steps.find(
  (step) => step.name === 'Fire the code-review routine',
)

describe('Code-review routine trigger', () => {
  it('contains only the request job, with a single step', () => {
    expect(Object.keys(workflow.jobs)).toEqual(['request'])
    expect(request.steps).toEqual([fire])
  })

  it('fires once per lifecycle event, never on every push', () => {
    // No `synchronize`: each push would start another review session. Mark the
    // pull request draft and ready again for a fresh review.
    expect(Object.keys(triggers)).toEqual(['pull_request'])
    expect(triggers.pull_request.types).toEqual([
      'opened',
      'reopened',
      'ready_for_review',
    ])
  })

  it('admits only non-draft, non-bot pull requests from this repository', () => {
    // Forks are not given the routine token; bots (Dependabot, release-plz)
    // are not reviewed. workflow-dispatch-job-conditions.test.mjs holds the
    // fork guard's spelling and meaning.
    const condition = String(request.if).replace(/\s+/g, ' ')
    expect(condition).toContain('github.event.pull_request.draft != true')
    expect(condition).toContain("github.event.pull_request.user.type != 'Bot'")
    expect(condition).toContain(
      'github.event.pull_request.head.repo.full_name == github.repository',
    )
  })

  it('runs one request per pull request at a time, never cancelling one', () => {
    // Cancelling a run mid-request could leave a session started behind a
    // cancelled check; a queued run is replaced by the next, bounding a burst.
    expect(workflow.concurrency).toEqual({
      group: `${gha('github.workflow')}-${gha('github.event.pull_request.number')}`,
      'cancel-in-progress': false,
    })
  })

  it('skips draft, bot and fork pull requests and runs the rest', () => {
    // Evaluated, not string-matched: a wrong operator between the clauses
    // still contains every clause.
    const REPO = 'cipherstash/stack'
    const context = (pullRequest) => ({
      github: {
        event_name: 'pull_request',
        repository: REPO,
        event: {
          pull_request: {
            head: { repo: { full_name: REPO } },
            draft: false,
            user: { type: 'User' },
            ...pullRequest,
          },
        },
      },
    })
    const condition = String(request.if)
    expect(runsWhen(condition, context({}))).toBe(true)
    expect(runsWhen(condition, context({ draft: true }))).toBe(false)
    expect(runsWhen(condition, context({ user: { type: 'Bot' } }))).toBe(false)
    expect(
      runsWhen(
        condition,
        context({ head: { repo: { full_name: 'contributor/stack' } } }),
      ),
    ).toBe(false)
  })

  it('reports a failed request without failing the pull request check', () => {
    // The review is advisory: an API error or outage shows in the run, not as
    // a red check on the pull request.
    expect(fire['continue-on-error']).toBe(true)
  })

  it('grants the job token nothing and stays bounded', () => {
    // The request is authenticated by the routine token alone.
    expect(workflow.permissions).toEqual({})
    expect(request.permissions).toBeUndefined()
    expect(request['runs-on']).toBe('ubuntu-latest')
    expect(request['timeout-minutes']).toBe(5)
  })

  it('reads the routine token from a secret and the trigger id from a variable', () => {
    expect(fire.env).toEqual({
      CLAUDE_ROUTINE_TOKEN: gha('secrets.CLAUDE_ROUTINE_TOKEN'),
      TRIGGER_ID: gha('vars.CLAUDE_ROUTINE_TRIGGER_ID'),
      PR_URL: gha('github.event.pull_request.html_url'),
      PR_NUMBER: gha('github.event.pull_request.number'),
      REPO: gha('github.repository'),
    })
    // Pull-request fields reach the script only through env, never expanded
    // into it.
    expect(fire.run).not.toMatch(/\$\{\{/)
  })
})

// The step's script, run as GitHub runs it (`bash -eo pipefail`), with `curl`
// replaced by a stub that records its arguments and standard input.
describe('Code-review routine trigger script', () => {
  let dir
  const baseEnv = () => ({
    PATH: `${dir}:${process.env.PATH}`,
    CURL_LOG: join(dir, 'curl.log'),
    CLAUDE_ROUTINE_TOKEN: 'sk-routine-token',
    TRIGGER_ID: 'trig_01ABCdef',
    PR_URL: 'https://github.com/cipherstash/stack/pull/7',
    PR_NUMBER: '7',
    REPO: 'cipherstash/stack',
  })
  const run = (env) =>
    spawnSync(
      'bash',
      ['--noprofile', '--norc', '-eo', 'pipefail', '-c', fire.run],
      {
        cwd: dir,
        encoding: 'utf8',
        env,
      },
    )
  const curlCall = () => {
    const [args, stdin] = readFileSync(join(dir, 'curl.log'), 'utf8').split(
      '\0',
    )
    return { args: JSON.parse(args), stdin }
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'code-review-'))
    const stub = join(dir, 'curl')
    writeFileSync(
      stub,
      `#!${process.execPath}
const { readFileSync, writeFileSync } = require('node:fs')
writeFileSync(process.env.CURL_LOG, JSON.stringify(process.argv.slice(2)) + '\\0' + readFileSync(0, 'utf8'))
process.exit(Number(process.env.CURL_EXIT ?? 0))
`,
    )
    chmodSync(stub, 0o755)
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('posts the pull request to the trigger, the token only on standard input', () => {
    const result = run(baseEnv())
    expect(result.status, result.stderr).toBe(0)
    const { args, stdin } = curlCall()

    expect(args).toContain(
      'https://api.anthropic.com/v1/claude_code/routines/trig_01ABCdef/fire',
    )
    expect(args.join(' ')).not.toContain('sk-routine-token')
    expect(stdin.trim()).toBe('Authorization: Bearer sk-routine-token')
    expect(args[args.indexOf('-H') + 1]).toBe('@-')

    const body = JSON.parse(args[args.indexOf('-d') + 1])
    expect(body).toEqual({
      text: 'Review pull request #7 in cipherstash/stack: https://github.com/cipherstash/stack/pull/7',
    })
  })

  it('does not retry, so a timed-out request never reviews twice', () => {
    expect(fire.run).not.toMatch(/--retry/)
  })

  it('fails the step when curl reports an HTTP error', () => {
    // curl exits 22 when --fail-with-body receives a 4xx or 5xx answer: a
    // revoked token or a deleted trigger must not read as a fired review.
    const result = run({ ...baseEnv(), CURL_EXIT: '22' })
    expect(result.status).toBe(22)
    expect(curlCall().args).toContain('--fail-with-body')
  })

  it('keeps quotes in pull-request fields inside the JSON body', () => {
    const result = run({ ...baseEnv(), PR_URL: 'https://x/"},"text":"evil' })
    expect(result.status, result.stderr).toBe(0)
    const { args } = curlCall()
    const body = JSON.parse(args[args.indexOf('-d') + 1])
    expect(Object.keys(body)).toEqual(['text'])
    expect(body.text).toContain('"},"text":"evil')
  })

  it('fails without calling curl when the token is missing', () => {
    const result = run({ ...baseEnv(), CLAUDE_ROUTINE_TOKEN: '' })
    expect(result.status).toBe(1)
    expect(result.stdout).toContain('::error::CLAUDE_ROUTINE_TOKEN is empty')
    expect(existsSync(join(dir, 'curl.log'))).toBe(false)
  })

  it.each([
    ['', 'unset'],
    ['trig_01../../other', 'a path'],
    ['trig_01?x=1', 'a query'],
    ['01ABCdef', 'no trig_ prefix'],
    ['../../other/trig_01ABC', 'a path before trig_'],
  ])('refuses trigger id %j (%s) without calling curl', (id) => {
    const result = run({ ...baseEnv(), TRIGGER_ID: id })
    expect(result.status).toBe(1)
    expect(result.stdout).toContain(
      '::error::CLAUDE_ROUTINE_TRIGGER_ID is not a trigger id',
    )
    expect(existsSync(join(dir, 'curl.log'))).toBe(false)
  })
})
