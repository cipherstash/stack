import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

const workflowPath = '.github/workflows/impact.yml'

// Evaluates the small subset of the Actions expression language these guards
// need (context paths, string literals, ==, !=, &&, ||, !), so a test asserts
// what an expression DOES for an event rather than how it is spelled.
function evaluate(expression, context) {
  const body = String(expression)
    .replace(/^\s*\$\{\{\s*/, '')
    .replace(/\s*\}\}\s*$/, '')
  const js = body
    .replace(/\b(github|steps)((?:\.[\w-]+)+)/g, (_, root, path) =>
      JSON.stringify(
        path
          .slice(1)
          .split('.')
          .reduce((value, key) => value?.[key], context[root]) ?? '',
      ),
    )
    .replace(/==/g, '===')
    .replace(/!===/g, '!==')
  return new Function(`return (${js})`)()
}

function interpolate(template, context) {
  return String(template).replace(/\$\{\{(.*?)\}\}/g, (_, expression) =>
    String(evaluate(expression, context)),
  )
}

const pushEvent = (sha) => ({
  github: { event_name: 'push', ref: 'refs/heads/main', sha },
})
const pullRequestEvent = (sha) => ({
  github: { event_name: 'pull_request', ref: 'refs/pull/7/merge', sha },
})

describe('advisory change impact', () => {
  it('applies every generated-output exclusion to both report scopes', () => {
    const all = readWorkflow('.github/impact-gate/all.yml')
    const source = readWorkflow('.github/impact-gate/source.yml')
    expect(source.ignore).toEqual(expect.arrayContaining(all.ignore))
  })

  it('reports every pull request and refreshes main with read-only permissions', () => {
    const workflow = readWorkflow(workflowPath)
    expect(workflow.on).toEqual({
      pull_request: null,
      push: { branches: ['main'] },
    })
    expect(workflow.permissions).toEqual({ contents: 'read' })
    const job = workflow.jobs.impact
    expect(job.permissions).toBeUndefined()
    expect(job.needs).toBeUndefined()
    const checkout = job.steps.find((step) =>
      step.uses?.startsWith('actions/checkout@'),
    )
    expect(checkout.with).toMatchObject({
      'fetch-depth': 0,
      'persist-credentials': false,
    })
  })

  it('keeps baseline caches compatible and saves every rebuilt pair', () => {
    const job = readWorkflow(workflowPath).jobs.impact
    const restore = job.steps.find((step) =>
      step.uses?.startsWith('actions/cache/restore@'),
    )
    expect(restore).toBeDefined()
    expect(restore.with.key).toContain('hashFiles(')
    expect(restore.with.key).toContain("'.github/impact-gate/**'")
    expect(restore.with.key).toContain("'scripts/impact-gate.py'")
    expect(restore.with.key).toContain("'.github/workflows/impact.yml'")
    expect(restore.with.key).toContain('steps.target.outputs.key')
    expect(restore.with.key).toContain(
      'github.event.pull_request.base.sha || github.sha',
    )
    expect(restore.with['restore-keys']).toBe(
      restore.with.key.replace(
        // biome-ignore lint/suspicious/noTemplateCurlyInString: literal Actions expression
        '-${{ github.event.pull_request.base.sha || github.sha }}',
        '-',
      ),
    )
    const save = job.steps.find((step) =>
      step.uses?.startsWith('actions/cache/save@'),
    )
    // F4: this used to pin `github.event_name == 'push' && …`, which is the
    // defect — a PR with no valid base cache rebuilt both scopes (~280 s) on
    // every synchronize. A PR cache is scoped to the PR ref and cannot clobber
    // main's, so a rebuilt pair is saved on both events, and never otherwise.
    for (const event of [pushEvent('a'), pullRequestEvent('b')]) {
      for (const rebuilt of ['true', 'false']) {
        const context = {
          ...event,
          steps: { prepare: { outputs: { rebuilt } } },
        }
        expect(
          Boolean(evaluate(save.if, context)),
          `${event.github.event_name}, rebuilt=${rebuilt}`,
        ).toBe(rebuilt === 'true')
      }
    }
    expect(save.with.path).toBe(restore.with.path)
  })

  it('never lets one main push cancel another before its baselines are saved', () => {
    // F3: a shared `impact-refs/heads/main` group with cancel-in-progress
    // cancelled a merge's run before "Save main baselines", so that SHA never
    // got a cache and PRs on it fell back to an ancestor or a full rebuild.
    const { concurrency } = readWorkflow(workflowPath)
    const first = interpolate(concurrency.group, pushEvent('1111'))
    const second = interpolate(concurrency.group, pushEvent('2222'))
    expect(first).not.toBe(second)
    // A superseded pull request run is still cancelled.
    const prA = pullRequestEvent('3333')
    const prB = pullRequestEvent('4444')
    expect(interpolate(concurrency.group, prA)).toBe(
      interpolate(concurrency.group, prB),
    )
    expect(String(interpolate(concurrency['cancel-in-progress'], prA))).toBe(
      'true',
    )
  })

  it('installs a fully pinned, hash-checked analysis toolchain', () => {
    // F5: two top-level pins left PyYAML, Pygments and pathspec floating, with
    // no hashes and no Dependabot coverage.
    const requirements = readFileSync(
      join(REPO_ROOT, '.github/impact-gate/requirements.txt'),
      'utf8',
    )
    const entries = requirements
      .replace(/\\\n/g, ' ')
      .split('\n')
      .map((line) => line.replace(/#.*/, '').trim())
      .filter(Boolean)
    const names = entries.map((entry) =>
      entry
        .split(/[=<>!~ ;[]/)[0]
        .toLowerCase()
        .replace(/_/g, '-'),
    )
    expect(names).toEqual(
      expect.arrayContaining([
        'impact-gate',
        'lizard',
        'pathspec',
        'pygments',
        'pyyaml',
      ]),
    )
    for (const entry of entries) {
      expect(entry, entry).toMatch(/^[\w.-]+==[\w.]+(\s|;)/)
      expect(entry, entry).toMatch(/--hash=sha256:[0-9a-f]{64}/)
    }
    const install = readWorkflow(workflowPath).jobs.impact.steps.find((step) =>
      step.run?.includes('.github/impact-gate/requirements.txt'),
    )
    expect(install.run).toContain('--require-hashes')
    expect(install.run).toContain('--no-deps')

    const pip = readWorkflow('.github/dependabot.yml').updates.find(
      (update) =>
        update['package-ecosystem'] === 'pip' &&
        update.directory === '/.github/impact-gate',
    )
    expect(pip).toBeDefined()
    expect(pip.cooldown).toEqual({ 'default-days': 7 })
    expect(pip.ignore).toContainEqual({
      'dependency-name': '*',
      'update-types': ['version-update:semver-major'],
    })
  })

  it('runs the real-CLI checks and reports PRs without masking tool errors', () => {
    const job = readWorkflow(workflowPath).jobs.impact
    const checks = job.steps.find((step) =>
      step.run?.includes('unittest discover'),
    )
    expect(checks).toBeDefined()
    const report = job.steps.find((step) =>
      step.run?.includes('scripts/impact-gate.py report'),
    )
    expect(report).toBeDefined()
    expect(report.if).toBe("github.event_name == 'pull_request'")
    expect(report.run).toContain('--base "$BASE_REF"')
    expect(report.run).toContain('--cache-dir "$BASELINE_DIR"')
    expect(report.run).not.toMatch(/\|\||\|\s*tee/)
    expect(job.env.BASE_REF).toContain('github.base_ref')
    expect(job['continue-on-error']).toBeUndefined()
    expect(job.steps.every((step) => !step['continue-on-error'])).toBe(true)
    expect(
      job.steps.some((step) => step.uses?.startsWith('officefloor/')),
    ).toBe(false)
    expect(job.steps.some((step) => step.run?.includes('pnpm install'))).toBe(
      false,
    )
    expect(job.defaults.run.shell).toBe('bash')
  })
})
