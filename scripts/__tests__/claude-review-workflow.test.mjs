import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { readWorkflow } from './lib/workflows.mjs'

const WORKFLOW = '.github/workflows/claude-review.yml'
const ACTION_SHA = 'bf38e86e58df9ebf3420326d019f955bb3be64dd'
const FULL_SHA = /^[0-9a-f]{40}$/
const gha = (expression) => `\${{ ${expression} }}`
// Exactly the `allowed-tools` frontmatter of
// plugins/code-review/commands/code-review.md at the pinned
// anthropics/claude-code commit. Re-read that file when bumping the pin.
const CODE_REVIEW_PLUGIN_TOOLS = [
  'Bash(gh issue view:*)',
  'Bash(gh search:*)',
  'Bash(gh issue list:*)',
  'Bash(gh pr comment:*)',
  'Bash(gh pr diff:*)',
  'Bash(gh pr view:*)',
  'Bash(gh pr list:*)',
  'mcp__github_inline_comment__create_inline_comment',
]

const workflow = readWorkflow(WORKFLOW)
const triggers = workflow.on ?? workflow[true]
const review = workflow.jobs.review
const steps = review.steps
const stepNamed = (name) => {
  const step = steps.find((candidate) => candidate.name === name)
  expect(step, `step "${name}"`).toBeDefined()
  return step
}
const claude = steps.find((step) =>
  String(step.uses ?? '').startsWith('anthropics/claude-code-action@'),
)
const claudeArgs = () => claude.with.claude_args.trim().split('\n')
const toolArg = (flag) => {
  const line = claudeArgs().find((arg) => arg.startsWith(`${flag} `))
  expect(line, flag).toBeDefined()
  return line.slice(flag.length + 2, -1).split(',')
}

describe('Claude pull-request review', () => {
  it('contains only the permission-pinned review job', () => {
    expect(Object.keys(workflow.jobs)).toEqual(['review'])
  })

  it('reviews on open and on request, not on every push', () => {
    expect(Object.keys(triggers)).toEqual(['pull_request'])
    expect(triggers.pull_request.types).toEqual([
      'opened',
      'ready_for_review',
      'reopened',
      'labeled',
    ])
    expect(triggers.pull_request['paths-ignore']).toEqual([
      '.changeset/**',
      '**/__snapshots__/**',
      '**/*.snap',
      'docs/plans/**',
    ])
  })

  it('admits only non-draft, non-bot pull requests from this repository', () => {
    const condition = String(review.if).replace(/\s+/g, ' ')
    expect(condition).toContain(
      'github.event.pull_request.head.repo.full_name == github.repository',
    )
    expect(condition).toContain('github.event.pull_request.draft != true')
    expect(condition).toContain("github.event.pull_request.user.type != 'Bot'")
  })

  it('runs on a labeled event only for the claude-review label', () => {
    const condition = String(review.if).replace(/\s+/g, ' ')
    expect(condition).toContain(
      "(github.event.action != 'labeled' || github.event.label.name == 'claude-review')",
    )
  })

  it('runs only when CLAUDE_REVIEW_ENABLED is switched on', () => {
    // Off unless the repository variable is exactly 'true', so the review can
    // be disabled or re-enabled without a pull request.
    expect(String(review.if).replace(/\s+/g, ' ')).toMatch(
      /^vars\.CLAUDE_REVIEW_ENABLED == 'true' && /,
    )
  })

  it('uses a Blacksmith arm64 runner and cancels superseded reviews', () => {
    expect(review['runs-on']).toBe('blacksmith-2vcpu-ubuntu-2404-arm')
    // An unrelated label gets a run-unique group, so it cannot cancel a review.
    expect(workflow.concurrency).toEqual({
      group: `${gha('github.workflow')}-${gha('github.event.pull_request.number')}${gha("github.event.action == 'labeled' && github.event.label.name != 'claude-review' && format('-{0}', github.run_id) || ''")}`,
      'cancel-in-progress': true,
    })
  })

  it('spends no runner time waiting before the review', () => {
    for (const step of steps) {
      expect(String(step.run ?? '')).not.toMatch(/\bsleep\b/)
    }
  })

  it('grants only the permissions needed to read, comment, and federate', () => {
    expect(workflow.permissions).toEqual({ contents: 'read' })
    expect(review.permissions).toEqual({
      contents: 'read',
      'pull-requests': 'write',
      'id-token': 'write',
    })
  })

  it('fails before checkout when federation identifiers are absent', () => {
    const preflight = review.steps.find(
      (step) => step.name === 'Require Anthropic federation configuration',
    )
    const checkoutIndex = review.steps.findIndex((step) =>
      String(step.uses ?? '').startsWith('actions/checkout@'),
    )
    expect(review.steps.indexOf(preflight)).toBeLessThan(checkoutIndex)
    expect(Object.keys(preflight.env).sort()).toEqual([
      'FEDERATION_RULE_ID',
      'ORGANIZATION_ID',
      'SERVICE_ACCOUNT_ID',
      'WORKSPACE_ID',
    ])
    expect(preflight.run).toContain('exit 1')
  })

  it('does not leave a checkout credential behind', () => {
    const checkouts = review.steps.filter((step) =>
      String(step.uses ?? '').startsWith('actions/checkout@'),
    )
    expect(checkouts.length).toBeGreaterThan(0)
    for (const checkout of checkouts) {
      expect(checkout.with['persist-credentials']).toBe(false)
    }
  })

  it('reviews under the base branch copy of every agent instruction file', () => {
    // The action restores the root CLAUDE.md from the base branch but not its
    // @imports or nested CLAUDE.md files, and the plugin audits against every
    // CLAUDE.md beside a changed file. Derived from CLAUDE.md so a new import
    // cannot go unrestored.
    const imports = readFileSync('CLAUDE.md', 'utf8')
      .split('\n')
      .filter((line) => /^@\S+$/.test(line.trim()))
      .map((line) => line.trim().slice(1))
    expect(imports).toContain('AGENTS.md')

    const baseCheckout = stepNamed('Checkout base-branch agent instructions')
    const restore = stepNamed('Restore base-branch agent instructions')
    expect(baseCheckout.with).toMatchObject({
      ref: gha('github.event.pull_request.base.sha'),
      path: '.review-base',
      'sparse-checkout-cone-mode': false,
    })
    const patterns = baseCheckout.with['sparse-checkout'].trim().split('\n')
    expect(patterns).toEqual(
      expect.arrayContaining(['CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md']),
    )
    // A non-cone pattern without a slash matches that name at any depth.
    for (const path of imports) {
      const name = path.split('/').pop()
      expect(patterns.includes(path) || patterns.includes(name)).toBe(true)
    }
    // Every name restored at any depth is first removed at every depth, so a
    // copy the base branch lacks does not survive.
    for (const name of patterns.filter((pattern) => !pattern.includes('/'))) {
      expect(restore.run).toContain(`-name ${name}`)
    }
    expect(restore.run).toContain('xargs -0 rm -f')
    expect(restore.run).toContain('cp ".review-base/$path" "$path"')
    expect(restore.run).toContain('realpath -m')
    expect(restore.run).toContain('rm -rf .review-base')

    expect(steps.indexOf(baseCheckout)).toBeLessThan(steps.indexOf(restore))
    expect(steps.indexOf(restore)).toBeLessThan(steps.indexOf(claude))
  })

  it('pins the reviewed Claude action release and authenticates only with OIDC', () => {
    expect(claude.id).toBe('claude-review')
    expect(claude.uses).toBe(`anthropics/claude-code-action@${ACTION_SHA}`)
    expect(claude.with).toMatchObject({
      anthropic_federation_rule_id: gha('vars.ANTHROPIC_FEDERATION_RULE_ID'),
      anthropic_organization_id: gha('vars.ANTHROPIC_ORGANIZATION_ID'),
      anthropic_service_account_id: gha('vars.ANTHROPIC_SERVICE_ACCOUNT_ID'),
      anthropic_workspace_id: gha('vars.ANTHROPIC_WORKSPACE_ID'),
    })
    expect(claude.with).not.toHaveProperty('anthropic_api_key')
    expect(claude.with).not.toHaveProperty('claude_code_oauth_token')
  })

  it('gives Claude the job token, not the Claude GitHub App token', () => {
    // Without `github_token` the action exchanges OIDC for a Claude App
    // installation token with write access to contents, pull requests and
    // issues; the job's `permissions:` block does not limit that token.
    expect(claude.with.github_token).toBe(gha('secrets.GITHUB_TOKEN'))
  })

  it('keeps Claude out of the git config holding that token', () => {
    // The action writes its token into the checkout's remote URL.
    expect(claude.with.claude_args).toMatch(
      /--disallowedTools "[^"]*Read\(\.\/\.git\/\*\*\)/,
    )
  })

  it('fails closed when the vendor action exits before Claude runs', () => {
    const guard = review.steps.find(
      (step) => step.name === 'Require completed Claude review',
    )

    expect(review.steps.indexOf(guard)).toBeGreaterThan(
      review.steps.indexOf(claude),
    )
    expect(guard).toMatchObject({
      if: 'always()',
      env: {
        REVIEW_CONCLUSION: gha('steps.claude-review.outputs.conclusion'),
      },
    })
    expect(guard.run).toContain('[ "$REVIEW_CONCLUSION" != "success" ]')
    expect(guard.run).toContain('exit 1')
  })

  it('stays in agent mode', () => {
    // `track_progress: true` would select tag mode, which grants git commit
    // and push and auto-accepts file edits.
    expect(claude.with).toMatchObject({
      track_progress: false,
      include_fix_links: false,
      classify_inline_comments: false,
      show_full_output: false,
    })
    expect(claude.with).not.toHaveProperty('use_sticky_comment')
    // Restricting setting sources would stop the restored CLAUDE.md and the
    // plugin loading at all.
    expect(claude.with.claude_args).not.toContain('--setting-sources')
  })

  it('runs the code-review plugin command on this pull request', () => {
    const prompt = claude.with.prompt.replace(/\s+/g, ' ')
    expect(
      prompt.startsWith(
        `/code-review ${gha('github.event.pull_request.number')} --comment`,
      ),
    ).toBe(true)
    // The command stops if Claude has already commented; a labeled re-run
    // must still review.
    expect(prompt).toContain('Review it even if Claude has already commented')
  })

  it('grants exactly the tools the pinned command declares, plus Task', () => {
    // A plugin command's frontmatter grants its own tools, unscoped, so these
    // cannot be narrowed to this pull request's number; listing them keeps
    // the grant visible and checked against the pin.
    expect(toolArg('--allowedTools').sort()).toEqual(
      [...CODE_REVIEW_PLUGIN_TOOLS, 'Task'].sort(),
    )
    expect(claudeArgs()).toEqual(
      expect.arrayContaining(['--model sonnet', '--max-turns 60']),
    )
  })

  it('never lets Claude edit, write, reach the web, or read .git', () => {
    const disallowed = toolArg('--disallowedTools')
    expect(disallowed).toEqual([
      'Edit',
      'Write',
      'NotebookEdit',
      'WebFetch',
      'WebSearch',
      // The action writes its token into the checkout's remote URL.
      'Read(./.git/**)',
    ])
    // A blanket `Bash` disallow overrides the scoped `Bash(gh …)` allows.
    expect(disallowed).not.toContain('Bash')
    expect(toolArg('--allowedTools')).not.toContain('Bash')
  })
})

describe('Claude review plugin', () => {
  const checkout = () => {
    const step = steps.find(
      (candidate) => candidate.with?.repository === 'anthropics/claude-code',
    )
    expect(step, 'checkout of anthropics/claude-code').toBeDefined()
    return step
  }

  it('checks out anthropics/claude-code at a full commit SHA, with no credentials', () => {
    expect(checkout().with.ref).toMatch(FULL_SHA)
    expect(checkout().with.path).toBe('.review-plugins/claude-code')
    expect(checkout().with['persist-credentials']).toBe(false)
    expect(checkout().with).not.toHaveProperty('token')
    // A pull request could otherwise commit files at the plugin path.
    const clear = stepNamed('Clear plugin checkout path')
    expect(clear.run).toContain('rm -rf .review-plugins')
    expect(steps.indexOf(clear)).toBeLessThan(steps.indexOf(checkout()))
    expect(steps.indexOf(checkout())).toBeLessThan(steps.indexOf(claude))
  })

  it('installs only the code-review plugin, from that checkout', () => {
    expect(claude.with.plugin_marketplaces.trim().split('\n')).toEqual([
      `${gha('github.workspace')}/.review-plugins/claude-code`,
    ])
    expect(claude.with.plugins.trim().split('\n')).toEqual([
      'code-review@claude-code-plugins',
    ])
  })
})
