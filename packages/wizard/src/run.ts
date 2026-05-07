import * as p from '@clack/prompts'
import { fetchIntegrationPrompt } from './agent/fetch-prompt.js'
import { initializeAgent } from './agent/interface.js'
import { checkReadiness } from './health-checks/index.js'
import {
  shutdownAnalytics,
  trackAgentStarted,
  trackFrameworkDetected,
  trackFrameworkSelected,
  trackHealthCheckResult,
  trackPrerequisiteMissing,
  trackWizardCompleted,
  trackWizardError,
  trackWizardStarted,
} from './lib/analytics.js'
import { WizardChangelog } from './lib/changelog.js'
import { INTEGRATIONS } from './lib/constants.js'
import {
  detectIntegration,
  detectPackageManager,
  detectTypeScript,
} from './lib/detect.js'
import { type WizardMode, gatherContext } from './lib/gather.js'
import { maybeInstallSkills } from './lib/install-skills.js'
import { runPostAgentSteps } from './lib/post-agent.js'
import { checkPrerequisites } from './lib/prerequisites.js'
import type { Integration, WizardSession } from './lib/types.js'
import { renderCallSiteReport, scanCallSites } from './lib/wire-call-sites.js'

interface RunOptions {
  cwd: string
  debug: boolean
  cliVersion: string
  /** Setup-lifecycle phase. `implement` (default) runs the original full
   *  flow (column selection → agent edits code → post-agent install/push
   *  /migrate → call-site scan). `plan` skips column selection and the
   *  post-agent steps; the agent's deliverable is `.cipherstash/plan.md`. */
  mode?: WizardMode
}

export async function run(options: RunOptions) {
  const mode: WizardMode = options.mode ?? 'implement'
  p.intro(
    mode === 'plan' ? 'CipherStash Wizard — plan mode' : 'CipherStash Wizard',
  )

  const startTime = Date.now()
  const changelog = new WizardChangelog(options.cwd)
  changelog.phase(
    'Session start',
    `cwd: \`${options.cwd}\`\ncli version: \`${options.cliVersion}\`\nmode: \`${mode}\``,
  )

  // Phase 1: Prerequisites
  const prereqs = await checkPrerequisites(options.cwd)
  if (!prereqs.ok) {
    trackPrerequisiteMissing(prereqs.missing)
    p.log.error('Missing prerequisites:')
    for (const msg of prereqs.missing) {
      p.log.warn(`  → ${msg}`)
    }
    p.outro('Please complete the steps above and try again.')
    await shutdownAnalytics()
    process.exit(1)
  }

  // Phase 2: Health checks
  const readiness = await checkReadiness()
  trackHealthCheckResult(readiness)
  if (readiness === 'not_ready') {
    trackWizardError('health_check_failed')
    p.log.error(
      'Required services are unreachable. Please check your network and try again.',
    )
    await shutdownAnalytics()
    process.exit(1)
  }
  if (readiness === 'ready_with_warnings') {
    p.log.warn('Some services are degraded — proceeding with caution.')
  }

  // Phase 3: Detect framework
  const s = p.spinner()
  s.start('Detecting project setup...')

  const detectedIntegration = detectIntegration(options.cwd)
  const hasTypeScript = detectTypeScript(options.cwd)
  const packageManager = detectPackageManager(options.cwd)

  s.stop(
    detectedIntegration
      ? `Detected: ${detectedIntegration}${hasTypeScript ? ' (TypeScript)' : ''}`
      : 'No specific framework detected.',
  )

  trackFrameworkDetected(detectedIntegration)

  // Phase 4: Confirm or select integration
  let selectedIntegration: Integration

  if (detectedIntegration) {
    const confirmed = await p.confirm({
      message: `Use ${detectedIntegration} integration?`,
      initialValue: true,
    })

    if (p.isCancel(confirmed)) {
      p.cancel('Cancelled.')
      process.exit(0)
    }

    if (confirmed) {
      selectedIntegration = detectedIntegration
    } else {
      selectedIntegration = await selectIntegration()
    }
  } else {
    selectedIntegration = await selectIntegration()
  }

  trackFrameworkSelected(
    selectedIntegration,
    selectedIntegration === detectedIntegration,
  )
  changelog.phase(
    'Integration selected',
    `\`${selectedIntegration}\` (detected: ${detectedIntegration ?? 'none'})`,
  )

  // Phase 5: Gather context — DB introspection, column selection, schema
  // files. All done via CLI prompts BEFORE the agent starts; no AI tokens
  // spent on discovery. Plan mode skips column selection.
  const gathered = await gatherContext({
    cwd: options.cwd,
    integration: selectedIntegration,
    packageManager,
    mode,
  })

  const encryptedTables = Array.from(
    new Set(gathered.selectedColumns.map((c) => c.tableName)),
  )
  if (mode === 'plan') {
    changelog.phase(
      'Plan-mode scope',
      gathered.selectedColumns.length > 0
        ? `${gathered.selectedColumns.length} pre-selected column(s); agent may revise.`
        : 'No columns pre-selected; agent will propose scope from the schema.',
    )
  } else {
    changelog.phase(
      'Columns selected',
      `${gathered.selectedColumns.length} column(s) across ${encryptedTables.length} table(s): ${encryptedTables.map((t) => `\`${t}\``).join(', ')}`,
    )
  }

  // Phase 6: Build session
  const session: WizardSession = {
    cwd: options.cwd,
    debug: options.debug,
    detectedIntegration,
    hasTypeScript,
    detectedPackageManager: packageManager,
    selectedIntegration,
    phase: 'running',
    authenticated: true,
    hasStashConfig: gathered.hasStashConfig,
    hasEqlInstalled: true,
  }

  // Phase 7: Run the agent with a surgical prompt
  trackWizardStarted(session)

  p.log.info('Starting AI agent...')

  try {
    trackAgentStarted(selectedIntegration)

    // Network/IO operations that don't depend on each other run in parallel.
    const [agent, fetched] = await Promise.all([
      initializeAgent(session),
      fetchIntegrationPrompt({
        ctx: gathered,
        cliVersion: options.cliVersion,
        runner: packageManager?.execCommand ?? 'npx',
        mode,
      }),
    ])

    if (session.debug) {
      p.log.info(`Prompt length: ${fetched.prompt.length} chars`)
      p.log.info(`Prompt version: ${fetched.promptVersion}`)
    }

    const result = await agent.run(fetched.prompt)

    if (result.success) {
      if (mode === 'plan') {
        changelog.phase(
          'Plan drafted',
          '`.cipherstash/plan.md` written. Review and run `stash impl` to execute.',
        )
        await finalize({
          selectedIntegration,
          cwd: options.cwd,
          changelog,
          startTime,
          // Skills install is offered in plan mode too — same agent rules
          // apply if the user re-engages an editor agent later to refine
          // the plan.
          outro:
            'Plan drafted at `.cipherstash/plan.md`. Review it, then run `stash impl` to implement.',
        })
      } else {
        // Kick the call-site scan off in the background; it's read-only
        // and independent of the post-agent install/push/migrate, so
        // overlapping the two cuts wall-time on large projects.
        const scanPromise = scanCallSites(
          options.cwd,
          encryptedTables,
          selectedIntegration,
        ).then(
          (matches) => ({ ok: true as const, matches }),
          (err: unknown) => ({
            ok: false as const,
            message: err instanceof Error ? err.message : String(err),
          }),
        )

        changelog.phase(
          'Agent completed',
          'Encryption client and schema wiring generated successfully.',
        )

        await runPostAgentSteps({
          cwd: options.cwd,
          integration: selectedIntegration,
          gathered,
          packageManager,
        })
        changelog.phase(
          'Post-agent steps complete',
          'Package install, `db install`, `db push`, and migrations finished.',
        )

        const scanResult = await scanPromise
        if (scanResult.ok) {
          const report = renderCallSiteReport(scanResult.matches)
          p.note(report, 'Server action & page call sites')
          changelog.phase('Call-site scan', report)
        } else {
          p.log.warn(`Could not scan for call sites: ${scanResult.message}`)
        }

        await finalize({
          selectedIntegration,
          cwd: options.cwd,
          changelog,
          startTime,
          outro:
            'Encryption is set up! Your data is now protected by CipherStash.',
        })
      }
    } else {
      trackWizardError(result.error ?? 'unknown', selectedIntegration)
      changelog.note(`Agent failed: ${result.error ?? 'unknown error'}`)
      await changelog.flush()
      p.log.error(result.error ?? 'Agent failed without a specific error.')
      p.outro('Wizard could not complete. See above for details.')
      await shutdownAnalytics()
      process.exit(1)
    }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'Agent execution failed.'
    trackWizardError(message, selectedIntegration)
    changelog.note(`Wizard threw: ${message}`)
    await changelog.flush()
    p.log.error(message)
    await shutdownAnalytics()
    process.exit(1)
  }

  await shutdownAnalytics()
}

/**
 * Shared post-agent tail: skills install, completion telemetry, log flush,
 * and outro. Both `plan` and `implement` flows fall through to this so
 * future tweaks to skills/analytics/changelog stay in one place.
 */
async function finalize(opts: {
  selectedIntegration: Integration
  cwd: string
  changelog: WizardChangelog
  startTime: number
  outro: string
}): Promise<void> {
  const installedSkills = await maybeInstallSkills(
    opts.cwd,
    opts.selectedIntegration,
  )
  if (installedSkills.length > 0) {
    opts.changelog.action(
      `Installed ${installedSkills.length} Claude skill(s).`,
      installedSkills.map((name) => `.claude/skills/${name}`),
    )
  }

  trackWizardCompleted(opts.selectedIntegration, Date.now() - opts.startTime)
  const logPath = await opts.changelog.flush()
  if (logPath) {
    p.log.info(`Wizard log written to ${logPath}`)
  }
  p.outro(opts.outro)
}

async function selectIntegration(): Promise<Integration> {
  const selected = await p.select<Integration>({
    message: 'Which integration are you using?',
    options: [
      {
        value: 'drizzle',
        label: 'Drizzle ORM',
        hint: 'modifies your existing schema',
      },
      {
        value: 'supabase',
        label: 'Supabase JS Client',
        hint: 'generates encryption client',
      },
      {
        value: 'prisma',
        label: 'Prisma',
        hint: 'experimental',
      },
      {
        value: 'generic',
        label: 'Raw SQL / Other',
        hint: 'generates encryption client',
      },
    ],
  })

  if (p.isCancel(selected)) {
    p.cancel('Cancelled.')
    process.exit(0)
  }

  return selected
}
