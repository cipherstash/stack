import { createHash } from 'node:crypto'

const precedence = [
  'isolation-violation',
  'infrastructure',
  'agent-limit',
  'install',
  'invalid-friction-log',
  'behaviour',
]
const stages = [
  'provisioning',
  'unmigrated-install',
  'seeding-snapshot',
  'migrator',
  'friction-validation',
  'app-host-install',
  'behaviour',
  'run-report',
]

/** Whole-Run orchestration. Drivers are harness-owned; agent output never supplies verdicts. */
export async function run({ id, manifest, driver, supervision = null }) {
  const report = {
    id,
    manifest,
    stages: [],
    failures: [],
    evidence: [],
    friction: null,
    migratorInvoked: false,
    editorEligible: false,
  }
  const ordinals = new Map()
  function evidence(stage, kind, checkId, payload, attributionUsable = true) {
    const ordinal = (ordinals.get(kind) ?? 0) + 1
    ordinals.set(kind, ordinal)
    report.evidence.push({
      id: `${id}/${kind}/${ordinal}`,
      stage,
      kind,
      checkId,
      payload,
      payloadDigest: createHash('sha256')
        .update(JSON.stringify(payload))
        .digest('hex'),
      attributionUsable,
      guideRevision: manifest.guideHash,
    })
  }
  let stopped = false
  async function stage(name, category, action, prerequisites = true) {
    if (stopped || !prerequisites) {
      report.stages.push({
        name,
        status: 'skipped',
        reason: stopped
          ? 'isolation supervisor stopped Run'
          : 'failed prerequisite',
      })
      return false
    }
    try {
      let actionError
      try {
        await action()
      } catch (error) {
        actionError = error
      }
      if (supervision) {
        let events
        try {
          events = await supervision.drain()
        } catch (error) {
          if (actionError) {
            const secondary = {
              stage: name,
              category,
              cause: String(actionError.message ?? actionError),
            }
            report.failures.push(secondary)
            evidence(name, 'stage-error', name, secondary)
          }
          error.infrastructure = true
          await supervision.stop()
          throw error
        }
        for (const event of events) {
          evidence(name, 'isolation-event', event.actor, event, false)
          if (event.result === 'success' && event.decision === 'forbidden') {
            stopped = true
            report.failures.push({
              stage: name,
              category: 'isolation-violation',
              cause: 'Trusted successful forbidden access',
              event,
            })
            await supervision.stop()
          }
        }
      }
      if (actionError) throw actionError
      report.stages.push({ name, status: stopped ? 'failed' : 'passed' })
      return true
    } catch (error) {
      const failure = {
        stage: name,
        category: error.infrastructure ? 'infrastructure' : category,
        cause: String(error.message ?? error),
      }
      report.failures.push(failure)
      evidence(
        name,
        category === 'invalid-friction-log' ? 'log-validation' : 'stage-error',
        name,
        failure,
        category !== 'invalid-friction-log',
      )
      report.stages.push({ name, status: 'failed', cause: failure.cause })
      return false
    }
  }
  const provisioned = await stage(stages[0], 'infrastructure', () =>
    driver.provision(),
  )
  const installed = await stage(
    stages[1],
    'install',
    () => driver.installUnmigrated(),
    provisioned,
  )
  const seeded = await stage(
    stages[2],
    'infrastructure',
    async () => {
      await driver.seed()
      await driver.snapshot()
    },
    installed,
  )
  const migrated = await stage(
    stages[3],
    'agent-limit',
    async () => {
      report.migratorInvoked = true
      const result = await driver.migrate()
      for (const call of result.toolCalls ?? [])
        evidence('migrator', 'agent-tool', call.id, call)
      if (result.exitCode !== 0 || result.limit)
        throw new Error(result.limit ?? `Migrator exited ${result.exitCode}`)
    },
    seeded,
  )
  await stage(
    stages[4],
    'invalid-friction-log',
    async () => {
      const friction = await driver.friction()
      if (!Array.isArray(friction))
        throw new Error('Friction Log must be an explicit list')
      for (const item of friction) {
        if (
          !item ||
          typeof item.section !== 'string' ||
          !item.section ||
          (manifest.guideSections &&
            !manifest.guideSections.includes(item.section)) ||
          !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(item.issue) ||
          typeof item.actionable !== 'boolean' ||
          typeof item.description !== 'string' ||
          typeof item.workaround !== 'string'
        )
          throw new Error('Malformed Friction Log entry')
        evidence(
          'friction-validation',
          'friction-item',
          `${item.section}/${item.issue}`,
          item,
        )
      }
      report.friction = friction
    },
    migrated,
  )
  const appInstalled = await stage(
    stages[5],
    'install',
    () => driver.installAppHost(),
    migrated,
  )
  await stage(
    stages[6],
    'behaviour',
    async () => {
      const checks = await driver.behaviour()
      for (const check of checks)
        evidence('behaviour', 'oracle-check', check.id, check)
      if (checks.some((check) => !check.passed))
        throw new Error('Behaviour checks failed')
    },
    appInstalled,
  )
  report.outcome =
    precedence.find((category) =>
      report.failures.some((f) => f.category === category),
    ) ??
    (report.friction?.some((item) => item.actionable)
      ? 'friction-only'
      : 'pass')
  report.stages.push({ name: stages[7], status: 'passed' })
  report.editorEligible =
    report.migratorInvoked &&
    !['isolation-violation', 'infrastructure'].includes(report.outcome)
  return report
}
