import { createHash } from 'node:crypto'
import { requiredOracleChecks } from './migration-checks.mjs'

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
  'initialization-snapshot',
  'migrator',
  'friction-validation',
  'app-host-install',
  'behaviour',
  'run-report',
]

/** Whole-Run orchestration. Drivers are harness-owned; agent output never supplies verdicts.
 * @param {{id:string, manifest:import('../types.js').Manifest, driver:import('../types.js').RunDriver, supervision?:import('../types.js').Supervision|null, writeIsolationTrail?:import('../types.js').IsolationTrailWriter}} options
 */
export async function run({
  id,
  manifest,
  driver,
  supervision = null,
  writeIsolationTrail,
}) {
  // ADR-0001 needs the full access trail, successful allowed reads included,
  // to attribute documentation access. It is too large to inline in the
  // report, so a supervised Run must have somewhere to write it.
  if (supervision && !writeIsolationTrail)
    throw new TypeError('A supervised Run requires writeIsolationTrail')
  /** @type {import('../types.js').RunReport} */
  const report = {
    id,
    manifest,
    stages: [],
    failures: [],
    evidence: [],
    friction: null,
    migratorInvoked: false,
    editorEligible: false,
    outcome: 'infrastructure',
  }
  const ordinals = new Map()
  /** @param {string} stage @param {string} kind @param {string} checkId @param {unknown} payload */
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
  /** @param {string} name @param {string} category @param {()=>Promise<unknown>} action */
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
              cause:
                actionError instanceof Error
                  ? actionError.message
                  : String(actionError),
            }
            report.failures.push(secondary)
            evidence(name, 'stage-error', name, secondary)
          }
          await supervision.stop()
          throw Object.assign(
            new Error(error instanceof Error ? error.message : String(error)),
            { infrastructure: true },
          )
        }
        for (const event of events) {
          // Inline only the events a verdict or a denial record turns on; the
          // routine allowed-and-successful ones live in the stage trail file.
          if (event.decision === 'forbidden' || event.result !== 'success')
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
        if (events.length && writeIsolationTrail) {
          const body = events
            .map((event) => `${JSON.stringify(event)}\n`)
            .join('')
          let file
          try {
            file = await writeIsolationTrail(name, body)
          } catch (error) {
            throw Object.assign(
              new Error(
                `Could not write isolation trail: ${error instanceof Error ? error.message : String(error)}`,
              ),
              { infrastructure: true },
            )
          }
          evidence(
            name,
            'isolation-trail',
            name,
            {
              file,
              events: events.length,
              sha256: createHash('sha256').update(body).digest('hex'),
            },
            false,
          )
        }
      }
      if (actionError) throw actionError
      report.stages.push({ name, status: stopped ? 'failed' : 'passed' })
      return true
    } catch (error) {
      const failure = {
        stage: name,
        category:
          error instanceof Error &&
          'infrastructure' in error &&
          error.infrastructure
            ? 'infrastructure'
            : category,
        cause: error instanceof Error ? error.message : String(error),
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
    'infrastructure',
    () => driver.installUnmigrated(),
    provisioned,
  )
  const initialized = await stage(
    stages[2],
    'infrastructure',
    async () => {
      await driver.initializeLegacyData()
      await driver.snapshot()
    },
    installed,
  )
  const migrated = await stage(
    stages[3],
    'agent-limit',
    async () => {
      report.migratorInvoked = true
      /** @param {{toolCalls?: {id:string, exitCode:number}[]}} source */
      const recordToolCalls = (source) => {
        for (const call of source.toolCalls ?? [])
          evidence('migrator', 'agent-tool', call.id, call)
      }
      let result
      try {
        result = await driver.migrate()
      } catch (error) {
        // A rejected Migrator carries the tool calls it made before failing.
        if (error && typeof error === 'object' && 'toolCalls' in error)
          recordToolCalls(
            /** @type {{toolCalls?: {id:string, exitCode:number}[]}} */ (error),
          )
        throw error
      }
      recordToolCalls(result)
      if (result.exitCode !== 0 || result.limit)
        throw new Error(result.limit ?? `Migrator exited ${result.exitCode}`)
    },
    initialized,
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
          typeof item.issue !== 'string' ||
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
      if (!Array.isArray(checks) || checks.length === 0)
        throw new Error('Behaviour checks must not be empty')
      for (const check of checks)
        evidence('behaviour', 'oracle-check', check.id, check)
      if (
        requiredOracleChecks.some(
          (id) => !checks.some((check) => check.id === id),
        )
      )
        throw new Error('Required migration or no-rewrite checks are missing')
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
