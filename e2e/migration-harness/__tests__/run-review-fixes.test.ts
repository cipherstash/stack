import { readFile } from 'node:fs/promises'
import ts from 'typescript'
import { expect, test } from 'vitest'

// F15: the harness tasks import no workspace package (real Runs install
// @cipherstash/stack from npm inside the isolation), so building the whole
// workspace first only adds cost and couples the harness to unrelated build
// breakage.
test('harness turbo tasks do not depend on building the workspace', async () => {
  const path = new URL('../../../turbo.json', import.meta.url)
  const parsed = ts.parseConfigFileTextToJson(
    'turbo.json',
    await readFile(path, 'utf8'),
  )
  expect(parsed.error, 'turbo.json must parse').toBeUndefined()
  const tasks = (
    parsed.config as { tasks: Record<string, { dependsOn?: string[] }> }
  ).tasks
  const harness = Object.entries(tasks).filter(([name]) =>
    name.startsWith('@cipherstash/e2e#harness:'),
  )
  expect(harness.map(([name]) => name).sort()).toEqual([
    '@cipherstash/e2e#harness:isolation-probe',
    '@cipherstash/e2e#harness:selftest',
    '@cipherstash/e2e#harness:store-probe',
    '@cipherstash/e2e#harness:typecheck',
  ])
  for (const [name, task] of harness) {
    expect(
      task.dependsOn ?? [],
      `${name} must not build dependencies`,
    ).not.toContain('^build')
  }
})

// F11 (run.mjs part): when the migrator rejects (protocol violation, spawn,
// execute or stop error), the tool calls it made before failing ride on the
// rejection error. The Run must still record them as `agent-tool` evidence,
// exactly as it does for a returned result — the failed Runs are the ones
// that most need diagnosing.
test('a rejected migrate still records agent-tool evidence for its tool calls', async () => {
  const { run } = await import('../run/run.mjs')
  const { requiredOracleChecks } = await import('../run/migration-checks.mjs')
  const toolCalls = [
    { id: 'tool-1', exitCode: 0 },
    { id: 'tool-2', exitCode: 1 },
  ]
  const report = await run({
    id: 'rejected',
    manifest: {
      stack: '1.2.1',
      guideHash: 'abc',
      fixtureRevision: 'revision',
      agents: {},
    },
    driver: {
      provision: async () => {},
      installUnmigrated: async () => {},
      initializeLegacyData: async () => {},
      snapshot: async () => {},
      migrate: async () => {
        throw Object.assign(new Error('protocol violation'), {
          stdout: 'partial out',
          stderr: 'partial err',
          toolCalls,
        })
      },
      friction: async () => [],
      installAppHost: async () => {},
      behaviour: async () =>
        requiredOracleChecks.map((id: string) => ({ id, passed: true })),
    },
  })
  expect(report.outcome).toBe('agent-limit')
  const agentTool = report.evidence.filter((e) => e.kind === 'agent-tool')
  expect(
    agentTool.map((e) => ({
      stage: e.stage,
      checkId: e.checkId,
      payload: e.payload,
    })),
    'tool calls carried on the rejection must be recorded as agent-tool evidence',
  ).toEqual([
    { stage: 'migrator', checkId: 'tool-1', payload: toolCalls[0] },
    { stage: 'migrator', checkId: 'tool-2', payload: toolCalls[1] },
  ])
  expect(agentTool.map((e) => e.id)).toEqual([
    'rejected/agent-tool/1',
    'rejected/agent-tool/2',
  ])
})

// F16: every supervisor access event used to be inlined into
// run-report.json, which can mean hundreds of thousands of records. ADR-0001
// (line 285) still needs the full trail, successful allowed reads included,
// so the trail moves to one NDJSON file per stage, referenced from the report
// by digest. Only forbidden or failed events stay inline.
test('the full isolation trail is written per stage and only forbidden or failed events stay inline', async () => {
  const { createHash } = await import('node:crypto')
  const { run } = await import('../run/run.mjs')
  const { requiredOracleChecks } = await import('../run/migration-checks.mjs')
  const allowed = {
    actor: 'migrator',
    decision: 'allowed',
    result: 'success',
    resource: '/workspace/node_modules/pkg/README.md',
  }
  const denied = {
    actor: 'migrator',
    decision: 'forbidden',
    result: 'denied',
    resource: '/canary',
  }
  const failed = {
    actor: 'migrator',
    decision: 'allowed',
    result: 'denied',
    resource: '/workspace/missing',
  }
  const written: Record<string, string> = {}
  let drains = 0
  const report = await run({
    id: 'trail',
    manifest: {
      stack: '1.2.1',
      guideHash: 'abc',
      fixtureRevision: 'revision',
      agents: {},
    },
    driver: {
      provision: async () => {},
      installUnmigrated: async () => {},
      initializeLegacyData: async () => {},
      snapshot: async () => {},
      migrate: async () => ({ exitCode: 0 }),
      friction: async () => [],
      installAppHost: async () => {},
      behaviour: async () =>
        requiredOracleChecks.map((id: string) => ({ id, passed: true })),
    },
    supervision: {
      // Only the migrator stage (the fourth drain) produces events.
      drain: async () => (++drains === 4 ? [allowed, denied, failed] : []),
      stop: async () => {},
    },
    writeIsolationTrail: async (stage: string, body: string) => {
      written[stage] = body
      return `isolation-events/${stage}.ndjson`
    },
  })
  expect(report.outcome).toBe('pass')
  const body = written.migrator
  expect(body, 'the migrator stage trail must be written').toBeDefined()
  expect(
    body
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line)),
  ).toEqual([allowed, denied, failed])
  const trails = report.evidence.filter((e) => e.kind === 'isolation-trail')
  expect(trails.map((e) => [e.stage, e.payload])).toEqual([
    [
      'migrator',
      {
        file: 'isolation-events/migrator.ndjson',
        events: 3,
        sha256: createHash('sha256').update(body).digest('hex'),
      },
    ],
  ])
  expect(
    report.evidence
      .filter((e) => e.kind === 'isolation-event')
      .map((e) => e.payload),
  ).toEqual([denied, failed])
})

test('a supervised Run without a trail writer is refused', async () => {
  const { run } = await import('../run/run.mjs')
  await expect(
    run({
      id: 'no-writer',
      manifest: { guideHash: null },
      driver: {} as never,
      supervision: { drain: async () => [], stop: async () => {} },
    }),
  ).rejects.toThrow(/writeIsolationTrail/)
})
