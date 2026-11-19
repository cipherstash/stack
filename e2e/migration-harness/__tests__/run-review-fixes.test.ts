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
