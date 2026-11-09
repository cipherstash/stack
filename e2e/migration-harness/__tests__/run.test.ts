import assert from 'node:assert/strict'
import { test } from 'vitest'
import { run } from '../run/run.mjs'

const manifest = {
  stack: '1.2.1',
  guideHash: 'abc',
  fixtureRevision: 'revision',
  agents: {},
}
function driver(overrides = {}) {
  return {
    provision: async () => {},
    installUnmigrated: async () => {},
    seed: async () => {},
    snapshot: async () => {},
    migrate: async () => ({ exitCode: 0 }),
    friction: async () => [],
    installAppHost: async () => {},
    behaviour: async () => [],
    ...overrides,
  }
}
test('a finished no-op Fake Migrator with empty friction passes behaviour', async () => {
  const report = await run({ id: 'noop', manifest, driver: driver() })
  assert.equal(report.outcome, 'pass')
  assert.equal(report.editorEligible, true)
  assert.equal(
    report.stages.every((s) => s.status === 'passed'),
    true,
  )
})

test('invalid friction remains primary while independent behaviour diagnostics run', async () => {
  let called = false
  const report = await run({
    id: 'invalid',
    manifest,
    driver: driver({
      friction: async () => null,
      behaviour: async () => {
        called = true
        return [{ id: 'get', passed: false }]
      },
    }),
  })
  assert.equal(report.outcome, 'invalid-friction-log')
  assert.equal(called, true)
  assert.deepEqual(
    report.failures.map((f) => f.category),
    ['invalid-friction-log', 'behaviour'],
  )
})
test('pre-Migrator installation failure skips dependents and excludes Editor', async () => {
  const report = await run({
    id: 'install',
    manifest,
    driver: driver({
      installUnmigrated: async () => {
        throw Error('npm failed')
      },
    }),
  })
  assert.equal(report.outcome, 'install')
  assert.equal(report.editorEligible, false)
  assert.deepEqual(
    report.stages.filter((s) => s.status === 'skipped').map((s) => s.name),
    [
      'seeding-snapshot',
      'migrator',
      'friction-validation',
      'app-host-install',
      'behaviour',
    ],
  )
})
for (const operation of ['seed', 'snapshot'])
  test(`${operation} exceptions fail setup as infrastructure`, async () => {
    const report = await run({
      id: operation,
      manifest,
      driver: driver({
        [operation]: async () => {
          throw Error('setup failed')
        },
      }),
    })
    assert.equal(report.outcome, 'infrastructure')
    assert.equal(report.editorEligible, false)
  })
test('recovered npm tools are diagnostic evidence rather than install failures', async () => {
  const report = await run({
    id: 'recovered',
    manifest,
    driver: driver({
      migrate: async () => ({
        exitCode: 0,
        toolCalls: [{ id: 'npm-1', exitCode: 1 }],
      }),
    }),
  })
  assert.equal(report.outcome, 'pass')
  assert.equal(report.evidence[0].id, 'recovered/agent-tool/1')
  assert.equal(report.evidence[0].guideRevision, 'abc')
})
test('agent failure after a failed npm command remains agent-limit', async () => {
  const report = await run({
    id: 'crash',
    manifest,
    driver: driver({
      migrate: async () => ({
        exitCode: 1,
        toolCalls: [{ id: 'npm-1', exitCode: 1 }],
      }),
    }),
  })
  assert.equal(report.outcome, 'agent-limit')
  assert.deepEqual(
    report.failures.map((f) => f.category),
    ['agent-limit'],
  )
})
test('App Host install failure outranks invalid friction', async () => {
  const report = await run({
    id: 'both',
    manifest,
    driver: driver({
      friction: async () => null,
      installAppHost: async () => {
        throw Error('npm failed')
      },
    }),
  })
  assert.equal(report.outcome, 'install')
})
test('trusted successful forbidden access stops later calls and excludes Editor', async () => {
  let later = false
  const report = await run({
    id: 'breach',
    manifest,
    driver: driver({
      migrate: async () => ({ exitCode: 0 }),
      installAppHost: async () => {
        later = true
      },
    }),
    supervision: {
      drain: async () => [
        {
          actor: 'migrator',
          decision: 'forbidden',
          result: 'success',
          resource: '/protected/canary',
        },
      ],
      stop: async () => {},
    },
  })
  assert.equal(report.outcome, 'isolation-violation')
  assert.equal(report.editorEligible, false)
  assert.equal(later, false)
})
test('caught denied access alone does not fail a Run', async () => {
  const report = await run({
    id: 'denied',
    manifest,
    driver: driver(),
    supervision: {
      drain: async () => [
        {
          actor: 'app-host',
          decision: 'forbidden',
          result: 'denied',
          resource: '/canary',
        },
      ],
      stop: async () => {},
    },
  })
  assert.equal(report.outcome, 'pass')
})
test('a broken trusted event stream is infrastructure even during Migrator', async () => {
  let count = 0
  const report = await run({
    id: 'stream',
    manifest,
    driver: driver(),
    supervision: {
      drain: async () => {
        if (++count === 4) throw Error('stream disconnected')
        return []
      },
      stop: async () => {},
    },
  })
  assert.equal(report.outcome, 'infrastructure')
})
test('successful forbidden access outranks an action error from terminated actor', async () => {
  let count = 0
  const report = await run({
    id: 'terminated',
    manifest,
    driver: driver({
      migrate: async () => {
        throw Error('killed')
      },
    }),
    supervision: {
      drain: async () =>
        ++count === 4
          ? [
              {
                actor: 'migrator',
                decision: 'forbidden',
                result: 'success',
                resource: '/canary',
              },
            ]
          : [],
      stop: async () => {},
    },
  })
  assert.equal(report.outcome, 'isolation-violation')
})
test('friction references must identify an input guide section', async () => {
  const report = await run({
    id: 'section',
    manifest: { ...manifest, guideSections: ['preamble', 'upgrade'] },
    driver: driver({
      friction: async () => [
        {
          section: 'invented',
          issue: 'missing-step',
          actionable: true,
          description: 'missing',
          workaround: 'guessed',
        },
      ],
    }),
  })
  assert.equal(report.outcome, 'invalid-friction-log')
})
test('actionable friction with passing behaviour is friction-only', async () => {
  const report = await run({
    id: 'friction',
    manifest,
    driver: driver({
      friction: async () => [
        {
          section: 'preamble',
          issue: 'missing-step',
          actionable: true,
          description: 'missing',
          workaround: 'guessed',
        },
      ],
    }),
  })
  assert.equal(report.outcome, 'friction-only')
  assert.equal(report.evidence[0].id, 'friction/friction-item/1')
})
test('behaviour failure outranks actionable friction', async () => {
  const report = await run({
    id: 'behaviour-failure',
    manifest,
    driver: driver({
      friction: async () => [
        {
          section: 'preamble',
          issue: 'missing-step',
          actionable: true,
          description: 'missing',
          workaround: 'guessed',
        },
      ],
      behaviour: async () => [{ id: 'behaviour.get', passed: false }],
    }),
  })
  assert.equal(report.outcome, 'behaviour')
})
test('stream failure retains the simultaneous actor failure as secondary evidence', async () => {
  let count = 0
  const report = await run({
    id: 'secondary',
    manifest,
    driver: driver({
      migrate: async () => {
        throw Error('actor crashed')
      },
    }),
    supervision: {
      drain: async () => {
        if (++count === 4) throw Error('stream lost')
        return []
      },
      stop: async () => {},
    },
  })
  assert.equal(report.outcome, 'infrastructure')
  assert.equal(
    report.failures.some(
      (f) => f.category === 'agent-limit' && f.cause === 'actor crashed',
    ),
    true,
  )
})
