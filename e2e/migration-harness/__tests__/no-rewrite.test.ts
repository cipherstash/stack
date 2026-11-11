import assert from 'node:assert/strict'
import { test } from 'vitest'
import { requiredOracleChecks } from '../run/migration-checks.mjs'
import { noRewrite } from '../run/no-rewrite.mjs'
import { run } from '../run/run.mjs'

const baseline = {
  dynamo: {
    Item: {
      pk: { S: 'legacy' },
      email__source: { S: 'cipher' },
      email__hmac: { S: 'term' },
    },
  },
  postgres: [
    {
      pk: 'legacy',
      email: { c: 'pg-cipher', hm: 'pg-term' },
      notes: { c: 'note' },
    },
  ],
}
for (const changed of [false, true]) {
  test(`Run records ${changed ? 'rewritten' : 'unchanged'} Legacy Data`, async () => {
    const current = structuredClone(baseline)
    if (changed) current.dynamo.Item.email__source.S = 'rewritten'
    const report = await run({
      id: 'rewrite',
      manifest: { guideHash: 'guide' },
      driver: {
        provision: async () => {},
        installUnmigrated: async () => {},
        initializeLegacyData: async () => {},
        snapshot: async () => {},
        migrate: async () => ({ exitCode: 0 }),
        friction: async () => [],
        installAppHost: async () => {},
        behaviour: async () => [
          noRewrite(baseline, current),
          ...requiredOracleChecks
            .filter((id) => id !== 'no-rewrite.legacy-bytes')
            .map((id) => ({ id, passed: true })),
        ],
      },
    })
    assert.equal(report.outcome, changed ? 'behaviour' : 'pass')
    const check = report.evidence.find(
      (e) => e.checkId === 'no-rewrite.legacy-bytes',
    )
    assert.ok(check)
    if (changed)
      assert.match(
        JSON.stringify(check.payload),
        /dynamo.*legacy.*email__source/,
      )
  })
}

test('Run rejects a rewritten duplicate Legacy Data row even when the original is last', async () => {
  const current = structuredClone(baseline)
  const rewritten = structuredClone(current.postgres[0])
  rewritten.email.c = 'rewritten'
  current.postgres.unshift(rewritten)
  const report = await run({
    id: 'duplicate-legacy',
    manifest: { guideHash: 'guide' },
    driver: {
      provision: async () => {},
      installUnmigrated: async () => {},
      initializeLegacyData: async () => {},
      snapshot: async () => {},
      migrate: async () => ({ exitCode: 0 }),
      friction: async () => [],
      installAppHost: async () => {},
      behaviour: async () => [
        noRewrite(baseline, current),
        ...requiredOracleChecks
          .filter((id) => id !== 'no-rewrite.legacy-bytes')
          .map((id) => ({ id, passed: true })),
      ],
    },
  })
  assert.equal(report.outcome, 'behaviour')
  assert.equal(report.editorEligible, true)
})
