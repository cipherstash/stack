import assert from 'node:assert/strict'
import { test } from 'vitest'
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
        behaviour: async () => [noRewrite(baseline, current)],
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
test('missing Postgres terms identify attributes without disclosing bytes', () => {
  const current = structuredClone(baseline)
  current.postgres = []
  const check = noRewrite(baseline, current)
  assert.equal(check.passed, false)
  assert.match(check.cause ?? '', /postgres.*legacy.*email.c/)
  assert.doesNotMatch(check.cause ?? '', /pg-cipher|pg-term/)
})
