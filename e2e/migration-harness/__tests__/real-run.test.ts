import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'vitest'
import { createRealDriver } from '../run/real-driver.mjs'
import { run } from '../run/run.mjs'

test('real Run fails provisioning before application execution when capability proof is unavailable', async () => {
  const output = await mkdtemp(join(tmpdir(), 'mh-proof-'))
  let executions = 0
  const manifest = {
    guideHash: null,
    stack: '^1.2.1',
    agents: { limits: { timeMs: 1000 } },
  }
  const isolation = {
    prove: async () => ({
      verified: false,
      backend: 'test-unverified',
      policies: {
        filesystem: 'none',
        network: 'none',
        migratorEnvironment: { id: 'none', storeSet: 'none' },
        appHost: { id: 'none', storeSet: 'none' },
      },
    }),
    exec: async () => {
      executions++
      throw Error('Application must not execute')
    },
    stop: async () => {},
    openAppHost: async () => {
      throw Error('Application must not execute')
    },
  }
  const driver = createRealDriver({
    id: 'proof',
    root: output,
    output,
    command: 'true',
    isolation,
    credentials: {},
    manifest,
  })
  try {
    const report = await run({ id: 'proof', manifest, driver })
    assert.equal(report.outcome, 'infrastructure')
    assert.equal(report.editorEligible, false)
    assert.equal(executions, 0)
    assert.equal(
      report.stages.find((stage) => stage.name === 'migrator')?.status,
      'skipped',
    )
  } finally {
    await driver.close()
    await rm(output, { recursive: true, force: true })
  }
})

test('Run rejects a Friction Log symlink without disclosing protected contents', async () => {
  const output = await mkdtemp(join(tmpdir(), 'mh-output-'))
  const protectedPath = join(output, 'protected.json')
  await mkdir(join(output, 'migrator'))
  await writeFile(protectedPath, 'secret-canary-1534')
  await symlink(protectedPath, join(output, 'migrator', 'friction.json'))
  const manifest = {
    guideHash: 'guide',
    stack: '1.2.1',
    agents: { limits: { timeMs: 1000 } },
  }
  const real = createRealDriver({
    id: 'symlink',
    root: output,
    output,
    command: 'true',
    isolation: {
      stop: async () => {},
      prove: async () => {
        throw Error('Unused proof')
      },
      exec: async () => {
        throw Error('Unused command')
      },
      openAppHost: async () => {
        throw Error('Unused application')
      },
    },
    credentials: {},
    manifest,
  })
  const driver = {
    ...real,
    provision: async () => {},
    installUnmigrated: async () => {},
    initializeLegacyData: async () => {},
    snapshot: async () => {},
    migrate: async () => ({ exitCode: 0 }),
    installAppHost: async () => {},
    behaviour: async () => [],
  }
  try {
    const report = await run({ id: 'symlink', manifest, driver })
    assert.equal(report.outcome, 'invalid-friction-log')
    assert.equal(JSON.stringify(report).includes('secret-canary-1534'), false)
  } finally {
    await real.close()
    await rm(output, { recursive: true, force: true })
  }
})
