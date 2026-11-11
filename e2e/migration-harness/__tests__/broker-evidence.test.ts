import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, test } from 'vitest'
import { requiredOracleChecks } from '../run/migration-checks.mjs'
import { runMigrator } from '../run/migrator.mjs'
import { run } from '../run/run.mjs'
import type { Manifest } from '../types.js'

const directories: string[] = []
afterEach(async () => {
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true })
})

async function invoke(
  command: string[],
  response: { exitCode: number; stdout: string; stderr: string },
  maxEvidenceBytes?: number,
) {
  const directory = await mkdtemp(join(tmpdir(), 'mh-evidence-test-'))
  directories.push(directory)
  const adapter = join(directory, 'adapter.mjs')
  await writeFile(
    adapter,
    `
    console.log(JSON.stringify(${JSON.stringify({ id: 'request-1', method: 'exec', command })}));
    process.stdin.once('data', () => process.exit(0));
  `,
  )
  return runMigrator({
    command: `node '${adapter}'`,
    execute: async () => response,
    stop: async () => {},
    timeoutMs: 2000,
    maxEvidenceBytes,
  })
}

test('broker retains responses with the command and request identity for private evidence', async () => {
  const command = ['npm', 'view', '@cipherstash/stack', 'readme']
  const response = {
    exitCode: 0,
    stdout: 'DOCUMENTATION-RESPONSE-CANARY',
    stderr: 'DIAGNOSTIC-RESPONSE-CANARY',
  }
  const result = await invoke(command, response)
  expect(result.exitCode).toBe(0)
  expect(result).toMatchObject({
    brokerEvidence: [{ id: 'request-1', command, result: response }],
  })
  // Raw command responses must not silently become inline Editor evidence.
  expect(result.toolCalls).toEqual([{ id: 'request-1', exitCode: 0 }])
})

test('explicit documentation retrieval is flagged for evidence review', async () => {
  const result = await invoke(['npm', 'view', '@cipherstash/stack', 'readme'], {
    exitCode: 0,
    stdout: 'package instructions',
    stderr: '',
  })
  expect(result).toMatchObject({
    documentationExposure: { status: 'observed' },
  })
})

test('an arbitrary shell command cannot establish the absence of supplementary documentation', async () => {
  const result = await invoke(['sh', '-c', 'node inspect.mjs'], {
    exitCode: 0,
    stdout: 'application output',
    stderr: '',
  })
  expect(result).toMatchObject({ documentationExposure: { status: 'unknown' } })
})

test('evidence retention has a byte budget and never labels incomplete records complete', async () => {
  const result = await invoke(
    ['true'],
    { exitCode: 0, stdout: 'x'.repeat(100), stderr: '' },
    64,
  )
  expect(result).toMatchObject({
    brokerEvidence: [],
    documentationExposure: {
      status: 'unknown',
      evidenceComplete: false,
      reviewRequired: true,
    },
  })
})

test.each(['openat', 'stat'])(
  'documentation exposure distinguishes a successful %s from metadata inspection',
  async (operation) => {
    const manifest: Manifest = {
      guideHash: 'guide',
      documentationExposure: {
        status: 'unknown',
        reviewRequired: true,
        evidenceComplete: true,
      },
    }
    let sent = false
    const report = await run({
      id: 'docs',
      manifest,
      driver: {
        provision: async () => {},
        installUnmigrated: async () => {},
        initializeLegacyData: async () => {},
        snapshot: async () => {},
        migrate: async () => ({ exitCode: 0 }),
        friction: async () => [],
        installAppHost: async () => {},
        behaviour: async () =>
          requiredOracleChecks.map((id) => ({ id, passed: true })),
      },
      supervision: {
        stop: async () => {},
        drain: () => {
          if (sent) return []
          sent = true
          return [
            {
              actor: 'migrator',
              stage: 'command',
              operation,
              resource: '/workspace/node_modules/example/README.md',
              decision: 'allowed',
              result: 'success',
            },
          ]
        },
      },
    })
    expect(report.manifest.documentationExposure?.status).toBe(
      operation === 'openat' ? 'possible' : 'unknown',
    )
    expect(report.manifest.documentationExposure?.reviewRequired).toBe(true)
  },
)
