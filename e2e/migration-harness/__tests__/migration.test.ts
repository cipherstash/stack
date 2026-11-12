import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'vitest'
import { migrationChecks } from '../run/migration-checks.mjs'
import { run } from '../run/run.mjs'

for (const stale of [false, true]) {
  test(`Run migration evidence ${stale ? 'rejects stale' : 'accepts removed'} boolean HMAC`, async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'mh-migration-'))
    await mkdir(join(workspace, 'src'))
    await writeFile(
      join(workspace, 'src/app.mjs'),
      'import { Encryption } from "@cipherstash/stack/v3"',
    )
    await writeFile(
      join(workspace, 'package.json'),
      JSON.stringify({ dependencies: { '@cipherstash/stack': '1.2.1' } }),
    )
    await writeFile(
      join(workspace, 'package-lock.json'),
      JSON.stringify({
        packages: {
          '': { dependencies: { '@cipherstash/stack': '1.2.1' } },
          'node_modules/@cipherstash/stack': {
            version: '1.2.1',
            dependencies: { '@cipherstash/protect-ffi': '0.31.0' },
          },
          'node_modules/@cipherstash/protect-ffi': { version: '0.31.0' },
        },
      }),
    )
    try {
      const report = await run({
        id: 'migration',
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
            { id: 'no-rewrite.legacy-bytes', passed: true },
            ...(await migrationChecks({
              workspace,
              installedWorkspace: workspace,
              ffiRange: '0.31.0',
              mutationSnapshot: {
                dynamo: {
                  Item: stale
                    ? { active__source: 'cipher', active__hmac: 'old' }
                    : { active__source: 'cipher' },
                },
              },
              stackVersion: '1.2.1',
            })),
          ],
        },
      })
      assert.equal(report.outcome, stale ? 'behaviour' : 'pass')
      assert.equal(
        Object(
          report.evidence.find(
            (e) => e.checkId === 'migration.active-hmac-absent',
          )?.payload,
        ).passed,
        !stale,
      )
    } finally {
      await rm(workspace, { recursive: true, force: true })
    }
  })
}
