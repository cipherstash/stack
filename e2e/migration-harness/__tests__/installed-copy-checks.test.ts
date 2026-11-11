import assert from 'node:assert/strict'
import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'vitest'
import { migrationChecks } from '../run/migration-checks.mjs'
import { run } from '../run/run.mjs'

const manifest = { dependencies: { '@cipherstash/stack': '1.2.1' } }
const lock = {
  packages: {
    '': manifest,
    'node_modules/@cipherstash/stack': { version: '1.2.1' },
    'node_modules/@cipherstash/protect-ffi': { version: '0.31.0' },
  },
}

for (const change of [
  {
    name: 'a Protect import',
    path: 'src/app.mjs',
    text: 'import "@cipherstash/protect"',
    check: 'migration.protect-dependencies-absent',
  },
  {
    name: 'a CTS endpoint shim',
    path: 'src/app.mjs',
    text: 'process.env.CS_CTS_HOST = "https://example.invalid"',
    check: 'migration.endpoint-shim-absent',
  },
  {
    name: 'a ZeroKMS endpoint shim',
    path: 'src/app.mjs',
    text: 'process.env.CS_ZEROKMS_HOST = "https://example.invalid"',
    check: 'migration.endpoint-shim-absent',
  },
  {
    name: 'a legacy manifest dependency',
    path: 'package.json',
    text: JSON.stringify({
      dependencies: {
        ...manifest.dependencies,
        '@cipherstash/protect': '10.2.1',
      },
    }),
    check: 'migration.protect-dependencies-absent',
  },
  {
    name: 'a legacy lockfile dependency',
    path: 'package-lock.json',
    text: JSON.stringify({
      packages: {
        ...lock.packages,
        'node_modules/@cipherstash/protect': { version: '10.2.1' },
      },
    }),
    check: 'migration.protect-dependencies-absent',
  },
  {
    name: 'a legacy FFI declaration',
    path: 'package.json',
    text: JSON.stringify({
      dependencies: {
        ...manifest.dependencies,
        '@cipherstash/protect-ffi': '0.18.1',
      },
    }),
    check: 'migration.protect-ffi-version',
  },
]) {
  test(`Run rejects ${change.name} introduced in the installed App Host copy`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'mh-installed-checks-'))
    const workspace = join(directory, 'migrator')
    const installedWorkspace = join(directory, 'app-host')
    try {
      await mkdir(join(workspace, 'src'), { recursive: true })
      await writeFile(join(workspace, 'package.json'), JSON.stringify(manifest))
      await writeFile(
        join(workspace, 'package-lock.json'),
        JSON.stringify(lock),
      )
      await writeFile(
        join(workspace, 'src/app.mjs'),
        'import "@cipherstash/stack/v3"',
      )
      await cp(workspace, installedWorkspace, { recursive: true })
      const inspect = () =>
        migrationChecks({
          workspace,
          installedWorkspace,
          stackVersion: '1.2.1',
          ffiRange: '0.31.0',
          mutationSnapshot: { dynamo: { Item: { active__source: 'cipher' } } },
        })
      assert.ok(
        (await inspect()).every((check) => check.passed),
        'The unchanged installed app must satisfy the migration requirements',
      )
      const report = await run({
        id: 'installed-copy',
        manifest: { guideHash: 'guide' },
        driver: {
          provision: async () => {},
          installUnmigrated: async () => {},
          initializeLegacyData: async () => {},
          snapshot: async () => {},
          migrate: async () => ({ exitCode: 0 }),
          friction: async () => [],
          installAppHost: async () => {
            // Model a lifecycle script changing only the deployed copy.
            await writeFile(join(installedWorkspace, change.path), change.text)
          },
          behaviour: async () => [
            { id: 'no-rewrite.legacy-bytes', passed: true },
            ...(await inspect()),
          ],
        },
      })
      assert.equal(
        report.outcome,
        'behaviour',
        'A clean Migrator workspace must not hide installed-copy regressions',
      )
      assert.ok(
        report.evidence.some(
          (entry) =>
            entry.checkId === change.check &&
            Object(entry.payload).passed === false,
        ),
        `The Run must name the failed ${change.check} requirement`,
      )
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })
}
