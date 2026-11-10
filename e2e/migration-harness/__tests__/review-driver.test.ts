import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { legacy } from '../run/behaviour.mjs'
import { migrationChecks, noRewriteCheck } from '../run/migration-checks.mjs'
import { createRealDriver } from '../run/real-driver.mjs'
import { run } from '../run/run.mjs'
import type { IsolationOptions } from '../types.js'

const observed = vi.hoisted(() => ({
  dispose: vi.fn(async () => {}),
  snapshot: vi.fn(async () => ({
    dynamo: { Item: { email__source: { S: 'original' } } },
    postgres: [{ pk: 'legacy', email: { c: 'original', hm: 'term' } }],
  })),
}))

vi.mock('../run/real-stores.mjs', () => ({
  disposeStores: observed.dispose,
  createStoreSet: async () => ({
    env: { DATABASE_URL: 'postgresql://actor:app-secret@127.0.0.1/db' },
    forwards: [],
    verify: async () => ({ ownsApplicationTables: true }),
    snapshot: observed.snapshot,
  }),
}))

vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>()
  const { promisify } = await import('node:util')
  const execute = promisify(actual.execFile)
  return {
    ...actual,
    execFile: Object.assign(
      (...args: unknown[]) => Reflect.apply(actual.execFile, undefined, args),
      {
        [promisify.custom]: async (
          file: string,
          args: string[],
          options?: import('node:child_process').ExecFileOptions,
        ) =>
          file === 'npm'
            ? { stdout: '"1.2.1"', stderr: '' }
            : execute(file, args, options),
      },
    ),
  }
})

const execute = promisify(execFile)
const root = fileURLToPath(new URL('../../../', import.meta.url))
const outputs: string[] = []
beforeEach(() => {
  observed.dispose.mockClear()
  observed.snapshot.mockClear()
})
afterEach(async () => {
  vi.unstubAllEnvs()
  for (const output of outputs.splice(0))
    await rm(output, { recursive: true, force: true })
})

async function setup(
  options: {
    command?: string
    gitFailure?: 'add' | 'diff'
    stopFails?: boolean
    timeoutMs?: number
  } = {},
) {
  const output = await mkdtemp(join(tmpdir(), 'mh-review-driver-'))
  outputs.push(output)
  const commands: IsolationOptions[] = []
  const calls: string[] = []
  const cancellations: Array<{ expected?: boolean } | undefined> = []
  const isolation = {
    prove: async () => ({
      verified: true,
      backend: 'test',
      policies: {
        filesystem: 'test',
        network: 'test',
        migratorEnvironment: { id: 'test', storeSet: 'test' },
        appHost: { id: 'test', storeSet: 'test' },
      },
    }),
    exec: async (invocation: IsolationOptions) => {
      commands.push(invocation)
      const [file, ...args] = invocation.command
      if (file === 'git') {
        if (options.gitFailure && args.includes(options.gitFailure))
          return { exitCode: 128, stdout: '', stderr: 'repository unavailable' }
        const result = await execute(file, args, { cwd: invocation.workspace })
        return { exitCode: 0, stdout: result.stdout, stderr: result.stderr }
      }
      return { exitCode: 0, stdout: '', stderr: '' }
    },
    stop: async (stopOptions?: { expected?: boolean }) => {
      cancellations.push(stopOptions)
      if (options.stopFails) throw Error('supervisor stop failed')
    },
    openAppHost: async () => ({
      call: async (method: string) => {
        calls.push(method)
        const pg = {
          pk: legacy.pk,
          email: legacy.email,
          age: legacy.age,
          notes: legacy.notes,
        }
        if (method === 'get') return legacy
        if (method === 'getPostgres') return pg
        if (method.startsWith('findPostgres')) return [pg]
        if (method.startsWith('find')) return [legacy]
        return null
      },
      close: async () => ({ exitCode: 0, stdout: '', stderr: '' }),
    }),
  }
  const driver = createRealDriver({
    id: 'review',
    root,
    output,
    command: options.command ?? 'true',
    isolation,
    credentials: { CS_CLIENT_KEY: 'app-secret' },
    manifest: {
      guideHash: 'guide',
      stack: '1.2.1',
      agents: { limits: { timeMs: options.timeoutMs ?? 5000, turns: 5 } },
    },
  })
  await driver.provision()
  return { driver, output, commands, calls, cancellations }
}

test('F1 records a committed migration relative to the prepared fixture', async () => {
  const { driver, output } = await setup()
  const workspace = join(output, 'migrator')
  await writeFile(
    join(workspace, 'migration-marker.txt'),
    'committed migration\n',
  )
  await execute('git', ['add', '.'], { cwd: workspace })
  await execute(
    'git',
    [
      '-c',
      'user.name=Test',
      '-c',
      'user.email=test@localhost',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '-qm',
      'Migrate',
    ],
    { cwd: workspace },
  )
  await driver.migrate()
  expect(await readFile(join(output, 'migration.diff'), 'utf8')).toContain(
    'committed migration',
  )
})

test.each(['add', 'diff'] as const)(
  'F1 rejects failed git %s instead of publishing an empty diff',
  async (gitFailure) => {
    const { driver } = await setup({ gitFailure })
    await expect(driver.migrate()).rejects.toThrow(/git.*128/)
  },
)

test('F2 runs the model adapter on the host and brokers its command into isolation', async () => {
  vi.stubEnv('MODEL_TEST_TOKEN', 'host-model-token')
  const adapterDir = await mkdtemp(join(tmpdir(), 'mh-adapter-'))
  outputs.push(adapterDir)
  const adapter = join(adapterDir, 'adapter.mjs')
  const marker = join(adapterDir, 'observed.json')
  await writeFile(
    adapter,
    `
    import { writeFileSync } from 'node:fs';
    import { createInterface } from 'node:readline';
    const lines = createInterface({input:process.stdin});
    process.stdout.write(JSON.stringify({id:'tool-1',method:'exec',command:['node','-e','console.log("isolated")']})+'\\n');
    for await (const line of lines) {
      const response=JSON.parse(line);
      writeFileSync(${JSON.stringify(marker)},JSON.stringify({token:process.env.MODEL_TEST_TOKEN,applicationSecret:process.env.CS_CLIENT_KEY,response}));
      break;
    }
    lines.close();
  `,
  )
  const { driver, commands } = await setup({ command: `node '${adapter}'` })
  const result = await driver.migrate()
  const contents = await readFile(marker, 'utf8').catch(() => '{}')
  expect(JSON.parse(contents)).toMatchObject({
    token: 'host-model-token',
    response: { id: 'tool-1', result: { exitCode: 0 } },
  })
  expect(JSON.parse(contents).applicationSecret).toBeUndefined()
  expect(
    commands.some(
      (entry) => entry.command[0] === 'node' && entry.actor === 'migrator',
    ),
  ).toBe(true)
  expect(commands.every((entry) => !entry.env?.MODEL_TEST_TOKEN)).toBe(true)
  expect(result.toolCalls).toContainEqual({ id: 'tool-1', exitCode: 0 })
})

test('F3 cannot report pass without migration-layer checks', async () => {
  const report = await run({
    id: 'missing-migration-layer',
    manifest: { guideHash: 'guide' },
    driver: {
      provision: async () => {},
      installUnmigrated: async () => {},
      initializeLegacyData: async () => {},
      snapshot: async () => {},
      migrate: async () => ({ exitCode: 0 }),
      friction: async () => [],
      installAppHost: async () => {},
      behaviour: async () => [{ id: 'behaviour.synthetic', passed: true }],
    },
  })
  expect(report.outcome).toBe('behaviour')
  expect(
    report.failures.some((failure) => /migration/i.test(failure.cause)),
  ).toBe(true)
})

test('F3 the unchanged fixture fails each required migration-layer check', async () => {
  const { driver } = await setup()
  await driver.snapshot()
  await driver.installAppHost()
  const checks = await driver.behaviour()
  for (const id of [
    'migration.protect-dependencies-absent',
    'migration.protect-ffi-version',
    'migration.endpoint-shim-absent',
    'migration.active-hmac-absent',
  ])
    expect(checks).toContainEqual(
      expect.objectContaining({ id, passed: false }),
    )
})

test('F5 checks legacy ciphertext after reads and before mutations', async () => {
  const { driver, calls } = await setup()
  await driver.snapshot()
  await driver.installAppHost()
  let readBeforeSnapshot = false
  let mutationBeforeSnapshot = false
  observed.snapshot.mockImplementationOnce(async () => {
    readBeforeSnapshot = calls.includes('findPostgresAge')
    mutationBeforeSnapshot =
      calls.includes('put') || calls.includes('setActive')
    return {
      dynamo: { Item: { email__source: { S: 'rewritten' } } },
      postgres: [{ pk: 'legacy', email: { c: 'original', hm: 'term' } }],
    }
  })
  const checks = await driver.behaviour()
  expect(checks).toContainEqual(
    expect.objectContaining({ id: 'no-rewrite.legacy-bytes', passed: false }),
  )
  expect(readBeforeSnapshot).toBe(true)
  expect(mutationBeforeSnapshot).toBe(false)
})

test('F12 disposes stores even when the isolation supervisor fails to stop', async () => {
  const { driver } = await setup({ stopFails: true })
  await expect(driver.close()).rejects.toThrow('supervisor stop failed')
  expect(observed.dispose).toHaveBeenCalledOnce()
})

test('F2 preserves timeout result without attempting Git after stopping isolation', async () => {
  const { driver, commands, cancellations } = await setup({
    command: 'sleep 10',
    timeoutMs: 50,
  })
  const result = await driver.migrate()
  expect(result).toMatchObject({ exitCode: 124, limit: 'time limit reached' })
  expect(commands).toEqual([])
  expect(cancellations).toEqual([{ expected: true }])
})

test('F5 ignores unrelated metadata but detects changed equality terms and missing snapshots', () => {
  const before = {
    dynamo: {
      Item: {
        email__source: { S: 'cipher' },
        email__hmac: { S: 'term' },
        other: { S: 'old' },
      },
    },
    postgres: [{ pk: 'legacy', email: { c: 'cipher', hm: 'term', v: 3 } }],
  }
  const after = structuredClone(before)
  after.dynamo.Item.other.S = 'new'
  after.postgres[0].email.v = 4
  expect(noRewriteCheck(before, after).passed).toBe(true)
  after.dynamo.Item.email__hmac.S = 'changed'
  expect(noRewriteCheck(before, after).passed).toBe(false)
  expect(noRewriteCheck(undefined, before).passed).toBe(false)
})

async function migratedFiles() {
  const workspace = await mkdtemp(join(tmpdir(), 'mh-migration-checks-'))
  outputs.push(workspace)
  const installedWorkspace = await mkdtemp(
    join(tmpdir(), 'mh-installed-checks-'),
  )
  outputs.push(installedWorkspace)
  await mkdir(join(workspace, 'src'))
  await writeFile(
    join(workspace, 'src/app.mjs'),
    'import { Encryption } from "@cipherstash/stack";\n// @cipherstash/protect appears only in this explanatory comment.\n',
  )
  const manifest = { dependencies: { '@cipherstash/stack': '1.2.1' } }
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': manifest,
      'node_modules/@cipherstash/stack': {
        version: '1.2.1',
        dependencies: { '@cipherstash/protect-ffi': '^0.33.0' },
      },
      'node_modules/@cipherstash/protect-ffi': { version: '0.33.2' },
    },
  }
  await writeFile(join(workspace, 'package.json'), JSON.stringify(manifest))
  await writeFile(join(workspace, 'package-lock.json'), JSON.stringify(lock))
  await writeFile(
    join(installedWorkspace, 'package-lock.json'),
    JSON.stringify(lock),
  )
  return {
    workspace,
    installedWorkspace,
    stackVersion: '1.2.1',
    ffiRange: '^0.33.0',
    mutationSnapshot: {
      dynamo: { Item: { active__source: { S: 'updated-ciphertext' } } },
    },
  }
}

test('F3 accepts migrated sources and the exact FFI version resolved for Stack', async () => {
  expect(
    (await migrationChecks(await migratedFiles())).every(
      (check) => check.passed,
    ),
  ).toBe(true)
})

test.each([
  ['legacy alias', 'migration.protect-dependencies-absent'],
  ['legacy import', 'migration.protect-dependencies-absent'],
  ['nested old ffi', 'migration.protect-ffi-version'],
  ['ffi alias', 'migration.protect-ffi-version'],
  ['endpoint shim', 'migration.endpoint-shim-absent'],
  ['stale active hmac', 'migration.active-hmac-absent'],
])('F3 rejects %s', async (scenario, id) => {
  const options = await migratedFiles()
  const manifestPath = join(options.workspace, 'package.json')
  if (scenario === 'legacy alias')
    await writeFile(
      manifestPath,
      JSON.stringify({
        dependencies: { old: 'npm:@cipherstash/protect@10.2.1' },
      }),
    )
  if (scenario === 'legacy import')
    await writeFile(
      join(options.workspace, 'src/app.mjs'),
      'const legacy = await import("@cipherstash/protect-dynamodb")',
    )
  if (scenario === 'nested old ffi') {
    const lockPath = join(options.workspace, 'package-lock.json')
    const lock = JSON.parse(await readFile(lockPath, 'utf8'))
    lock.packages['node_modules/nested/node_modules/@cipherstash/protect-ffi'] =
      { version: '0.18.1' }
    await writeFile(lockPath, JSON.stringify(lock))
  }
  if (scenario === 'ffi alias')
    await writeFile(
      manifestPath,
      JSON.stringify({
        dependencies: { old: 'npm:@cipherstash/protect-ffi@0.18.1' },
      }),
    )
  if (scenario === 'endpoint shim')
    await writeFile(
      join(options.workspace, 'src/app.mjs'),
      'process.env.CS_CTS_HOST = "https://old.invalid"',
    )
  if (scenario === 'stale active hmac')
    Object.assign(options.mutationSnapshot.dynamo.Item, {
      active__hmac: { S: 'stale' },
    })
  expect(
    (await migrationChecks(options)).find((check) => check.id === id)?.passed,
  ).toBe(false)
})
