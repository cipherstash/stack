import { execFile } from 'node:child_process'
import {
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { legacy } from '../run/behaviour.mjs'
import { runMigrator } from '../run/migrator.mjs'
import { createRealDriver } from '../run/real-driver.mjs'
import type { IsolationOptions } from '../types.js'

// Regression tests for PR #1576 review items 5, 6 and 7 (F9, F10, F11).

const original = () => ({
  dynamo: { Item: { email__source: { S: 'original' } } },
  postgres: [{ pk: 'legacy', email: { c: 'original', hm: 'term' } }],
})
const observed = vi.hoisted(() => ({
  snapshot: vi.fn(async (_pk?: string): Promise<unknown> => undefined),
}))

vi.mock('../run/real-stores.mjs', () => ({
  disposeStores: async () => {},
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
  observed.snapshot.mockReset()
  observed.snapshot.mockImplementation(async () => original())
})
afterEach(async () => {
  for (const output of outputs.splice(0))
    await rm(output, { recursive: true, force: true })
})

async function setup(options: { command?: string } = {}) {
  const output = await mkdtemp(join(tmpdir(), 'mh-review-fixes-'))
  outputs.push(output)
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
      const [file, ...args] = invocation.command
      if (file === 'git') {
        const result = await execute(file, args, { cwd: invocation.workspace })
        return { exitCode: 0, stdout: result.stdout, stderr: result.stderr }
      }
      return { exitCode: 0, stdout: 'isolated output', stderr: '' }
    },
    stop: async () => {},
    openAppHost: async () => ({
      call: async (method: string) => {
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
    id: 'review-fixes',
    root,
    output,
    command: options.command ?? 'true',
    isolation,
    credentials: { CS_CLIENT_KEY: 'app-secret' },
    manifest: {
      guideHash: 'guide',
      stack: '1.2.1',
      agents: { limits: { timeMs: 5000, turns: 5 } },
    },
  })
  await driver.provision()
  return { driver, output }
}

async function adapter(source: string) {
  const directory = await mkdtemp(join(tmpdir(), 'mh-review-fixes-adapter-'))
  outputs.push(directory)
  const path = join(directory, 'adapter.mjs')
  await writeFile(path, source)
  return `node '${path}'`
}

// Emits a valid tool call, waits for its response, then breaks the protocol.
const protocolViolation = `
  import { createInterface } from 'node:readline';
  process.stderr.write('adapter diagnostics before failure\\n');
  const lines = createInterface({input:process.stdin});
  process.stdout.write(JSON.stringify({id:'tool-1',method:'exec',command:['npm','test']})+'\\n');
  for await (const line of lines) { break }
  process.stdout.write('not-json\\n');
  setTimeout(()=>{},10000);
`

test.each([
  ['the no-rewrite snapshot', undefined],
  ['the afterSetActive snapshot', 'mutation'],
])(
  'F9 marks a store failure during %s as infrastructure',
  async (_name, failingPk) => {
    const { driver } = await setup()
    await driver.snapshot()
    await driver.installAppHost()
    observed.snapshot.mockImplementation(async (pk?: string) => {
      if (pk === failingPk) throw Error('Dynamo snapshot failed: 500')
      return original()
    })
    const failure = await driver.behaviour().then(
      () => undefined,
      (error: unknown) => error,
    )
    expect(failure).toBeInstanceOf(Error)
    expect(failure).toMatchObject({ infrastructure: true })
  },
)

test('F10 the oracle copy keeps relative symlinks relative', async () => {
  const { driver, output } = await setup()
  const workspace = join(output, 'migrator')
  await mkdir(join(workspace, 'node_modules', '.bin'), { recursive: true })
  await mkdir(join(workspace, 'node_modules', 'tool'), { recursive: true })
  await writeFile(join(workspace, 'node_modules', 'tool', 'cli.js'), '')
  await symlink(
    '../tool/cli.js',
    join(workspace, 'node_modules', '.bin', 'tool'),
  )
  await driver.installUnmigrated()
  expect(
    await readlink(join(output, 'app-host', 'node_modules', '.bin', 'tool')),
  ).toBe('../tool/cli.js')
})

test('F10 the App Host copy keeps relative symlinks relative', async () => {
  const { driver, output } = await setup()
  const workspace = join(output, 'migrator')
  await mkdir(join(workspace, 'lib'), { recursive: true })
  await writeFile(join(workspace, 'lib', 'v3.mjs'), '')
  await symlink('./lib/v3.mjs', join(workspace, 'current.mjs'))
  await driver.installAppHost()
  await driver.close()
  expect(await readlink(join(output, 'app-host', 'current.mjs'))).toBe(
    './lib/v3.mjs',
  )
})

test('F11 a rejected Migrator exposes its partial transcript and tool calls', async () => {
  const failure = await runMigrator({
    command: await adapter(protocolViolation),
    execute: async () => ({ exitCode: 0, stdout: 'ok', stderr: '' }),
    stop: async () => {},
    timeoutMs: 5000,
  }).then(
    () => undefined,
    (error: unknown) => error,
  )
  expect(failure).toBeInstanceOf(Error)
  expect(String(failure)).toMatch(/invalid JSON/)
  expect(failure).toMatchObject({
    stderr: expect.stringContaining('adapter diagnostics before failure'),
    stdout: expect.stringContaining('not-json'),
    toolCalls: [{ id: 'tool-1', exitCode: 0 }],
  })
})

test('F11 a rejected Migrator still leaves its transcript on disk', async () => {
  const { driver, output } = await setup({
    command: await adapter(protocolViolation),
  })
  await expect(driver.migrate()).rejects.toThrow(/invalid JSON/)
  const transcript = await readFile(
    join(output, 'migrator-transcript.log'),
    'utf8',
  ).catch(() => '')
  expect(transcript).toContain('adapter diagnostics before failure')
  expect(transcript).toContain('not-json')
})
