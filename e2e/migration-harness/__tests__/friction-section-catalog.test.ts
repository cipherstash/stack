import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, test, vi } from 'vitest'
import { createRealDriver } from '../run/real-driver.mjs'
import { run } from '../run/run.mjs'
import type { Manifest } from '../types.js'

vi.mock('../run/real-stores.mjs', () => ({
  disposeStores: async () => {},
  createStoreSet: async () => ({
    verify: async () => ({ ownsApplicationTables: true }),
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

const roots: string[] = []
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true })
})

test('prepared workspace publishes the exact manifest section catalog and complete friction schema', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mh-friction-catalog-'))
  roots.push(root)
  const fixture = join(root, 'e2e/migration-harness/fixture')
  const guideDirectory = join(root, 'docs/migration')
  await mkdir(fixture, { recursive: true })
  await mkdir(guideDirectory, { recursive: true })
  await writeFile(join(fixture, 'package.json.template'), '{"private":true}')
  await writeFile(
    join(fixture, 'README.md'),
    'Record unclear instructions and failed approaches in `friction.md`.\nuse the harness acceptance command for those checks.',
  )
  await writeFile(
    join(guideDirectory, 'protect-dynamodb-to-stack.md'),
    '# Ciphertext/search terms\n## Ciphertext/search terms\n### Deploy & rollback!\n',
  )
  const manifest: Manifest & { stack: string } = {
    stack: '1.2.1',
    guideHash: '',
  }
  const output = join(root, 'run')
  const driver = createRealDriver({
    id: 'catalog',
    root,
    output,
    command: 'true',
    credentials: {},
    manifest,
    isolation: {
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
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '' }),
      openAppHost: async () => {
        throw Error('No application execution belongs in catalog preparation')
      },
      stop: async () => {},
    },
  })
  await driver.provision()
  const workspace = join(output, 'migrator')
  const schemaText = await readFile(
    join(workspace, 'friction-schema.json'),
    'utf8',
  ).catch(() => null)
  expect(
    schemaText,
    'Migrator must receive the exact accepted section IDs',
  ).not.toBeNull()
  const schema = JSON.parse(schemaText ?? '{}')
  expect(manifest.guideSections).toEqual([
    'preamble',
    'ciphertext-search-terms',
    'ciphertext-search-terms-2',
    'deploy-rollback',
  ])
  expect(schema).toMatchObject({
    type: 'array',
    items: {
      type: 'object',
      required: ['section', 'issue', 'actionable', 'description', 'workaround'],
      properties: {
        section: { type: 'string', enum: manifest.guideSections },
        issue: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
        actionable: { type: 'boolean' },
        description: { type: 'string' },
        workaround: { type: 'string' },
      },
    },
  })
  const readme = await readFile(join(workspace, 'README.md'), 'utf8')
  expect(readme).toContain('friction-schema.json')
  expect(readme).toContain('/workspace/friction.json')
  expect(readme).toContain('[]')

  const friction = schema.items.properties.section.enum.map(
    (section: string) => ({
      section,
      issue: 'observed-gap',
      actionable: false,
      description: 'Synthetic catalog validation',
      workaround: '',
    }),
  )
  await writeFile(join(workspace, 'friction.json'), JSON.stringify(friction))
  const validate = () =>
    run({
      id: 'catalog-validation',
      manifest,
      driver: {
        provision: async () => {},
        installUnmigrated: async () => {},
        initializeLegacyData: async () => {},
        snapshot: async () => {},
        migrate: async () => ({ exitCode: 0 }),
        friction: driver.friction,
        installAppHost: async () => {},
        behaviour: async () => [],
      },
    })
  const report = await validate()
  expect(report.stages).toContainEqual({
    name: 'friction-validation',
    status: 'passed',
  })
  expect(report.friction).toEqual(friction)

  schema.items.properties.section.enum = ['invented-section']
  await writeFile(
    join(workspace, 'friction-schema.json'),
    JSON.stringify(schema),
  )
  await writeFile(
    join(workspace, 'friction.json'),
    JSON.stringify([{ ...friction[0], section: 'invented-section' }]),
  )
  const tampered = await validate()
  expect(tampered.stages).toContainEqual(
    expect.objectContaining({ name: 'friction-validation', status: 'failed' }),
  )
  expect(manifest.guideSections).not.toContain('invented-section')
})
