import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

const { executeDocker, connect } = vi.hoisted(() => ({
  executeDocker: vi.fn(),
  connect: vi.fn(),
}))
vi.mock('node:child_process', () => ({
  execFile: Object.assign(vi.fn(), {
    [Symbol.for('nodejs.util.promisify.custom')]: executeDocker,
  }),
}))
vi.mock('postgres', () => ({ default: connect }))

import { createStoreSet, disposeStores } from '../run/real-stores.mjs'

let dockerCalls: string[][]
let statements: { database: string; text: string; values: unknown[] }[]
let endings: string[]
let networks: Map<string, boolean>
let containers: Map<string, { networks: string[]; args: string[] }>
let enforceInternalPorts: boolean
let cleanupFailure: string | null
let actorOrdinal = 0

beforeEach(() => {
  dockerCalls = []
  statements = []
  endings = []
  networks = new Map()
  containers = new Map()
  enforceInternalPorts = false
  cleanupFailure = null
  executeDocker.mockImplementation(async (_program: string, args: string[]) => {
    dockerCalls.push(args)
    if (args[0] === 'network' && args[1] === 'create')
      networks.set(args.at(-1) ?? '', args.includes('--internal'))
    if (args[0] === 'run' || args[0] === 'create') {
      containers.set(args[args.indexOf('--name') + 1], {
        networks: args.flatMap((arg, index) =>
          arg === '--network' ? [args[index + 1]] : [],
        ),
        args,
      })
    }
    if (args[0] === 'network' && args[1] === 'connect')
      containers.get(args[3])?.networks.push(args[2])
    if (args[0] === 'port') {
      const container = containers.get(args[1])
      if (
        enforceInternalPorts &&
        container?.networks.every((network) => networks.get(network) === true)
      )
        throw Error(`no public port '${args[2]}' published for ${args[1]}`)
      return { stdout: '127.0.0.1:49152\n', stderr: '' }
    }
    if (
      cleanupFailure === 'container removal' &&
      args[0] === 'rm' &&
      args.at(-1)?.startsWith('mh-pg-')
    )
      throw Error('container removal failed')
    return { stdout: '', stderr: '' }
  })
  connect.mockImplementation(({ database }: { database: string }) => {
    const query = async (
      strings: TemplateStringsArray,
      ...values: unknown[]
    ) => {
      statements.push({ database, text: strings.join('?'), values })
      return []
    }
    return Object.assign(query, {
      unsafe: async (text: string) => {
        statements.push({ database, text, values: [] })
        if (cleanupFailure && text.startsWith(cleanupFailure))
          throw Error(`${cleanupFailure} failed`)
        return []
      },
      end: async () => {
        endings.push(database)
        if (cleanupFailure === 'admin end' && database === 'postgres')
          throw Error('admin end failed')
      },
    })
  })
})

afterEach(() => vi.unstubAllGlobals())

async function provision(
  resources: import('../run/real-stores.mjs').Resource[],
) {
  return createStoreSet({
    runId: 'review',
    actor: `oracle${++actorOrdinal}`,
    eqlBundle: fileURLToPath(new URL('../run/stores.mjs', import.meta.url)),
    resources,
  })
}

for (const failure of [
  'DROP DATABASE',
  'DROP ROLE',
  'admin end',
  'container removal',
]) {
  test(`F13 releases the last Postgres lease after ${failure} fails`, async () => {
    const resources: import('../run/real-stores.mjs').Resource[] = []
    await provision(resources)
    const pg = [...containers.keys()].find((name) => name.startsWith('mh-pg-'))
    const network = dockerCalls
      .find((args) => args[0] === 'network' && args[1] === 'create')
      ?.at(-1)
    cleanupFailure = failure

    await disposeStores(resources)

    expect(endings).toContain('postgres')
    expect(dockerCalls).toContainEqual(['rm', '-f', '-v', pg])
    expect(dockerCalls).toContainEqual(['network', 'rm', network])
  })
}

test('F19 administers private stores without publishing internal-only containers', async () => {
  enforceInternalPorts = true
  const resources: import('../run/real-stores.mjs').Resource[] = []
  try {
    const result = await provision(resources).then(
      (stores) => ({ stores, error: null }),
      (error: Error) => ({ stores: null, error: error.message }),
    )
    expect(result.error).toBeNull()
    expect(result.stores).not.toBeNull()
    for (const forward of result.stores?.forwards ?? []) {
      const target = containers.get(forward.targetHost)
      expect(target?.networks).toEqual([forward.network])
      expect(networks.get(forward.network)).toBe(true)
      expect(target?.args).not.toContain('-p')
    }
    const published = [...containers.values()].filter((container) =>
      container.args.includes('-p'),
    )
    expect(published).toHaveLength(2)
    for (const container of published)
      expect(container.args[container.args.indexOf('-p') + 1]).toMatch(
        /^127\.0\.0\.1::\d+$/,
      )
  } finally {
    await disposeStores(resources)
  }
})

test('the Oracle snapshot reads the selected record from both assigned stores', async () => {
  const requests: string[] = []
  vi.stubGlobal('fetch', async (_url: string, options: { body: string }) => {
    requests.push(options.body)
    return { ok: true, json: async () => ({ Item: { pk: { S: 'mutation' } } }) }
  })
  const resources: import('../run/real-stores.mjs').Resource[] = []
  try {
    const stores = await provision(resources)
    const snapshot: (pk: string) => Promise<unknown> = stores.snapshot
    await snapshot('mutation')

    expect(JSON.parse(requests[0]).Key).toEqual({ pk: { S: 'mutation' } })
    expect(
      statements.find((query) => query.text.includes('SELECT pk, email::jsonb'))
        ?.values,
    ).toEqual(['mutation'])
  } finally {
    await disposeStores(resources)
  }
})
