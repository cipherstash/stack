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
let statements: {
  database: string
  username: string
  text: string
  values: unknown[]
}[]
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
  connect.mockImplementation(
    ({ database, username }: { database: string; username: string }) => {
      const query = async (
        strings: TemplateStringsArray,
        ...values: unknown[]
      ) => {
        statements.push({ database, username, text: strings.join('?'), values })
        return []
      }
      return Object.assign(query, {
        unsafe: async (text: string) => {
          statements.push({ database, username, text, values: [] })
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
    },
  )
})

afterEach(() => vi.unstubAllGlobals())

async function provision(
  resources: import('../run/real-stores.mjs').Resource[],
  postgresV2 = false,
) {
  return createStoreSet({
    runId: 'review',
    actor: `oracle${++actorOrdinal}`,
    eqlBundle: fileURLToPath(new URL('../run/stores.mjs', import.meta.url)),
    resources,
    postgresV2,
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

test('the PostgreSQL snapshot runs as the Run application role, never as the superuser', async () => {
  const resources: import('../run/real-stores.mjs').Resource[] = []
  try {
    const stores = await provision(resources)
    statements = []
    await stores.postgresSnapshot()
    const reads = statements.filter((query) =>
      /pg_attribute|FROM customers|pg_index/.test(query.text),
    )
    expect(reads.length).toBeGreaterThan(0)
    // A migration can replace customers with a view over a SECURITY INVOKER
    // function; read as postgres, that function would run as superuser.
    for (const read of reads) {
      expect(read.username).not.toBe('postgres')
      expect(read.username).toMatch(/^mh_/)
      expect(read.database).toBe(read.username)
    }
  } finally {
    await disposeStores(resources)
  }
})

const eqlV2Sql = 'SELECT 1; -- synthetic EQL v2 bundle'

test('the EQL v2 bundle download is bounded and refused unless its digest matches', async () => {
  const fetches: { url: string; signal: unknown }[] = []
  vi.stubGlobal(
    'fetch',
    async (url: string, options?: { signal?: unknown }) => {
      fetches.push({ url, signal: options?.signal })
      return { ok: true, status: 200, text: async () => eqlV2Sql }
    },
  )
  const resources: import('../run/real-stores.mjs').Resource[] = []
  try {
    const result = await provision(resources, true).then(
      () => null,
      (error: Error) => error.message,
    )
    expect(result).toMatch(/digest/i)
    expect(fetches).toHaveLength(1)
    expect(fetches[0].signal).toBeInstanceOf(AbortSignal)
    expect(statements.some((query) => query.text === eqlV2Sql)).toBe(false)
  } finally {
    await disposeStores(resources)
  }
})
