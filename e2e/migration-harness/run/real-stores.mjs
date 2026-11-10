import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { promisify } from 'node:util'
import postgres from 'postgres'
import { provisionPostgres } from './stores.mjs'

const exec = promisify(execFile)
/** @param {string[]} args */
export async function docker(args) {
  return (
    await exec('docker', args, { maxBuffer: 16 * 1024 * 1024 })
  ).stdout.trim()
}

/** Publish a host-only administration relay while the store stays internal-only.
 * @param {string} target @param {number} port @param {string} network
 * @param {Resource[]} resources */
async function publishAdminPort(target, port, network, resources) {
  const relay = `${target}-admin`
  const adminNetwork = `${relay}-network`
  resources.push(() => docker(['network', 'rm', adminNetwork]))
  resources.push(relay)
  await docker(['network', 'create', adminNetwork])
  await docker([
    'run',
    '-d',
    '--name',
    relay,
    '--network',
    adminNetwork,
    '--network',
    network,
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--sysctl',
    'net.ipv4.ip_forward=0',
    '--read-only',
    '--pids-limit',
    '32',
    '--memory',
    '64m',
    '-p',
    `127.0.0.1::${port}`,
    'node:22-bookworm-slim',
    'node',
    '-e',
    `const net = require('node:net');
net.createServer((client) => {
  const upstream = net.connect({ host: process.argv[1], port: Number(process.argv[2]) });
  client.on('error', () => upstream.destroy());
  upstream.on('error', () => client.destroy());
  client.on('close', () => upstream.destroy());
  upstream.on('close', () => client.destroy());
  client.pipe(upstream).pipe(client);
}).listen(Number(process.argv[2]), '0.0.0.0');`,
    target,
    String(port),
  ])
  const binding = await docker(['port', relay, `${port}/tcp`])
  const match = /^127\.0\.0\.1:(\d+)$/.exec(binding)
  if (!match) throw Error('Store administration relay has no loopback binding')
  return Number(match[1])
}

// Runs in an Iteration share one server per actor; databases and roles remain per Run.
/** @type {Map<string, ReturnType<typeof initializePostgres>>} */
const sharedServers = new Map()
/** @param {string} actor @param {string} eqlBundle */
async function initializePostgres(actor, eqlBundle) {
  const password = randomBytes(24).toString('hex')
  const pg = `mh-pg-${randomBytes(8).toString('hex')}-${actor}`
  const network = `${pg}-network`
  /** @type {Resource[]} */
  const resources = [() => docker(['network', 'rm', network]), pg]
  /** @type {import('postgres').Sql|undefined} */
  let admin
  try {
    await docker(['network', 'create', '--internal', network])
    await docker([
      'run',
      '-d',
      '--name',
      pg,
      '--network',
      network,
      '-e',
      `POSTGRES_PASSWORD=${password}`,
      '--tmpfs',
      '/var/lib/postgresql/data:rw,nosuid,nodev,size=512m',
      'postgres:17-alpine',
    ])
    const pgPort = await publishAdminPort(pg, 5432, network, resources)
    admin = postgres({
      host: '127.0.0.1',
      port: pgPort,
      username: 'postgres',
      password,
      database: 'postgres',
      connect_timeout: 2,
      max: 1,
    })
    let ready = false
    let readinessError
    for (let attempt = 0; attempt < 60; attempt++) {
      try {
        await admin`SELECT 1`
        ready = true
        break
      } catch (error) {
        readinessError =
          error instanceof Error && 'code' in error
            ? String(error.code)
            : String(error)
        await new Promise((resolve) => setTimeout(resolve, 500))
      }
    }
    if (!ready) throw Error(`Postgres readiness timed out (${readinessError})`)
    await admin.unsafe('CREATE DATABASE mh_template')
    const template = postgres({
      host: '127.0.0.1',
      port: pgPort,
      username: 'postgres',
      password,
      database: 'mh_template',
      max: 1,
    })
    try {
      await template.unsafe(await readFile(eqlBundle, 'utf8'))
      await template.unsafe(
        'REVOKE CONNECT ON DATABASE mh_template FROM PUBLIC',
      )
    } finally {
      await template.end()
    }
    return { pg, pgPort, password, admin, network, resources, leases: 0 }
  } catch (error) {
    if (admin) await admin.end({ timeout: 1 }).catch(() => {})
    await disposeStores(resources)
    throw error
  }
}

/** Harness-only store administration; none of these handles enters an actor.
 * @typedef {string|(()=>Promise<unknown>)} Resource
 * @param {{runId:string,actor:string,eqlBundle:string,resources:Resource[]}} options */
export async function createStoreSet({ runId, actor, eqlBundle, resources }) {
  if (!sharedServers.has(actor))
    sharedServers.set(actor, initializePostgres(actor, eqlBundle))
  const pending = sharedServers.get(actor)
  if (!pending) throw Error('Postgres server initialization missing')
  let shared
  try {
    shared = await pending
  } catch (error) {
    sharedServers.delete(actor)
    throw error
  }
  const { pg, pgPort, password, admin, network } = shared
  shared.leases++
  /** @type {Awaited<ReturnType<typeof provisionPostgres>>|undefined} */
  let identity
  resources.push(async () => {
    try {
      if (identity) {
        try {
          await admin.unsafe(
            `DROP DATABASE IF EXISTS "${identity.database}" WITH (FORCE)`,
          )
        } finally {
          await admin.unsafe(`DROP ROLE IF EXISTS "${identity.role}"`)
        }
      }
    } finally {
      shared.leases--
      if (!shared.leases) {
        sharedServers.delete(actor)
        await admin.end({ timeout: 1 }).catch(() => {})
        await disposeStores(shared.resources)
      }
    }
  })
  const dynamo = `mh-dynamo-${runId.slice(0, 8)}-${actor}`
  const dynamoNetwork = `${dynamo}-network`
  resources.push(() => docker(['network', 'rm', dynamoNetwork]))
  resources.push(dynamo)
  await docker(['network', 'create', '--internal', dynamoNetwork])
  await docker([
    'run',
    '-d',
    '--name',
    dynamo,
    '--network',
    dynamoNetwork,
    'amazon/dynamodb-local:2.6.1',
    '-jar',
    'DynamoDBLocal.jar',
    '-inMemory',
    '-sharedDb',
  ])
  const dynamoPort = await publishAdminPort(
    dynamo,
    8000,
    dynamoNetwork,
    resources,
  )
  identity = await provisionPostgres(admin, {
    runId: runId.slice(0, 16),
    actor,
    template: 'mh_template',
  })
  const snapshotSql = postgres({
    host: '127.0.0.1',
    port: pgPort,
    username: 'postgres',
    password,
    database: identity.database,
    max: 1,
  })
  resources.push(() => snapshotSql.end({ timeout: 1 }))
  await snapshotSql.unsafe(`GRANT USAGE ON SCHEMA eql_v3 TO "${identity.role}"`)
  await snapshotSql.unsafe(
    `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v3 TO "${identity.role}"`,
  )
  await snapshotSql.unsafe(
    `GRANT USAGE ON SCHEMA eql_v3_internal TO "${identity.role}"`,
  )
  await snapshotSql.unsafe(
    `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v3_internal TO "${identity.role}"`,
  )
  const env = {
    DATABASE_URL: `postgresql://${identity.role}:${identity.password}@127.0.0.1:5432/${identity.database}`,
    HARNESS_DYNAMO_URL: 'http://127.0.0.1:8000',
    HARNESS_TABLE: 'customers',
  }
  return {
    env,
    async verify() {
      const own = postgres({
        host: '127.0.0.1',
        port: pgPort,
        username: identity.role,
        password: identity.password,
        database: identity.database,
        max: 1,
      })
      const canary = `${identity.database}_denied`
      await admin.unsafe(`CREATE DATABASE "${canary}"`)
      await admin.unsafe(`REVOKE CONNECT ON DATABASE "${canary}" FROM PUBLIC`)
      try {
        await own.unsafe(
          'CREATE TABLE public.__harness_ownership_probe (id integer, email public.eql_v3_text_eq, age public.eql_v3_integer_eq, notes public.eql_v3_text)',
        )
        const [owner] =
          await own`SELECT tableowner FROM pg_tables WHERE tablename = '__harness_ownership_probe'`
        if (owner.tableowner !== identity.role)
          throw Error('Application role does not own created table')
        await own.unsafe('DROP TABLE public.__harness_ownership_probe')
        await own.unsafe(
          'SELECT eql_v3.eq(NULL::public.eql_v3_integer_eq, NULL::eql_v3.query_integer_eq)',
        )
        const other = postgres({
          host: '127.0.0.1',
          port: pgPort,
          username: identity.role,
          password: identity.password,
          database: canary,
          max: 1,
          connect_timeout: 2,
        })
        let denied = false
        try {
          await other`SELECT 1`
        } catch (error) {
          denied =
            error instanceof Error && 'code' in error && error.code === '42501'
        } finally {
          await other.end({ timeout: 1 })
        }
        if (!denied) throw Error('Cross-Run database connection was not denied')
        const logs = await exec('docker', ['logs', pg])
        if (
          !`${logs.stdout}\n${logs.stderr}`.includes(
            `permission denied for database "${canary}"`,
          )
        )
          throw Error('Postgres CONNECT denial has no server-side evidence')
        return {
          ownsApplicationTables: true,
          crossDatabaseConnectDenied: true,
          serverLogConfirmed: true,
        }
      } finally {
        await own.end()
        await admin.unsafe(`DROP DATABASE "${canary}" WITH (FORCE)`)
      }
    },
    forwards: [
      {
        host: '127.0.0.1',
        port: 5432,
        targetHost: pg,
        targetPort: 5432,
        network,
      },
      {
        host: '127.0.0.1',
        port: 8000,
        targetHost: dynamo,
        targetPort: 8000,
        network: dynamoNetwork,
      },
    ],
    async snapshot(pk = 'legacy') {
      const response = await fetch(`http://127.0.0.1:${dynamoPort}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-amz-json-1.0',
          'x-amz-target': 'DynamoDB_20120810.GetItem',
          authorization:
            'AWS4-HMAC-SHA256 Credential=migrationfixture/20261109/us-east-1/dynamodb/aws4_request, SignedHeaders=host;x-amz-date, Signature=0',
          'x-amz-date': '20261109T000000Z',
        },
        body: JSON.stringify({
          TableName: 'customers',
          Key: { pk: { S: pk } },
          ConsistentRead: true,
        }),
      })
      if (!response.ok)
        throw Error(`Dynamo snapshot failed: ${response.status}`)
      return {
        dynamo: await response.json(),
        postgres:
          await snapshotSql`SELECT pk, email::jsonb, age::jsonb, notes::jsonb FROM customers WHERE pk = ${pk}`,
      }
    },
  }
}

/** @param {Resource[]} resources */
export async function disposeStores(resources) {
  for (const resource of [...resources].reverse()) {
    if (typeof resource === 'function') await resource().catch(() => {})
    else await docker(['rm', '-f', '-v', resource]).catch(() => {})
  }
}
