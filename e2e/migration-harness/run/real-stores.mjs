import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { promisify } from 'node:util'
import postgres from 'postgres'
import { provisionPostgres } from './stores.mjs'

const exec = promisify(execFile)
export async function docker(args) {
  return (
    await exec('docker', args, { maxBuffer: 16 * 1024 * 1024 })
  ).stdout.trim()
}

// Runs in an Iteration share one server per actor; databases and roles remain per Run.
const sharedServers = new Map()
async function initializePostgres(actor, eqlBundle) {
  const password = randomBytes(24).toString('hex')
  const pg = `mh-pg-${randomBytes(8).toString('hex')}-${actor}`
  let admin
  try {
    await docker([
      'run',
      '-d',
      '--name',
      pg,
      '-e',
      `POSTGRES_PASSWORD=${password}`,
      '--tmpfs',
      '/var/lib/postgresql/data:rw,nosuid,nodev,size=512m',
      '-p',
      '127.0.0.1::5432',
      'postgres:17-alpine',
    ])
    const pgPort = Number(
      (await docker(['port', pg, '5432/tcp'])).split(':').at(-1),
    )
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
        readinessError = error.code ?? error.message
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
    return { pg, pgPort, password, admin, leases: 0 }
  } catch (error) {
    if (admin) await admin.end({ timeout: 1 }).catch(() => {})
    await docker(['rm', '-f', '-v', pg]).catch(() => {})
    throw error
  }
}

/** Harness-only store administration; none of these handles enters an actor. */
export async function createStoreSet({ runId, actor, eqlBundle, resources }) {
  if (!sharedServers.has(actor))
    sharedServers.set(actor, initializePostgres(actor, eqlBundle))
  const pending = sharedServers.get(actor)
  let shared
  try {
    shared = await pending
  } catch (error) {
    sharedServers.delete(actor)
    throw error
  }
  const { pg, pgPort, password, admin } = shared
  shared.leases++
  let identity
  resources.push(async () => {
    if (identity) {
      await admin.unsafe(
        `DROP DATABASE IF EXISTS "${identity.database}" WITH (FORCE)`,
      )
      await admin.unsafe(`DROP ROLE IF EXISTS "${identity.role}"`)
    }
    shared.leases--
    if (!shared.leases) {
      sharedServers.delete(actor)
      await admin.end({ timeout: 1 })
      await docker(['rm', '-f', '-v', pg])
    }
  })
  const dynamo = `mh-dynamo-${runId.slice(0, 8)}-${actor}`
  resources.push(dynamo)
  await docker([
    'run',
    '-d',
    '--name',
    dynamo,
    '-p',
    '127.0.0.1::8000',
    'amazon/dynamodb-local:2.6.1',
    '-jar',
    'DynamoDBLocal.jar',
    '-inMemory',
    '-sharedDb',
  ])
  const dynamoPort = Number(
    (await docker(['port', dynamo, '8000/tcp'])).split(':').at(-1),
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
          'CREATE TABLE public.__harness_ownership_probe (id integer)',
        )
        const [owner] =
          await own`SELECT tableowner FROM pg_tables WHERE tablename = '__harness_ownership_probe'`
        if (owner.tableowner !== identity.role)
          throw Error('Application role does not own created table')
        await own.unsafe('DROP TABLE public.__harness_ownership_probe')
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
          denied = error.code === '42501'
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
        targetHost: '127.0.0.1',
        targetPort: pgPort,
      },
      {
        host: '127.0.0.1',
        port: 8000,
        targetHost: '127.0.0.1',
        targetPort: dynamoPort,
      },
    ],
    async snapshot() {
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
          Key: { pk: { S: 'legacy' } },
          ConsistentRead: true,
        }),
      })
      if (!response.ok)
        throw Error(`Dynamo snapshot failed: ${response.status}`)
      return {
        dynamo: await response.json(),
        postgres:
          await snapshotSql`SELECT pk, email::jsonb, age::jsonb, notes::jsonb FROM customers WHERE pk = 'legacy'`,
      }
    },
  }
}

export async function disposeStores(resources) {
  for (const resource of [...resources].reverse()) {
    if (typeof resource === 'function') await resource().catch(() => {})
    else await docker(['rm', '-f', '-v', resource]).catch(() => {})
  }
}
