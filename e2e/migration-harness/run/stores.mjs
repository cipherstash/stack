// Admin-only provisioning statements. Application code receives only its own
// role and database, never this connection or the template credentials.
import { randomBytes } from 'node:crypto'
export async function provisionPostgres(admin, { runId, actor, template }) {
  const suffix = `${runId.replace(/[^a-z0-9]/gi, '').toLowerCase()}_${actor}`
  if (!/^[a-z0-9_]{1,48}$/.test(suffix) || !/^[a-z0-9_]+$/.test(template))
    throw Error('Invalid Store Set identity')
  const role = `mh_${suffix}`
  const password = randomBytes(24).toString('hex')
  const identifier = (value) => `"${value}"`
  await admin.unsafe(
    `CREATE ROLE ${identifier(role)} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`,
  )
  try {
    // Shared maintenance/template databases must be locked down during server setup.
    const databases =
      await admin`SELECT datname FROM pg_database WHERE datallowconn`
    for (const { datname } of databases)
      await admin.unsafe(
        `REVOKE CONNECT ON DATABASE ${identifier(datname.replaceAll('"', '""'))} FROM PUBLIC`,
      )
    await admin.unsafe(
      `CREATE DATABASE ${identifier(role)} WITH TEMPLATE ${identifier(template)} OWNER ${identifier(role)}`,
    )
    await admin.unsafe(
      `REVOKE CONNECT ON DATABASE ${identifier(role)} FROM PUBLIC`,
    )
    await admin.unsafe(
      `GRANT CONNECT, CREATE ON DATABASE ${identifier(role)} TO ${identifier(role)}`,
    )
    return { database: role, role, password }
  } catch (error) {
    await admin
      .unsafe(`DROP DATABASE IF EXISTS ${identifier(role)} WITH (FORCE)`)
      .catch(() => {})
    await admin
      .unsafe(`DROP ROLE IF EXISTS ${identifier(role)}`)
      .catch(() => {})
    throw error
  }
}
