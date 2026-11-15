import postgres from 'postgres'
import { createExample } from './postgres.ts'

const command = process.argv[2]
if (!['seed', 'migrate', 'verify', 'write', 'rollback'].includes(command)) {
  throw new Error(
    'Usage: npm run postgres -- seed|migrate|verify|write|rollback',
  )
}
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required')
const sql = postgres(process.env.DATABASE_URL, { prepare: false })
try {
  const app = await createExample(sql, 'protect_upgrade_example')
  if (command === 'seed') {
    await app.seed()
    console.log(
      'Seeded three Protect-written v2 rows. Legacy equality matches:',
      (await app.find('v2', 'age', 36)).length,
    )
  } else if (command === 'migrate') {
    await app.migrate()
    console.log(
      'Verified v3 target columns committed; v2 source columns retained.',
    )
  } else if (command === 'verify') {
    // Do not print plaintext or ciphertext from a customer's test data.
    console.log('Readable v3 rows:', (await app.read('v3')).length)
    console.log(
      'Expected example age matches:',
      (await app.find('v3', 'age', 36)).length,
    )
  } else if (command === 'write') {
    await app.write()
    console.log('Wrote a new v3-only row. Simple rollback is now refused.')
  } else {
    await app.rollback()
    console.log(
      'Removed unchanged target columns; legacy reads remain available.',
    )
  }
} finally {
  await sql.end()
}
