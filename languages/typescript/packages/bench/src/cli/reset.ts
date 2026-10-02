import { connect } from '../harness/db.js'

async function main() {
  const client = await connect()
  try {
    await client.query('DROP TABLE IF EXISTS bench')
    console.log('[bench:reset] dropped bench table')
  } finally {
    await client.end()
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
