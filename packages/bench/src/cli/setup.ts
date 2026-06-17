import { buildBench, teardownBench } from '../drizzle/setup.js'
import { applySchema } from '../harness/db.js'
import { seed } from '../harness/seed.js'

async function main() {
  const handle = await buildBench()
  try {
    console.log('[bench:setup] applying schema')
    await applySchema(handle.pgClient)

    console.log('[bench:setup] seeding')
    const result = await seed(handle)
    console.log(`[bench:setup] done: ${JSON.stringify(result)}`)
  } finally {
    await teardownBench(handle)
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
