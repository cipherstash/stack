// This entrypoint may run ONLY inside the verified App Host boundary. The
// controller never imports it or the workspace's application in its own process.
// `node app-host.mjs migrate` instead runs the workspace's one-off conversion
// entry point, `src/migrate.mjs` `migrate(env)`, once and exits: zero when it
// resolves, non-zero when it throws or refuses.
import { createInterface } from 'node:readline'
import { pathToFileURL } from 'node:url'

const methods = new Set([
  'put',
  'get',
  'findEmail',
  'findEmailLower',
  'findAge',
  'findBalance',
  'findActive',
  'setActive',
  'copyToPostgres',
  'getPostgres',
  'findPostgresEmail',
  'findPostgresAge',
  'copyToDynamo',
  'close',
])
const mode = process.argv[2] ?? 'serve'
if (!['serve', 'migrate'].includes(mode)) throw Error('Unknown App Host mode')
if (mode === 'migrate') {
  const { migrate } = await import(
    pathToFileURL(`${process.cwd()}/src/migrate.mjs`).href
  )
  if (typeof migrate !== 'function')
    throw Error('src/migrate.mjs must export migrate(env)')
  await migrate(process.env)
  // A conversion that leaves a pool open must not hold the Oracle until timeout.
  process.exit(0)
} else {
  const { createApp } = await import(
    pathToFileURL(`${process.cwd()}/src/app.mjs`).href
  )
  const { createStores } = await import(
    pathToFileURL(`${process.cwd()}/src/stores.mjs`).href
  )
  const stores = await createStores(process.env)
  try {
    await stores.init()
  } finally {
    await stores.close()
  }
  const app = await createApp(process.env)
  for await (const line of createInterface({ input: process.stdin })) {
    let id
    try {
      const request = JSON.parse(line)
      id = request.id
      if (!methods.has(request.method) || !Array.isArray(request.args))
        throw Error('Invalid App Host request')
      const result = await app[request.method](...request.args)
      process.stdout.write(
        `${JSON.stringify({ id, result: result ?? null })}\n`,
      )
    } catch (error) {
      process.stdout.write(
        `${JSON.stringify({ id, error: error instanceof Error ? error.message : String(error) })}\n`,
      )
    }
  }
  await app.close()
}
