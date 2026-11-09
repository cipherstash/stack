// This entrypoint may run ONLY inside the verified App Host boundary. The
// controller never imports it or the workspace's application in its own process.
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
const { createApp } = await import(
  pathToFileURL(`${process.cwd()}/src/app.mjs`).href
)
const app = await createApp(process.env)
for await (const line of createInterface({ input: process.stdin })) {
  let id
  try {
    const request = JSON.parse(line)
    id = request.id
    if (!methods.has(request.method) || !Array.isArray(request.args))
      throw Error('Invalid App Host request')
    const result = await app[request.method](...request.args)
    process.stdout.write(`${JSON.stringify({ id, result: result ?? null })}\n`)
  } catch (error) {
    process.stdout.write(
      `${JSON.stringify({ id, error: String(error.message ?? error) })}\n`,
    )
  }
}
await app.close()
