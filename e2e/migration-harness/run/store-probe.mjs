import { randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { createStoreSet, disposeStores } from './real-stores.mjs'

const resources = []
try {
  const stores = await createStoreSet({
    runId: randomUUID(),
    actor: 'oracle',
    eqlBundle: fileURLToPath(
      new URL(
        '../../../packages/eql/packages/eql/sql/cipherstash-encrypt.sql',
        import.meta.url,
      ),
    ),
    resources,
  })
  console.log(JSON.stringify(await stores.verify()))
} finally {
  await disposeStores(resources)
}
