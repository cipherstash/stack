import { createIsolation } from '../isolation.mjs'

const isolation = createIsolation()
try {
  console.log(JSON.stringify(await isolation.prove(), null, 2))
} finally {
  await isolation.stop()
}
