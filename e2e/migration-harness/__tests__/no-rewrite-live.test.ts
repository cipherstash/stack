import 'dotenv/config'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'vitest'
import { createIsolation } from '../isolation.mjs'
import { createRealDriver } from '../run/real-driver.mjs'
import { run } from '../run/run.mjs'

const keys = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
  'CS_CLIENT_ACCESS_KEY',
]
const enabled =
  process.env.HARNESS_LIVE === '1' && keys.every((key) => process.env[key])
for (const rewrite of [false, true]) {
  test.skipIf(!enabled)(
    `real Run ${rewrite ? 'detects a read rewrite' : 'keeps Legacy Data unchanged through mutations'}`,
    async () => {
      const output = await mkdtemp(resolve(tmpdir(), 'mh-no-rewrite-'))
      const isolation = createIsolation()
      const manifest = { stack: '^1.2.1', guideHash: null }
      const replacement =
        'async get(pk) { if (pk === "legacy") { const customer = await decrypt(await stores.get(pk)); await this.put(customer); }'
      const script = `import {readFile,writeFile} from "node:fs/promises"; const p="src/app.mjs"; let s=await readFile(p,"utf8"); s=s.replace("async get(pk) {", ${JSON.stringify(replacement)}); await writeFile(p,s); await writeFile("friction.json","[]")`
      const command = rewrite
        ? `node --input-type=module -e '${script}'`
        : `printf '[]' > friction.json`
      const driver = createRealDriver({
        id: `live-${Date.now()}-${rewrite}`,
        root: fileURLToPath(new URL('../../..', import.meta.url)),
        output,
        command,
        isolation,
        credentials: Object.fromEntries(
          keys.map((key) => [key, process.env[key] ?? '']),
        ),
        manifest,
      })
      try {
        const report = await run({
          id: 'live-no-rewrite',
          manifest,
          driver,
          supervision: isolation,
        })
        const check = report.evidence.find(
          (e) => e.checkId === 'no-rewrite.legacy-bytes',
        )
        assert.ok(check, JSON.stringify(report))
        assert.equal(Object(check.payload).passed, !rewrite)
        if (rewrite)
          assert.match(JSON.stringify(check.payload), /legacy.*__source/)
      } finally {
        await driver.close()
        await rm(output, { recursive: true, force: true })
      }
    },
    600_000,
  )
}
