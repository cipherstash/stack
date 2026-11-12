import 'dotenv/config'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
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
// HARNESS_LIVE=1 asks for these Runs, so a missing credential fails them
// rather than skipping them silently.
const enabled = process.env.HARNESS_LIVE === '1'
const missing = keys.filter((key) => !process.env[key])
for (const rewrite of [false, true]) {
  test.skipIf(!enabled)(
    `real Run ${rewrite ? 'detects a read rewrite' : 'keeps Legacy Data unchanged through mutations'}`,
    async () => {
      assert.deepEqual(
        missing,
        [],
        `HARNESS_LIVE=1 requires ${keys.join(', ')}`,
      )
      const output = await mkdtemp(resolve(tmpdir(), 'mh-no-rewrite-'))
      const isolation = createIsolation()
      const manifest = { stack: '^1.2.1', guideHash: null }
      const replacement =
        'async get(pk) { if (pk === "legacy") { const customer = await decrypt(await stores.get(pk)); await this.put(customer); }'
      const script = `import {readFile,writeFile} from "node:fs/promises"; const p="src/app.mjs"; let s=await readFile(p,"utf8"); s=s.replace("async get(pk) {", ${JSON.stringify(replacement)}); await writeFile(p,s); await writeFile("friction.json","[]")`
      const tool = rewrite
        ? `node --input-type=module -e '${script}'`
        : `printf '[]' > friction.json`
      const adapter = resolve(output, 'adapter.mjs')
      await (await import('node:fs/promises')).writeFile(
        adapter,
        `
        import {createInterface} from 'node:readline';
        const lines=createInterface({input:process.stdin});
        console.log(JSON.stringify({id:'fake',method:'exec',command:['sh','-c',${JSON.stringify(tool)}]}));
        for await(const line of lines){ const response=JSON.parse(line); process.exitCode=response.result.exitCode; break; }
        lines.close();
      `,
      )
      const command = `node '${adapter}'`
      const driver = createRealDriver({
        // Store names use the first eight characters, so they must vary per Run.
        id: randomUUID(),
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
