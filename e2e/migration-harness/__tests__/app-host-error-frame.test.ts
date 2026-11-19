import { spawn } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { expect, test } from 'vitest'

const appHost = fileURLToPath(new URL('../run/app-host.mjs', import.meta.url))

// The App Host is the RPC boundary: safePostgresCause classifies an application
// failure by its SQLSTATE, so the frame must carry an allowlisted code.
test('App Host error frames carry an allowlisted error code and drop any other', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'mh-app-host-frame-'))
  try {
    await mkdir(join(workspace, 'src'))
    await writeFile(
      join(workspace, 'src/stores.mjs'),
      'export async function createStores() { return { init: async () => {}, close: async () => {} } }\n',
    )
    await writeFile(
      join(workspace, 'src/app.mjs'),
      `export async function createApp() {
  return {
    get: async (code) => { throw Object.assign(Error('application failure'), { code }) },
    close: async () => {},
  }
}
`,
    )
    const child = spawn(process.execPath, [appHost], {
      cwd: workspace,
      stdio: ['pipe', 'pipe', 'inherit'],
    })
    const lines = createInterface({ input: child.stdout })[
      Symbol.asyncIterator
    ]()
    const call = async (id: number, code: string) => {
      child.stdin.write(
        `${JSON.stringify({ id, method: 'get', args: [code] })}\n`,
      )
      const { value } = await lines.next()
      return JSON.parse(String(value))
    }
    expect(await call(1, '42P01')).toEqual({
      id: 1,
      error: 'application failure',
      code: '42P01',
    })
    expect(await call(2, 'ECONNRESET')).toMatchObject({ code: 'ECONNRESET' })
    expect(await call(3, 'ada@example.com')).toEqual({
      id: 3,
      error: 'application failure',
    })
    child.stdin.end()
    await new Promise((resolve) => child.on('close', resolve))
  } finally {
    await rm(workspace, { recursive: true, force: true })
  }
})
