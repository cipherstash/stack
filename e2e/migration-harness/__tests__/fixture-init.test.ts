import { spawn } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test } from 'vitest'

test('D6 App Host initializes assigned stores before calling the unchanged application', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'harness-init-'))
  await mkdir(join(workspace, 'src'))
  await writeFile(
    join(workspace, 'src/stores.mjs'),
    `let ready = false; export async function createStores() { return { init: async () => { ready = true }, close: async () => {} } }; export function isReady() { return ready }`,
  )
  await writeFile(
    join(workspace, 'src/app.mjs'),
    `import {isReady} from './stores.mjs'; export async function createApp() { return { put: async () => { if (!isReady()) throw Error('application tables do not exist'); return 'stored' }, close: async () => {} } }`,
  )
  try {
    const output = await new Promise<string>((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [fileURLToPath(new URL('../run/app-host.mjs', import.meta.url))],
        { cwd: workspace, stdio: ['pipe', 'pipe', 'pipe'] },
      )
      let stdout = '',
        stderr = ''
      child.stdout.on('data', (data) => {
        stdout += data
      })
      child.stderr.on('data', (data) => {
        stderr += data
      })
      child.on('error', reject)
      child.on('close', (code) =>
        code === 0 ? resolve(stdout) : reject(Error(stderr)),
      )
      child.stdin.end(
        `${JSON.stringify({ id: 1, method: 'put', args: [{ pk: 'legacy' }] })}\n`,
      )
    })
    expect(JSON.parse(output)).toEqual({ id: 1, result: 'stored' })
  } finally {
    await rm(workspace, { recursive: true, force: true })
  }
})
