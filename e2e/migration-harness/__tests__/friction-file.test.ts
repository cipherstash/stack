import { execFile, spawn } from 'node:child_process'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { expect, test } from 'vitest'

test('R3 a Friction Log FIFO is rejected without blocking the controller', async () => {
  const output = await mkdtemp(join(tmpdir(), 'harness-friction-fifo-'))
  try {
    await mkdir(join(output, 'migrator'))
    await promisify(execFile)('mkfifo', [
      join(output, 'migrator/friction.json'),
    ])
    const driverUrl = new URL('../run/real-driver.mjs', import.meta.url).href
    // The blocked open runs in a disposable process so a regression cannot
    // strand a libuv worker in the test runner after its timeout.
    const script = `
      import { createRealDriver } from ${JSON.stringify(driverUrl)};
      const driver = createRealDriver({
        id: 'fifo', root: ${JSON.stringify(output)}, output: ${JSON.stringify(output)},
        command: 'true', isolation: {}, credentials: {},
        manifest: { stack: '1.2.1', guideHash: 'guide' }
      });
      try { await driver.friction(); process.stdout.write('accepted'); }
      catch { process.stdout.write('rejected'); }
    `
    const outcome = await new Promise<string>((resolve, reject) => {
      const child = spawn(
        process.execPath,
        ['--input-type=module', '-e', script],
        {
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      )
      let stdout = ''
      let timedOut = false
      const timer = setTimeout(() => {
        timedOut = true
        child.kill('SIGKILL')
      }, 1500)
      child.stdout.on('data', (data) => {
        stdout += data
      })
      child.on('error', (error) => {
        clearTimeout(timer)
        reject(error)
      })
      child.on('close', () => {
        clearTimeout(timer)
        resolve(timedOut ? 'blocked-open' : stdout)
      })
    })
    expect(outcome).toBe('rejected')
  } finally {
    await rm(output, { recursive: true, force: true })
  }
})
