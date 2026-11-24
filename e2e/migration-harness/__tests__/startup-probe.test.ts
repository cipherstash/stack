import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { expect, test } from 'vitest'

const exec = promisify(execFile)
const startup = fileURLToPath(
  new URL('../isolation/startup.mjs', import.meta.url),
)
const targets = JSON.stringify(
  [32884, 32885, 32886, 32887].map((port) => ({ host: '127.0.0.1', port })),
)

// Run the production startup probe, replacing only net.connect. Each entry of
// `script` decides one connection attempt: 'refused', 'self' (the socket is
// connected to itself) or 'listener' (a different endpoint answered).
async function probe(script: string[]) {
  const preload = `
    import net from 'node:net'
    import { EventEmitter } from 'node:events'
    const script = ${JSON.stringify(script)}
    let attempt = 0
    net.connect = ({ host, port }) => {
      const outcome = script[Math.min(attempt++, script.length - 1)]
      const socket = new EventEmitter()
      socket.destroy = () => {}
      socket.setTimeout = () => {}
      socket.remoteAddress = host
      socket.remotePort = port
      socket.localAddress = host
      socket.localPort = outcome === 'self' ? port : port + 1000
      setImmediate(() =>
        outcome === 'refused'
          ? socket.emit('error', Error('ECONNREFUSED'))
          : socket.emit('connect'),
      )
      return socket
    }
    process.on('exit', () => console.log('attempts=' + attempt))
  `
  const env: Record<string, string | undefined> = {
    ...process.env,
    HARNESS_STARTUP_TARGETS: targets,
  }
  for (const name of [
    'HARNESS_CONFIG',
    'OPENAI_API_KEY',
    'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN',
    'HARNESS_MODEL_CANARY',
  ])
    delete env[name]
  return exec(
    process.execPath,
    [
      '--import',
      `data:text/javascript,${encodeURIComponent(preload)}`,
      startup,
    ],
    { env },
  ).then(
    ({ stdout }) => ({ exitCode: 0, output: stdout }),
    (error) => ({
      exitCode: error.code as number,
      output: `${error.stdout}${error.stderr}`,
    }),
  )
}

test('startup probe retries a connection that reached only itself', async () => {
  const result = await probe(['self', 'refused'])
  expect(result).toMatchObject({ exitCode: 0 })
  // Four targets, and one extra attempt for the self-connection.
  expect(result.output).toContain('attempts=5')
})

test('startup probe fails when a different endpoint answers', async () => {
  const result = await probe(['listener'])
  expect(result.exitCode).not.toBe(0)
  expect(result.output).toContain('Forbidden listener reached')
})

test('startup probe fails when every attempt connects to itself', async () => {
  const result = await probe(['self'])
  expect(result.exitCode).not.toBe(0)
  expect(result.output).toContain('Network probe kept connecting to itself')
  expect(result.output).toContain('attempts=3')
})
