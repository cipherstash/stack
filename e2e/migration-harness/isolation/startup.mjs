// Immutable image code, run under the same UID, namespace and observer before
// any dependency script or application command. Contains synthetic probes only.

import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'

for (const name of [
  'HARNESS_CONFIG',
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'HARNESS_MODEL_CANARY',
]) {
  if (process.env[name])
    throw Error(`Host credential/configuration leaked: ${name}`)
}
for (const path of [
  '/trace/canary',
  '/var/run/docker.sock',
  '/forwards/0.sock',
]) {
  let obtained = false
  try {
    fs.readFileSync(path)
    obtained = true
  } catch {}
  if (obtained) throw Error(`Startup probe obtained protected content: ${path}`)
}
async function denied(host, port) {
  await new Promise((resolve, reject) => {
    const socket = net.connect({ host, port })
    socket.once('connect', () => {
      socket.destroy()
      reject(Error('Forbidden listener reached'))
    })
    socket.once('error', () => resolve())
    socket.setTimeout(1000, () => {
      socket.destroy()
      reject(Error('Network probe had no enforcement result'))
    })
  })
}
await denied('198.51.100.1', 443)
await denied('127.0.0.1', 65534)
// Exercise descendant lifecycle-script tracing with the same observer.
fs.mkdirSync('/tmp/harness-startup', { recursive: true })
fs.writeFileSync(
  '/tmp/harness-startup/package.json',
  JSON.stringify({
    scripts: {
      probe:
        "node -e \"try { require('fs').readFileSync('/trace/canary'); process.exit(1) } catch {}\"",
    },
  }),
)
const child = spawnSync(
  'npm',
  ['--prefix', '/tmp/harness-startup', 'run', 'probe', '--silent'],
  {
    env: { ...process.env, npm_config_update_notifier: 'false' },
    stdio: 'pipe',
  },
)
if (child.status !== 0)
  throw Error(`Lifecycle startup probe failed: ${child.stderr}`)
