import { spawn } from 'node:child_process'
import { mkdtemp, chmod, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createInterface } from 'node:readline'
import { randomUUID } from 'node:crypto'

const here = dirname(fileURLToPath(import.meta.url))
const image = 'cipherstash-migration-isolation:local'
const infrastructure = (message) => Object.assign(Error(message), { infrastructure: true })

function command(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'], ...options })
    let stdout = '', stderr = ''
    child.stdout.on('data', data => { stdout += data })
    child.stderr.on('data', data => { stderr += data })
    child.on('error', reject)
    child.on('close', exitCode => resolve({ exitCode, stdout, stderr }))
  })
}

/** Linux Docker namespaces enforce the boundary; a root-owned ptrace observer
 * produces events on a channel separate from every actor's output. No socket
 * giving access to the Docker daemon is mounted in the actor container.
 */
export function createIsolation({ onEvent = (_event) => {} } = {}) {
  const events = []
  const active = new Set()
  let proven = false, fatal = null
  async function start({ actor, workspace, env = {}, command: argv, forwards = [], probe = false, canary = null, timeoutMs = 40 * 60 * 1000 }) {
    if ((!proven && !probe) || fatal) throw fatal ?? infrastructure('Isolation capability proof has not passed')
    const dir = await mkdtemp(join(tmpdir(), 'migration-isolation-'))
    await chmod(dir, 0o755)
    const name = `migration-${randomUUID()}`
    const volume = `${name}-forwards`
    const relays = []
    const mapped = []
    const created = await command(['volume', 'create', volume])
    if (created.exitCode) throw infrastructure(`Cannot create isolated forwarder volume: ${created.stderr}`)
    const release = async () => {
      await Promise.all(relays.map(relay => command(["rm", "-f", relay])))
      await command(["volume", "rm", volume])
      await rm(dir, { recursive: true, force: true })
    }
    try {
    for (const [index, forward] of forwards.entries()) {
      const address = forward.host === '127.0.0.1' ? '127.0.0.1' : `127.0.0.${index + 2}`
      const relay = `${name}-relay-${index}`
      const target = ['127.0.0.1', 'localhost'].includes(forward.targetHost) ? 'host.docker.internal' : forward.targetHost
      const started = await command(['run', '-d', '--rm', '--name', relay,
        '--add-host', 'host.docker.internal:host-gateway', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--read-only',
        '--mount', `type=volume,src=${volume},dst=/forwards`, '--entrypoint', 'socat', image,
        `UNIX-LISTEN:/forwards/${index}.sock,fork,mode=600`, `TCP:${target}:${forward.targetPort}`])
      if (started.exitCode) throw infrastructure(`Cannot start assigned forwarder: ${started.stderr}`)
      relays.push(relay)
      const ready = await command(['exec', relay, 'sh', '-c', `for i in 1 2 3 4 5; do test -S /forwards/${index}.sock && exit 0; sleep 0.1; done; exit 1`])
      if (ready.exitCode) throw infrastructure('Assigned forwarder failed startup')
      mapped.push({ ...forward, address, index })
    }
    } catch (error) { await release(); throw error }
    const config = Buffer.from(JSON.stringify({ actor, env, command: argv, forwards: mapped, uid: process.getuid() || 65534, gid: process.getgid() || 65534 })).toString('base64')
    const args = ['run', '--rm', '--name', name, '-i', '--network', 'none', '--read-only',
      '--cap-drop', 'ALL', '--cap-add', 'SYS_PTRACE', '--cap-add', 'DAC_READ_SEARCH', '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--cap-add', 'SETPCAP',
      '--security-opt', 'no-new-privileges', '--pids-limit', '256', '--memory', '1g',
      '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777', '--tmpfs', '/trace:rw,nosuid,nodev,size=64m,mode=700',
      '--mount', `type=bind,src=${workspace},dst=/workspace`,
      '--mount', `type=volume,src=${volume},dst=/forwards,readonly`,
      '--mount', `type=bind,src=${join(here, 'run/app-host.mjs')},dst=/harness/app-host.mjs,readonly`,
      '-e', `HARNESS_CONFIG=${config}`]
    for (const forward of mapped) if (forward.host !== '127.0.0.1') args.push('--add-host', `${forward.host}:${forward.address}`)
    if (canary) args.push('--mount', `type=bind,src=${canary},dst=/protected-canary,readonly`)
    args.push(image)
    const child = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = '', stderr = '', streamEnded = false, exitCode, failure
    let onOutput = (_text) => {}
    const stop = () => command(['kill', name]).catch(() => {})
    let timedOut = false
    const timer = setTimeout(() => { timedOut = true; void stop() }, timeoutMs)
    const running = { stop }
    active.add(running)
    const completion = new Promise((resolve, reject) => {
      child.on('error', reject)
      child.stderr.on('data', data => { stderr += data })
      createInterface({ input: child.stdout }).on('line', line => {
        try {
          const frame = JSON.parse(line)
          if (frame.kind === 'event') {
            events.push(frame.event)
            onEvent(frame.event)
            if (frame.event.decision === 'forbidden' && frame.event.result === 'success') {
              fatal = infrastructure('Successful forbidden access stopped the isolated actor')
              for (const actorProcess of active) if (actorProcess !== running) void actorProcess.stop()
            }
          } else if (frame.kind === 'stdout') {
            const text = Buffer.from(frame.data, 'base64').toString()
            stdout += text
            onOutput(text)
          } else if (frame.kind === 'stderr') stderr += Buffer.from(frame.data, 'base64').toString()
          else if (frame.kind === 'stream-end') streamEnded = true
          else if (frame.kind === 'stream-error') failure = infrastructure(frame.error)
          else if (frame.kind === 'exit') exitCode = frame.exitCode
          else throw Error('Unknown supervisor frame')
        } catch (error) { failure = infrastructure(`Invalid trusted event stream: ${error.message}`); void stop() }
      })
      child.on('close', async code => {
        clearTimeout(timer)
        active.delete(running)
        await release()
        if (timedOut) { resolve({ exitCode: 124, stdout, stderr, timedOut }); return }
        if (!streamEnded || exitCode === undefined) failure ??= infrastructure(`Broken trusted event stream (Docker exit ${code}): ${stderr}`)
        if (failure) { failure.message += `: ${stderr}; last forbidden event: ${JSON.stringify(events.filter(event => event.decision === "forbidden").at(-1))}`; fatal = failure; reject(failure) }
        else resolve({ exitCode, stdout, stderr })
      })
    })
    return { child, completion, stop, setOutput(callback) { onOutput = callback } }
  }
  const backend = {
    id: 'docker-linux-network-none-root-ptrace-v1',
    async prove() {
      const build = await command(['build', '-t', image, join(here, 'isolation')])
      if (build.exitCode !== 0) throw infrastructure(`Isolation image build failed: ${build.stderr}`)
      const workspace = await mkdtemp(join(here, '.migration-probe-'))
      await chmod(workspace, 0o777)
      const canary = join(workspace, 'canary')
      await writeFile(canary, 'SYNTHETIC-NOT-A-SECRET')
      await chmod(canary, 0o644)
      try {
        const actor = 'startup-probe'
        const probe = await start({ actor, workspace, probe: true, command: ['node', '-e',
          "const fs=require('fs'); try{fs.readFileSync('/trace/events')}catch{}; try{fs.readFileSync('/var/run/docker.sock')}catch{}; console.log('probe-ready')"] })
        probe.child.stdin.end()
        const result = await probe.completion
        if (result.exitCode !== 0 || !result.stdout.includes('probe-ready') || !events.some(event => event.actor === actor && event.result === 'denied')) throw infrastructure(`Filesystem denial or trusted stream startup probe failed: ${JSON.stringify(result)}; events ${events.length}`)
        const mismatch = await start({ actor: 'policy-mismatch-probe', workspace, probe: true, canary,
          command: ['node', '-e', "require('fs').readFileSync('/protected-canary'); setTimeout(()=>console.log('later-call'),1000)"] })
        mismatch.child.stdin.end()
        const mismatchResult = await mismatch.completion
        if (!events.some(event => event.actor === 'policy-mismatch-probe' && event.resource === '/protected-canary' && event.decision === 'forbidden' && event.result === 'success') || mismatchResult.exitCode === 0) throw infrastructure(`Supervisor mismatch/termination probe failed: ${JSON.stringify(mismatchResult)}; ${JSON.stringify(events.filter(event => event.actor === 'policy-mismatch-probe' && (event.resource.includes('protected') || event.decision === 'forbidden')))}`)
        let laterBlocked = false
        try { await start({ actor: 'later-call', workspace, probe: true, command: ['true'] }) } catch { laterBlocked = true }
        if (!laterBlocked) throw infrastructure('Supervisor permitted a call after a forbidden-access event')
        fatal = null
        events.length = 0
        proven = true
        return { backend: backend.id, verified: true, policies: { filesystem: "workspace-and-runtime-only", network: "namespace-local-forwarders-only" } }
      } finally { await rm(workspace, { recursive: true, force: true }) }
    },
    async exec(options) {
      const process = await start(options)
      process.child.stdin.end()
      return process.completion
    },
    async openAppHost(options) {
      const process = await start({ ...options, actor: options.actor ?? 'app-host', command: ['node', '/harness/app-host.mjs'] })
      const pending = new Map()
      let buffer = '', serial = 0
      process.setOutput(text => {
        buffer += text
        while (buffer.includes('\n')) {
          const end = buffer.indexOf('\n'), line = buffer.slice(0, end)
          buffer = buffer.slice(end + 1)
          try {
            const message = JSON.parse(line), request = pending.get(message.id)
            if (!request) continue
            pending.delete(message.id)
            if (message.error) request.reject(Error(message.error))
            else request.resolve(message.result)
          } catch { /* Application logging is untrusted diagnostic output. */ }
        }
      })
      process.completion.then(result => {
        for (const request of pending.values()) request.reject(Error(`App Host exited ${result.exitCode}: ${result.stderr}`))
        pending.clear()
      }, error => { for (const request of pending.values()) request.reject(error); pending.clear() })
      return {
        call(method, args = []) {
          if (fatal) return Promise.reject(fatal)
          return new Promise((resolve, reject) => {
            const id = ++serial
            pending.set(id, { resolve, reject })
            process.child.stdin.write(`${JSON.stringify({ id, method, args })}\n`)
          })
        },
        async close() { process.child.stdin.end(); return process.completion },
      }
    },
    drain() { if (fatal && !events.some(event => event.decision === 'forbidden' && event.result === 'success')) throw fatal; return events.splice(0) },
    async stop() { await Promise.all([...active].map(process => process.stop())) },
  }
  return backend
}
