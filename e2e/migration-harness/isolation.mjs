import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { StringDecoder } from 'node:string_decoder'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const image = 'cipherstash-migration-isolation:local'
/** @param {string} message */
const infrastructure = (message) =>
  Object.assign(Error(message), { infrastructure: true })
/** @param {import('./types.js').AccessEvent} event */
const isBreach = (event) =>
  event.decision === 'forbidden' && event.result === 'success'

/** @param {string[]} args @returns {Promise<{exitCode:number|null,stdout:string,stderr:string}>} */
function command(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = '',
      stderr = ''
    child.stdout.on('data', (data) => {
      stdout += data
    })
    child.stderr.on('data', (data) => {
      stderr += data
    })
    child.on('error', reject)
    child.on('close', (exitCode) => resolve({ exitCode, stdout, stderr }))
  })
}

/** Linux Docker namespaces enforce the boundary; a root-owned ptrace observer
 * produces events on a channel separate from every actor's output. No socket
 * giving access to the Docker daemon is mounted in the actor container.
 */
/** @param {{onEvent?:(event:import('./types.js').AccessEvent)=>void, limits?:{outputBytes?:number,eventCount?:number,eventBytes?:number,frameBytes?:number}}} options */
export function createIsolation({
  onEvent = (_event) => {},
  limits = {},
} = {}) {
  const budget = {
    outputBytes: 16 * 1024 * 1024,
    eventCount: 250_000,
    eventBytes: 64 * 1024 * 1024,
    // supervise.py emits up to 1 MiB of stderr in one base64 JSON frame.
    frameBytes: 2 * 1024 * 1024,
    ...limits,
  }
  if (
    Object.values(budget).some(
      (value) => !Number.isSafeInteger(value) || value <= 0,
    )
  )
    throw Error('Invalid isolation evidence limits')
  let retainedEventBytes = 0
  let retainedEventCount = 0
  /** @type {import('./types.js').AccessEvent[]} */
  const events = []
  /** @type {Set<{stop:(options?:{expected?:boolean})=>Promise<unknown>,settled:()=>Promise<unknown>}>} */
  const active = new Set()
  /** @type {string[]} */
  const proofContainers = []
  /** @type {string|null} */
  let proofNetwork = null
  /** @type {Array<{host:string,port:number}>} */
  const forbiddenTargets = []
  /** @type {Error|null} */
  let fatal = null
  let proven = false
  /** @param {import('./types.js').IsolationOptions} options */
  async function start({
    actor,
    workspace,
    env = {},
    command: argv,
    forwards = [],
    probe = false,
    canary = null,
    timeoutMs = 40 * 60 * 1000,
    testKillTracer = false,
  }) {
    if ((!proven && !probe) || fatal)
      throw fatal ?? infrastructure('Isolation capability proof has not passed')
    const dir = await mkdtemp(join(tmpdir(), 'migration-isolation-'))
    await chmod(dir, 0o755)
    const name = `migration-${randomUUID()}`
    const volume = `${name}-forwards`
    /** @type {string[]} */
    const relays = []
    const mapped = []
    const created = await command(['volume', 'create', volume])
    if (created.exitCode)
      throw infrastructure(
        `Cannot create isolated forwarder volume: ${created.stderr}`,
      )
    const release = async () => {
      await Promise.all(relays.map((relay) => command(['rm', '-f', relay])))
      await command(['volume', 'rm', volume])
      await rm(dir, { recursive: true, force: true })
    }
    try {
      for (const [index, forward] of forwards.entries()) {
        const address =
          forward.host === '127.0.0.1' ? '127.0.0.1' : `127.0.0.${index + 2}`
        const relay = `${name}-relay-${index}`
        const target = forward.targetHost
        if (['127.0.0.1', 'localhost'].includes(target))
          throw infrastructure(
            'Store forwarders require a private Docker network target',
          )
        const started = await command([
          'run',
          '-d',
          '--rm',
          '--name',
          relay,
          '--network',
          forward.network ?? 'bridge',
          '--cap-drop',
          'ALL',
          '--security-opt',
          'no-new-privileges',
          '--read-only',
          '--mount',
          `type=volume,src=${volume},dst=/forwards`,
          '--entrypoint',
          'socat',
          image,
          `UNIX-LISTEN:/forwards/${index}.sock,fork,mode=600`,
          `TCP:${target}:${forward.targetPort}`,
        ])
        if (started.exitCode)
          throw infrastructure(
            `Cannot start assigned forwarder: ${started.stderr}`,
          )
        relays.push(relay)
        const ready = await command([
          'exec',
          relay,
          'sh',
          '-c',
          `for i in 1 2 3 4 5; do test -S /forwards/${index}.sock && exit 0; sleep 0.1; done; exit 1`,
        ])
        if (ready.exitCode)
          throw infrastructure('Assigned forwarder failed startup')
        mapped.push({ ...forward, address, index })
      }
    } catch (error) {
      await release()
      throw error
    }
    const config = Buffer.from(
      JSON.stringify({
        actor,
        env,
        command: argv,
        forwards: mapped,
        uid: process.getuid?.() || 65534,
        gid: process.getgid?.() || 65534,
        testKillTracer,
        modelCanary: name,
        forbiddenTargets,
      }),
    ).toString('base64')
    const args = [
      'run',
      '--rm',
      '--name',
      name,
      '-i',
      '--network',
      'none',
      '--read-only',
      '--cap-drop',
      'ALL',
      '--cap-add',
      'SYS_PTRACE',
      '--cap-add',
      'DAC_READ_SEARCH',
      '--cap-add',
      'SETUID',
      '--cap-add',
      'SETGID',
      '--cap-add',
      'SETPCAP',
      '--security-opt',
      'no-new-privileges',
      '--pids-limit',
      '256',
      '--memory',
      '1g',
      '--tmpfs',
      '/tmp:rw,nosuid,nodev,size=256m,mode=1777',
      '--tmpfs',
      '/trace:rw,nosuid,nodev,size=64m,mode=700',
      '--mount',
      `type=bind,src=${workspace},dst=/workspace`,
      '--mount',
      `type=volume,src=${volume},dst=/forwards,readonly`,
      '--mount',
      `type=bind,src=${join(here, 'run/app-host.mjs')},dst=/harness/app-host.mjs,readonly`,
      '-e',
      'HARNESS_CONFIG',
      '-e',
      `HARNESS_MODEL_CANARY=${name}`,
    ]
    for (const forward of mapped)
      if (forward.host !== '127.0.0.1')
        args.push('--add-host', `${forward.host}:${forward.address}`)
    if (canary)
      args.push(
        '--mount',
        `type=bind,src=${canary},dst=/protected-canary,readonly`,
      )
    args.push(image)
    const child = spawn('docker', args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, HARNESS_CONFIG: config },
    })
    /** @type {number|undefined} */
    let actorExit
    /** @type {number|undefined} */
    let exitCode
    /** @type {Error|undefined} */
    let failure
    let stdout = '',
      stderr = '',
      streamEnded = false
    /** @type {(text:string)=>void} */
    let onOutput = (_text) => {}
    /** @type {Promise<boolean>|null} */
    let expectedCancellation = null
    /** @param {{expected?:boolean}} options */
    const stop = ({ expected = false } = {}) => {
      const killed = command(['kill', name])
      if (!expected) return killed.catch(() => {})
      expectedCancellation = killed.then(
        (result) => result.exitCode === 0,
        () => false,
      )
      return killed.then((result) => {
        if (result.exitCode !== 0)
          throw infrastructure('Could not cancel isolated actor')
      })
    }
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      void stop()
    }, timeoutMs)
    const running = { stop, settled: () => completion }
    active.add(running)
    /** @type {Promise<import('./types.js').IsolationResult>} */
    const completion = new Promise((resolve, reject) => {
      child.on('error', reject)
      let outputBytes = 0
      let overflowed = false
      /** Stop instead of presenting truncated supervision as complete evidence. */
      function overflow() {
        if (overflowed) return
        overflowed = true
        failure = infrastructure('Isolation output or evidence limit exceeded')
        fatal = failure
        void stop()
      }
      /** @param {string} value */
      function retainOutput(value) {
        outputBytes += Buffer.byteLength(value)
        if (outputBytes > budget.outputBytes) overflow()
        return !overflowed
      }
      child.stderr.on('data', (data) => {
        if (!overflowed && retainOutput(data.toString())) stderr += data
      })
      /** @param {string} line */
      function receive(line) {
        if (overflowed) return
        try {
          const frame = JSON.parse(line)
          if (frame.kind === 'event') {
            retainedEventCount++
            retainedEventBytes += Buffer.byteLength(line)
            if (
              retainedEventCount > budget.eventCount ||
              retainedEventBytes > budget.eventBytes
            ) {
              overflow()
              return
            }
            events.push(frame.event)
            onEvent(frame.event)
            if (isBreach(frame.event)) {
              fatal = infrastructure(
                'Successful forbidden access stopped the isolated actor',
              )
              for (const actorProcess of active)
                if (actorProcess !== running) void actorProcess.stop()
            }
          } else if (frame.kind === 'stdout') {
            const text = Buffer.from(frame.data, 'base64').toString()
            if (retainOutput(text)) {
              stdout += text
              onOutput(text)
            }
          } else if (frame.kind === 'stderr') {
            const text = Buffer.from(frame.data, 'base64').toString()
            if (retainOutput(text)) stderr += text
          } else if (frame.kind === 'actor-exit') {
            if (frame.actor !== actor || !Number.isInteger(frame.exitCode))
              throw Error('Invalid actor exit identity')
            if (frame.stage === 'command') actorExit = frame.exitCode
          } else if (frame.kind === 'stream-end') streamEnded = true
          else if (frame.kind === 'stream-error')
            failure = infrastructure(frame.error)
          else if (frame.kind === 'exit') exitCode = frame.exitCode
          else throw Error('Unknown supervisor frame')
        } catch (error) {
          failure = infrastructure(
            `Invalid trusted event stream: ${error instanceof Error ? error.message : String(error)}`,
          )
          void stop()
        }
      }
      // readline buffers an unterminated frame without a bound. Split incrementally
      // and reject before retaining a frame larger than the trusted protocol permits.
      const decoder = new StringDecoder('utf8')
      let buffer = ''
      child.stdout.on('data', (chunk) => {
        if (overflowed) return
        const text = decoder.write(chunk)
        let offset = 0
        while (offset < text.length && !overflowed) {
          const newline = text.indexOf('\n', offset)
          const end = newline < 0 ? text.length : newline
          const part = text.slice(offset, end)
          if (
            Buffer.byteLength(buffer) + Buffer.byteLength(part) >
            budget.frameBytes
          ) {
            overflow()
            return
          }
          buffer += part
          if (newline < 0) break
          receive(buffer)
          buffer = ''
          offset = newline + 1
        }
      })
      child.stdout.on('end', () => {
        if (!overflowed && buffer) receive(buffer + decoder.end())
      })
      child.on('close', async (code) => {
        clearTimeout(timer)
        active.delete(running)
        await release()
        if (timedOut && !failure) {
          resolve({ exitCode: 124, stdout, stderr, timedOut })
          return
        }
        const cancelled = expectedCancellation
          ? await expectedCancellation
          : false
        const stoppedForBreach = events.some(
          (event) => event.actor === actor && isBreach(event),
        )
        if (
          (!cancelled &&
            (!streamEnded ||
              exitCode === undefined ||
              (!stoppedForBreach && actorExit !== exitCode))) ||
          (!stoppedForBreach &&
            actorExit !== undefined &&
            exitCode !== undefined &&
            actorExit !== exitCode)
        )
          failure ??= infrastructure(
            `Broken trusted event stream (Docker exit ${code}): ${stderr}`,
          )
        if (failure) {
          failure.message += `: ${stderr}; last forbidden event: ${JSON.stringify(events.filter((event) => event.decision === 'forbidden').at(-1))}`
          fatal = failure
          reject(failure)
        } else if (
          cancelled &&
          (!streamEnded || exitCode === undefined || actorExit === undefined)
        )
          resolve({ exitCode: 130, stdout, stderr })
        else if (exitCode !== undefined) resolve({ exitCode, stdout, stderr })
      })
    })
    return {
      child,
      completion,
      stop,
      /** @param {(text:string)=>void} callback */
      setOutput(callback) {
        onOutput = callback
      },
    }
  }
  const backend = {
    id: 'docker-linux-network-none-root-ptrace-v1',
    async prove() {
      const build = await command([
        'build',
        '-t',
        image,
        join(here, 'isolation'),
      ])
      if (build.exitCode !== 0)
        throw infrastructure(`Isolation image build failed: ${build.stderr}`)
      proofNetwork = `migration-proof-${randomUUID()}`
      const network = await command(['network', 'create', proofNetwork])
      if (network.exitCode)
        throw infrastructure('Cannot create capability-probe network')
      for (const role of ['assigned', 'cross-run']) {
        const listener = `${proofNetwork}-${role}`
        const started = await command([
          'run',
          '-d',
          '--rm',
          '--name',
          listener,
          '--network',
          proofNetwork,
          '--cap-drop',
          'ALL',
          '--read-only',
          '--security-opt',
          'no-new-privileges',
          '-p',
          '127.0.0.1::8080',
          '--entrypoint',
          'node',
          image,
          '-e',
          "require('net').createServer(s=>s.end('synthetic-listener-ready')).listen(8080,'0.0.0.0')",
        ])
        if (started.exitCode)
          throw infrastructure(`Cannot create ${role} listener`)
        proofContainers.push(listener)
        const ready = await command([
          'exec',
          listener,
          'node',
          '-e',
          "const n=require('net'); let tries=0; function check(){const s=n.connect(8080,'127.0.0.1'); s.on('data',d=>{if(d.toString()==='synthetic-listener-ready')process.exit(0)}); s.on('error',()=>{if(++tries>50)process.exit(1);setTimeout(check,100)})};check()",
        ])
        if (ready.exitCode)
          throw infrastructure(`${role} canary listener is not live`)
        const inspection = await command([
          'inspect',
          '--format',
          '{{json .NetworkSettings.Networks}}',
          listener,
        ])
        const address = JSON.parse(inspection.stdout)[proofNetwork].IPAddress
        const published = await command(['port', listener, '8080/tcp'])
        const port = Number(published.stdout.trim().split(':').at(-1))
        if (!address || !Number.isInteger(port) || port < 1)
          throw infrastructure('Canary listener identity was not resolved')
        forbiddenTargets.push(
          { host: address, port: 8080 },
          { host: '127.0.0.1', port },
        )
      }
      const workspace = await mkdtemp(join(here, '.migration-probe-'))
      await chmod(workspace, 0o777)
      const canary = join(workspace, 'canary')
      await writeFile(canary, 'SYNTHETIC-NOT-A-SECRET')
      await chmod(canary, 0o644)
      try {
        const gitProbe = await start({
          actor: 'git-tool-probe',
          workspace,
          probe: true,
          command: ['git', '--version'],
        })
        gitProbe.child.stdin.end()
        const gitResult = await gitProbe.completion
        if (
          gitResult.exitCode !== 0 ||
          !gitResult.stdout.startsWith('git version ')
        )
          throw infrastructure('Git is unavailable in the isolated runtime')
        const actor = 'startup-probe'
        const probe = await start({
          actor,
          workspace,
          probe: true,
          command: [
            'node',
            '-e',
            "const fs=require('fs'); try{fs.readFileSync('/trace/events')}catch{}; try{fs.readFileSync('/var/run/docker.sock')}catch{}; console.log('probe-ready')",
          ],
        })
        probe.child.stdin.end()
        const result = await probe.completion
        if (
          result.exitCode !== 0 ||
          !result.stdout.includes('probe-ready') ||
          !events.some(
            (event) => event.actor === actor && event.result === 'denied',
          )
        )
          throw infrastructure(
            `Filesystem denial or trusted stream startup probe failed: ${JSON.stringify(result)}; events ${events.length}`,
          )
        const mismatch = await start({
          actor: 'policy-mismatch-probe',
          workspace,
          probe: true,
          canary,
          command: [
            'node',
            '-e',
            "require('fs').readFileSync('/protected-canary'); setTimeout(()=>console.log('later-call'),1000)",
          ],
        })
        mismatch.child.stdin.end()
        const mismatchResult = await mismatch.completion
        if (
          !events.some(
            (event) =>
              event.actor === 'policy-mismatch-probe' &&
              event.resource === '/protected-canary' &&
              event.decision === 'forbidden' &&
              event.result === 'success',
          ) ||
          mismatchResult.exitCode === 0
        )
          throw infrastructure(
            `Supervisor mismatch/termination probe failed: ${JSON.stringify(mismatchResult)}; ${JSON.stringify(events.filter((event) => event.actor === 'policy-mismatch-probe' && (event.resource.includes('protected') || event.decision === 'forbidden')))}`,
          )
        let laterBlocked = false
        try {
          await start({
            actor: 'later-call',
            workspace,
            probe: true,
            command: ['true'],
          })
        } catch {
          laterBlocked = true
        }
        if (!laterBlocked)
          throw infrastructure(
            'Supervisor permitted a call after a forbidden-access event',
          )
        fatal = null
        const assigned = await start({
          actor: 'assigned-network-probe',
          workspace,
          probe: true,
          forwards: [
            {
              host: '127.0.0.1',
              port: 18080,
              targetHost: proofContainers[0],
              targetPort: 8080,
              network: proofNetwork,
            },
          ],
          command: [
            'node',
            '-e',
            "const s=require('net').connect(18080,'127.0.0.1');s.on('data',d=>{if(d.toString()!=='synthetic-listener-ready')process.exit(1);console.log('assigned-forwarder-ready')});s.on('error',()=>process.exit(1))",
          ],
        })
        assigned.child.stdin.end()
        const assignedResult = await assigned.completion
        if (
          assignedResult.exitCode ||
          !assignedResult.stdout.includes('assigned-forwarder-ready')
        )
          throw infrastructure(
            'Assigned loopback forwarder did not reach its live listener',
          )
        const observerLoss = await start({
          actor: 'observer-loss-probe',
          workspace,
          probe: true,
          testKillTracer: true,
          command: ['node', '-e', 'setInterval(()=>{},1000)'],
        })
        observerLoss.child.stdin.end()
        let lossDetected = false
        try {
          await observerLoss.completion
        } catch (error) {
          lossDetected =
            error instanceof Error &&
            'infrastructure' in error &&
            error.infrastructure === true
        }
        if (!lossDetected)
          throw infrastructure(
            'Observer loss was not an infrastructure failure',
          )
        fatal = null
        events.length = 0
        proven = true
        return {
          backend: backend.id,
          verified: true,
          policies: {
            filesystem: 'workspace-and-runtime-only',
            network: 'namespace-local-forwarders-only',
            migratorEnvironment: {
              id: 'migrator-workspace-and-migrator-stores-v1',
              storeSet: 'migrator',
            },
            appHost: {
              id: 'app-host-workspace-and-oracle-stores-v1',
              storeSet: 'oracle',
            },
          },
        }
      } finally {
        await rm(workspace, { recursive: true, force: true })
      }
    },
    /** @param {import('./types.js').IsolationOptions} options */
    async exec(options) {
      const actorProcess = await start(options)
      actorProcess.child.stdin.end()
      return actorProcess.completion
    },
    /** @param {Omit<import('./types.js').IsolationOptions,'command'|'actor'> & {actor?:string}} options */
    async openAppHost(options) {
      const actorProcess = await start({
        ...options,
        actor: options.actor ?? 'app-host',
        command: ['node', '/harness/app-host.mjs'],
      })
      /** @type {Map<number,{resolve:(value:unknown)=>void,reject:(error:unknown)=>void}>} */
      const pending = new Map()
      /** @type {unknown} */
      let terminalError = null
      /** @param {unknown} error */
      function rejectCalls(error) {
        terminalError = error
        for (const request of pending.values()) request.reject(error)
        pending.clear()
      }
      let buffer = '',
        serial = 0
      actorProcess.setOutput((text) => {
        buffer += text
        while (buffer.includes('\n')) {
          const end = buffer.indexOf('\n'),
            line = buffer.slice(0, end)
          buffer = buffer.slice(end + 1)
          try {
            const message = JSON.parse(line),
              request = pending.get(message.id)
            if (!request) continue
            pending.delete(message.id)
            if (message.error) request.reject(Error(message.error))
            else request.resolve(message.result)
          } catch {
            /* Application logging is untrusted diagnostic output. */
          }
        }
      })
      actorProcess.child.stdin.on('error', rejectCalls)
      actorProcess.completion.then((result) => {
        rejectCalls(
          Error(`App Host exited ${result.exitCode}: ${result.stderr}`),
        )
      }, rejectCalls)
      return {
        /** @param {string} method @param {unknown[]} args @returns {Promise<unknown>} */
        call(method, args = []) {
          if (fatal) return Promise.reject(fatal)
          if (terminalError) return Promise.reject(terminalError)
          return new Promise((resolve, reject) => {
            const id = ++serial
            pending.set(id, { resolve, reject })
            actorProcess.child.stdin.write(
              `${JSON.stringify({ id, method, args })}\n`,
            )
          })
        },
        async close() {
          actorProcess.child.stdin.end()
          return actorProcess.completion
        },
      }
    },
    drain() {
      if (fatal && !events.some(isBreach)) throw fatal
      return events.splice(0)
    },
    /** Expected cancellation waits for actor shutdown so the caller can drain all events.
     * @param {{expected?:boolean}} options */
    async stop({ expected = false } = {}) {
      const stopped = await Promise.allSettled(
        [...active].map(async (process) => {
          await process.stop({ expected })
          if (expected) await process.settled()
        }),
      )
      await Promise.all(
        proofContainers.splice(0).map((name) => command(['rm', '-f', name])),
      )
      if (proofNetwork) await command(['network', 'rm', proofNetwork])
      proofNetwork = null
      const failure = stopped.find((result) => result.status === 'rejected')
      if (failure?.status === 'rejected') throw failure.reason
    },
  }
  return backend
}
