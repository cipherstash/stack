import { execFileSync } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { dirname, relative, resolve } from 'node:path'
import { PassThrough } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

const { spawnDocker } = vi.hoisted(() => ({ spawnDocker: vi.fn() }))
vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:child_process')>()),
  spawn: spawnDocker,
}))

import { createIsolation } from '../isolation.mjs'

const harness = resolve(dirname(fileURLToPath(import.meta.url)), '..')

type Frame = (value: Record<string, unknown>) => void
type Child = {
  stdout: PassThrough
  stderr: PassThrough
  emit: (event: string, ...args: unknown[]) => boolean
}
type Behaviour = (frame: Frame, child: Child, name: string) => boolean | void

const forbidden = (actor: string) => ({
  actor,
  resource: '/protected-canary',
  decision: 'forbidden',
  result: 'success',
})
const isBreach = (event: { decision?: string; result?: string }) =>
  event.decision === 'forbidden' && event.result === 'success'

/** Per-actor overrides of the synthetic supervisor; return true to keep the
 * container running (the behaviour then closes it itself). */
let behaviours: Record<string, Behaviour> = {}
/** Answer for `docker kill`. */
let killResult: (name: string) => { exitCode: number; stderr: string } =
  () => ({
    exitCode: 0,
    stderr: '',
  })
const containers = new Map<string, Child>()
let afterKill: (name: string) => void = () => {}

function finish(frame: Frame, actor: string, exitCode: number) {
  frame({ kind: 'actor-exit', actor, stage: 'command', exitCode })
  frame({ kind: 'stream-end' })
  frame({ kind: 'exit', exitCode })
}

// Probe behaviour of a healthy capability proof, as in isolation-regressions.
const proofProbes: Record<string, Behaviour> = {
  'git-tool-probe': (frame) => {
    frame({
      kind: 'stdout',
      data: Buffer.from('git version 2.39.5').toString('base64'),
    })
    finish(frame, 'git-tool-probe', 0)
  },
  'startup-probe': (frame) => {
    frame({
      kind: 'event',
      event: { actor: 'startup-probe', result: 'denied' },
    })
    frame({
      kind: 'stdout',
      data: Buffer.from('probe-ready\n').toString('base64'),
    })
    finish(frame, 'startup-probe', 0)
  },
  'policy-mismatch-probe': (frame) => {
    frame({ kind: 'event', event: forbidden('policy-mismatch-probe') })
    frame({ kind: 'stream-end' })
    frame({ kind: 'exit', exitCode: 1 })
  },
  'assigned-network-probe': (frame) => {
    frame({
      kind: 'stdout',
      data: Buffer.from('assigned-forwarder-ready\n').toString('base64'),
    })
    finish(frame, 'assigned-network-probe', 0)
  },
  'observer-loss-probe': (frame) => {
    frame({
      kind: 'stream-error',
      error: 'ptrace observer ended without the actor exit record',
    })
    frame({ kind: 'stream-end' })
    frame({ kind: 'exit', exitCode: 1 })
  },
}

beforeEach(() => {
  behaviours = {}
  killResult = () => ({ exitCode: 0, stderr: '' })
  afterKill = () => {}
  containers.clear()
  let proofNetwork = ''
  spawnDocker.mockImplementation(
    (_bin, args: string[], opts: { env?: Record<string, string> }) => {
      const child = Object.assign(new EventEmitter(), {
        stdin: Object.assign(new EventEmitter(), {
          write: vi.fn(),
          end: vi.fn(),
        }),
        stdout: new PassThrough(),
        stderr: new PassThrough(),
      })
      setImmediate(() => {
        if (args[0] === 'kill') {
          const answer = killResult(args[1])
          if (answer.stderr) child.stderr.write(answer.stderr)
          child.stdout.end()
          child.stderr.end()
          child.emit('close', answer.exitCode)
          setImmediate(() => afterKill(args[1]))
          return
        }
        if (args[0] === 'network' && args[1] === 'create')
          proofNetwork = args[2]
        if (args[0] === 'inspect')
          child.stdout.write(
            JSON.stringify({ [proofNetwork]: { IPAddress: '172.30.0.2' } }),
          )
        if (args[0] === 'port') child.stdout.write('127.0.0.1:18001')
        if (args[0] === 'run' && args.includes('-i')) {
          const encoded = opts.env?.HARNESS_CONFIG ?? ''
          const { actor } = JSON.parse(
            Buffer.from(encoded, 'base64').toString(),
          )
          const name = args[args.indexOf('--name') + 1]
          containers.set(name, child)
          const frame: Frame = (value) =>
            child.stdout.write(`${JSON.stringify(value)}\n`)
          const behaviour =
            behaviours[actor] ??
            proofProbes[actor] ??
            (() => finish(frame, actor, 0))
          if (behaviour(frame, child, name) === true) return
        }
        child.stdout.end()
        child.stderr.end()
        child.emit('close', 0)
      })
      return child
    },
  )
})

afterEach(() => vi.clearAllMocks())

const exec = (isolation: ReturnType<typeof createIsolation>, actor: string) =>
  isolation.exec({
    actor,
    workspace: '/synthetic-workspace',
    command: ['true'],
    probe: true,
  })

const allowedEvent = (actor: string, index: number) => ({
  kind: 'event',
  event: {
    actor,
    stage: 'command',
    pid: 1,
    operation: 'stat',
    resource: `/workspace/file-${index}`,
    decision: 'allowed',
    result: 'success',
  },
})

// F1: the event budget bounds events HELD, so draining must release it.
test('drained events no longer count against the retained event budget', async () => {
  behaviours.busy = (frame) => {
    frame(allowedEvent('busy', 0))
    finish(frame, 'busy', 0)
  }
  const isolation = createIsolation({ limits: { eventCount: 2 } })
  for (let i = 0; i < 3; i++) {
    await expect(exec(isolation, 'busy')).resolves.toMatchObject({
      exitCode: 0,
    })
    expect(isolation.drain()).toHaveLength(1)
  }
})

test('events cleared at the end of the capability proof no longer count against the budget', async () => {
  behaviours.busy = (frame) => {
    frame(allowedEvent('busy', 0))
    frame(allowedEvent('busy', 1))
    finish(frame, 'busy', 0)
  }
  // The proof itself observes two events (startup denial, policy mismatch).
  const isolation = createIsolation({ limits: { eventCount: 2 } })
  await isolation.prove()
  await expect(exec(isolation, 'busy')).resolves.toMatchObject({
    exitCode: 0,
  })
  expect(isolation.drain()).toHaveLength(2)
})

// F2: a proof failing after the policy-mismatch probe must not leave its
// synthetic forbidden-success canary for the Run to report as a violation.
test.each([
  [
    'assigned-network-probe',
    ((frame) => finish(frame, 'assigned-network-probe', 1)) as Behaviour,
  ],
  [
    'observer-loss-probe',
    ((frame) => finish(frame, 'observer-loss-probe', 0)) as Behaviour,
  ],
])(
  'a capability proof failing at %s does not leave its synthetic breach for drain()',
  async (actor, behaviour) => {
    behaviours[actor] = behaviour
    const isolation = createIsolation()
    await expect(isolation.prove()).rejects.toMatchObject({
      infrastructure: true,
    })
    let drained: Array<{ decision?: string; result?: string }> = []
    try {
      drained = isolation.drain()
    } catch {
      // Throwing infrastructure is also acceptable: the failure is not masked.
    }
    expect(drained.filter(isBreach)).toEqual([])
  },
)

// F3: supervise.py splits output into 16 KiB chunks with no regard for
// character boundaries, so each stream needs its own decoder.
test.each(['stdout', 'stderr'])(
  'a multi-byte character split across two %s frames is decoded intact',
  async (kind) => {
    const bytes = Buffer.from('guide → step — done')
    const split = bytes.indexOf(Buffer.from('→')) + 1
    behaviours.split = (frame) => {
      frame({ kind, data: bytes.subarray(0, split).toString('base64') })
      frame({ kind, data: bytes.subarray(split).toString('base64') })
      finish(frame, 'split', 0)
    }
    const result = await exec(createIsolation(), 'split')
    expect(result[kind as 'stdout' | 'stderr']).toContain('guide → step — done')
    expect(result[kind as 'stdout' | 'stderr']).not.toContain('�')
  },
)

// F4: the --rm container exited on its own just before the expected stop;
// it is still active until its close handler runs, and `docker kill` fails.
test.each([
  'Error response from daemon: cannot kill container: abc: container abc is not running',
  'Error response from daemon: No such container: abc',
])(
  'expected cancellation of an actor that already exited is not infrastructure (%s)',
  async (stderr) => {
    let exited = false
    behaviours.finished = (frame, child, name) => {
      finish(frame, 'finished', 0)
      exited = true
      afterKill = (killed) => {
        if (killed !== name) return
        child.stdout.end()
        child.stderr.end()
        child.emit('close', 0)
      }
      return true
    }
    killResult = () => ({ exitCode: 1, stderr })
    const isolation = createIsolation()
    const execution = exec(isolation, 'finished').then(
      (result) => result,
      (error: Error) => error,
    )
    await vi.waitFor(() => expect(exited).toBe(true))
    await expect(isolation.stop({ expected: true })).resolves.toBeUndefined()
    expect(await execution).toMatchObject({ exitCode: 0 })
  },
)

// F6: the probe workspace must not be left as an untracked, unignored,
// world-writable directory in the package if the job dies mid-proof.
test('the capability-probe workspace is outside the package or git-ignored', async () => {
  const isolation = createIsolation()
  await isolation.prove()
  const mount = spawnDocker.mock.calls
    .map(([, args]) => args as string[])
    .filter((args) => args[0] === 'run' && args.includes('-i'))
    .flat()
    .find(
      (arg) => arg.startsWith('type=bind,') && arg.endsWith(',dst=/workspace'),
    )
  expect(mount).toBeDefined()
  const workspace = /src=([^,]+)/.exec(mount ?? '')?.[1] ?? ''
  const inside = !relative(harness, workspace).startsWith('..')
  let ignored = false
  if (inside)
    try {
      execFileSync('git', ['check-ignore', '-q', workspace], { cwd: harness })
      ignored = true
    } catch {}
  expect(!inside || ignored).toBe(true)
})
