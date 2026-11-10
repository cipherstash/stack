import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

const { spawnDocker } = vi.hoisted(() => ({ spawnDocker: vi.fn() }))
vi.mock('node:child_process', () => ({ spawn: spawnDocker }))

import { createIsolation } from '../isolation.mjs'

type Options = { env?: Record<string, string> }

beforeEach(() => {
  let proofNetwork = ''
  const live = new Map<
    string,
    { actor: string; child: ReturnType<typeof spawnDocker> }
  >()
  // Docker's authenticated supervisor transport is the external dependency.
  // Actor output stays framed separately from trusted observer events.
  spawnDocker.mockImplementation((_bin, args: string[], opts: Options) => {
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
        const running = live.get(args[1])
        if (running) {
          live.delete(args[1])
          if (running.actor === 'cancel-stream-error')
            running.child.stdout.write(
              `${JSON.stringify({ kind: 'stream-error', error: 'observer disconnected before cancellation' })}\n`,
            )
          if (running.actor === 'cancel-malformed')
            running.child.stdout.write('not-json\n')
          if (running.actor === 'cancel-contradictory') {
            running.child.stdout.write(
              `${JSON.stringify({ kind: 'actor-exit', actor: running.actor, stage: 'command', exitCode: 1 })}\n`,
            )
            running.child.stdout.write(
              `${JSON.stringify({ kind: 'exit', exitCode: 0 })}\n`,
            )
          }
          if (running.actor === 'cancel-breach')
            running.child.stdout.write(
              `${JSON.stringify({ kind: 'event', event: { actor: running.actor, resource: '/protected-canary', decision: 'forbidden', result: 'success' } })}\n`,
            )
          running.child.stdout.end()
          running.child.stderr.end()
          running.child.emit('close', 137)
        }
      }
      if (args[0] === 'network' && args[1] === 'create') proofNetwork = args[2]
      if (args[0] === 'inspect')
        child.stdout.write(
          JSON.stringify({ [proofNetwork]: { IPAddress: '172.30.0.2' } }),
        )
      if (args[0] === 'port') child.stdout.write('127.0.0.1:18001')
      if (args[0] === 'run' && args.includes('-i')) {
        const encoded = opts.env?.HARNESS_CONFIG
        if (!encoded)
          throw Error('Mocked isolated invocation is missing its configuration')
        const { actor } = JSON.parse(Buffer.from(encoded, 'base64').toString())
        if (actor.startsWith('cancel-')) {
          live.set(args[args.indexOf('--name') + 1], { actor, child })
          return
        }
        const frame = (value: Record<string, unknown>) =>
          child.stdout.write(`${JSON.stringify(value)}\n`)
        if (actor === 'startup-probe') {
          frame({ kind: 'event', event: { actor, result: 'denied' } })
          frame({
            kind: 'stdout',
            data: Buffer.from('probe-ready\n').toString('base64'),
          })
        } else if (actor === 'policy-mismatch-probe') {
          frame({
            kind: 'event',
            event: {
              actor,
              resource: '/protected-canary',
              decision: 'forbidden',
              result: 'success',
            },
          })
        } else if (actor === 'assigned-network-probe') {
          frame({
            kind: 'stdout',
            data: Buffer.from('assigned-forwarder-ready\n').toString('base64'),
          })
        } else if (actor === 'observer-loss-probe') {
          frame({
            kind: 'stream-error',
            error: 'ptrace observer ended without the actor exit record',
          })
        }
        if (
          ![
            'lost-observer',
            'observer-loss-probe',
            'policy-mismatch-probe',
          ].includes(actor)
        ) {
          frame({
            kind: 'actor-exit',
            actor,
            stage: 'command',
            exitCode: ['startup-probe', 'assigned-network-probe'].includes(
              actor,
            )
              ? 0
              : 1,
          })
        }
        frame({ kind: 'stream-end' })
        // App Host failed before receiving any application call.
        frame({
          kind: 'exit',
          exitCode: ['startup-probe', 'assigned-network-probe'].includes(actor)
            ? 0
            : 1,
        })
      }
      child.stdout.end()
      child.stderr.end()
      child.emit('close', 0)
    })
    return child
  })
})

test('observer termination without an actor exit record is infrastructure even with stream-end', async () => {
  const isolation = createIsolation()
  await isolation.prove()
  await expect(
    isolation.exec({
      actor: 'lost-observer',
      workspace: '/synthetic-workspace',
      command: ['true'],
    }),
  ).rejects.toMatchObject({ infrastructure: true })
})

afterEach(() => vi.clearAllMocks())

test('an App Host that already exited rejects later calls so the Run can report failure', async () => {
  const isolation = createIsolation()
  await isolation.prove()
  const host = await isolation.openAppHost({
    workspace: '/synthetic-workspace',
  })
  await host.close()
  const outcome = await Promise.race([
    host.call('get', ['customer']).then(
      () => 'resolved',
      () => 'rejected',
    ),
    new Promise((resolve) => setTimeout(() => resolve('hung'), 25)),
  ])
  expect(outcome).toBe('rejected')
})

test('actor configuration reaches Docker through its environment without appearing in process arguments', async () => {
  const isolation = createIsolation()
  const secret = 'SYNTHETIC-DOCKER-CREDENTIAL'
  await isolation.exec({
    actor: 'credential-probe',
    workspace: '/synthetic-workspace',
    command: ['true'],
    env: { CS_CLIENT_KEY: secret },
    probe: true,
  })
  const invocation = spawnDocker.mock.calls.find(
    ([_executable, args]) => args[0] === 'run' && args.includes('-i'),
  )
  expect(invocation).toBeDefined()
  const [, args, options] = invocation ?? []
  expect(args.some((arg: string) => arg.startsWith('HARNESS_CONFIG='))).toBe(
    false,
  )
  expect(args).toContain('HARNESS_CONFIG')
  const configuration = JSON.parse(
    Buffer.from(options.env.HARNESS_CONFIG, 'base64').toString(),
  )
  expect(configuration.env.CS_CLIENT_KEY).toBe(secret)
})

async function startCancellable(actor: string) {
  const isolation = createIsolation()
  const execution = isolation
    .exec({
      actor,
      workspace: '/synthetic-workspace',
      command: ['true'],
      probe: true,
    })
    .then(
      (result) => result,
      (error: Error) => error,
    )
  await vi.waitFor(() =>
    expect(
      spawnDocker.mock.calls.some(
        ([_bin, args]) => args[0] === 'run' && args.includes('-i'),
      ),
    ).toBe(true),
  )
  return { isolation, execution }
}

test('expected cancellation accepts its interrupted stream without poisoning later supervision', async () => {
  const { isolation, execution } = await startCancellable('cancel-requested')
  let settled = false
  void execution.then(() => {
    settled = true
  })
  await isolation.stop({ expected: true })
  expect(settled).toBe(true)
  expect(await execution).toMatchObject({ exitCode: 130 })
  expect(() => isolation.drain()).not.toThrow()
})

test.each(['cancel-stream-error', 'cancel-malformed', 'cancel-contradictory'])(
  'expected cancellation preserves %s infrastructure failures',
  async (actor) => {
    const { isolation, execution } = await startCancellable(actor)
    await isolation.stop({ expected: true }).catch(() => {})
    expect(await execution).toMatchObject({ infrastructure: true })
    expect(() => isolation.drain()).toThrow()
  },
)

test('expected cancellation retains successful forbidden access evidence', async () => {
  const { isolation, execution } = await startCancellable('cancel-breach')
  await isolation.stop({ expected: true }).catch(() => {})
  await execution
  expect(isolation.drain()).toContainEqual({
    actor: 'cancel-breach',
    resource: '/protected-canary',
    decision: 'forbidden',
    result: 'success',
  })
})

test.each(['cancel-stream-error', 'cancel-malformed'])(
  'an actor timeout preserves an observed %s infrastructure failure',
  async (actor) => {
    const isolation = createIsolation()
    await expect(
      isolation.exec({
        actor,
        workspace: '/synthetic-workspace',
        command: ['true'],
        probe: true,
        timeoutMs: 10,
      }),
    ).rejects.toMatchObject({ infrastructure: true })
    expect(() => isolation.drain()).toThrow()
  },
)
