import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

const { spawnDocker } = vi.hoisted(() => ({ spawnDocker: vi.fn() }))
vi.mock('node:child_process', () => ({ spawn: spawnDocker }))

import { createIsolation } from '../isolation.mjs'

beforeEach(() => {
  let proofNetwork = ''
  // Docker's authenticated supervisor transport is the external dependency.
  // Actor output stays framed separately from trusted observer events.
  spawnDocker.mockImplementation((_executable: string, args: string[]) => {
    const child = Object.assign(new EventEmitter(), {
      stdin: Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),
      }),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
    })
    setImmediate(() => {
      if (args[0] === 'network' && args[1] === 'create') proofNetwork = args[2]
      if (args[0] === 'inspect')
        child.stdout.write(
          JSON.stringify({ [proofNetwork]: { IPAddress: '172.30.0.2' } }),
        )
      if (args[0] === 'port') child.stdout.write('127.0.0.1:18001')
      if (args[0] === 'run' && args.includes('-i')) {
        const encoded = args.find((arg) => arg.startsWith('HARNESS_CONFIG='))
        if (!encoded)
          throw Error('Mocked isolated invocation is missing its configuration')
        const { actor } = JSON.parse(
          Buffer.from(
            encoded.slice('HARNESS_CONFIG='.length),
            'base64',
          ).toString(),
        )
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
