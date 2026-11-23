import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { afterEach, expect, test, vi } from 'vitest'

const { spawnDocker } = vi.hoisted(() => ({ spawnDocker: vi.fn() }))
vi.mock('node:child_process', () => ({ spawn: spawnDocker }))

import { createIsolation } from '../isolation.mjs'

afterEach(() => vi.clearAllMocks())

test.each([
  'stdout',
  'stderr',
  'docker-stderr',
  'events',
  'event-bytes',
  'frame',
])(
  'bounded supervision stops excessive %s before retaining unbounded host evidence',
  async (channel) => {
    spawnDocker.mockImplementation((_bin, args: string[]) => {
      const child = Object.assign(new EventEmitter(), {
        stdin: { end: vi.fn() },
        stdout: new PassThrough(),
        stderr: new PassThrough(),
      })
      setImmediate(() => {
        if (args[0] === 'run' && args.includes('-i')) {
          const frame = (value: unknown) =>
            child.stdout.write(`${JSON.stringify(value)}\n`)
          if (channel === 'events' || channel === 'event-bytes') {
            for (let i = 0; i < 3; i++)
              frame({
                kind: 'event',
                event: {
                  actor: 'bounded-probe',
                  stage: 'command',
                  pid: 1,
                  operation: 'stat',
                  resource: `/workspace/file-${i}`,
                  decision: 'allowed',
                  result: 'success',
                },
              })
          } else if (channel === 'frame') {
            child.stdout.write('x'.repeat(65))
          } else if (channel === 'docker-stderr') {
            child.stderr.write('x'.repeat(65))
          } else {
            frame({
              kind: channel,
              data: Buffer.from('x'.repeat(65)).toString('base64'),
            })
          }
          frame({
            kind: 'actor-exit',
            actor: 'bounded-probe',
            stage: 'command',
            exitCode: 0,
          })
          frame({ kind: 'stream-end' })
          frame({ kind: 'exit', exitCode: 0 })
        }
        child.stdout.end()
        child.stderr.end()
        child.emit('close', 0)
      })
      return child
    })
    const options = {
      limits: {
        outputBytes: 64,
        eventCount: 2,
        eventBytes: channel === 'event-bytes' ? 64 : 1024,
        frameBytes: channel === 'frame' ? 64 : 1024,
      },
    }
    const isolation = createIsolation(options)
    await expect(
      isolation.exec({
        actor: 'bounded-probe',
        workspace: '/synthetic-workspace',
        command: ['true'],
        probe: true,
      }),
    ).rejects.toMatchObject({
      infrastructure: true,
      message: expect.stringMatching(/limit/i),
    })
    expect(spawnDocker.mock.calls.some(([, args]) => args[0] === 'kill')).toBe(
      true,
    )
    expect(() => isolation.drain()).toThrow(/limit/i)
  },
)

test('default frame budget accepts the supervisor maximum one-MiB stderr payload', async () => {
  // supervise.py reads up to 1 MiB of diagnostics and emits one base64 frame.
  const stderr = 'x'.repeat(1024 * 1024)
  spawnDocker.mockImplementation((_bin, args: string[]) => {
    const child = Object.assign(new EventEmitter(), {
      stdin: { end: vi.fn() },
      stdout: new PassThrough(),
      stderr: new PassThrough(),
    })
    setImmediate(() => {
      if (args[0] === 'run' && args.includes('-i')) {
        for (const frame of [
          { kind: 'stderr', data: Buffer.from(stderr).toString('base64') },
          {
            kind: 'actor-exit',
            actor: 'stderr-probe',
            stage: 'command',
            exitCode: 0,
          },
          { kind: 'stream-end' },
          { kind: 'exit', exitCode: 0 },
        ])
          child.stdout.write(`${JSON.stringify(frame)}\n`)
      }
      child.stdout.end()
      child.stderr.end()
      child.emit('close', 0)
    })
    return child
  })
  const isolation = createIsolation()
  await expect(
    isolation.exec({
      actor: 'stderr-probe',
      workspace: '/synthetic-workspace',
      command: ['true'],
      probe: true,
    }),
  ).resolves.toMatchObject({ exitCode: 0, stderr })
  expect(spawnDocker.mock.calls.some(([, args]) => args[0] === 'kill')).toBe(
    false,
  )
})
