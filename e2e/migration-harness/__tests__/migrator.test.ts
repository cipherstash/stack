import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, test, vi } from 'vitest'
import { runMigrator } from '../run/migrator.mjs'

const directories: string[] = []
afterEach(async () => {
  for (const path of directories.splice(0))
    await rm(path, { recursive: true, force: true })
})
async function adapter(source: string) {
  const directory = await mkdtemp(join(tmpdir(), 'mh-broker-test-'))
  directories.push(directory)
  const path = join(directory, 'adapter.mjs')
  await writeFile(path, source)
  return `node '${path}'`
}
const result = { exitCode: 0, stdout: 'isolated output', stderr: '' }

test('broker rejects malformed JSON without executing a tool', async () => {
  const execute = vi.fn(async () => result)
  const stop = vi.fn(async () => {})
  await expect(
    runMigrator({
      command: await adapter(
        'console.log("not-json"); setTimeout(()=>{},10000)',
      ),
      execute,
      stop,
      timeoutMs: 1000,
    }),
  ).rejects.toThrow('invalid JSON')
  expect(execute).not.toHaveBeenCalled()
  expect(stop).toHaveBeenCalledOnce()
})

test('broker rejects duplicate IDs and caller-supplied execution context', async () => {
  for (const request of [
    [
      { id: 'same', method: 'exec', command: ['true'] },
      { id: 'same', method: 'exec', command: ['true'] },
    ],
    [
      {
        id: 'escape',
        method: 'exec',
        command: ['true'],
        workspace: '/protected',
      },
    ],
  ]) {
    const execute = vi.fn(async () => result)
    const messages = `${request.map((item) => JSON.stringify(item)).join('\n')}\n`
    await expect(
      runMigrator({
        command: await adapter(
          `process.stdout.write(${JSON.stringify(messages)});setTimeout(()=>{},10000)`,
        ),
        execute,
        stop: async () => {},
        timeoutMs: 1000,
      }),
    ).rejects.toThrow('invalid or duplicate')
    expect(execute.mock.calls.length).toBeLessThanOrEqual(1)
  }
})

test('broker enforces a tool-call limit independently of the model-turn budget', async () => {
  const request =
    JSON.stringify({ id: 'one', method: 'exec', command: ['true'] }) +
    '\n' +
    JSON.stringify({ id: 'two', method: 'exec', command: ['true'] }) +
    '\n'
  const stop = vi.fn(async () => {})
  const outcome = await runMigrator({
    command: await adapter(
      `process.stdout.write(${JSON.stringify(request)});setTimeout(()=>{},10000)`,
    ),
    execute: async () => result,
    stop,
    timeoutMs: 1000,
    maxToolCalls: 1,
  })
  expect(outcome).toMatchObject({
    exitCode: 124,
    limit: 'tool call limit reached',
  })
  expect(stop).toHaveBeenCalledOnce()
})

test('broker timeout awaits cancellation and the outstanding isolated tool before returning', async () => {
  const timeline: string[] = []
  let finish: ((value: typeof result) => void) | undefined
  const stop = vi.fn(async () => {
    timeline.push('stop')
    await new Promise((resolve) => setTimeout(resolve, 20))
    finish?.(result)
    timeline.push('cancelled')
  })
  const outcome = await runMigrator({
    command: await adapter(
      `console.log(JSON.stringify({id:'pending',method:'exec',command:['sleep','60']}));setTimeout(()=>{},10000)`,
    ),
    execute: async () => {
      timeline.push('started')
      const value = await new Promise<typeof result>((resolve) => {
        finish = resolve
      })
      await new Promise((resolve) => setTimeout(resolve, 20))
      timeline.push('settled')
      return value
    },
    stop,
    timeoutMs: 500,
  })
  timeline.push('returned')
  expect(outcome).toMatchObject({ exitCode: 124, limit: 'time limit reached' })
  expect(stop).toHaveBeenCalledOnce()
  expect(timeline).toEqual([
    'started',
    'stop',
    'cancelled',
    'settled',
    'returned',
  ])
})

test.each([0, -1, 1.5, Number.NaN])(
  'broker rejects invalid model-turn budget %s',
  async (maxModelTurns) => {
    await expect(
      runMigrator({
        command: 'true',
        execute: async () => result,
        stop: async () => {},
        maxModelTurns,
      }),
    ).rejects.toThrow('Invalid Migrator limits')
  },
)

// A failure after an earlier tool call succeeded must not discard that call's
// record: the driver writes it to incomplete broker evidence before rethrowing.
test('broker carries completed tool records through an isolation failure', async () => {
  const messages = ['first', 'second']
    .map((id) => JSON.stringify({ id, method: 'exec', command: ['true'] }))
    .join('\n')
  let calls = 0
  const execute = vi.fn(async () => {
    if (++calls === 2)
      throw Object.assign(Error('isolation broke'), { infrastructure: true })
    return result
  })
  const failure = await runMigrator({
    command: await adapter(
      `process.stdout.write(${JSON.stringify(`${messages}\n`)});setTimeout(()=>{},10000)`,
    ),
    execute,
    stop: async () => {},
    timeoutMs: 5000,
  }).then(
    () => undefined,
    (error) => error,
  )
  expect(failure?.message).toBe('isolation broke')
  expect(failure?.migratorResult).toMatchObject({
    toolCalls: [{ id: 'first', exitCode: 0 }],
    brokerEvidence: [{ id: 'first', command: ['true'], result }],
    documentationExposure: { evidenceComplete: false },
  })
})

test('broker preserves an infrastructure failure from isolated execution', async () => {
  const failure = Object.assign(Error('trusted stream failed'), {
    infrastructure: true,
  })
  await expect(
    runMigrator({
      command: await adapter(
        `console.log(JSON.stringify({id:'failed',method:'exec',command:['true']}));setTimeout(()=>{},10000)`,
      ),
      execute: async () => {
        throw failure
      },
      stop: async () => {},
      timeoutMs: 1000,
    }),
  ).rejects.toBe(failure)
})

test('broker rejects invalid or duplicate runtime metadata without treating it as a tool', async () => {
  const runtime = {
    provider: 'claude-code',
    version: '2.1.300',
    model: 'resolved-sonnet',
    numTurns: 1,
    permissionMode: 'acceptEdits',
  }
  for (const messages of [
    [{ method: 'runtime', runtime: { ...runtime, numTurns: -1 } }],
    [{ method: 'runtime', runtime: { ...runtime, apiKey: 'not-exportable' } }],
    [
      { method: 'runtime', runtime },
      { method: 'runtime', runtime },
    ],
  ]) {
    const execute = vi.fn(async () => result)
    await expect(
      runMigrator({
        command: await adapter(
          `process.stdout.write(${JSON.stringify(`${messages.map((message) => JSON.stringify(message)).join('\n')}\n`)});setTimeout(()=>{},10000)`,
        ),
        execute,
        stop: async () => {},
        timeoutMs: 1000,
      }),
    ).rejects.toThrow('invalid or duplicate runtime metadata')
    expect(execute).not.toHaveBeenCalled()
  }
})
