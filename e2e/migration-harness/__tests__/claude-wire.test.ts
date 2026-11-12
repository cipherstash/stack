import { PassThrough } from 'node:stream'
import { expect, test, vi } from 'vitest'
import { readMessages } from '../run/claude-wire.mjs'

// Each message is bounded; the stream as a whole is not. Claude's output and
// the broker's responses repeat many valid results over a Run, and a lifetime
// cap used to end the Run after about 18 results of 900 KiB.
test('readMessages bounds each message but not the stream as a whole', async () => {
  const stream = new PassThrough()
  const receive = vi.fn()
  const fail = vi.fn()
  readMessages(stream, receive, fail)
  const line = `${JSON.stringify({ text: 'x'.repeat(900 * 1024) })}\n`
  for (let i = 0; i < 20; i++) stream.write(line)
  stream.end()
  await new Promise((resolve) => stream.on('end', resolve))
  expect(fail).not.toHaveBeenCalled()
  expect(receive).toHaveBeenCalledTimes(20)
})

test('readMessages still fails on a single message over 1 MiB', async () => {
  const stream = new PassThrough()
  const fail = vi.fn()
  readMessages(stream, () => {}, fail)
  stream.write('x'.repeat(1024 * 1024 + 1))
  stream.end()
  await new Promise((resolve) => stream.on('end', resolve))
  expect(fail).toHaveBeenCalledWith(Error('Protocol output limit exceeded'))
})
