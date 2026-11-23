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

test('readMessages accepts a chunk spanning two individually valid messages', () => {
  const stream = new PassThrough()
  const receive = vi.fn()
  const fail = vi.fn()
  readMessages(stream, receive, fail)
  const first = { text: 'x'.repeat(1024 * 1024 - 20) }
  const second = { text: 'y'.repeat(64) }
  const line = JSON.stringify(first)
  stream.write(line.slice(0, -5))
  stream.end(`${line.slice(-5)}\n${JSON.stringify(second)}\n`)
  expect(receive).toHaveBeenCalledTimes(2)
  expect(receive.mock.calls[0]?.[0]?.text.length).toBe(first.text.length)
  expect(receive.mock.calls[1]?.[0]).toEqual(second)
  expect(fail).not.toHaveBeenCalled()
})
