/** Bounded newline-delimited JSON framing shared by the trusted adapter and MCP bridge.
 * Each message is bounded at 1 MiB (UTF-16 units). The stream as a whole is
 * not: a Run repeats many valid results, and the broker bounds each one well
 * under this limit (`migrator.mjs`), so a lifetime cap only ended valid Runs.
 * @param {import('node:stream').Readable} stream
 * @param {(message:any)=>void} receive
 * @param {(error:Error)=>void} fail
 */
export function readMessages(stream, receive, fail) {
  let buffer = ''
  stream.setEncoding('utf8')
  stream.on('data', (chunk) => {
    buffer += chunk
    if (buffer.length > 1024 * 1024) {
      fail(Error('Protocol output limit exceeded'))
      return
    }
    for (;;) {
      const end = buffer.indexOf('\n')
      if (end < 0) break
      const line = buffer.slice(0, end)
      buffer = buffer.slice(end + 1)
      try {
        receive(JSON.parse(line))
      } catch {
        fail(Error('Invalid protocol message'))
        return
      }
    }
  })
  stream.on('end', () => {
    if (buffer.trim()) fail(Error('Unfinished protocol message'))
  })
  stream.on('error', fail)
}

/** @param {unknown} command @returns {command is string[]} */
export function validCommand(command) {
  return (
    Array.isArray(command) &&
    command.length > 0 &&
    Boolean(command[0]) &&
    command.every((arg) => typeof arg === 'string' && !arg.includes('\0'))
  )
}
