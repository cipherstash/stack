/** Bounded newline-delimited JSON framing shared by the trusted adapter and MCP bridge.
 * Each message is bounded at 1 MiB (UTF-16 units). The stream as a whole is
 * not: a Run repeats many valid results, and the broker bounds each one well
 * under this limit (`migrator.mjs`), so a lifetime cap only ended valid Runs.
 * @param {import('node:stream').Readable} stream
 * @param {(message:any)=>void} receive
 * @param {(error:Error)=>void} fail
 */
export function readMessages(stream, receive, fail) {
  const maxMessageLength = 1024 * 1024
  let buffer = ''
  let failed = false
  /** @param {Error} error */
  function reject(error) {
    if (failed) return
    failed = true
    buffer = ''
    fail(error)
  }
  stream.setEncoding('utf8')
  stream.on('data', (chunk) => {
    if (failed) return
    buffer += chunk
    for (;;) {
      const end = buffer.indexOf('\n')
      if (end < 0) break
      if (end > maxMessageLength) {
        reject(Error('Protocol output limit exceeded'))
        return
      }
      const line = buffer.slice(0, end)
      buffer = buffer.slice(end + 1)
      try {
        receive(JSON.parse(line))
      } catch {
        reject(Error('Invalid protocol message'))
        return
      }
    }
    if (buffer.length > maxMessageLength)
      reject(Error('Protocol output limit exceeded'))
  })
  stream.on('end', () => {
    if (buffer.trim()) reject(Error('Unfinished protocol message'))
  })
  stream.on('error', reject)
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
