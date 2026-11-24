import { connect } from 'node:net'
import { readMessages, validCommand } from './claude-wire.mjs'

// This trusted stdio MCP server never spawns commands. Its only capability is
// forwarding argument arrays to the host adapter's fixed isolation broker.
const token = process.env.MIGRATION_BRIDGE_TOKEN
const path = process.env.MIGRATION_BRIDGE_SOCKET
if (!token || !path) throw Error('Missing migration bridge configuration')
const socket = connect(path)
/** @type {Set<string|number>} */
const pending = new Set()
/** @param {unknown} message */
function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`)
}
/** @param {string|number|null} id @param {number} code @param {string} message */
function error(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } })
}
function fail() {
  socket.destroy()
  process.exitCode = 1
  process.stdin.destroy()
}
readMessages(
  socket,
  (message) => {
    if (!pending.delete(message.id) || !message.result) {
      fail()
      return
    }
    send({
      jsonrpc: '2.0',
      id: message.id,
      result: {
        content: [{ type: 'text', text: JSON.stringify(message.result) }],
        isError: message.result.exitCode !== 0,
      },
    })
  },
  fail,
)
socket.on('close', () => {
  if (pending.size) fail()
  process.stdin.destroy()
})
readMessages(
  process.stdin,
  (message) => {
    const id = message?.id
    if (message?.jsonrpc !== '2.0') {
      error(null, -32600, 'Invalid request')
      return
    }
    if (id === undefined && message.method?.startsWith('notifications/')) return
    if ((typeof id !== 'string' && typeof id !== 'number') || pending.has(id)) {
      error(null, -32600, 'Invalid request ID')
      return
    }
    if (message.method === 'initialize') {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'migration-exec', version: '1.0.0' },
        },
      })
    } else if (message.method === 'ping') {
      send({ jsonrpc: '2.0', id, result: {} })
    } else if (message.method === 'tools/list') {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            {
              name: 'exec',
              description:
                'Run an argument array in the isolated Migrator Environment at /workspace. Use this for every file operation and command. No host paths or environment overrides are accepted.',
              inputSchema: {
                type: 'object',
                properties: {
                  command: {
                    type: 'array',
                    items: { type: 'string' },
                    minItems: 1,
                  },
                },
                required: ['command'],
                additionalProperties: false,
              },
            },
          ],
        },
      })
    } else if (message.method === 'tools/call') {
      const args = message.params?.arguments
      if (
        message.params?.name !== 'exec' ||
        !args ||
        !validCommand(args.command) ||
        Object.keys(args).some((key) => key !== 'command')
      ) {
        error(
          id,
          -32602,
          'Only exec with a command argument array is supported',
        )
        return
      }
      pending.add(id)
      socket.write(`${JSON.stringify({ token, id, command: args.command })}\n`)
    } else error(id, -32601, 'Method not found')
  },
  fail,
)
process.stdin.on('end', () => socket.end())
