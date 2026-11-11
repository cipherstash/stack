import { execFile, spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import { readMessages, validCommand } from './claude-wire.mjs'

/** Run the trusted host CLI; its MCP bridge is the only application tool.
 * Options are trusted operator configuration, never model-provided.
 * @param {{executable?:string, model?:string, input?:import('node:stream').Readable, output?:import('node:stream').Writable}} options
 */
export async function runClaudeAdapter({
  executable = 'claude',
  model = 'sonnet',
  input = process.stdin,
  output = process.stdout,
} = {}) {
  if (process.env.HARNESS_BROKER_PROTOCOL !== 'json-lines-exec-v1')
    throw Error('Claude adapter requires the harness broker')
  if (!process.env.ANTHROPIC_API_KEY)
    throw Error(
      'Claude adapter requires an explicit ANTHROPIC_API_KEY; login sessions are not used',
    )
  const maxTurns = Number(process.env.HARNESS_MAX_MODEL_TURNS)
  if (!Number.isSafeInteger(maxTurns) || maxTurns < 1)
    throw Error('Invalid model-turn budget')
  const directory = await mkdtemp(join(tmpdir(), 'mh-claude-'))
  const socketPath = join(directory, 'exec.sock')
  const token = randomBytes(32).toString('hex')
  // In particular, do not inherit NODE_OPTIONS, CLAUDE_*, cloud auth, CS_*, or
  // ANTHROPIC_BASE_URL. The only model provider is the public Anthropic API.
  const env = {
    PATH: process.env.PATH,
    HOME: directory,
    TMPDIR: directory,
    CLAUDE_CONFIG_DIR: directory,
    ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
  }
  /** @type {Map<string,{socket:import('node:net').Socket,id:string|number}>} */
  const pending = new Map()
  /** @type {Set<import('node:net').Socket>} */
  const sockets = new Set()
  let counter = 0
  /** @type {import('node:child_process').ChildProcess | undefined} */
  let child
  /** @type {Error|undefined} */
  let failure
  /** @param {Error} error */
  function fail(error) {
    failure ??= error
    child?.kill('SIGKILL')
    for (const socket of sockets) socket.destroy()
  }
  /** @param {unknown} message */
  function send(message) {
    output.write(`${JSON.stringify(message)}\n`)
  }
  const server = createServer((socket) => {
    sockets.add(socket)
    socket.on('close', () => {
      sockets.delete(socket)
      if ([...pending.values()].some((item) => item.socket === socket))
        fail(Error('MCP bridge disconnected during a tool call'))
    })
    readMessages(
      socket,
      (message) => {
        if (
          message?.token !== token ||
          !validCommand(message.command) ||
          !['string', 'number'].includes(typeof message.id) ||
          Object.keys(message).some(
            (key) => !['token', 'id', 'command'].includes(key),
          )
        ) {
          fail(Error('Invalid MCP bridge request'))
          return
        }
        const id = `claude-${++counter}`
        pending.set(id, { socket, id: message.id })
        send({ id, method: 'exec', command: message.command })
      },
      fail,
    )
  })
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(socketPath, () => resolve(undefined))
    })
    await chmod(socketPath, 0o600)
    const config = join(directory, 'mcp.json')
    await writeFile(
      config,
      JSON.stringify({
        mcpServers: {
          migration: {
            command: process.execPath,
            args: [fileURLToPath(new URL('./claude-mcp.mjs', import.meta.url))],
            env: {
              MIGRATION_BRIDGE_SOCKET: socketPath,
              MIGRATION_BRIDGE_TOKEN: token,
              ANTHROPIC_API_KEY: '',
            },
          },
        },
      }),
      { mode: 0o600 },
    )
    const { stdout: versionOutput } = await promisify(execFile)(
      executable,
      ['--version'],
      { cwd: directory, env, timeout: 10000, maxBuffer: 4096 },
    ).catch(() => {
      throw Error('Unable to read Claude CLI version')
    })
    const version = versionOutput.trim()
    if (!version || version.length > 256)
      throw Error('Invalid Claude CLI version')
    readMessages(
      input,
      (message) => {
        const request = pending.get(message?.id)
        if (
          !request ||
          !message.result ||
          !Number.isInteger(message.result.exitCode) ||
          typeof message.result.stdout !== 'string' ||
          typeof message.result.stderr !== 'string'
        ) {
          fail(Error('Invalid harness broker response'))
          return
        }
        pending.delete(message.id)
        request.socket.write(
          `${JSON.stringify({ id: request.id, result: message.result })}\n`,
        )
      },
      fail,
    )
    const prompt =
      'Upgrade the Fixture App in /workspace using only /workspace/migration-guide.md. Read that guide through the exec tool, follow its applicable migration procedure, and verify the migrated application. All commands and file access must use the exec tool in the isolated Migrator Environment. Record guide friction in /workspace/friction.json as a JSON array of objects with section, issue, actionable (boolean), description, and workaround. Write [] when there is no friction. Do not invent prior-run context.'
    const args = [
      '--bare',
      '--restricted',
      '--tools',
      '',
      '--strict-mcp-config',
      '--mcp-config',
      config,
      '--setting-sources',
      '',
      '--disable-slash-commands',
      '--no-chrome',
      '--no-session-persistence',
      '--permission-mode',
      'acceptEdits',
      '--allowedTools',
      'mcp__migration__exec',
      '--permission-prompts',
      'none',
      '--model',
      model,
      '--max-turns',
      String(maxTurns),
      '--output-format',
      'stream-json',
      '--verbose',
      '-p',
      prompt,
    ]
    child = spawn(executable, args, {
      cwd: directory,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    /** @type {string|undefined} */
    let resolvedModel
    /** @type {{num_turns:number,subtype:string,is_error:boolean}|undefined} */
    let result
    let diagnosticBytes = 0
    child.stderr?.on('data', (data) => {
      // CLI diagnostics can contain environment/provider details; do not export them.
      diagnosticBytes += data.length
      if (diagnosticBytes > 1024 * 1024)
        fail(Error('Claude diagnostic output limit exceeded'))
    })
    if (!child.stdout) throw Error('Missing Claude output channel')
    readMessages(
      child.stdout,
      (message) => {
        if (message?.type === 'system' && message.subtype === 'init') {
          if (
            resolvedModel ||
            message.permissionMode !== 'acceptEdits' ||
            typeof message.model !== 'string' ||
            !message.model ||
            message.model.length > 256 ||
            !Array.isArray(message.tools) ||
            message.tools.some(
              (/** @type {unknown} */ tool) => tool !== 'mcp__migration__exec',
            ) ||
            !message.tools.includes('mcp__migration__exec')
          ) {
            fail(Error('Claude initialized with unexpected model or tools'))
            return
          }
          resolvedModel = message.model
        } else if (message?.type === 'result') {
          if (
            result ||
            !Number.isSafeInteger(message.num_turns) ||
            message.num_turns < 0 ||
            typeof message.subtype !== 'string' ||
            typeof message.is_error !== 'boolean'
          ) {
            fail(Error('Invalid Claude result'))
            return
          }
          result = message
        }
        // Assistant text, tool arguments and tool output are never parsed as broker requests.
      },
      fail,
    )
    const code = await new Promise((resolve, reject) => {
      child?.once('error', reject)
      child?.once('close', resolve)
    })
    if (failure) throw failure
    if (pending.size || !resolvedModel || !result)
      throw Error('Claude exited without a complete runtime result')
    send({
      method: 'runtime',
      runtime: {
        provider: 'claude-code',
        version,
        model: resolvedModel,
        numTurns: result.num_turns,
        permissionMode: 'acceptEdits',
      },
    })
    if (result.num_turns > maxTurns || result.subtype === 'error_max_turns')
      return 124
    return code === 0 && !result.is_error && result.subtype === 'success'
      ? 0
      : 1
  } finally {
    input.pause()
    child?.kill('SIGKILL')
    for (const socket of sockets) socket.destroy()
    await new Promise((resolve) => server.close(resolve))
    await rm(directory, { recursive: true, force: true })
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  runClaudeAdapter().then(
    (code) => {
      process.exitCode = code
    },
    (error) => {
      process.stderr.write(
        `${error instanceof Error ? error.message : 'Claude adapter failed'}\n`,
      )
      process.exitCode = 1
    },
  )
}
