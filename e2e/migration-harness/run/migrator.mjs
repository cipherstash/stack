import { spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** Escaped JSON length allowed for each of a result's stdout and stderr.
 * An adapter may wrap a result in one more JSON string (the Claude MCP bridge
 * does), which at most doubles an escaped string's length. Two streams at
 * this bound stay under the 1 MiB protocol line limit after that wrapping.
 */
export const RESULT_STREAM_CHARS = 192 * 1024

/** Bound one stream by its JSON-escaped length, cutting at a code point and
 * appending a marker so the model can retry with a narrower command.
 * @param {string} text
 * @param {number} [limit]
 */
export function boundStream(text, limit = RESULT_STREAM_CHARS) {
  if (JSON.stringify(text).length - 2 <= limit) return text
  const marker = (/** @type {number} */ omitted) =>
    `\n[harness: output truncated; ${omitted} of ${text.length} characters omitted. Use a narrower command.]`
  const budget = limit - (JSON.stringify(marker(text.length)).length - 2)
  let used = 0
  let end = 0
  for (const point of text) {
    const cost = JSON.stringify(point).length - 2
    if (used + cost > budget) break
    used += cost
    end += point.length
  }
  return `${text.slice(0, end)}${marker(text.length - end)}`
}

/** @param {import('../types.js').IsolationResult} result */
function boundResult(result) {
  return {
    ...result,
    stdout: boundStream(result.stdout),
    stderr: boundStream(result.stderr),
  }
}

/** @param {string[]} command */
function requestsReadme(command) {
  if (command[0] !== 'npm' || !['view', 'info', 'show'].includes(command[1]))
    return false
  // `npm view <package> [field...]`: the first positional names the package.
  const fields = command
    .slice(2)
    .filter((arg) => !arg.startsWith('-'))
    .slice(1)
  return fields.some((field) => /^readme(?:\.|$)/i.test(field))
}

/** Run a trusted model adapter on the host. Its only application tool is the
 * JSON-lines exec broker; the caller supplies the fixed isolated execution context.
 * @param {{command:string, execute:(command:string[],timeoutMs:number)=>Promise<import('../types.js').IsolationResult>, stop:()=>Promise<unknown>, timeoutMs?:number, maxToolCalls?:number, maxModelTurns?:number, maxEvidenceBytes?:number}} options
 * @returns {Promise<import('../types.js').MigratorResult & {stdout:string,stderr:string}>}
 */
export async function runMigrator({
  command,
  execute,
  stop,
  timeoutMs = 40 * 60 * 1000,
  maxToolCalls = 200,
  maxModelTurns = 200,
  maxEvidenceBytes = 8 * 1024 * 1024,
}) {
  if (
    !Number.isFinite(timeoutMs) ||
    timeoutMs <= 0 ||
    !Number.isSafeInteger(maxToolCalls) ||
    maxToolCalls <= 0 ||
    !Number.isSafeInteger(maxModelTurns) ||
    maxModelTurns <= 0 ||
    !Number.isSafeInteger(maxEvidenceBytes) ||
    maxEvidenceBytes <= 0
  )
    throw Error('Invalid Migrator limits')
  const directory = await mkdtemp(join(tmpdir(), 'migration-adapter-'))
  const env = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) =>
        !key.startsWith('CS_') &&
        !key.startsWith('HARNESS_') &&
        key !== 'DATABASE_URL',
    ),
  )
  Object.assign(env, {
    HARNESS_BROKER_PROTOCOL: 'json-lines-exec-v1',
    HARNESS_WORKSPACE: '/workspace',
    HARNESS_GUIDE: '/workspace/migration-guide.md',
    HARNESS_FRICTION_LOG: '/workspace/friction.json',
    HARNESS_MAX_TOOL_CALLS: String(maxToolCalls),
    HARNESS_MAX_MODEL_TURNS: String(maxModelTurns),
    // terminate() SIGKILLs the adapter before its own cleanup runs. Its
    // temporary files (Claude's holds the bridge token) land here instead,
    // and the finally below always removes this directory.
    TMPDIR: directory,
  })
  try {
    return await new Promise((resolve, reject) => {
      const child = spawn('/bin/sh', ['-c', command], {
        cwd: directory,
        env,
        detached: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      })
      const deadline = Date.now() + timeoutMs
      const seen = new Set()
      /** @type {Array<{id:string,exitCode:number}>} */
      const toolCalls = []
      /** @type {NonNullable<import('../types.js').MigratorResult['brokerEvidence']>} */
      const brokerEvidence = []
      let evidenceBytes = 0
      let evidenceComplete = true
      /** @type {import('../types.js').DocumentationExposure} */
      const documentationExposure = {
        status: 'unknown',
        reviewRequired: true,
        evidenceComplete: true,
      }

      let buffer = '',
        stdout = '',
        stderr = ''
      let stopped = false,
        closed = false,
        pending = 0
      /** @type {string|undefined} */
      let limit
      /** @type {import('../types.js').MigratorResult['runtime']} */
      let runtime
      /** @type {Error|undefined} */
      let failure
      let queue = Promise.resolve()
      let cancellation = Promise.resolve()
      /** Terminate the adapter's process group and every active isolated tool. */
      function terminate() {
        if (stopped) return
        stopped = true
        if (child.pid) {
          try {
            process.kill(-child.pid, 'SIGKILL')
          } catch {
            child.kill('SIGKILL')
          }
        }
        cancellation = stop().then(
          () => {},
          (error) => {
            if (
              !failure ||
              (error instanceof Error &&
                'infrastructure' in error &&
                error.infrastructure)
            )
              failure = error instanceof Error ? error : Error(String(error))
          },
        )
      }
      /** @param {string} message */
      function invalid(message) {
        failure ??= Error(`Migrator protocol: ${message}`)
        terminate()
      }
      const timer = setTimeout(() => {
        limit = 'time limit reached'
        terminate()
      }, timeoutMs)
      child.on('error', (error) => {
        failure = error
        terminate()
      })
      child.stdin.on('error', () => {
        if (!closed && !stopped) invalid('adapter closed its response channel')
      })
      child.stderr.on('data', (data) => {
        stderr += data
        if (stderr.length > 16 * 1024 * 1024)
          invalid('diagnostic output limit exceeded')
      })
      child.stdout.on('data', (data) => {
        if (stopped) return
        buffer += data
        stdout += data
        if (buffer.length > 1024 * 1024 || stdout.length > 16 * 1024 * 1024) {
          invalid('request output limit exceeded')
          return
        }
        while (!stopped) {
          const end = buffer.indexOf('\n')
          if (end === -1) break
          const line = buffer.slice(0, end)
          buffer = buffer.slice(end + 1)
          let request
          try {
            request = JSON.parse(line)
          } catch {
            invalid('invalid JSON')
            return
          }
          if (request?.method === 'runtime') {
            const value = request.runtime
            if (
              runtime ||
              !value ||
              value.provider !== 'claude-code' ||
              value.permissionMode !== 'acceptEdits' ||
              !Number.isSafeInteger(value.numTurns) ||
              value.numTurns < 0 ||
              ![value.model, value.version].every(
                (item) =>
                  typeof item === 'string' &&
                  item.length > 0 &&
                  item.length <= 256,
              ) ||
              Object.keys(request).some(
                (key) => !['method', 'runtime'].includes(key),
              ) ||
              Object.keys(value).some(
                (key) =>
                  ![
                    'provider',
                    'permissionMode',
                    'numTurns',
                    'model',
                    'version',
                  ].includes(key),
              )
            ) {
              invalid('invalid or duplicate runtime metadata')
              return
            }
            runtime = value
            if (value.numTurns > maxModelTurns) {
              limit = 'model turn limit reached'
              terminate()
            }
            continue
          }
          if (
            request?.method !== 'exec' ||
            typeof request.id !== 'string' ||
            !request.id ||
            request.id.length > 128 ||
            seen.has(request.id) ||
            !Array.isArray(request.command) ||
            request.command.length === 0 ||
            request.command.some(
              (/** @type {unknown} */ arg) =>
                typeof arg !== 'string' || arg.includes('\0'),
            ) ||
            !request.command[0] ||
            Object.keys(request).some(
              (key) => !['id', 'method', 'command'].includes(key),
            )
          ) {
            invalid('invalid or duplicate exec request')
            return
          }
          seen.add(request.id)
          if (seen.size > maxToolCalls) {
            limit = 'tool call limit reached'
            terminate()
            return
          }
          pending++
          queue = queue.then(async () => {
            if (stopped || closed) return
            try {
              const result = await execute(
                request.command,
                Math.max(1, deadline - Date.now()),
              )
              toolCalls.push({ id: request.id, exitCode: result.exitCode })
              // Keep raw responses private, separate from exportable tool metadata.
              const record = {
                id: request.id,
                command: request.command,
                result,
              }
              const bytes = Buffer.byteLength(JSON.stringify(record))
              if (evidenceBytes + bytes <= maxEvidenceBytes) {
                brokerEvidence.push(record)
                evidenceBytes += bytes
              } else evidenceComplete = false
              // This recognizes explicit retrieval only; unrecognized commands never
              // prove absence. File-access evidence supplies another positive signal.
              if (
                result.exitCode === 0 &&
                result.stdout.trim() &&
                requestsReadme(request.command)
              )
                documentationExposure.status = 'observed'
              documentationExposure.evidenceComplete = evidenceComplete
              if (!stopped && !closed)
                child.stdin.write(
                  `${JSON.stringify({ id: request.id, result: boundResult(result) })}\n`,
                )
            } catch (error) {
              failure = error instanceof Error ? error : Error(String(error))
              terminate()
            } finally {
              pending--
            }
          })
        }
      })
      child.on('close', async (code) => {
        closed = true
        clearTimeout(timer)
        if (!stopped && (pending || buffer.trim()))
          invalid('adapter exited with an unfinished request')
        await cancellation
        await queue
        // An adapter that reported runtime metadata and exits 124 stopped on
        // its model-turn limit, even when its own turn count is within budget.
        if (!limit && code === 124 && runtime)
          limit = 'model turn limit reached'
        const outcome = {
          exitCode: limit ? 124 : (code ?? 1),
          limit,
          toolCalls: [...toolCalls],
          brokerEvidence,
          documentationExposure,
          ...(runtime ? { runtime } : {}),
          stdout,
          stderr,
        }
        if (failure) {
          // Completed tool calls still happened; carry them to the caller,
          // marked incomplete, so a later failure does not erase them.
          documentationExposure.evidenceComplete = false
          Object.defineProperty(failure, 'migratorResult', {
            value: outcome,
            configurable: true,
          })
          reject(failure)
          return
        }
        resolve(outcome)
      })
    })
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}
