/**
 * Agent initialization and configuration.
 *
 * Sets up the Claude Agent SDK with:
 * - CipherStash-hosted LLM gateway
 * - Sandboxed tool permissions
 * - MCP server for wizard-tools
 * - Security hooks
 * - Interactive conversation loop (user can reply to agent questions)
 */

import type { PermissionResult } from '@anthropic-ai/claude-agent-sdk'
import auth from '@cipherstash/auth'
import * as p from '@clack/prompts'
import { GATEWAY_URL } from '../lib/constants.js'
import { PACKAGE_MANAGERS } from '../lib/detect.js'
import { formatAgentOutput } from '../lib/format.js'
import type { WizardSession } from '../lib/types.js'
import { classifyError, formatWizardError } from './errors.js'
import { scanPreToolUse } from './hooks.js'

const { AutoStrategy } = auth

// Lazy-load the SDK module to handle cases where it may not be installed.
// biome-ignore lint/suspicious/noExplicitAny: dynamic import
let _sdkModule: any = null
async function getSDKModule() {
  if (!_sdkModule) {
    _sdkModule = await import('@anthropic-ai/claude-agent-sdk')
  }
  return _sdkModule
}

export interface WizardAgent {
  session: WizardSession
  run: (prompt: string) => Promise<WizardAgentResult>
}

export interface WizardAgentResult {
  success: boolean
  /** Concatenated assistant text output. */
  output: string
  /** Duration in ms. */
  durationMs: number
  /** Error message if not successful. */
  error?: string
}

/** Package manager DLX runner prefixes (tools run via runner dlx). */
const RUNNER_PREFIXES = Object.values(PACKAGE_MANAGERS).map(
  (pm) => pm.execCommand,
)

/** Tools allowed to run via any DLX runner. */
const ALLOWED_DLX_TOOLS = ['drizzle-kit', 'tsc', 'stash db'] as const

/** Allowed Bash commands — whitelist approach. */
const ALLOWED_BASH_COMMANDS = [
  // Package managers
  'npm install',
  'npm uninstall',
  'npm list',
  'npm run',
  'pnpm add',
  'pnpm remove',
  'pnpm list',
  'pnpm run',
  'yarn add',
  'yarn remove',
  'yarn list',
  'yarn run',
  'bun add',
  'bun remove',
  'bun run',
  // Build & validation
  'stash db',
]

/**
 * Check whether `cmd` is a `<runner> <tool>` invocation we allow the agent to run.
 * Strips any of the four runner prefixes, then matches the remainder against
 * the allowed tools. Returns true if the prefix-stripped command starts with
 * any allowed tool token.
 */
function isAllowedDlxCommand(cmd: string): boolean {
  for (const prefix of RUNNER_PREFIXES) {
    if (cmd.startsWith(`${prefix} `)) {
      const rest = cmd.slice(prefix.length + 1)
      // Token-boundary match: the tool name must be the entire remainder, or
      // the tool name followed by a space (then args). A bare `startsWith`
      // would let `drizzle-kit-malicious` slip through `drizzle-kit`.
      return ALLOWED_DLX_TOOLS.some(
        (t) => rest === t || rest.startsWith(`${t} `),
      )
    }
  }
  return false
}

/** Filesystem paths the agent is allowed to write to. */
const ALLOWED_WRITE_PATHS = [
  // Project directory (set dynamically)
  '.',
  // Temp directories
  '/tmp',
  '/private/tmp',
]

/** Sensitive file patterns the agent must not read directly. */
const SENSITIVE_FILE_PATTERNS = [
  /\.env($|\.)/, // .env, .env.local, .env.production, etc.
  /auth\.json$/, // ~/.cipherstash/auth.json
  /secretkey\.json$/, // ~/.cipherstash/secretkey.json
  /credentials/i, // Various credential files
]

function isSensitivePath(filePath: string): boolean {
  return SENSITIVE_FILE_PATTERNS.some((p) => p.test(filePath))
}

/**
 * Validate whether a tool use is permitted.
 * Returns true if allowed, or a string reason if blocked.
 *
 * Security layers:
 * 1. YARA-style pre-execution scan (hooks.ts)
 * 2. Sensitive file path blocking for Read/Grep/Glob
 * 3. Bash command allowlist with operator blocking
 */
export function wizardCanUseTool(
  toolName: string,
  input: Record<string, unknown>,
): true | string {
  // Layer 1: Run YARA-style pre-execution scan
  const hookResult = scanPreToolUse(
    toolName,
    String(input.command ?? input.file_path ?? ''),
  )
  if (hookResult.blocked) {
    return hookResult.reason ?? 'Blocked by security scan'
  }

  // Layer 2: Block sensitive file access for Read/Grep/Glob
  if (toolName === 'Read' || toolName === 'Edit' || toolName === 'Write') {
    const filePath = String(input.file_path ?? '')
    if (isSensitivePath(filePath)) {
      return `Access to ${filePath} is blocked. Sensitive files must be managed through the wizard-tools MCP server.`
    }
  }

  if (toolName === 'Grep') {
    const path = String(input.path ?? '')
    const glob = String(input.glob ?? '')
    if (isSensitivePath(path) || isSensitivePath(glob)) {
      return 'Searching in sensitive files (.env, credentials) is blocked.'
    }
  }

  if (toolName === 'Glob') {
    const pattern = String(input.pattern ?? '')
    if (isSensitivePath(pattern)) {
      return 'Globbing for sensitive files (.env, credentials) is blocked.'
    }
  }

  // Layer 3: Bash command restrictions
  if (toolName === 'Bash') {
    const command = String(input.command ?? '')

    // Block newlines (command chaining via multiline)
    if (command.includes('\n')) {
      return 'Multi-line commands are not allowed for security reasons.'
    }

    // Block direct .env access via Bash
    if (/\.(env|env\.local)/.test(command)) {
      return 'Direct .env file access via Bash is blocked. Use the wizard-tools MCP server instead.'
    }

    // Check against allowed commands (including DLX variants)
    const isAllowed =
      ALLOWED_BASH_COMMANDS.some((allowed) => command.startsWith(allowed)) ||
      isAllowedDlxCommand(command)
    if (!isAllowed) {
      return `Command not in allowlist. Allowed: ${ALLOWED_BASH_COMMANDS.join(', ')}, or ${RUNNER_PREFIXES.join('/')} <tool> for: ${ALLOWED_DLX_TOOLS.join(', ')}`
    }
  }

  return true
}

/**
 * Get a valid CipherStash access token.
 * Uses AutoStrategy which checks (in order):
 *   1. CS_CLIENT_ACCESS_KEY env var → access key auth (CI/CD)
 *   2. ~/.cipherstash/auth.json → OAuth token auth (CLI users)
 * Handles refresh automatically.
 */
async function getAccessToken(): Promise<string | undefined> {
  try {
    const strategy = AutoStrategy.detect()
    const result = await strategy.getToken()
    return result.token
  } catch {
    return undefined
  }
}

/**
 * Friendly tool name for spinner messages.
 */
function describeToolUse(
  toolName: string,
  input: Record<string, unknown>,
): string {
  switch (toolName) {
    case 'Read':
      return `Reading ${shortenPath(String(input.file_path ?? ''))}`
    case 'Write':
      return `Writing ${shortenPath(String(input.file_path ?? ''))}`
    case 'Edit':
      return `Editing ${shortenPath(String(input.file_path ?? ''))}`
    case 'Glob':
      return `Searching for files matching ${input.pattern ?? '...'}`
    case 'Grep':
      return `Searching for "${input.pattern ?? '...'}" in files`
    case 'Bash': {
      const cmd = String(input.command ?? '')
      return `Running: ${cmd.length > 60 ? `${cmd.slice(0, 57)}...` : cmd}`
    }
    default:
      return `Using ${toolName}`
  }
}

function shortenPath(filePath: string): string {
  const parts = filePath.split('/')
  if (parts.length <= 3) return filePath
  return `.../${parts.slice(-2).join('/')}`
}

/**
 * Detect whether the agent's last assistant message is asking the user a question
 * (i.e. it ended its turn with text, no pending tool use).
 */
function looksLikeQuestion(text: string): boolean {
  const trimmed = text.trim()
  // Ends with a question mark or contains common question patterns
  if (trimmed.endsWith('?')) return true
  if (
    /let me know|which .*(do you|would you|should)|please (choose|select|confirm|tell)/i.test(
      trimmed,
    )
  )
    return true
  return false
}

/** Max conversation turns to prevent runaway loops. */
const MAX_CONVERSATION_TURNS = 10

/**
 * Initialize the wizard agent with the Claude Agent SDK.
 *
 * Supports interactive conversation — when the agent asks the user a question,
 * the wizard pauses, shows the output, prompts for input, and sends the reply
 * back to the agent as a follow-up message.
 */
export async function initializeAgent(
  session: WizardSession,
): Promise<WizardAgent> {
  const accessToken = await getAccessToken()

  return {
    session,
    async run(prompt: string): Promise<WizardAgentResult> {
      const start = Date.now()

      const spinner = p.spinner()
      spinner.start('Connecting to CipherStash AI gateway...')

      const sdk = await getSDKModule()
      const { query } = sdk

      // Set gateway env vars for the Agent SDK
      const env: Record<string, string | undefined> = {
        ...process.env,
        ANTHROPIC_BASE_URL: GATEWAY_URL,
        ANTHROPIC_API_KEY: undefined, // Clear any user key
      }

      if (accessToken) {
        env.ANTHROPIC_AUTH_TOKEN = accessToken
      }

      // Message queue: the prompt stream pulls from this.
      // We push the initial prompt, then push follow-ups when the user replies.
      const messageQueue: Array<{ role: 'user'; content: string }> = []
      let queueResolver: (() => void) | null = null
      let done = false

      function pushMessage(content: string) {
        messageQueue.push({ role: 'user', content })
        queueResolver?.()
      }

      function signalDone() {
        done = true
        queueResolver?.()
      }

      // Async generator that yields user messages as they arrive
      const createPromptStream = async function* () {
        // Yield initial prompt
        pushMessage(prompt)

        while (!done) {
          // Wait for a message to be available
          while (messageQueue.length === 0 && !done) {
            await new Promise<void>((resolve) => {
              queueResolver = resolve
            })
          }

          if (done && messageQueue.length === 0) break

          const msg = messageQueue.shift()!
          yield {
            type: 'user' as const,
            session_id: '',
            message: msg,
            parent_tool_use_id: null,
          }
        }
      }

      const allCollectedText: string[] = []
      let currentTurnText: string[] = []
      let success = false
      let errorMessage: string | undefined
      let receivedFirstMessage = false
      let turnCount = 0
      let lastAssistantHadToolUse = false
      let spinnerActive = true

      const sdkOptions = {
        model: 'claude-sonnet-4-20250514',
        cwd: session.cwd,
        permissionMode: 'acceptEdits' as const,
        // Schema discovery is done pre-agent. Agent needs Glob/Grep to find app code to edit.
        allowedTools: ['Read', 'Write', 'Edit', 'Glob', 'Grep', 'Bash'],
        tools: ['Read', 'Write', 'Edit', 'Glob', 'Grep', 'Bash'],
        disallowedTools: ['Agent', 'WebFetch', 'WebSearch', 'NotebookEdit'],
        env,
        maxTurns: 50,
        persistSession: false,
        thinking: { type: 'disabled' as const },
        canUseTool: async (
          toolName: string,
          input: Record<string, unknown>,
        ): Promise<PermissionResult> => {
          const result = wizardCanUseTool(toolName, input)
          if (result === true) {
            if (spinnerActive) {
              spinner.message(describeToolUse(toolName, input))
            }
            return { behavior: 'allow' }
          }
          return { behavior: 'deny', message: result }
        },
        sandbox: {
          enabled: true,
          filesystem: {
            allowWrite: [session.cwd, '/tmp', '/private/tmp'],
          },
        },
        stderr: session.debug
          ? (data: string) => {
              p.log.warn(`[agent stderr] ${data.trim()}`)
            }
          : undefined,
      }

      // biome-ignore lint/suspicious/noExplicitAny: SDK message types vary
      let response: AsyncGenerator<any>
      try {
        response = query({
          prompt: createPromptStream(),
          options: sdkOptions,
        })
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Unknown error'
        if (spinnerActive) {
          spinner.stop('Failed to start agent')
        }
        const runner = session.detectedPackageManager?.execCommand ?? 'npx'
        return {
          success: false,
          output: '',
          durationMs: Date.now() - start,
          error: classifyError(undefined, msg, runner),
        }
      }

      try {
        for await (const message of response) {
          // First message from the agent — update spinner
          if (!receivedFirstMessage && message.type === 'assistant') {
            receivedFirstMessage = true
            spinner.message('Agent is analyzing your project...')
          }

          if (message.type === 'assistant') {
            lastAssistantHadToolUse = false
            const content = message.message?.content
            if (Array.isArray(content)) {
              for (const block of content) {
                if (block.type === 'text' && typeof block.text === 'string') {
                  currentTurnText.push(block.text)
                  allCollectedText.push(block.text)
                }

                if (block.type === 'tool_use') {
                  lastAssistantHadToolUse = true
                  if (spinnerActive) {
                    const desc = describeToolUse(
                      block.name ?? 'unknown',
                      (block.input as Record<string, unknown>) ?? {},
                    )
                    spinner.message(desc)
                  }
                }
              }
            }
          }

          if (message.type === 'system' && message.subtype === 'init') {
            if (spinnerActive) {
              spinner.message('Agent initialized, starting work...')
            }
          }

          if (message.type === 'result') {
            turnCount++

            const isSuccess = message.subtype === 'success' && !message.is_error
            if (isSuccess) {
              const turnText = currentTurnText.join('\n').trim()

              // Check if the agent is asking the user a question
              // (text-only response, no tool calls, and looks like a question)
              if (
                turnText.length > 0 &&
                !lastAssistantHadToolUse &&
                looksLikeQuestion(turnText) &&
                turnCount < MAX_CONVERSATION_TURNS
              ) {
                // Stop spinner, show agent output, prompt user
                if (spinnerActive) {
                  spinner.stop('Agent needs your input')
                  spinnerActive = false
                }

                console.log('')
                console.log(formatAgentOutput(turnText))
                console.log('')

                const userReply = await p.text({
                  message: 'Your reply (or "done" to finish):',
                  placeholder: 'Type your answer...',
                })

                if (
                  p.isCancel(userReply) ||
                  userReply.toLowerCase().trim() === 'done'
                ) {
                  // User wants to stop
                  success = true
                  signalDone()
                } else {
                  // Send reply to the agent, restart spinner
                  currentTurnText = []
                  spinner.start('Agent is working...')
                  spinnerActive = true
                  pushMessage(userReply)
                }
              } else {
                // Agent is done (made changes, gave final instructions, etc.)
                success = true
                const durationSec = ((Date.now() - start) / 1000).toFixed(1)
                if (spinnerActive) {
                  spinner.stop(`Agent completed in ${durationSec}s`)
                  spinnerActive = false
                }

                if (turnText.length > 0) {
                  console.log('')
                  console.log(formatAgentOutput(turnText))
                  console.log('')
                }

                signalDone()
              }
            } else {
              // Extract as much detail as possible from the result message
              const errorDetail =
                message.error_details ??
                message.result ??
                message.last_assistant_message ??
                'Agent execution failed'

              if (session.debug) {
                p.log.warn(
                  `[debug] Result message: ${JSON.stringify(
                    {
                      subtype: message.subtype,
                      is_error: message.is_error,
                      error: message.error,
                      error_details: message.error_details,
                      result: message.result?.slice(0, 500),
                      last_assistant_message:
                        message.last_assistant_message?.slice(0, 500),
                      stop_reason: message.stop_reason,
                    },
                    null,
                    2,
                  )}`,
                )
              }

              const runner =
                session.detectedPackageManager?.execCommand ?? 'npx'
              errorMessage = classifyError(message.error, errorDetail, runner)

              if (spinnerActive) {
                spinner.stop('Agent encountered an error')
                spinnerActive = false
              }

              signalDone()
            }
          }
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Unknown error'
        if (spinnerActive) {
          spinner.stop('Agent connection lost')
          spinnerActive = false
        }

        const runner = session.detectedPackageManager?.execCommand ?? 'npx'
        errorMessage = classifyError(undefined, msg, runner)
        signalDone()
      }

      // Safety net: if we never got a result message
      if (!success && !errorMessage) {
        errorMessage = formatWizardError(
          'The wizard agent exited without completing.',
          'This may indicate a transient issue with the AI service.',
        )
        if (spinnerActive) {
          spinner.stop('Agent disconnected unexpectedly')
        }
      }

      return {
        success,
        output: allCollectedText.join('\n'),
        durationMs: Date.now() - start,
        error: errorMessage,
      }
    },
  }
}
