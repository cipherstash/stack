import * as p from '@clack/prompts'
import { isInteractive } from '../../../config/tty.js'
import type { InitProvider, InitState, InitStep } from '../types.js'

/**
 * Resolve whether the user queries encrypted data via CipherStash Proxy or
 * directly via the SDK. Captured as a flag (--proxy / --no-proxy) or an
 * interactive prompt, and stored on state.usesProxy.
 *
 * The prompt is non-blocking: cancellation falls back to false (SDK-only,
 * the default). In non-interactive contexts without a flag, defaults to false
 * and logs an info message.
 */
export const resolveProxyChoiceStep: InitStep = {
  id: 'resolve-proxy-choice',
  name: 'Resolve proxy choice',
  async run(state: InitState, _provider: InitProvider): Promise<InitState> {
    // If the flag was already set by the user, use it
    if (state.usesProxy !== undefined) {
      return state
    }

    // Prompt only when it's safe to: stdin is a real TTY and we're not in CI.
    // Via the shared `isInteractive()` (config/tty.ts) so this gate matches
    // every other prompt gate. Keying off `process.stdout.isTTY` was wrong on
    // both counts — it ignored CI entirely (a runner with an allocated TTY
    // blocked here forever), and a redirected stdin still hangs clack `select`,
    // which reads from /dev/tty.
    if (isInteractive()) {
      const choice = await p.select({
        message:
          'Are you planning to query encrypted data via CipherStash Proxy, or directly via the SDK?',
        options: [
          {
            value: false,
            label: 'Directly via the SDK (most common)',
          },
          {
            value: true,
            label: 'CipherStash Proxy',
          },
        ],
        initialValue: false,
      })

      // Non-blocking: if cancelled, default to false
      if (p.isCancel(choice)) {
        p.log.info(
          'Cancelled proxy choice; defaulting to SDK-only mode (no `stash db push` in default flows).',
        )
        return { ...state, usesProxy: false }
      }

      return { ...state, usesProxy: choice }
    }

    // Non-interactive: default to false and log
    p.log.info(
      'No --proxy flag set; defaulting to SDK-only mode (no `stash db push` in default flows).',
    )
    return { ...state, usesProxy: false }
  },
}
