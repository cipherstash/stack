import { createRequestLogger, initLogger } from 'evlog'

/**
 * Log level for the Stack logger.
 *
 * Configured via the `STASH_STACK_LOG` environment variable.
 *
 * - `'error'` — Only errors (default when `STASH_STACK_LOG` is not set).
 * - `'info'`  — Info and errors.
 * - `'debug'` — Debug, info, and errors.
 */
export type LogLevel = 'debug' | 'info' | 'error'

const validLevels: readonly LogLevel[] = ['debug', 'info', 'error'] as const

function levelFromEnv(): LogLevel {
  // `process` is absent in a Worker or Deno isolate. This module is reachable
  // from `@cipherstash/stack/adapter-kit` (`src/adapter-kit.ts:60`), which the
  // Supabase, Drizzle and Prisma Next adapters all value-import — an unguarded
  // read here is a ReferenceError at import time on those runtimes. Guard
  // `process.env` too: some partial polyfills define `process` without `env`,
  // where `process.env.STASH_STACK_LOG` would throw just the same.
  const env =
    typeof process === 'undefined' || !process.env
      ? undefined
      : process.env.STASH_STACK_LOG
  if (env && validLevels.includes(env as LogLevel)) return env as LogLevel
  return 'error'
}

function samplingRatesForLevel(level: LogLevel): Record<string, number> {
  // evlog uses sampling rates: 100 = always emit, 0 = never emit
  switch (level) {
    case 'debug':
      return { debug: 100, info: 100, warn: 100, error: 100 }
    case 'info':
      return { debug: 0, info: 100, warn: 100, error: 100 }
    case 'error':
    default:
      return { debug: 0, info: 0, warn: 0, error: 100 }
  }
}

let initialized = false

/**
 * Initialize the Stack logger.
 *
 * The log level is read from the `STASH_STACK_LOG` environment variable.
 * When the variable is not set, the default is `'error'` (errors only).
 *
 * @internal
 */
export function initStackLogger(): void {
  if (initialized) return
  initialized = true

  const level = levelFromEnv()
  const rates = samplingRatesForLevel(level)

  initLogger({
    env: { service: '@cipherstash/stack' },
    enabled: true,
    sampling: { rates },
  })
}

// Auto-init with defaults on first import
initStackLogger()

export { createRequestLogger }

// Stringify only the first arg (the message string); drop subsequent args
// which may contain sensitive objects (e.g. encryptConfig, plaintext).
function safeMessage(args: unknown[]): string {
  return typeof args[0] === 'string' ? args[0] : ''
}

// Logger for simple one-off logs used across Stack interfaces.
export const logger = {
  debug(...args: unknown[]) {
    const log = createRequestLogger()
    log.set({
      level: 'debug',
      source: '@cipherstash/stack',
      message: safeMessage(args),
    })
    log.emit()
  },
  info(...args: unknown[]) {
    const log = createRequestLogger()
    log.set({ source: '@cipherstash/stack' })
    log.info(safeMessage(args))
    log.emit()
  },
  warn(...args: unknown[]) {
    const log = createRequestLogger()
    log.warn(safeMessage(args))
    log.emit()
  },
  error(...args: unknown[]) {
    const log = createRequestLogger()
    log.error(safeMessage(args))
    log.emit()
  },
}
