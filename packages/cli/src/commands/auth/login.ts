import auth from '@cipherstash/auth'
import * as p from '@clack/prompts'

const { beginDeviceCodeFlow, bindClientDevice } = auth

// Region selection lives in a native-free module so its pure helpers and
// resolution policy stay unit-testable. Re-exported here so existing
// `import { regions, selectRegion, … } from '../auth/login.js'` call sites
// (e.g. the init authenticate step) keep resolving without a change.
export {
  normalizeRegion,
  REGION_ENV_VAR,
  regionSlugs,
  regions,
  resolveRegion,
  selectRegion,
} from './region.js'

export interface LoginOptions {
  /**
   * Emit newline-delimited JSON events instead of pretty clack output, so an
   * agent can capture the device-code URL as data and trigger the flow for a
   * human to complete. Events (one JSON object per line, all on stdout):
   *   { status: 'authorization_required', userCode, verificationUri,
   *     verificationUriComplete, expiresIn }   — emitted immediately
   *   { status: 'authorized', expiresAt, expiresAtIso }  — on success
   *   { status: 'error', code?, message }                — on failure
   */
  json?: boolean
  /**
   * Whether to auto-open the verification URL in the user's browser.
   * Defaults to true (unchanged). `--no-open` sets this false for headless /
   * agent contexts where the human will click the printed URL instead.
   */
  open?: boolean
}

/** Emit one NDJSON auth event to stdout. */
function emitAuthEvent(event: Record<string, unknown>): void {
  console.log(JSON.stringify(event))
}

/** Best-effort `.code` from an `@cipherstash/auth` AuthError, else undefined. */
function authErrorCode(err: unknown): string | undefined {
  return err && typeof err === 'object' && 'code' in err
    ? String((err as { code: unknown }).code)
    : undefined
}

export async function login(
  region: string,
  _referrer: string | undefined,
  opts: LoginOptions = {},
) {
  const json = opts.json ?? false
  const openBrowser = opts.open ?? true

  // Spinner and pretty logs would corrupt the JSON stream — suppress in json mode.
  const s = json ? null : p.spinner()

  // Must be 'cli' — it's the only OAuth client_id registered with CTS.
  // Passing anything else (e.g. `cli-supabase`) causes INVALID_CLIENT.
  let pending: Awaited<ReturnType<typeof beginDeviceCodeFlow>>
  try {
    pending = await beginDeviceCodeFlow(region, 'cli')
  } catch (err) {
    if (json) {
      emitAuthEvent({
        status: 'error',
        code: authErrorCode(err) ?? 'begin_failed',
        message: err instanceof Error ? err.message : 'Unknown error',
      })
      process.exit(1)
    }
    throw err
  }

  if (json) {
    // The "trigger" event — an agent surfaces verificationUriComplete to the
    // human, who completes authorization in their browser.
    emitAuthEvent({
      status: 'authorization_required',
      userCode: pending.userCode,
      verificationUri: pending.verificationUri,
      verificationUriComplete: pending.verificationUriComplete,
      expiresIn: pending.expiresIn,
    })
  } else {
    p.log.info(`Your code is: ${pending.userCode}`)
    p.log.info(`Visit: ${pending.verificationUriComplete}`)
    p.log.info(`Code expires in: ${pending.expiresIn}s`)
  }

  if (openBrowser) {
    const opened = pending.openInBrowser()
    if (!opened && !json) {
      p.log.warn(
        'Could not open browser — please visit the URL above manually.',
      )
    }
  }

  s?.start('Waiting for authorization...')
  let authResult: Awaited<ReturnType<typeof pending.pollForToken>>
  try {
    authResult = await pending.pollForToken()
  } catch (err) {
    s?.stop('Authorization failed.')
    if (json) {
      emitAuthEvent({
        status: 'error',
        code: authErrorCode(err) ?? 'poll_failed',
        message: err instanceof Error ? err.message : 'Unknown error',
      })
      process.exit(1)
    }
    throw err
  }
  s?.stop('Authenticated!')

  const expiresAtIso = new Date(authResult.expiresAt * 1000).toISOString()
  if (json) {
    emitAuthEvent({
      status: 'authorized',
      expiresAt: authResult.expiresAt,
      expiresAtIso,
    })
  } else {
    p.log.info(`Token expires at: ${expiresAtIso}`)
  }
}

export interface BindDeviceOptions {
  /** Emit a JSON event instead of pretty clack output. */
  json?: boolean
}

export async function bindDevice(opts: BindDeviceOptions = {}) {
  const json = opts.json ?? false
  const s = json ? null : p.spinner()
  s?.start('Binding device to the default Keyset...')

  try {
    await bindClientDevice()
    if (json) {
      emitAuthEvent({ status: 'device_bound' })
    } else {
      s?.stop('Your device has been bound to the default Keyset!')
    }
  } catch (error) {
    if (json) {
      emitAuthEvent({
        status: 'error',
        code: authErrorCode(error) ?? 'bind_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      })
    } else {
      s?.stop('Failed to bind your device to the default Keyset!')
      p.log.error(error instanceof Error ? error.message : 'Unknown error')
    }
    process.exit(1)
  }
}
