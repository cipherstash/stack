import { existsSync, writeFileSync } from 'node:fs'
import { basename, resolve } from 'node:path'
import auth from '@cipherstash/auth'
import * as p from '@clack/prompts'
import { isInteractive } from '../../config/tty.js'
import { messages } from '../../messages.js'
import { emitJsonError, emitJsonEvent } from '../auth/events.js'
import { detectPackageManager, runnerCommand } from '../init/utils.js'

const { DeviceSessionStrategy } = auth

export interface EnvOptions {
  /** Write the emitted block to `.env.production.local` instead of stdout. */
  write?: boolean
  /** Name for the minted access key + ZeroKMS client. Required non-interactively. */
  name?: string
  /** Emit a single JSON object instead of a dotenv block. Implies no prompts. */
  json?: boolean
}

/**
 * Mint deployment credentials from the local device-code session (CIP-2997,
 * stack#663) and print them as env vars.
 *
 * Uses the CTS + ZeroKMS APIs the dashboard itself uses, authenticated with
 * the device-session token from `stash auth login`:
 *
 * 1. `GET  {cts}/api/workspaces`     → the workspace's region → `CS_WORKSPACE_CRN`
 * 2. `POST {zerokms}/create-client`  → `CS_CLIENT_ID` / `CS_CLIENT_KEY`
 * 3. `POST {cts}/api/access-keys`    → `CS_CLIENT_ACCESS_KEY`
 *
 * The access key is minted with the server-default **member** role — the CLI
 * deliberately has no `--role`: a runtime credential never needs more, and
 * admin keys should be minted in the dashboard where they're visible. The
 * key is returned exactly once by CTS; we print it and never persist it
 * (except via an explicit `--write`).
 *
 * Ordering is deliberate: the ZeroKMS client is created *before* the access
 * key, so the only partial-failure leftover is an inert client record —
 * never an unaccounted-for live credential.
 */
export async function envCommand(options: EnvOptions = {}): Promise<void> {
  const json = options.json ?? false
  const runner = runnerCommand(detectPackageManager(), '').trim()
  const cliRef = `${runner} stash`

  if (!json) p.intro(`${cliRef} env`)

  // Resolve the key name BEFORE touching the profile or the network: the
  // non-interactive missing-name failure must be reachable without
  // credentials (it is what the e2e suite exercises), and an early exit
  // here can never leave partial server-side state behind.
  const keyName = await resolveKeyName(options, json, cliRef)

  const s = json ? null : p.spinner()
  s?.start('Minting deployment credentials...')

  let creds: MintedCredentials
  try {
    creds = await mintCredentials(keyName)
  } catch (err) {
    s?.stop('Could not mint deployment credentials.')
    const failure =
      err instanceof MintError
        ? err
        : new MintError(
            'mint_failed',
            err instanceof Error ? err.message : String(err),
          )
    if (json) {
      emitJsonError(failure.code, failure.message)
    } else {
      p.log.error(failure.message)
      if (failure.hint) p.log.info(failure.hint.replaceAll('{cli}', cliRef))
    }
    process.exit(1)
    return // unreachable; keeps control flow explicit for tests that stub exit
  }

  s?.stop('Deployment credentials minted.')

  if (json) {
    emitJsonEvent({ status: 'minted', ...creds })
    return
  }

  const block = formatEnvBlock(creds, cliRef)

  if (options.write) {
    const target = resolve(process.cwd(), '.env.production.local')
    if (existsSync(target)) {
      if (!isInteractive()) {
        p.log.error(
          `${target} already exists — refusing to overwrite non-interactively. Remove it first, or run without --write and redirect the output yourself.`,
        )
        process.exit(1)
        return
      }
      const overwrite = await p.confirm({
        message: `${target} already exists. Overwrite?`,
        initialValue: false,
      })
      if (p.isCancel(overwrite) || !overwrite) {
        p.cancel('Aborted.')
        return
      }
    }

    // 0600: the file holds two live secrets.
    writeFileSync(target, block, { encoding: 'utf-8', mode: 0o600 })
    p.log.success(`Wrote ${target}`)
    p.log.warn(
      'This file contains live secrets — keep it out of version control.',
    )
    p.outro('Done!')
    return
  }

  // Default: print to stdout so users can pipe into secret stores / CI env.
  // Use `console.log` (not `p.*`) so the output is clean for redirection.
  console.log(block)
  p.outro('Done!')
}

// ---------------------------------------------------------------------------
// Key-name resolution
// ---------------------------------------------------------------------------

async function resolveKeyName(
  options: EnvOptions,
  json: boolean,
  cliRef: string,
): Promise<string> {
  const explicit = options.name?.trim()
  if (explicit) return explicit

  if (json || !isInteractive()) {
    const message = `${messages.env.missingName} — pass --name <name> (e.g. \`${cliRef} env --name my-app-prod\`).`
    if (json) {
      emitJsonError('missing_name', message)
    } else {
      p.log.error(message)
    }
    process.exit(1)
    // process.exit is stubbed in unit tests; throw so the command can't
    // continue with an undefined name there.
    throw new MintError('missing_name', message)
  }

  const suggested = suggestKeyName()
  const answer = await p.text({
    message: 'Name for this deployment credential',
    initialValue: suggested,
    validate: (value) =>
      value.trim().length === 0 ? 'A name is required.' : undefined,
  })
  if (p.isCancel(answer)) {
    p.cancel('Cancelled.')
    process.exit(0)
    throw new MintError('cancelled', 'Cancelled.')
  }
  return answer.trim()
}

/** Default key name: the project directory, sanitised, e.g. `my-app-prod`. */
function suggestKeyName(): string {
  const dir = basename(process.cwd())
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return `${dir || 'app'}-prod`
}

// ---------------------------------------------------------------------------
// Credential minting
// ---------------------------------------------------------------------------

interface MintedCredentials {
  keyName: string
  workspaceCrn: string
  clientId: string
  /** Hex-encoded — the historical `CS_CLIENT_KEY` format every SDK accepts. */
  clientKey: string
  accessKey: string
}

/**
 * Error with a machine-readable code (surfaced on the `--json` stream) and an
 * optional human hint (printed as a follow-up log line; `{cli}` is replaced
 * with the detected runner, e.g. `npx stash`).
 */
class MintError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly hint?: string,
  ) {
    super(message)
    this.name = 'MintError'
  }
}

const LOGIN_HINT = 'Run `{cli} auth login` and try again.'

/** Shape of one workspace in `GET /api/workspaces` (cts-web `UserWorkspace`). */
interface UserWorkspace {
  id: string
  region: string
}

async function mintCredentials(keyName: string): Promise<MintedCredentials> {
  // 1. Device session from ~/.cipherstash (written by `stash auth login`).
  const strategyResult = DeviceSessionStrategy.fromProfile()
  if (strategyResult.failure) {
    throw new MintError(
      'not_logged_in',
      `Not logged in: ${strategyResult.failure.error.message}`,
      LOGIN_HINT,
    )
  }
  const tokenResult = await strategyResult.data.getToken()
  if (tokenResult.failure) {
    throw new MintError(
      'session_invalid',
      `Could not refresh your session: ${tokenResult.failure.error.message}`,
      LOGIN_HINT,
    )
  }
  const { token, workspaceId, issuer, services } = tokenResult.data

  const ctsBase = trimTrailingSlash(issuer)
  const zerokmsUrl = services?.zerokms
  if (!zerokmsUrl) {
    throw new MintError(
      'no_zerokms_service',
      'Your session token carries no ZeroKMS service URL — re-authenticate and try again.',
      LOGIN_HINT,
    )
  }
  const zerokmsBase = trimTrailingSlash(zerokmsUrl)

  // 2. Workspace region → CRN. The region in the workspace listing is
  //    server-authoritative (CTS derives it from the workspace's host), so
  //    this works for self-hosted CTS too — no issuer-hostname parsing.
  const wsResponse = await apiFetch(`${ctsBase}/api/workspaces`, token)
  if (!wsResponse.ok) {
    throw await httpError(
      'list_workspaces_failed',
      'list workspaces',
      wsResponse,
    )
  }
  const workspaces = (await wsResponse.json()) as UserWorkspace[]
  const workspace = workspaces.find((w) => w.id === workspaceId)
  if (!workspace) {
    throw new MintError(
      'workspace_not_found',
      `Workspace ${workspaceId} is not in your workspace list — your session may be stale.`,
      LOGIN_HINT,
    )
  }
  const workspaceCrn = `crn:${workspace.region}:${workspaceId}`

  // 3. ZeroKMS client — CS_CLIENT_ID / CS_CLIENT_KEY. Created BEFORE the
  //    access key (see the ordering note in the command doc).
  const clientResponse = await apiFetch(`${zerokmsBase}/create-client`, token, {
    method: 'POST',
    body: JSON.stringify({
      name: keyName,
      description: `Created by \`stash env\` for deployment`,
    }),
  })
  if (!clientResponse.ok) {
    throw await httpError(
      'create_client_failed',
      'create the ZeroKMS client',
      clientResponse,
    )
  }
  const client = (await clientResponse.json()) as {
    id: string
    client_key: string
  }
  // ZeroKMS returns the key material base64-encoded; emit hex, the historical
  // CS_CLIENT_KEY format that every released SDK accepts (base64 tolerance
  // only landed in cipherstash-client 0.40).
  const clientKey = Buffer.from(client.client_key, 'base64').toString('hex')

  // 4. Access key — CS_CLIENT_ACCESS_KEY. Role deliberately omitted: CTS
  //    defaults to member, and the CLI does not mint anything stronger.
  const keyResponse = await apiFetch(`${ctsBase}/api/access-keys`, token, {
    method: 'POST',
    body: JSON.stringify({ keyName, workspaceId }),
  })
  if (!keyResponse.ok) {
    const leftover = ` (Note: the ZeroKMS client '${keyName}' was already created — it is inert without an access key, but you may want to remove it in the dashboard.)`
    if (keyResponse.status === 403) {
      throw new MintError(
        'not_admin',
        `Creating access keys requires the admin role in this workspace — ask a workspace admin to mint the key in the dashboard, or to grant you admin.${leftover}`,
      )
    }
    const base = await httpError(
      'create_access_key_failed',
      'create the access key',
      keyResponse,
    )
    throw new MintError(
      base.code,
      `${base.message} If the name is already taken, rerun with a different --name.${leftover}`,
    )
  }
  const { accessKey } = (await keyResponse.json()) as { accessKey: string }

  return { keyName, workspaceCrn, clientId: client.id, clientKey, accessKey }
}

function trimTrailingSlash(url: string): string {
  return url.replace(/\/+$/, '')
}

function apiFetch(
  url: string,
  token: string,
  init?: { method?: string; body?: string },
): Promise<Response> {
  return fetch(url, {
    method: init?.method ?? 'GET',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'user-agent': 'stash-cli',
    },
    body: init?.body,
  })
}

/** Build a MintError from a non-2xx response, including the body (which CTS
 *  keeps free of secrets) but never the request's bearer token. */
async function httpError(
  code: string,
  action: string,
  response: Response,
): Promise<MintError> {
  const body = (await response.text().catch(() => '')).slice(0, 500)
  return new MintError(
    code,
    `Could not ${action}: HTTP ${response.status}${body ? ` — ${body}` : ''}`,
  )
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function formatEnvBlock(creds: MintedCredentials, cliRef: string): string {
  return [
    `# Generated by \`${cliRef} env\` — CipherStash deployment credentials ('${creds.keyName}')`,
    '# CS_CLIENT_KEY and CS_CLIENT_ACCESS_KEY are secrets. Do not commit them.',
    `CS_WORKSPACE_CRN=${creds.workspaceCrn}`,
    `CS_CLIENT_ID=${creds.clientId}`,
    `CS_CLIENT_KEY=${creds.clientKey}`,
    `CS_CLIENT_ACCESS_KEY=${creds.accessKey}`,
    '',
  ].join('\n')
}
