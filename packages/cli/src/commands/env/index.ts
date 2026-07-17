import { chmodSync, existsSync, writeFileSync } from 'node:fs'
import { basename, resolve } from 'node:path'
import auth from '@cipherstash/auth'
import * as p from '@clack/prompts'
import { z } from 'zod'
import { CliExit } from '../../cli/exit.js'
import { isInteractive } from '../../config/tty.js'
import { messages } from '../../messages.js'
import { emitJsonError, emitJsonEvent } from '../auth/events.js'
import { detectPackageManager, runnerCommand } from '../init/utils.js'

const { DeviceSessionStrategy } = auth

/**
 * All human-facing chrome (intro, spinner, prompts, logs) is routed to
 * STDERR. Stdout carries exactly one thing: the dotenv block (or, with
 * `--json`, the NDJSON events) — so `stash env > prod.env` and pipes into
 * dotenv consumers stay clean, and prompts remain visible on the terminal
 * even when stdout is redirected.
 */
const CHROME = { output: process.stderr } as const

export interface EnvOptions {
  /**
   * Write the emitted block to a file instead of stdout. `true` uses the
   * default `.env.production.local`; a string names the target path.
   */
  write?: boolean | string
  /** Name for the minted access key + ZeroKMS client. Required non-interactively. */
  name?: string
  /** True when `--name` was passed with no value (argv put it in the boolean flags). */
  nameMissingValue?: boolean
  /** A stray positional argument (e.g. `stash env my-app`) — rejected with guidance. */
  unexpectedArg?: string
  /** Emit NDJSON events instead of a dotenv block. Implies no prompts. */
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
 * The access key is minted with the **member** role — pinned in the request
 * AND asserted on the response; the CLI deliberately has no `--role` (admin
 * keys belong in the dashboard, where they're visible). The key is returned
 * exactly once by CTS; we print it and never persist it (except via an
 * explicit `--write`).
 *
 * Ordering is deliberate, and everything that can refuse without server
 * state does so BEFORE minting: argv problems, the key name, and the
 * `--write` overwrite decision are all resolved first, so a refusal never
 * discards a minted credential. Within the mint, the ZeroKMS client is
 * created before the access key, so the only partial-failure leftover is an
 * inert client record — never an unaccounted-for live credential.
 *
 * Exits via {@link CliExit} (never deep `process.exit`) so run() records the
 * outcome for telemetry.
 */
export async function envCommand(options: EnvOptions = {}): Promise<void> {
  const json = options.json ?? false
  const runner = runnerCommand(detectPackageManager(), '').trim()
  const cliRef = `${runner} stash`

  if (!json) p.intro(`${cliRef} env`, CHROME)

  try {
    await runEnv(options, json, cliRef)
  } catch (err) {
    // CliExit(0) from a cancel path — already rendered; just unwind.
    if (err instanceof CliExit) throw err
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
      p.log.error(failure.message, CHROME)
      if (failure.hint) {
        p.log.info(failure.hint.replaceAll('{cli}', cliRef), CHROME)
      }
    }
    throw new CliExit(1)
  }
}

async function runEnv(
  options: EnvOptions,
  json: boolean,
  cliRef: string,
): Promise<void> {
  // Everything refusable without server state fails BEFORE minting: argv
  // shape, the key name, and the --write overwrite decision. This ordering
  // is load-bearing — the access key is shown exactly once, so no local
  // refusal may run after it exists (and it keeps the failure paths
  // credential-free, which is what the e2e suite exercises).
  if (options.unexpectedArg) {
    throw new MintError(
      'unexpected_argument',
      `${messages.env.unexpectedArgument} '${options.unexpectedArg}' — pass the credential name with --name (e.g. \`${cliRef} env --name ${options.unexpectedArg}\`).`,
    )
  }
  if (options.nameMissingValue) {
    throw new MintError(
      'name_requires_value',
      `${messages.env.nameRequiresValue} — e.g. \`${cliRef} env --name my-app-prod\`.`,
    )
  }

  const keyName = await resolveKeyName(options, json, cliRef)
  const writeTarget = await resolveWriteTarget(options, json)

  const s = json ? null : p.spinner(CHROME)
  s?.start('Minting deployment credentials...')
  let creds: MintedCredentials
  try {
    creds = await mintCredentials(keyName)
  } catch (err) {
    s?.stop('Could not mint deployment credentials.')
    throw err
  }
  s?.stop('Deployment credentials minted.')

  const block = formatEnvBlock(creds, cliRef)

  if (writeTarget) {
    writeEnvFile(writeTarget, block)
    if (json) {
      // Deliberately secret-free: the secrets are in the 0600 file, so the
      // machine-readable confirmation never lands them in a captured log.
      emitJsonEvent({
        status: 'written',
        path: writeTarget,
        keyName: creds.keyName,
        workspaceCrn: creds.workspaceCrn,
        clientId: creds.clientId,
      })
      return
    }
    p.log.success(`Wrote ${writeTarget}`, CHROME)
    p.log.warn(
      'This file contains live secrets — keep it out of version control.',
      CHROME,
    )
    p.outro('Done!', CHROME)
    return
  }

  if (json) {
    emitJsonEvent({ status: 'minted', ...creds })
    return
  }

  // Stdout carries the block and nothing else (chrome is on stderr), so
  // users can redirect or pipe it straight into a secret store.
  console.log(block)
  p.outro('Done!', CHROME)
}

// ---------------------------------------------------------------------------
// Pre-mint resolution: key name and --write target
// ---------------------------------------------------------------------------

async function resolveKeyName(
  options: EnvOptions,
  json: boolean,
  cliRef: string,
): Promise<string> {
  const explicit = options.name?.trim()
  if (explicit) return explicit

  if (json || !isInteractive()) {
    throw new MintError(
      'missing_name',
      `${messages.env.missingName} — pass --name <name> (e.g. \`${cliRef} env --name my-app-prod\`).`,
    )
  }

  const answer = await p.text({
    message: 'Name for this deployment credential',
    initialValue: suggestKeyName(),
    validate: (value) =>
      value.trim().length === 0 ? 'A name is required.' : undefined,
    ...CHROME,
  })
  if (p.isCancel(answer)) {
    p.cancel('Cancelled.', CHROME)
    throw new CliExit(0)
  }
  return answer.trim()
}

/**
 * Resolve and PREFLIGHT the `--write` target before anything is minted: a
 * refused or declined overwrite must never discard a shown-exactly-once
 * credential.
 */
async function resolveWriteTarget(
  options: EnvOptions,
  json: boolean,
): Promise<string | null> {
  if (!options.write) return null
  const target = resolve(
    process.cwd(),
    typeof options.write === 'string' ? options.write : '.env.production.local',
  )
  if (!existsSync(target)) return target

  if (json || !isInteractive()) {
    throw new MintError(
      'write_conflict',
      `${target} already exists — refusing to overwrite non-interactively. Remove it first, or pass a different path to --write.`,
    )
  }
  const overwrite = await p.confirm({
    message: `${target} already exists. Overwrite?`,
    initialValue: false,
    ...CHROME,
  })
  if (p.isCancel(overwrite) || !overwrite) {
    p.cancel('Aborted — nothing was minted.', CHROME)
    throw new CliExit(0)
  }
  return target
}

/** Default key name: the project directory, sanitised, e.g. `my-app-prod`. */
function suggestKeyName(): string {
  const dir = basename(process.cwd())
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return `${dir || 'app'}-prod`
}

/**
 * Write the dotenv block with owner-only permissions. `writeFileSync`'s
 * `mode` only applies when the file is CREATED, so an overwrite of an
 * existing (possibly 0644) file must be followed by an explicit chmod for
 * the documented 0600 guarantee to hold.
 */
function writeEnvFile(target: string, block: string): void {
  writeFileSync(target, block, { encoding: 'utf-8', mode: 0o600 })
  chmodSync(target, 0o600)
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

// The API responses cross an ownership boundary — CTS/ZeroKMS version these
// shapes, not this repo — so each one is validated before any field reaches
// the emitted env block. An `as`-cast here would print `undefined` into a
// credentials file after a live, shown-exactly-once key was already minted.
const workspaceListSchema = z.array(z.object({ id: z.string() }).passthrough())
const workspaceRegionSchema = z.object({ region: z.string().min(1) })
const createClientSchema = z
  .object({ id: z.string().min(1), client_key: z.string().min(1) })
  .passthrough()
const accessKeySchema = z
  .object({ accessKey: z.string().min(1), role: z.string().optional() })
  .passthrough()

/** Standard padded base64 — rejected BEFORE Node's lenient decoder can turn
 *  a hex/enveloped/garbled key into plausible-looking wrong bytes. */
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/

function parsed<T>(schema: z.ZodType<T>, data: unknown, what: string): T {
  const result = schema.safeParse(data)
  if (!result.success) {
    const issue = result.error.issues[0]
    throw new MintError(
      'unexpected_response',
      `Unexpected ${what} response shape (${issue ? `${issue.path.join('.') || '<root>'}: ${issue.message}` : 'invalid'}) — the service API may have changed; check for a newer CLI release.`,
    )
  }
  return result.data
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
  //    The list is validated loosely (only `id`), then OUR workspace
  //    strictly — an unrelated malformed entry must not block the mint.
  const wsResponse = await apiFetch(`${ctsBase}/api/workspaces`, token)
  if (!wsResponse.ok) {
    throw await httpError(
      'list_workspaces_failed',
      'list workspaces',
      wsResponse,
    )
  }
  const workspaces = parsed(
    workspaceListSchema,
    await wsResponse.json(),
    'workspace list',
  )
  const workspace = workspaces.find((w) => w.id === workspaceId)
  if (!workspace) {
    throw new MintError(
      'workspace_not_found',
      `Workspace ${workspaceId} is not in your workspace list — your session may be stale.`,
      LOGIN_HINT,
    )
  }
  const { region } = parsed(workspaceRegionSchema, workspace, 'workspace')
  const workspaceCrn = `crn:${region}:${workspaceId}`

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
  const client = parsed(
    createClientSchema,
    await clientResponse.json(),
    'create-client',
  )
  // ZeroKMS returns the key material base64-encoded; emit hex, the historical
  // CS_CLIENT_KEY format that every released SDK accepts (base64 tolerance
  // only landed in cipherstash-client 0.40). Node's base64 decoder is
  // lenient, so the format is checked first — silently transcoding a
  // non-base64 value would emit a plausible-looking but corrupt key.
  if (!BASE64.test(client.client_key) || client.client_key.length % 4 !== 0) {
    throw new MintError(
      'unexpected_response',
      'ZeroKMS returned client key material in an unexpected encoding — refusing to emit a possibly-corrupt CS_CLIENT_KEY. Check for a newer CLI release.',
    )
  }
  const clientKey = Buffer.from(client.client_key, 'base64').toString('hex')

  // 4. Access key — CS_CLIENT_ACCESS_KEY. The member role is pinned in the
  //    request (CTS also defaults to member) AND asserted on the response:
  //    the docs promise this command cannot mint anything stronger, so a
  //    server that returns a different role fails the command rather than
  //    silently handing out an over-privileged credential.
  const keyResponse = await apiFetch(`${ctsBase}/api/access-keys`, token, {
    method: 'POST',
    body: JSON.stringify({ keyName, workspaceId, role: 'member' }),
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
  const accessKeyBody = parsed(
    accessKeySchema,
    await keyResponse.json(),
    'access key',
  )
  if (accessKeyBody.role && accessKeyBody.role.toLowerCase() !== 'member') {
    throw new MintError(
      'unexpected_role',
      `CTS returned a '${accessKeyBody.role}' access key where member was requested — refusing to emit it. Revoke '${keyName}' in the dashboard.`,
    )
  }

  return {
    keyName,
    workspaceCrn,
    clientId: client.id,
    clientKey,
    accessKey: accessKeyBody.accessKey,
  }
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
