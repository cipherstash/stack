import { chmodSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import { CliExit } from '../../cli/exit.js'
import { messages } from '../../messages.js'
import { emitJsonError, emitJsonEvent } from '../auth/events.js'

/**
 * `stash keyset create` / `stash keyset rewrap` (CIP-5312): keyset records for
 * the key vendor backends (AWS KMS, Google Cloud KMS, Azure Managed HSM, Vault
 * Transit, the static key backend). ZeroKMS users never need them.
 *
 * The vendor calls are made by Rust, through `keysetCreate` / `keysetRewrap`
 * in the `@cipherstash/auth` native binding, with the same vendor clients the
 * Rust and Go SDKs use. Credentials come from each vendor's environment chain;
 * no flag carries a secret. A static key is named by the environment variable
 * that holds it (`--key-env`), never passed as a value.
 *
 * As with `stash env`, every human-facing line goes to STDERR, and stdout
 * carries only the dotenv block (or, with `--json`, one NDJSON event), so
 * `stash keyset create … > keyset.env` stays clean.
 */
const CHROME = { output: process.stderr } as const

/**
 * The `--backend` values: each short name, and the full name that the output
 * (`# backend: …`, the `backend` of `--json`) and the SDKs use. `--backend`
 * takes either, so a value the output gives is a valid input. The Rust side
 * (`BACKENDS` in `@cipherstash/auth`) holds the same table.
 */
export const KEYSET_BACKEND_NAMES = {
  aws: 'aws-kms',
  gcp: 'gcp-kms',
  azure: 'azure-managed-hsm',
  vault: 'vault-transit',
  static: 'static',
} as const

/** The short `--backend` names, in the order the help text lists them. */
export const KEYSET_BACKENDS = Object.keys(KEYSET_BACKEND_NAMES) as Array<
  keyof typeof KEYSET_BACKEND_NAMES
>

/** The full names that are not also a short name. */
const KEYSET_FULL_BACKENDS = Object.values(KEYSET_BACKEND_NAMES).filter(
  (name) => !(KEYSET_BACKENDS as readonly string[]).includes(name),
)

/** Whether `--backend` takes `value`. */
export function isKeysetBackend(value: string): boolean {
  return (
    (KEYSET_BACKENDS as readonly string[]).includes(value) ||
    (KEYSET_FULL_BACKENDS as readonly string[]).includes(value)
  )
}

/**
 * The `--mode` values. `derived` is the only key mode in this release, and
 * the default.
 */
export const KEYSET_MODES = ['derived'] as const

/**
 * The prefix of the dotenv variable the record is printed as. No SDK reads it
 * by itself today: the app passes its value to `encrypt.WithKeysetRecords`
 * (Go) or `KeysetRecord::parse` (Rust).
 */
export const RECORD_VAR = 'CS_KEYSET_RECORD'

/** The dotenv variable a generated static key is printed as. */
export const STATIC_KEY_VAR = 'CS_STATIC_KEY'

/** Every keyset record starts with this. */
const RECORD_PREFIX = 'stack-keyset:'
const RECORD_PATTERN = /stack-keyset:[A-Za-z0-9_-]+/g

// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point.
const CONTROL_CHARS = /[\x00-\x1f\x7f]/

/** The flags shared by both subcommands. */
interface OutputOptions {
  /** Write the block to this file (mode 0600) instead of stdout. */
  out?: string
  /** Overwrite an existing `--out` file. */
  force?: boolean
  /** Emit one NDJSON event instead of a dotenv block. */
  json?: boolean
}

export interface KeysetCreateOptions extends OutputOptions {
  backend?: string
  vendorKey?: string
  mode?: string
  name?: string
  keyEnv?: string
}

export interface KeysetRewrapOptions extends OutputOptions {
  /** The record, as the positional argument. */
  record?: string
  /** A file holding the record (a dotenv block from `--out`, or the bare record). */
  in?: string
  vendorKey?: string
  keyEnv?: string
  newKeyEnv?: string
}

/** A value-taking flag that argv parsing turned into a boolean (no value). */
export type MissingValues = string[]

/** What the native binding returns (`KeysetResult` in `@cipherstash/auth`). */
interface KeysetResult {
  record: string
  keysetId: string
  name?: string
  backend: string
  mode: string
  vendorKey: string
  generatedStaticKey?: string
}

interface KeysetFailure {
  type: string
  error: Error
  help?: string
  vendor?: string
  kind?: string
}

type NativeResult =
  | { data: KeysetResult; failure?: undefined }
  | { data?: undefined; failure: KeysetFailure }

/** An error with a code for the `--json` stream and an optional hint. */
export class KeysetError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly hint?: string,
  ) {
    super(message)
    this.name = 'KeysetError'
  }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

export async function keysetCreateCommand(
  options: KeysetCreateOptions,
  missingValues: MissingValues = [],
): Promise<void> {
  await run('create', options, async () => {
    rejectMissingValues(missingValues)
    const input = validateCreate(options)
    const outPath = resolveOut(options)
    const auth = await loadNative()
    const result = (await auth.keysetCreate(input)) as NativeResult
    return { result: unwrap(result), outPath }
  })
}

export async function keysetRewrapCommand(
  options: KeysetRewrapOptions,
  missingValues: MissingValues = [],
): Promise<void> {
  await run('rewrap', options, async () => {
    rejectMissingValues(missingValues)
    const input = validateRewrap(options)
    const outPath = resolveOut(options)
    const auth = await loadNative()
    const result = (await auth.keysetRewrap(input)) as NativeResult
    return { result: unwrap(result), outPath }
  })
}

/** Unknown `stash keyset <sub>`. */
export function keysetUnknownSubcommand(sub: string | undefined): never {
  p.log.error(
    `${messages.keyset.unknownSubcommand}: ${sub ?? '(none)'}`,
    CHROME,
  )
  p.log.info(messages.keyset.zeroKmsNote, CHROME)
  throw new CliExit(1)
}

// ---------------------------------------------------------------------------
// The run loop: one place renders success and failure for both subcommands
// ---------------------------------------------------------------------------

async function run(
  verb: 'create' | 'rewrap',
  options: OutputOptions,
  body: () => Promise<{ result: KeysetResult; outPath: string | undefined }>,
): Promise<void> {
  const json = options.json ?? false
  if (!json) p.intro(`stash keyset ${verb}`, CHROME)
  try {
    const s = json ? null : p.spinner(CHROME)
    let outcome: { result: KeysetResult; outPath: string | undefined }
    s?.start(
      verb === 'create' ? 'Creating the keyset...' : 'Rewrapping the keyset...',
    )
    try {
      outcome = await body()
    } catch (err) {
      s?.stop(
        verb === 'create'
          ? 'Could not create the keyset.'
          : 'Could not rewrap the keyset.',
      )
      throw err
    }
    s?.stop(verb === 'create' ? 'Keyset created.' : 'Keyset rewrapped.')
    render(verb, outcome.result, outcome.outPath, options)
  } catch (err) {
    if (err instanceof CliExit) throw err
    const failure =
      err instanceof KeysetError
        ? err
        : new KeysetError(
            'keyset_failed',
            err instanceof Error ? err.message : String(err),
          )
    if (json) {
      emitJsonError(failure.code, failure.message, failure.hint)
    } else {
      p.log.error(failure.message, CHROME)
      if (failure.hint) p.log.info(failure.hint, CHROME)
    }
    throw new CliExit(1)
  }
}

function render(
  verb: 'create' | 'rewrap',
  result: KeysetResult,
  outPath: string | undefined,
  options: OutputOptions,
): void {
  const envVar = recordVar(result.name)
  const block = formatBlock(result, envVar)
  const event = {
    keysetId: result.keysetId,
    ...(result.name !== undefined ? { name: result.name } : {}),
    backend: result.backend,
    mode: result.mode,
    vendorKey: result.vendorKey,
    envVar,
    record: result.record,
  }
  const status = verb === 'create' ? 'created' : 'rewrapped'

  if (outPath) {
    writeOut(outPath, block, options.force ?? false)
    if (options.json) {
      // Secret-free, as `stash env --write --json` is: a generated static key
      // is in the 0600 file only.
      emitJsonEvent({
        status: 'written',
        path: outPath,
        ...event,
        ...(result.generatedStaticKey ? { staticKeyVar: STATIC_KEY_VAR } : {}),
      })
      return
    }
    p.log.success(`Wrote ${outPath}`, CHROME)
  } else if (options.json) {
    emitJsonEvent({
      status,
      ...event,
      ...(result.generatedStaticKey
        ? {
            staticKeyVar: STATIC_KEY_VAR,
            staticKey: result.generatedStaticKey,
          }
        : {}),
    })
    return
  } else {
    console.log(block)
  }

  if (result.generatedStaticKey) {
    p.log.warn(messages.keyset.generatedStaticKeyWarning, CHROME)
  }
  p.log.info(
    `No SDK reads ${envVar} by itself: pass its value to encrypt.WithKeysetRecords (Go) or KeysetRecord::parse (Rust).`,
    CHROME,
  )
  if (verb === 'rewrap') {
    p.log.info(messages.keyset.rewrapNote, CHROME)
  }
  p.outro('Done!', CHROME)
}

// ---------------------------------------------------------------------------
// Validation (no native code: these run before the binding loads)
// ---------------------------------------------------------------------------

function rejectMissingValues(missing: MissingValues): void {
  if (missing.length > 0) {
    throw new KeysetError(
      'missing_flag_value',
      `${missing.map((flag) => `--${flag}`).join(', ')} ${missing.length === 1 ? 'requires' : 'require'} a value.`,
    )
  }
}

function validateCreate(options: KeysetCreateOptions) {
  const missing = [
    !options.backend && '--backend',
    !options.vendorKey && '--vendor-key',
  ].filter(Boolean)
  if (missing.length > 0) {
    throw new KeysetError(
      'missing_flag',
      `${messages.keyset.missingCreateFlags}: ${missing.join(', ')}.`,
      'For example: stash keyset create --backend aws --vendor-key <key ARN>',
    )
  }
  const backend = options.backend as string
  if (!isKeysetBackend(backend)) {
    throw new KeysetError(
      'invalid_backend',
      `${messages.keyset.unknownBackend} '${backend}'. Use one of: ${KEYSET_BACKENDS.join(', ')}. The full names ${KEYSET_FULL_BACKENDS.join(', ')} also work.`,
      messages.keyset.zeroKmsNote,
    )
  }
  const mode = options.mode ?? 'derived'
  if (!(KEYSET_MODES as readonly string[]).includes(mode)) {
    throw new KeysetError(
      'invalid_mode',
      `Unknown key mode '${mode}'. Use derived.`,
    )
  }
  if (backend !== 'static' && options.keyEnv !== undefined) {
    throw new KeysetError(
      'invalid_option',
      '--key-env is only for --backend static.',
    )
  }
  rejectControlChars('--vendor-key', options.vendorKey)
  rejectControlChars('--name', options.name)
  rejectEnvName('--key-env', options.keyEnv)
  return {
    backend,
    vendorKey: options.vendorKey as string,
    mode,
    ...(options.name !== undefined ? { name: options.name } : {}),
    ...(options.keyEnv !== undefined ? { staticKeyEnv: options.keyEnv } : {}),
  }
}

function validateRewrap(options: KeysetRewrapOptions) {
  if (options.record !== undefined && options.in !== undefined) {
    throw new KeysetError(
      'invalid_option',
      'Pass the record as an argument or with --in, not both.',
    )
  }
  let record: string
  if (options.in !== undefined) {
    record = readRecordFile(options.in)
  } else if (options.record !== undefined) {
    record = options.record.trim()
  } else {
    throw new KeysetError(
      'missing_record',
      messages.keyset.missingRecord,
      'For example: stash keyset rewrap --in keyset.env --out keyset.env --force',
    )
  }
  if (!record.startsWith(RECORD_PREFIX)) {
    throw new KeysetError(
      'invalid_record',
      `This is not a keyset record: it does not start with ${RECORD_PREFIX}`,
    )
  }
  rejectControlChars('--vendor-key', options.vendorKey)
  rejectEnvName('--key-env', options.keyEnv)
  rejectEnvName('--new-key-env', options.newKeyEnv)
  return {
    record,
    ...(options.vendorKey !== undefined
      ? { vendorKey: options.vendorKey }
      : {}),
    ...(options.keyEnv !== undefined ? { staticKeyEnv: options.keyEnv } : {}),
    ...(options.newKeyEnv !== undefined
      ? { newStaticKeyEnv: options.newKeyEnv }
      : {}),
  }
}

/**
 * Read the one keyset record in `path`: a dotenv block that `--out` wrote, or
 * a file holding the bare record.
 */
export function readRecordFile(path: string): string {
  let text: string
  try {
    text = readFileSync(resolve(process.cwd(), path), 'utf-8')
  } catch (err) {
    throw new KeysetError(
      'read_failed',
      `Could not read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    )
  }
  const records = [...new Set(text.match(RECORD_PATTERN) ?? [])]
  if (records.length === 0) {
    throw new KeysetError(
      'invalid_record',
      `${path} holds no keyset record (no ${RECORD_PREFIX} text).`,
    )
  }
  if (records.length > 1) {
    throw new KeysetError(
      'invalid_record',
      `${path} holds ${records.length} keyset records. Rewrap them one at a time: pass each record as an argument.`,
    )
  }
  return records[0] as string
}

function rejectControlChars(flag: string, value: string | undefined): void {
  if (value !== undefined && CONTROL_CHARS.test(value)) {
    throw new KeysetError(
      'invalid_option',
      `${flag} must not contain newlines or control characters.`,
    )
  }
}

/** `--key-env` names a variable; it never holds the key itself. */
function rejectEnvName(flag: string, value: string | undefined): void {
  if (value !== undefined && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new KeysetError(
      'invalid_option',
      `${flag} takes the NAME of an environment variable (for example ${flag} ${STATIC_KEY_VAR}), not the key itself.`,
    )
  }
}

function resolveOut(options: OutputOptions): string | undefined {
  return options.out === undefined
    ? undefined
    : resolve(process.cwd(), options.out)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/**
 * The dotenv variable for a record: `CS_KEYSET_RECORD`, or
 * `CS_KEYSET_RECORD_<NAME>` for a named keyset.
 */
export function recordVar(name: string | undefined): string {
  const suffix = (name ?? '')
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return suffix ? `${RECORD_VAR}_${suffix}` : RECORD_VAR
}

/**
 * The dotenv block. Values in comments are JSON-quoted, so a name or key
 * reference from a record cannot break out of its comment line.
 */
export function formatBlock(result: KeysetResult, envVar: string): string {
  const lines = [
    '# CipherStash keyset record for a key vendor backend.',
    `# backend: ${result.backend}, mode: ${result.mode}`,
    `# keyset id: ${result.keysetId}${result.name !== undefined ? `, name: ${JSON.stringify(result.name)}` : ''}`,
    `# vendor key: ${JSON.stringify(result.vendorKey)}`,
    '# The record is not secret. Only the vendor key can unwrap its key.',
    `${envVar}=${result.record}`,
  ]
  if (result.generatedStaticKey) {
    lines.push(
      '',
      `# The static key for vendor key ${JSON.stringify(result.vendorKey)}. THIS IS A SECRET:`,
      '# keep it in a secret store. It is the only copy, and without it the keyset cannot be read.',
      `${STATIC_KEY_VAR}=${result.generatedStaticKey}`,
    )
  }
  return lines.join('\n')
}

function writeOut(path: string, block: string, force: boolean): void {
  try {
    // `wx` refuses an existing file atomically; `--force` overwrites it.
    writeFileSync(path, `${block}\n`, {
      encoding: 'utf-8',
      mode: 0o600,
      flag: force ? 'w' : 'wx',
    })
    chmodSync(path, 0o600)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new KeysetError(
        'write_conflict',
        `${path} already exists. Pass --force to overwrite it, or choose another path.`,
      )
    }
    throw new KeysetError(
      'write_failed',
      `Could not write ${path}: ${err instanceof Error ? err.message : String(err)}`,
    )
  }
}

// ---------------------------------------------------------------------------
// The native binding
// ---------------------------------------------------------------------------

interface NativeKeyset {
  keysetCreate(options: unknown): Promise<unknown>
  keysetRewrap(options: unknown): Promise<unknown>
}

async function loadNative(): Promise<NativeKeyset> {
  const mod: { default?: unknown } = await import('@cipherstash/auth')
  const auth = mod.default ?? mod
  if (!hasKeysetFunctions(auth)) {
    throw new KeysetError(
      'native_outdated',
      'The installed @cipherstash/auth has no keyset functions. Install the @cipherstash/auth version this stash release pins.',
    )
  }
  return auth
}

function hasKeysetFunctions(value: unknown): value is NativeKeyset {
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as Record<string, unknown>
  return (
    typeof candidate.keysetCreate === 'function' &&
    typeof candidate.keysetRewrap === 'function'
  )
}

function unwrap(result: NativeResult): KeysetResult {
  if (result.failure) {
    const failure = result.failure
    throw new KeysetError(
      failure.type.toLowerCase(),
      failure.error.message,
      failure.help ?? hintFor(failure),
    )
  }
  return result.data
}

/** A remedy for the failures that have an obvious one. */
function hintFor(failure: KeysetFailure): string | undefined {
  switch (failure.type) {
    case 'VENDOR_CONFIG':
      return messages.keyset.vendorConfigHint
    case 'VENDOR_ERROR':
      return failure.kind === 'AccessDenied'
        ? 'Check that the credentials in this environment may use the vendor key (encrypt and decrypt).'
        : undefined
    default:
      return undefined
  }
}
