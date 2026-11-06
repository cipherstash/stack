/**
 * A log-safe description of a failure, for an adapter's error log.
 *
 * An adapter's catch sees errors from every layer below it (query validation,
 * encryption, the database client, the network), and any of their messages may
 * quote a plaintext value. The library promises never to log plaintext, so an
 * error log names the failure's KIND, never its message: the error's class plus
 * the fixed identifiers libraries attach to it. The full message still goes back
 * to the caller, who owns the decision to log it.
 *
 * The identifiers read are `type`, `code` and `authCode`, from the error itself
 * and from a nested `encryptionError` (the shape the Supabase adapter's
 * `EncryptionFailedError` carries). Each must look like an identifier — word
 * characters, `.` or `-`, at most 64 — so a library that puts data into one of
 * these fields cannot smuggle it into the log.
 *
 * @example
 *   describeFailure(new TypeError('value "x" is bad'))   // 'TypeError'
 *   describeFailure({ code: '42883', message: '…' })      // 'object: 42883'
 */
export function describeFailure(err: unknown): string {
  const kind =
    err instanceof Error
      ? (safeIdentifier(err.name) ?? 'Error')
      : err === null
        ? 'null'
        : typeof err
  const ids = [
    ...identifiersOf(err),
    ...identifiersOf(fieldOf(err, 'encryptionError')),
  ]
  return [kind, ...new Set(ids)].join(': ')
}

const IDENTIFIER = /^[\w.-]{1,64}$/

function safeIdentifier(value: unknown): string | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  return typeof value === 'string' && IDENTIFIER.test(value) ? value : undefined
}

function fieldOf(value: unknown, key: string): unknown {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)[key]
    : undefined
}

function identifiersOf(value: unknown): string[] {
  return (['type', 'code', 'authCode'] as const)
    .map((key) => safeIdentifier(fieldOf(value, key)))
    .filter((id): id is string => id !== undefined)
}
