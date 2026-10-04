import type {
  ProtectAuthErrorCode,
  ProtectErrorCode,
} from '@cipherstash/protect-ffi'

export function failureMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

export function authFailureCode(
  error: unknown,
): ProtectAuthErrorCode | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const { authCode } = error as { authCode?: unknown }
  return typeof authCode === 'string' ? authCode : undefined
}

export type FailureDiagnostics = {
  code?: ProtectErrorCode
  authCode?: ProtectAuthErrorCode
  help?: string
  url?: string
}

export function failureDiagnostics(
  error: unknown,
  readCode: (error: unknown) => ProtectErrorCode | undefined,
): FailureDiagnostics {
  const diagnostics: FailureDiagnostics = {}

  const code = readCode(error)
  if (code) diagnostics.code = code

  const authCode = authFailureCode(error)
  if (authCode) diagnostics.authCode = authCode

  const { help, url } = (error ?? {}) as { help?: unknown; url?: unknown }
  if (typeof help === 'string' && help !== '') diagnostics.help = help
  if (typeof url === 'string' && url !== '') diagnostics.url = url

  return diagnostics
}
