import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { CONTEXT_REL_PATH, type ContextFile } from './write-context.js'

/**
 * Validate that a parsed JSON value has the minimum shape callers rely
 * on. We only check the fields downstream code dereferences without
 * a guard — `integration`, `packageManager`, and `schemas`. Other
 * fields (cliVersion, generatedAt, etc.) are informational and absent
 * values won't crash anything.
 *
 * A wider schema check would belong in a runtime validator (zod, etc.);
 * this is the minimum to keep `stash status`, `stash plan`, and `stash
 * impl` from hard-failing on a hand-edited or partial-write file.
 */
function isContextFile(x: unknown): x is ContextFile {
  if (!x || typeof x !== 'object') return false
  const obj = x as Record<string, unknown>
  return (
    typeof obj.integration === 'string' &&
    typeof obj.packageManager === 'string' &&
    Array.isArray(obj.schemas)
  )
}

/**
 * Read the `.cipherstash/context.json` file written by `stash init`.
 * Returns `undefined` when the file is missing, unparseable, or doesn't
 * have the expected shape — both `stash plan` and `stash impl` use that
 * signal to point the user back at `stash init` rather than crashing.
 *
 * Never throws on bad input. Malformed JSON and wrong-shape objects are
 * both treated as "no context."
 */
export function readContextFile(cwd: string): ContextFile | undefined {
  const path = resolve(cwd, CONTEXT_REL_PATH)
  if (!existsSync(path)) return undefined
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf-8')) as unknown
    if (!isContextFile(parsed)) return undefined
    // Normalize usesProxy to a strict boolean: older files lack it and a
    // hand-edited file could hold any JSON value, so coerce to `true` only
    // when it is exactly `true` and `false` otherwise.
    return {
      ...parsed,
      usesProxy: parsed.usesProxy === true,
    }
  } catch {
    return undefined
  }
}
