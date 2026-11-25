// The type errors a caller sees. A wrong argument to `encrypt` must name the
// public types, `Value` and `Json`, and never the marker that brands a
// `Json`. `type-tests/` checks that the code does not compile; this suite
// compiles a snippet with the TypeScript compiler and reads the message.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import { afterAll, describe, expect, it } from 'vitest'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const scratch = mkdtempSync(join(tmpdir(), 'recipher-type-messages-'))
afterAll(() => rmSync(scratch, { recursive: true, force: true }))

/** Compiles `source` against the package, and returns its error messages. */
function messages(source: string): string[] {
  const config = ts.getParsedCommandLineOfConfigFile(
    join(root, 'tsconfig.json'),
    {},
    { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} },
  )
  if (config === undefined) {
    throw new Error('tsconfig.json did not parse')
  }
  const file = join(scratch, 'snippet.ts')
  writeFileSync(
    file,
    `import type { Json, Keyset, Value } from ${JSON.stringify(join(root, 'src', 'index.ts'))}\n${source}`,
  )
  const program = ts.createProgram([file], config.options)
  return ts
    .getPreEmitDiagnostics(program, program.getSourceFile(file))
    .map((diagnostic) =>
      ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'),
    )
}

describe('a value that is not a Value', () => {
  it('names Value and Json, not the marker, when passed to encrypt', () => {
    const found = messages(`
declare const keyset: Keyset
const document = { a: 1 }
void keyset.encrypt(document)
void keyset.encrypt({ a: 1 })
const json: Json = document
const value: Value = document
void json
void value
`)
    expect(found).toHaveLength(4)
    const text = found.join('\n')
    expect(text).toContain("parameter of type 'Value'")
    expect(text).toContain("required in type 'Json'")
    expect(text).not.toContain('JsonMarker')
  })
})
