import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { runInNewContext } from 'node:vm'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'

const guide = readFileSync(
  new URL('../../docs/migration/protect-dynamodb-to-stack.md', import.meta.url),
  'utf8',
)
const fences = [...guide.matchAll(/```typescript\n([\s\S]*?)\n```/g)].map(
  (match) => match[1],
)
const conversion =
  fences.find((code) => code.includes('ACCESS EXCLUSIVE')) ?? ''
const credentials = fences.find((code) => code.includes('workspaceCrn:')) ?? ''
const setup = `import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'
const customers = encryptedTable('customers', {email: types.TextEq('email'), age: types.IntegerEq('age'), notes: types.Text('notes')})
const users = customers
const client = await Encryption({schemas: [customers]})
`

// Compile the actual customer paste, in the same module-resolution context as
// the example. Diagnostics are assertion data, never a build-error surrogate.
function diagnostics(code: string) {
  const filename = fileURLToPath(
    new URL('../migration-guide/pasted-guide.ts', import.meta.url),
  )
  const options: ts.CompilerOptions = {
    strict: true,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ESNext,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    allowImportingTsExtensions: true,
  }
  const host = ts.createCompilerHost(options)
  const original = host.getSourceFile.bind(host)
  host.getSourceFile = (
    path,
    languageVersion,
    onError,
    shouldCreateNewSourceFile,
  ) =>
    path === filename
      ? ts.createSourceFile(path, code, languageVersion, true)
      : original(path, languageVersion, onError, shouldCreateNewSourceFile)
  const program = ts.createProgram([filename], options, host)
  return ts
    .getPreEmitDiagnostics(program)
    .map((diagnostic) =>
      ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'),
    )
}

type Payload = {
  v: number
  k?: string
  i: { t: string; c: string }
  c: string
  hm?: string
}
const columns = ['email', 'age', 'notes'] as const
const originalPlain = { email: 'ada@example.com', age: 36, notes: 'engines' }

type Fault =
  | 'none'
  | 'wrong-plaintext'
  | 'source-item'
  | 'target-item'
  | 'source-count'
  | 'target-count'
  | 'source-order'
  | 'target-order'
  | 'target-row'
  | 'term-count'
  | 'term-mismatch'

// Execute the actual pasted implementation with only SQL/SDK boundaries faked.
// The SQL fake supplies fixed results, not a second parser or migration engine.
async function executeConversion(fault: Fault = 'none', example = false) {
  const row: Record<string, string | Payload> = { pk: 'ada' }
  for (const column of columns)
    row[column] = {
      v: 2,
      k: 'ct',
      i: { t: 'customers', c: column },
      c: column,
      ...(column === 'notes' ? {} : { hm: column }),
    }
  const target: Record<string, string | Payload> = {
    pk: fault === 'target-row' ? 'wrong-row' : 'ada',
  }
  for (const column of columns)
    target[`${column}_v3`] = { ...(row[column] as Payload), v: 3 }
  const plain = (payload: Payload) =>
    originalPlain[payload.i.c as keyof typeof originalPlain]
  type Input = { id: string; data: Payload }
  type Output =
    | { id: string; data: string | number }
    | { id: string; error: string }
  function bulk(inputs: Input[], generation: 'source' | 'target') {
    const results: Output[] = inputs.map(({ id, data }) => ({
      id,
      data:
        generation === 'target' &&
        fault === 'wrong-plaintext' &&
        data.i.c === 'notes'
          ? 'wrong-but-consistent'
          : plain(data),
    }))
    if (fault === `${generation}-item`)
      results[1] = { id: '1', error: 'synthetic failure' }
    if (fault === `${generation}-count`) results.pop()
    if (fault === `${generation}-order`) results.reverse()
    return { data: results }
  }
  const legacy = {
    decrypt: vi.fn(),
    bulkDecrypt: vi.fn(async (inputs: Input[]) => bulk(inputs, 'source')),
  }
  const stack = {
    decrypt: vi.fn(),
    bulkDecrypt: vi.fn(async (inputs: Input[]) => bulk(inputs, 'target')),
    encryptQuery: vi.fn(async (terms: { column: string }[]) => {
      const results = terms.map(({ column }) => ({
        hm: fault === 'term-mismatch' ? 'wrong' : column,
      }))
      if (fault === 'term-count') results.pop()
      return { data: results }
    }),
  }
  const statements: string[] = []
  const sql = Object.assign(
    (parts: TemplateStringsArray | string) => {
      if (typeof parts === 'string') return parts
      const query = parts.join('?')
      statements.push(query)
      if (query.includes('AS unsupported')) return [{ unsupported: false }]
      if (query.includes('SELECT attname'))
        return ['pk', ...columns].map((attname) => ({
          attname,
          supported_type: true,
        }))
      if (query.includes('SELECT pk'))
        return [query.includes('email_v3::jsonb') ? target : row]
      return []
    },
    {
      begin: async (fn: (tx: unknown) => Promise<void>) => {
        try {
          await fn(sql)
          statements.push('COMMIT')
        } catch (error) {
          statements.push('ROLLBACK')
          throw error
        }
      },
      end: async () => {},
    },
  )
  function executable(source: string) {
    const parsed = ts.createSourceFile(
      'snippet.ts',
      source,
      ts.ScriptTarget.ESNext,
      true,
    )
    const withoutImports = parsed.statements
      .filter(
        (statement) =>
          !ts.isImportDeclaration(statement) &&
          !ts.isExportDeclaration(statement),
      )
      .map((statement) => statement.getFullText(parsed))
      .join('\n')
    return ts
      .transpileModule(withoutImports, {
        compilerOptions: {
          target: ts.ScriptTarget.ESNext,
          module: ts.ModuleKind.ESNext,
        },
      })
      .outputText.replace(/\bexport /g, '')
      .replace(/import.meta.url/g, "'file:///imported.ts'")
  }
  const exampleSource = readFileSync(
    new URL('../migration-guide/postgres.ts', import.meta.url),
    'utf8',
  )
  let failure: unknown
  try {
    await runInNewContext(
      `(async () => {${executable(conversion)}; ${example ? executable(exampleSource) : ''}; await (await ${example ? 'createExample' : 'createConversion'}(sql, 'customers')).migrate()})()`,
      {
        sql,
        csColumn: () => ({
          equality() {
            return this
          },
          dataType() {
            return this
          },
        }),
        csTable: (_name: string, fields: object) => fields,
        encryptedTable: (_name: string, fields: object) => fields,
        types: {
          TextEq: () => 'email',
          IntegerEq: () => 'age',
          Text: () => 'notes',
        },
        protect: async () => legacy,
        Encryption: async () => stack,
        process: {
          argv: [],
          env: { CS_WORKSPACE_CRN: 'test:ap-southeast-2:test' },
        },
      },
    )
  } catch (error) {
    failure = error
  }
  return { failure, legacy, client: stack, statements }
}

describe('pasted migration guide', () => {
  it('G1: the conversion compiles with strict TypeScript', () => {
    expect(diagnostics(conversion)).toEqual([])
  })

  it('G2: refuses a Stack interpretation that disagrees with Protect', async () => {
    const result = await executeConversion('wrong-plaintext')
    expect(
      result.failure,
      'independent source validation must reject a consistently wrong Stack plaintext',
    ).toMatchObject({ message: 'Conversion verification failed in notes' })
    expect(result.statements).toContain('ROLLBACK')
    expect(result.statements.some((query) => query.includes('ANALYZE'))).toBe(
      false,
    )
  })

  it('G5: retains source plaintext and decrypts converted values in bulk', async () => {
    const result = await executeConversion()
    expect(result.failure).toBeUndefined()
    expect(result.legacy.decrypt).not.toHaveBeenCalled()
    expect(result.legacy.bulkDecrypt).toHaveBeenCalledTimes(1)
    expect(result.client.encryptQuery).toHaveBeenCalledTimes(1)
    expect(result.statements).toContain('COMMIT')
    expect(result.client.decrypt).not.toHaveBeenCalled()
    expect(result.client.bulkDecrypt).toHaveBeenCalledTimes(1)
  })

  it('G5: the executable example does not decrypt each source twice under the lock', async () => {
    const result = await executeConversion('none', true)
    expect(result.failure).toBeUndefined()
    expect(result.legacy.decrypt).not.toHaveBeenCalled()
    expect(result.legacy.bulkDecrypt).toHaveBeenCalledTimes(1)
    expect(result.client.encryptQuery).toHaveBeenCalledTimes(1)
    expect(result.statements).toContain('COMMIT')
    expect(result.client.decrypt).not.toHaveBeenCalled()
    expect(result.client.bulkDecrypt).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['source-item', 'Source bulk item failed or reordered'],
    ['target-item', 'Target bulk item failed or reordered'],
    ['source-count', 'Source bulk count mismatch'],
    ['target-count', 'Target bulk count mismatch'],
    ['source-order', 'Source bulk item failed or reordered'],
    ['target-order', 'Target bulk item failed or reordered'],
    ['target-row', 'Conversion verification failed: row identity mismatch'],
    ['term-count', 'Equality term count mismatch'],
    ['term-mismatch', 'Unsupported equality mapping in email'],
  ] as const)('rejects %s before commit', async (fault, message) => {
    const result = await executeConversion(fault)
    expect(result.failure).toMatchObject({ message })
    expect(result.statements).toContain('ROLLBACK')
    expect(result.statements).not.toContain('COMMIT')
    expect(result.statements.some((query) => query.includes('ANALYZE'))).toBe(
      false,
    )
  })

  it('G3: reproduces the complete canonical module without drift', () => {
    const canonical = readFileSync(
      new URL('../migration-guide/postgres-conversion.ts', import.meta.url),
      'utf8',
    )
    expect(conversion).toBe(canonical.trimEnd())
    expect(() =>
      execFileSync(process.execPath, [
        fileURLToPath(
          new URL('../../scripts/sync-migration-guide.mjs', import.meta.url),
        ),
        '--check',
      ]),
    ).not.toThrow()
  })

  it('G6: links the portable example and guide at an immutable revision', () => {
    const readme = readFileSync(
      new URL('../migration-guide/README.md', import.meta.url),
      'utf8',
    )
    const links = [...`${guide}\n${readme}`.matchAll(/\]\(([^)]+)\)/g)]
      .map((match) => match[1])
      .filter(
        (url) =>
          url.includes('migration-guide/') ||
          url.includes('protect-dynamodb-to-stack.md'),
      )
    expect(links.length).toBeGreaterThan(0)
    for (const link of links)
      expect(link).toMatch(
        /^https:\/\/github\.com\/cipherstash\/stack\/blob\/[0-9a-f]{40}\//,
      )
  })

  it('G7: the explicit credentials example compiles without an undeclared env object', () => {
    expect(
      diagnostics(
        setup.replace(
          'const client = await Encryption({schemas: [customers]})',
          '',
        ) + credentials,
      ),
    ).toEqual([])
  })
})
