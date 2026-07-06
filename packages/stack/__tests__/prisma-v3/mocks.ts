import type { EncryptionClient } from '@/encryption'

// ---------------------------------------------------------------------------
// Shared mocks for the prisma-v3 suites.
//
// The integration only touches a narrow slice of the encryption client and
// the Prisma client, so both are simulated: the encryption mock produces
// deterministic fake envelopes (carrying the plaintext in `pt` so the fake
// decrypt can undo them), and the Prisma mocks record every call. This pins
// the WIRE ENCODING the integration produces — the part CI can verify
// without a live Postgres + ZeroKMS.
// ---------------------------------------------------------------------------

export type FakeEnvelope = {
  v: 3
  i: { t: string; c: string }
  c: string
  hm: string
  pt: unknown
}

export function fakeEnvelope(value: unknown, column: string): FakeEnvelope {
  const pt = value instanceof Date ? value.toISOString() : value
  return {
    v: 3,
    i: { t: 'tbl', c: column },
    c: `ct:${String(pt)}`,
    hm: `hm:${String(pt)}`,
    pt,
  }
}

export function isFakeEnvelope(value: unknown): value is FakeEnvelope {
  return (
    typeof value === 'object' &&
    value !== null &&
    'pt' in value &&
    'c' in value &&
    'hm' in value
  )
}

/** A chainable operation resolving to `{ data }`, like the real ones. */
function operation<T>(data: T, calls?: OperationCalls) {
  const op = {
    withLockContext: (lockContext: unknown) => {
      calls?.lockContexts.push(lockContext)
      return op
    },
    audit: (config: unknown) => {
      calls?.audits.push(config)
      return op
    },
    then: (
      onfulfilled?: ((value: { data: T }) => unknown) | null,
      onrejected?: ((reason: unknown) => unknown) | null,
    ) => Promise.resolve({ data }).then(onfulfilled, onrejected),
  }
  return op
}

export type OperationCalls = {
  lockContexts: unknown[]
  audits: unknown[]
}

type SchemaLike = {
  build(): { columns: Record<string, unknown> }
  buildColumnKeyMap(): Record<string, string>
}

/**
 * Deterministic mock of the slice of {@link EncryptionClient} the prisma
 * integration consumes. Records lock contexts and audit configs passed to any
 * operation in `calls`.
 */
export function createMockEncryptionClient() {
  const calls: OperationCalls & { encrypted: unknown[] } = {
    lockContexts: [],
    audits: [],
    encrypted: [],
  }

  const encryptedProps = (table: SchemaLike): string[] =>
    Object.keys(table.buildColumnKeyMap())

  const dbName = (table: SchemaLike, prop: string): string =>
    table.buildColumnKeyMap()[prop] ?? prop

  const encryptModel = (model: Record<string, unknown>, table: SchemaLike) => {
    const props = encryptedProps(table)
    const out: Record<string, unknown> = { ...model }
    for (const prop of props) {
      if (!(prop in model)) continue
      const value = model[prop]
      out[prop] =
        value == null ? null : fakeEnvelope(value, dbName(table, prop))
    }
    return out
  }

  const decryptModel = (model: Record<string, unknown>) => {
    const out: Record<string, unknown> = { ...model }
    for (const [key, value] of Object.entries(model)) {
      if (isFakeEnvelope(value)) out[key] = value.pt
    }
    return out
  }

  const client = {
    encrypt: (value: unknown, opts: { column: { getName(): string } }) => {
      const envelope =
        value == null ? null : fakeEnvelope(value, opts.column.getName())
      calls.encrypted.push(envelope)
      return operation(envelope, calls)
    },
    encryptModel: (model: Record<string, unknown>, table: SchemaLike) =>
      operation(encryptModel(model, table), calls),
    bulkEncryptModels: (models: Record<string, unknown>[], table: SchemaLike) =>
      operation(
        models.map((m) => encryptModel(m, table)),
        calls,
      ),
    decryptModel: (model: Record<string, unknown>) =>
      operation(decryptModel(model), calls),
    bulkDecryptModels: (models: Record<string, unknown>[]) =>
      operation(models.map(decryptModel), calls),
  }

  return { client: client as unknown as EncryptionClient, calls }
}

/** An encryption client whose every operation resolves to a failure. */
export function createFailingEncryptionClient(message = 'boom') {
  const failed = () => ({
    withLockContext: () => failed(),
    audit: () => failed(),
    then: (onfulfilled?: ((value: unknown) => unknown) | null) =>
      Promise.resolve({ failure: { message } }).then(onfulfilled),
  })
  const client = {
    encrypt: failed,
    encryptModel: failed,
    bulkEncryptModels: failed,
    decryptModel: failed,
    bulkDecryptModels: failed,
  }
  return client as unknown as EncryptionClient
}

// ---------------------------------------------------------------------------
// Prisma mocks
// ---------------------------------------------------------------------------

/**
 * Minimal stand-in for the generated client's `Prisma` namespace: `sql`
 * captures the template strings + values into an inspectable object, and
 * `DbNull` is a unique sentinel the tests can assert on by identity.
 */
export const PrismaDbNull = Symbol('Prisma.DbNull')

export type CapturedSql = { strings: ReadonlyArray<string>; values: unknown[] }

export const fakePrismaNamespace = {
  sql: (strings: ReadonlyArray<string>, ...values: unknown[]): CapturedSql => ({
    strings,
    values,
  }),
  DbNull: PrismaDbNull,
}

/** Render a captured fragment to a flat SQL string with `$n` placeholders. */
export function renderSql(fragment: CapturedSql): string {
  return fragment.strings.reduce(
    (acc, part, i) => (i === 0 ? part : `${acc}$${i}${part}`),
    '',
  )
}

export type QueryHookArgs = {
  model: string
  operation: string
  args: Record<string, unknown>
  query: (args: Record<string, unknown>) => Promise<unknown>
}

/**
 * Fake Prisma client: `$extends` records the extension and returns a client
 * whose model delegates route through the extension's `$allOperations` hook
 * with a caller-provided base `query` implementation.
 */
export function createFakePrismaClient(
  baseQuery: (call: {
    model: string
    operation: string
    args: Record<string, unknown>
  }) => unknown,
) {
  const captured: {
    extension?: {
      query?: {
        $allModels?: {
          $allOperations?: (call: QueryHookArgs) => Promise<unknown>
        }
      }
    }
    rawQueries: unknown[]
  } = { rawQueries: [] }

  const client = {
    $extends(extension: NonNullable<typeof captured.extension>) {
      captured.extension = extension
      return {
        __extended: true,
        /** Test harness: invoke an operation as Prisma's runtime would. */
        async run(
          model: string,
          operation: string,
          args: Record<string, unknown>,
        ) {
          const hook = captured.extension?.query?.$allModels?.$allOperations
          const query = (a: Record<string, unknown>) =>
            Promise.resolve(baseQuery({ model, operation, args: a }))
          if (!hook) return query(args)
          return hook({ model, operation, args, query })
        },
      }
    },
    $queryRaw(query: unknown) {
      captured.rawQueries.push(query)
      return Promise.resolve(
        baseQuery({ model: '$raw', operation: '$queryRaw', args: { query } }),
      )
    },
  }

  return { client, captured }
}
