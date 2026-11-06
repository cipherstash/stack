import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from 'vitest'
import { CliExit } from '../../../cli/exit.js'
import { messages } from '../../../messages.js'

// The vendor calls happen in the native binding. Fake it at that boundary, so
// the unit suite is native-free (the binding's own tests drive the static key
// backend for real).
const authMock = vi.hoisted(() => ({
  keysetCreate: vi.fn(),
  keysetRewrap: vi.fn(),
}))
vi.mock('@cipherstash/auth', () => ({ default: authMock }))

const clack = vi.hoisted(() => {
  const spinnerInstance = { start: vi.fn(), stop: vi.fn() }
  return {
    spinnerInstance,
    intro: vi.fn(),
    outro: vi.fn(),
    spinner: vi.fn(() => spinnerInstance),
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), success: vi.fn() },
  }
})
vi.mock('@clack/prompts', () => clack)

const {
  formatBlock,
  keysetCreateCommand,
  keysetRewrapCommand,
  readRecordFile,
  recordVar,
} = await import('../index.js')

const RECORD = 'stack-keyset:AQECAAAAAAAAAAAAAAAAAAAAAAA'

function result(over: Record<string, unknown> = {}) {
  return {
    record: RECORD,
    keysetId: '0f0e0d0c-0b0a-4908-8706-050403020100',
    name: 'users',
    backend: 'aws-kms',
    mode: 'wrapped',
    vendorKey: 'arn:aws:kms:us-east-1:111122223333:key/k',
    ...over,
  }
}

async function expectExit(promise: Promise<void>, code: number) {
  try {
    await promise
  } catch (err) {
    expect(err).toBeInstanceOf(CliExit)
    expect((err as CliExit).code).toBe(code)
    return
  }
  throw new Error(`expected CliExit(${code}), but the command returned`)
}

let stdout: MockInstance<typeof console.log>
let dir: string

beforeEach(() => {
  vi.clearAllMocks()
  stdout = vi.spyOn(console, 'log').mockImplementation(() => {})
  dir = mkdtempSync(join(tmpdir(), 'stash-keyset-'))
})

afterEach(() => {
  stdout.mockRestore()
  rmSync(dir, { recursive: true, force: true })
})

const printed = () =>
  stdout.mock.calls.map((call: unknown[]) => String(call[0])).join('\n')
const errors = () =>
  clack.log.error.mock.calls.map((call) => String(call[0])).join('\n')

describe('stash keyset create', () => {
  it('passes the flags to the native binding and prints a dotenv block', async () => {
    authMock.keysetCreate.mockResolvedValue({ data: result() })
    await keysetCreateCommand({
      backend: 'aws',
      vendorKey: 'arn:aws:kms:us-east-1:111122223333:key/k',
      mode: 'wrapped',
      name: 'users',
    })
    expect(authMock.keysetCreate).toHaveBeenCalledWith({
      backend: 'aws',
      vendorKey: 'arn:aws:kms:us-east-1:111122223333:key/k',
      mode: 'wrapped',
      name: 'users',
    })
    const out = printed()
    expect(out).toContain(`CS_KEYSET_RECORD_USERS=${RECORD}`)
    expect(out).toContain('# backend: aws-kms, mode: wrapped')
    // Stdout carries only the block: every line is a comment, blank or VAR=.
    for (const line of out.split('\n')) {
      expect(
        line === '' || line.startsWith('#') || /^[A-Z_]+=/.test(line),
      ).toBe(true)
    }
  })

  it('refuses missing flags before loading the binding', async () => {
    await expectExit(keysetCreateCommand({ backend: 'aws' }), 1)
    expect(errors()).toContain(messages.keyset.missingCreateFlags)
    expect(errors()).toContain('--vendor-key, --mode')
    expect(authMock.keysetCreate).not.toHaveBeenCalled()
  })

  it('refuses an unknown backend and says ZeroKMS needs no keyset', async () => {
    await expectExit(
      keysetCreateCommand({
        backend: 'zerokms',
        vendorKey: 'k',
        mode: 'derived',
      }),
      1,
    )
    expect(errors()).toContain(messages.keyset.unknownBackend)
    const hints = clack.log.info.mock.calls.map((call) => String(call[0]))
    expect(hints).toContain(messages.keyset.zeroKmsNote)
  })

  it('refuses wrapped data keys on the static backend', async () => {
    await expectExit(
      keysetCreateCommand({
        backend: 'static',
        vendorKey: 'k',
        mode: 'wrapped',
      }),
      1,
    )
    expect(errors()).toContain(messages.keyset.staticDerivedOnly)
    expect(authMock.keysetCreate).not.toHaveBeenCalled()
  })

  it('takes a variable NAME in --key-env, never a key', async () => {
    await expectExit(
      keysetCreateCommand({
        backend: 'static',
        vendorKey: 'k',
        mode: 'derived',
        keyEnv: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
      }),
      1,
    )
    expect(errors()).toContain('NAME of an environment variable')
    // The refused value is not echoed.
    expect(errors()).not.toContain('AAECAwQF')

    await expectExit(
      keysetCreateCommand({
        backend: 'aws',
        vendorKey: 'k',
        mode: 'wrapped',
        keyEnv: 'CS_STATIC_KEY',
      }),
      1,
    )
    expect(errors()).toContain('--key-env is only for --backend static')
  })

  it('refuses a name with a control character', async () => {
    await expectExit(
      keysetCreateCommand({
        backend: 'aws',
        vendorKey: 'k',
        mode: 'wrapped',
        name: 'a\nCS_X=1',
      }),
      1,
    )
    expect(authMock.keysetCreate).not.toHaveBeenCalled()
  })

  it('reports a flag that lost its value', async () => {
    await expectExit(keysetCreateCommand({}, ['out']), 1)
    expect(errors()).toContain('--out requires a value')
  })

  it('maps a native failure to an error and a hint', async () => {
    const error = new Error(
      'Could not configure the aws-kms client from the environment: no region',
    )
    authMock.keysetCreate.mockResolvedValue({
      failure: { type: 'VENDOR_CONFIG', error, vendor: 'aws-kms' },
    })
    await expectExit(
      keysetCreateCommand({ backend: 'aws', vendorKey: 'k', mode: 'wrapped' }),
      1,
    )
    expect(errors()).toContain('no region')
    const hints = clack.log.info.mock.calls.map((call) => String(call[0]))
    expect(hints).toContain(messages.keyset.vendorConfigHint)
  })

  it('emits the --json error envelope with the native code', async () => {
    authMock.keysetCreate.mockResolvedValue({
      failure: {
        type: 'VENDOR_ERROR',
        kind: 'AccessDenied',
        error: new Error('denied'),
      },
    })
    await expectExit(
      keysetCreateCommand({
        backend: 'aws',
        vendorKey: 'k',
        mode: 'wrapped',
        json: true,
      }),
      1,
    )
    const event = JSON.parse(printed())
    expect(event).toMatchObject({
      status: 'error',
      code: 'vendor_error',
      message: 'denied',
    })
    expect(event.hint).toContain('credentials')
  })

  it('prints a generated static key and warns that it is a secret', async () => {
    authMock.keysetCreate.mockResolvedValue({
      data: result({
        backend: 'static',
        mode: 'derived',
        name: undefined,
        vendorKey: 'dev-key',
        generatedStaticKey: 'c2VjcmV0LXN0YXRpYy1rZXktZm9yLXRlc3Rpbmc=',
      }),
    })
    await keysetCreateCommand({
      backend: 'static',
      vendorKey: 'dev-key',
      mode: 'derived',
    })
    expect(authMock.keysetCreate).toHaveBeenCalledWith({
      backend: 'static',
      vendorKey: 'dev-key',
      mode: 'derived',
    })
    const out = printed()
    expect(out).toContain(`CS_KEYSET_RECORD=${RECORD}`)
    expect(out).toContain(
      'CS_STATIC_KEY=c2VjcmV0LXN0YXRpYy1rZXktZm9yLXRlc3Rpbmc=',
    )
    expect(clack.log.warn).toHaveBeenCalledWith(
      messages.keyset.generatedStaticKeyWarning,
      expect.anything(),
    )
  })

  it('writes --out with mode 0600, refuses to overwrite without --force', async () => {
    authMock.keysetCreate.mockResolvedValue({
      data: result({ generatedStaticKey: 'c2VjcmV0' }),
    })
    const out = join(dir, 'keyset.env')
    const options = {
      backend: 'aws',
      vendorKey: 'k',
      mode: 'wrapped',
      out,
      json: true,
    }
    await keysetCreateCommand(options)
    expect(statSync(out).mode & 0o777).toBe(0o600)
    expect(readFileSync(out, 'utf-8')).toContain(
      `CS_KEYSET_RECORD_USERS=${RECORD}`,
    )
    // The --json confirmation never carries the static key.
    const event = JSON.parse(printed())
    expect(event).toMatchObject({
      status: 'written',
      path: out,
      staticKeyVar: 'CS_STATIC_KEY',
    })
    expect(JSON.stringify(event)).not.toContain('c2VjcmV0')

    stdout.mockClear()
    await expectExit(keysetCreateCommand(options), 1)
    expect(JSON.parse(printed())).toMatchObject({ code: 'write_conflict' })

    await keysetCreateCommand({ ...options, force: true })
  })

  it('tells the user when the installed binding is too old', async () => {
    const { keysetCreate } = authMock
    // biome-ignore lint/suspicious/noExplicitAny: removing a mocked method.
    ;(authMock as any).keysetCreate = undefined
    try {
      await expectExit(
        keysetCreateCommand({
          backend: 'aws',
          vendorKey: 'k',
          mode: 'wrapped',
        }),
        1,
      )
      expect(errors()).toContain('has no keyset functions')
    } finally {
      authMock.keysetCreate = keysetCreate
    }
  })
})

describe('stash keyset rewrap', () => {
  it('reads the record from --in and passes the static key variables', async () => {
    const file = join(dir, 'keyset.env')
    writeFileSync(file, formatBlock(result(), 'CS_KEYSET_RECORD_USERS'))
    authMock.keysetRewrap.mockResolvedValue({
      data: result({ vendorKey: 'b' }),
    })
    await keysetRewrapCommand({
      in: file,
      vendorKey: 'b',
      keyEnv: 'OLD_KEY',
      newKeyEnv: 'NEW_KEY',
    })
    expect(authMock.keysetRewrap).toHaveBeenCalledWith({
      record: RECORD,
      vendorKey: 'b',
      staticKeyEnv: 'OLD_KEY',
      newStaticKeyEnv: 'NEW_KEY',
    })
    const hints = clack.log.info.mock.calls.map((call) => String(call[0]))
    expect(hints).toContain(messages.keyset.rewrapNote)
  })

  it('maps a refused rewrap to its own code, message and hint', async () => {
    authMock.keysetRewrap.mockResolvedValue({
      failure: {
        type: 'REWRAP_REFUSED',
        error: new Error('native text'),
        help: 'native help',
      },
    })
    await expectExit(
      keysetRewrapCommand({ record: RECORD, vendorKey: 'other', json: true }),
      1,
    )
    const event = JSON.parse(printed())
    expect(event).toMatchObject({
      status: 'error',
      code: 'rewrap_refused',
      message: messages.keyset.rewrapRefused,
      hint: messages.keyset.rewrapRefusedHint,
    })
  })

  it('takes the record as an argument, trimmed', async () => {
    authMock.keysetRewrap.mockResolvedValue({ data: result() })
    await keysetRewrapCommand({ record: `  ${RECORD}\n`, json: true })
    expect(authMock.keysetRewrap).toHaveBeenCalledWith({ record: RECORD })
    expect(JSON.parse(printed())).toMatchObject({
      status: 'rewrapped',
      record: RECORD,
      envVar: 'CS_KEYSET_RECORD_USERS',
    })
  })

  it('refuses no record, two sources, and text that is not a record', async () => {
    await expectExit(keysetRewrapCommand({}), 1)
    expect(errors()).toContain(messages.keyset.missingRecord)
    await expectExit(keysetRewrapCommand({ record: RECORD, in: 'x' }), 1)
    await expectExit(keysetRewrapCommand({ record: 'hello' }), 1)
    expect(authMock.keysetRewrap).not.toHaveBeenCalled()
  })

  it('rewrites the --in file in place with --force', async () => {
    const file = join(dir, 'keyset.env')
    writeFileSync(file, `${RECORD}\n`)
    const next = 'stack-keyset:AQECAQEBAQEBAQEBAQEBAQEBAQE'
    authMock.keysetRewrap.mockResolvedValue({ data: result({ record: next }) })
    await keysetRewrapCommand({ in: file, out: file, force: true })
    expect(readFileSync(file, 'utf-8')).toContain(next)
    expect(statSync(file).mode & 0o777).toBe(0o600)
  })
})

describe('readRecordFile', () => {
  it('refuses a file with no record or with two', () => {
    const none = join(dir, 'none')
    writeFileSync(none, 'FOO=bar\n')
    expect(() => readRecordFile(none)).toThrow('holds no keyset record')
    const two = join(dir, 'two')
    writeFileSync(two, `A=${RECORD}\nB=stack-keyset:BBBB\n`)
    expect(() => readRecordFile(two)).toThrow('holds 2 keyset records')
  })
})

describe('recordVar and formatBlock', () => {
  it('derives the variable from the name', () => {
    expect(recordVar(undefined)).toBe('CS_KEYSET_RECORD')
    expect(recordVar('users')).toBe('CS_KEYSET_RECORD_USERS')
    expect(recordVar('billing-eu 2')).toBe('CS_KEYSET_RECORD_BILLING_EU_2')
    expect(recordVar('---')).toBe('CS_KEYSET_RECORD')
  })

  it('quotes a name from a record so it cannot leave its comment line', () => {
    const block = formatBlock(
      result({ name: 'x\nEVIL=1' }),
      'CS_KEYSET_RECORD_X',
    )
    expect(block.split('\n').some((line) => line.startsWith('EVIL='))).toBe(
      false,
    )
  })
})
