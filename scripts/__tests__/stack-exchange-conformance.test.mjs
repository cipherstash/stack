import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  checkEnvironment,
  writeReport,
} from '../stack-conformance-evidence.mjs'
import {
  CORPUS,
  checkArtifacts,
  checkCorpus,
  checkRows,
  compared,
  GUESTS,
  inFreshDirectory,
  lanes,
  lockedVersions,
  NOT_ENROLLED,
  PROFILE,
  RUNNERS,
  requireGuests,
  requireRunner,
} from '../stack-exchange-conformance.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

const read = (path) => readFileSync(join(REPO_ROOT, path), 'utf8')
const corpus = JSON.parse(read(CORPUS))
const contract = read('conformance/stack-encrypt/exchange-contract.md')

const scratch = []
const tempDir = () => {
  const dir = mkdtempSync(join(tmpdir(), 'stack-exchange-test-'))
  scratch.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of scratch.splice(0))
    rmSync(dir, { recursive: true, force: true })
})

/** A plausible fresh artifact file, to mutate. */
function artifacts(language) {
  const values = Object.fromEntries(
    JSON.parse(read('conformance/stack-encrypt/v1/values.json'))
      .cases.filter((c) => !c.expected_error)
      .map((c) => [c.id, { c: 'ab', terms: {} }]),
  )
  return {
    version: 1,
    profile: PROFILE,
    producer: {
      language,
      sdk: 'x',
      sdk_version: '1',
      backend: language === 'rust' ? 'native' : 'wasi',
      engine: { name: 'stack-encrypt', version: '0.0.0', guest_sha256: null },
      key_source: { kind: 'deterministic', seed: corpus.seed },
      profiles: [PROFILE, 'record-values-v1'],
      capabilities: corpus.required_capabilities,
      toolchain: null,
    },
    values,
    record: Object.fromEntries(
      corpus.record.rows.map((row) => [
        row.id,
        { passthrough: {}, fields: {} },
      ]),
    ),
    blobs: Object.fromEntries(corpus.blob.cases.map((c) => [c.id, 'ab'])),
  }
}

describe('fresh cross-language artifact exchange', () => {
  it('enrolls both directions of every kind for the runners that exist', () => {
    expect(RUNNERS).toEqual(['rust', 'go'])
    expect(NOT_ENROLLED).toEqual(['python', 'typescript'])
    const rows = lanes()
    expect(rows).toHaveLength(8)
    for (const kind of ['values', 'record', 'blobs', 'eql-rows']) {
      expect(rows).toContainEqual({ kind, producer: 'go', consumer: 'rust' })
      expect(rows).toContainEqual({ kind, producer: 'rust', consumer: 'go' })
      expect(contract).toContain(`\`${kind}\``)
    }
    for (const row of rows) {
      expect(RUNNERS).toContain(row.producer)
      expect(RUNNERS).toContain(row.consumer)
      expect(row.producer).not.toBe(row.consumer)
    }
    for (const language of NOT_ENROLLED)
      expect(contract).toMatch(new RegExp(language, 'i'))
  })

  it('reads a corpus that names every lane, and refuses one that drops a lane', () => {
    expect(() => checkCorpus(corpus)).not.toThrow()
    expect(corpus.seed).toMatch(/^[0-9a-f]{64}$/)
    expect(corpus.record.fields.map((f) => f.name)).toEqual([
      ...new Set(corpus.record.fields.map((f) => f.name)),
    ])
    for (const row of corpus.record.rows)
      expect(Object.keys(row.values).sort()).toEqual(
        corpus.record.fields.map((f) => f.name).sort(),
      )
    for (const [path, change] of [
      ['values.corpus', 'other.json'],
      ['record.rows', []],
      ['blob.cases', []],
      ['eql.schema', 'eql_v3'],
      ['eql.fixture', 'packages/eql/tests/encryption/fixtures/missing.json'],
    ]) {
      const changed = structuredClone(corpus)
      const keys = path.split('.')
      let node = changed
      for (const key of keys.slice(0, -1)) node = node[key]
      node[keys.at(-1)] = change
      expect(() => checkCorpus(changed), path).toThrow()
    }
    const noPassthrough = structuredClone(corpus)
    for (const field of noPassthrough.record.fields) field.passthrough = false
    expect(() => checkCorpus(noPassthrough)).toThrow('passthrough')
  })

  it('fails a required lane on a missing or empty guest', () => {
    const base = tempDir()
    expect(() => requireGuests(base)).toThrow(
      `Missing or empty guest: ${GUESTS[0]}`,
    )
    // Present but empty is the shape a failed build leaves behind.
    const empty = join(base, 'empty.wasm')
    writeFileSync(empty, '')
    expect(() => requireGuests(base, ['empty.wasm'])).toThrow(
      'Missing or empty guest: empty.wasm',
    )
    writeFileSync(empty, 'not empty')
    expect(() => requireGuests(base, ['empty.wasm'])).not.toThrow()
    expect(GUESTS).toEqual([
      'encrypt/testdata/stack_encrypt_guest_deterministic.wasm',
      'encrypt/testdata/stack_encrypt_guest_eql_deterministic.wasm',
    ])
  })

  it('fails a required lane on a missing runner', () => {
    expect(() =>
      requireRunner('stack-exchange-runner-that-does-not-exist', ['version']),
    ).toThrow('Missing runner: stack-exchange-runner-that-does-not-exist')
    expect(requireRunner(process.execPath, ['--version'])).toMatch(/^v\d+/)
  })

  it('fails before running anything when the toolchain is absent', () => {
    // With no PATH, neither go nor mise can be found: the script must stop
    // at its own preflight, by name, with no producer or consumer run.
    const result = spawnSync(
      process.execPath,
      ['scripts/stack-exchange-conformance.mjs'],
      {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        env: { HOME: process.env.HOME, PATH: tempDir() },
      },
    )
    expect(result.status).not.toBe(0)
    expect(result.stderr).toMatch(/Missing (or empty guest|runner)/)
    expect(result.stdout).not.toContain('Exchange conformance:')
  })

  it('refuses the EQL fixture-update variable before running anything', () => {
    // TestV4RowsMatchTheCommittedFixture, the Go EQL producer, rewrites
    // v4_rows.json under it.
    for (const value of ['', '0', '1'])
      expect(() => checkEnvironment({ EQL_UPDATE_FIXTURES: value })).toThrow(
        'EQL_UPDATE_FIXTURES',
      )
    const result = spawnSync(
      process.execPath,
      ['scripts/stack-exchange-conformance.mjs'],
      {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        env: { ...process.env, EQL_UPDATE_FIXTURES: '1' },
      },
    )
    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain(
      'Conformance cannot update fixtures: EQL_UPDATE_FIXTURES',
    )
    expect(result.stdout).not.toContain('Exchange conformance:')
  })

  it('keeps the fresh directory and prints its path when the report step fails', () => {
    const parent = tempDir()
    const log = vi.fn()
    let fresh
    expect(() =>
      inFreshDirectory(
        (dir) => {
          fresh = dir
          writeFileSync(join(dir, 'rust.json'), '{}')
          // The report's tail: a lockfile without the engine crates.
          lockedVersions('', ['stack-encrypt'])
        },
        { parent, log },
      ),
    ).toThrow('stack-encrypt is not in the lockfile')
    expect(existsSync(join(fresh, 'rust.json'))).toBe(true)
    expect(log).toHaveBeenCalledWith(
      `Exchange conformance: artifacts kept in ${fresh}`,
    )

    const passed = inFreshDirectory(
      (dir) => writeFileSync(join(dir, 'rust.json'), '{}'),
      { parent, log: vi.fn() },
    )
    expect(existsSync(passed)).toBe(false)
  })

  it('writes the report before the fresh directory is removed', () => {
    // The tail (lockfiles, cargo metadata, git, the report) runs inside the
    // fresh directory's scope, so its failure keeps the artifacts too.
    const script = read('scripts/stack-exchange-conformance.mjs')
    const main = script.slice(script.indexOf('export function main('))
    const scope = main.slice(main.indexOf('inFreshDirectory((fresh) => {'))
    expect(scope).toContain("writeReport('exchange.json', report)")
    expect(scope).toContain('lockedVersions(rootLock')
    expect(main).not.toContain('rmSync(')
    expect(main).not.toContain('mkdtempSync(')
  })

  it('requires nonempty fresh outputs of every kind from the named producer', () => {
    const dir = tempDir()
    const path = join(dir, 'go.json')
    expect(() => checkArtifacts(path, 'go', corpus)).toThrow(
      'Empty fresh output',
    )
    writeFileSync(path, '')
    expect(() => checkArtifacts(path, 'go', corpus)).toThrow(
      'Empty fresh output',
    )
    const good = artifacts('go')
    writeFileSync(path, JSON.stringify(good))
    expect(checkArtifacts(path, 'go', corpus).counts).toEqual({
      values: Object.keys(good.values).length,
      record: corpus.record.rows.length,
      blobs: corpus.blob.cases.length,
    })
    expect(() => checkArtifacts(path, 'rust', corpus)).toThrow(
      'produced by go, expected rust',
    )
    for (const [name, mutate] of [
      ['values', (a) => (a.values = {})],
      ['record', (a) => delete a.record[corpus.record.rows[0].id]],
      ['blobs', (a) => (a.blobs = {})],
      ['profile', (a) => (a.profile = 'other')],
      ['seed', (a) => (a.producer.key_source.seed = '00')],
      [
        'engine',
        (a) => {
          a.producer.engine.version = null
          a.producer.engine.guest_sha256 = null
        },
      ],
      ['sdk', (a) => (a.producer.sdk = '')],
    ]) {
      const bad = artifacts('go')
      mutate(bad)
      writeFileSync(path, JSON.stringify(bad))
      expect(() => checkArtifacts(path, 'go', corpus), name).toThrow()
    }
  })

  it('requires nonempty fresh EQL rows of the fixture table and producer', () => {
    const path = join(tempDir(), 'rows.json')
    expect(() => checkRows(path, 'rust', corpus)).toThrow('Empty fresh output')
    writeFileSync(path, JSON.stringify({ table: 'profiles', rows: [] }))
    expect(() => checkRows(path, 'rust', corpus)).toThrow('not profiles rows')
    writeFileSync(path, JSON.stringify({ table: 'other', rows: [{}] }))
    expect(() => checkRows(path, 'rust', corpus)).toThrow('not profiles rows')
    const producer = {
      language: 'rust',
      sdk: 'eql-bindings',
      sdk_version: '1.0.0',
      backend: 'native',
      engine: { name: 'stack-encrypt', version: '0.0.0', guest_sha256: null },
      schema: 'eql_v4',
    }
    const rows = (p) => ({ producer: p, table: 'profiles', rows: [{}, {}] })
    writeFileSync(path, JSON.stringify(rows(producer)))
    expect(checkRows(path, 'rust', corpus)).toEqual({ rows: 2, producer })
    // A misrouted file, or one with no manifest, is refused.
    expect(() => checkRows(path, 'go', corpus)).toThrow(
      'produced by rust, expected go',
    )
    for (const [name, bad] of [
      ['no producer', undefined],
      ['no sdk', { ...producer, sdk: '' }],
      ['no engine', { ...producer, engine: { name: 'stack-encrypt' } }],
      ['another schema', { ...producer, schema: 'eql_v3' }],
    ]) {
      writeFileSync(path, JSON.stringify(rows(bad)))
      expect(() => checkRows(path, 'rust', corpus), name).toThrow()
    }
  })

  it('reads engine versions from the three lockfiles', () => {
    const lock =
      '[[package]]\nname = "a"\nversion = "1.0.0"\n\n[[package]]\nname = "b"\nversion = "2.0.0"\n\n[[package]]\nname = "b"\nversion = "3.0.0"\n'
    expect(lockedVersions(lock, ['a', 'b'])).toEqual({
      a: ['1.0.0'],
      b: ['2.0.0', '3.0.0'],
    })
    expect(() => lockedVersions(lock, ['c'])).toThrow(
      'c is not in the lockfile',
    )
    for (const path of [
      'Cargo.lock',
      'languages/golang/encrypt/guest/Cargo.lock',
      'packages/eql/Cargo.lock',
    ])
      expect(
        lockedVersions(read(path), ['stack-encrypt', 'vitaminc-aead-frame']),
      ).toBeTruthy()
  })

  it('is the runners the contract and the aggregate task name', () => {
    expect(
      read('packages/stack-encrypt/tests/exchange_conformance.rs'),
    ).toContain('fn fresh_artifact_exchange')
    expect(
      read('languages/golang/encrypt/exchange_conformance_test.go'),
    ).toContain('func TestArtifactExchange(t *testing.T)')
    expect(read('packages/eql/tests/encryption/tests/v4_types.rs')).toContain(
      'async fn rows_rust_seals_open_in_the_go_sdk',
    )
    expect(read('languages/golang/encrypt/eql_v4_test.go')).toContain(
      'func TestV4RowsTheRustSuiteSealedOpenInGo(t *testing.T)',
    )
    const aggregate = read('scripts/stack-conformance.sh')
    expect(aggregate).toContain('node scripts/stack-exchange-conformance.mjs')
    expect(aggregate).toMatch(
      /cargo nextest run[^\n]*--test exchange_conformance/,
    )
    expect(read('mise.toml')).toContain('[tasks."test:conformance:exchange"]\n')
    expect(read('mise.toml')).toContain(
      'run = "node scripts/stack-exchange-conformance.mjs"',
    )
    for (const name of [
      'STACK_EXCHANGE_OUTPUT',
      'STACK_EXCHANGE_INPUT',
      'EQL_V4_RUST_ROWS',
      'test:conformance:exchange',
      'released-version',
    ])
      expect(contract).toContain(name)
    expect(read('conformance/stack-encrypt/README.md')).toContain(
      'exchange-contract.md',
    )
  })

  it('runs the exchange task in required CI and retains its report', () => {
    const workflow = readWorkflow('.github/workflows/tests-golang.yml')
    const job = workflow.jobs['wasi-check']
    expect(job.env.MISE_ENV).toBe('test')
    const steps = job.steps
    const step = steps.findIndex(
      (s) => s.run === 'mise run test:conformance:exchange',
    )
    expect(step).toBeGreaterThan(-1)
    expect(steps[step].if).toBeUndefined()
    expect(steps[step]['continue-on-error']).toBeUndefined()
    expect(steps[step].env.STACK_CONFORMANCE_REPORT_DIR).toBeTruthy()
    for (const guest of [
      'mise run wasm:guest:build:deterministic',
      'mise run wasm:guest:build:eql:deterministic',
    ])
      expect(steps.findIndex((s) => s.run === guest)).toBeLessThan(step)
    expect(
      steps.some(
        (s) =>
          s.uses?.startsWith('actions/upload-artifact@') &&
          s.with?.name === 'exchange-conformance' &&
          s.with['if-no-files-found'] === 'error',
      ),
    ).toBe(true)
    const triggers = workflow.on ?? workflow[true]
    for (const event of ['push', 'pull_request']) {
      for (const path of [
        'scripts/stack-exchange-conformance.mjs',
        'scripts/stack-conformance-evidence.mjs',
        'conformance/stack-encrypt/**',
        'packages/eql/tests/encryption/**',
      ])
        expect(triggers[event].paths).toContain(path)
    }
  })

  it('prints its report and writes it only under the report directory', () => {
    const print = vi.spyOn(process.stdout, 'write').mockReturnValue(true)
    try {
      const dir = join(tempDir(), 'reports')
      writeReport('exchange.json', { a: 1 }, {})
      expect(print).toHaveBeenLastCalledWith('{\n  "a": 1\n}\n')
      expect(() => readFileSync(join(dir, 'exchange.json'))).toThrow()
      writeReport(
        'exchange.json',
        { a: 1 },
        { STACK_CONFORMANCE_REPORT_DIR: dir },
      )
      expect(readFileSync(join(dir, 'exchange.json'), 'utf8')).toBe(
        '{\n  "a": 1\n}\n',
      )
    } finally {
      print.mockRestore()
    }
  })

  it('compares derived query terms in every direction that stores terms', () => {
    for (const lane of lanes()) {
      const what = compared(lane)
      expect(what, `${lane.kind} ${lane.producer}`).not.toMatch(/ciphertext/)
      if (lane.kind !== 'blobs')
        expect(what, `${lane.kind} ${lane.producer}`).toContain(
          "the consumer's derived query terms",
        )
    }
  })
})
