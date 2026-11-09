import { resolve } from 'node:path'
import { describe, expect, test } from 'vitest'
import { codecPathFor } from './v4-codec'

// No credentials or database: this only checks where the suite looks for the
// codec `mise run eql:v4:codec` builds.
const eqlRoot = resolve(__dirname, '../../../../../../packages/eql')
const binary = 'debug/examples/v4_codec'

describe('codecPathFor', () => {
  test('defaults to the EQL workspace target directory', () => {
    expect(codecPathFor({})).toBe(resolve(eqlRoot, 'target', binary))
  })

  test('follows an absolute CARGO_TARGET_DIR', () => {
    expect(codecPathFor({ CARGO_TARGET_DIR: '/tmp/cargo-target' })).toBe(
      resolve('/tmp/cargo-target', binary),
    )
  })

  // `eql:v4:codec` runs cargo from `packages/eql`, and cargo resolves a
  // relative CARGO_TARGET_DIR against its working directory.
  test('resolves a relative CARGO_TARGET_DIR against packages/eql', () => {
    expect(codecPathFor({ CARGO_TARGET_DIR: 'build/target' })).toBe(
      resolve(eqlRoot, 'build/target', binary),
    )
  })

  test('EQL_V4_CODEC wins over CARGO_TARGET_DIR', () => {
    expect(
      codecPathFor({
        EQL_V4_CODEC: '/opt/v4_codec',
        CARGO_TARGET_DIR: '/tmp/cargo-target',
      }),
    ).toBe('/opt/v4_codec')
  })
})
