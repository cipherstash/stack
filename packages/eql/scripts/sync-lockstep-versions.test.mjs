import { describe, expect, test } from 'vitest'
import { bumpCargoPackageVersion } from './sync-lockstep-versions.mjs'

const CARGO = `[package]
name = "eql-bindings"
version = "0.4.2"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
`

describe('lockstep Cargo.toml version bump', () => {
  test('rewrites only the [package] version', () => {
    const out = bumpCargoPackageVersion(CARGO, '3.0.0-alpha.7')
    expect(out).toContain('version = "3.0.0-alpha.7"')
    expect(out).toContain('serde = { version = "1", features = ["derive"] }')
    expect(out).not.toContain('version = "0.4.2"')
  })

  test('never rewrites a column-0 version line outside [package]', () => {
    const longFormDeps = `[dependencies.serde]
version = "1"

[package]
name = "eql-bindings"
version = "0.4.2"
`
    const out = bumpCargoPackageVersion(longFormDeps, '3.0.0')
    expect(out).toContain('[dependencies.serde]\nversion = "1"')
    expect(out).toContain('name = "eql-bindings"\nversion = "3.0.0"')
  })

  test('fails loudly when there is no [package] section or version line', () => {
    expect(() => bumpCargoPackageVersion('[dependencies]\nserde = "1"\n', '3.0.0')).toThrow(
      /no \[package\] section/,
    )
    expect(() =>
      bumpCargoPackageVersion('[package]\nname = "eql-bindings"\n', '3.0.0'),
    ).toThrow(/did not find a version line/)
  })

  test('round-trips the real crate manifest shape', () => {
    const real = `[package]
name = "eql-bindings"
version = "3.0.0-alpha.2"
edition = "2021"
license = "MIT"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
`
    const out = bumpCargoPackageVersion(real, '3.0.0-alpha.3')
    expect(out.match(/version = "3\.0\.0-alpha\.3"/g)).toHaveLength(1)
    expect(out).toContain('serde_json = "1"')
  })
})
