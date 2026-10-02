import { describe, expect, it } from 'vitest'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `_build-ffi-artifacts.yml` builds the seven `@cipherstash/protect-ffi`
 * tarballs that `release.yml`'s `publish-ffi` uploads. Every Linux binary's C
 * library is checked before it is packed. Without the check, only a hand-run
 * ffi-preflight sees a glibc-linked musl binary, which fails to load on musl
 * systems such as Alpine Linux, and a release would publish it.
 */

const workflow = readWorkflow('.github/workflows/_build-ffi-artifacts.yml')
const steps = workflow?.jobs?.binaries?.steps ?? []
const runOf = (step) => String(step?.run ?? '')
const named = (name) => steps.findIndex((step) => step?.name === name)

/** A GitHub Actions expression, as the parsed workflow holds it. */
const gha = (expression) => `\${{ ${expression} }}`

describe('_build-ffi-artifacts.yml', () => {
  it('checks the C library of every Linux binary before it is packed', () => {
    const check = steps.findIndex((step) =>
      runOf(step).includes('scripts/check-c-library.sh'),
    )
    const place = named('Place the binding in its platform package')
    const pack = named('Pack the platform package')
    expect(place).toBeGreaterThan(-1)
    expect(check).toBeGreaterThan(place)
    expect(check).toBeLessThan(pack)
    expect(String(steps[check].if)).toContain("runner.os == 'Linux'")
    // The binary that is packed, under the leg's own platform name.
    expect(steps[check].env?.PLATFORM).toBe(gha('matrix.cfg.platform'))
    expect(runOf(steps[check])).toMatch(
      /check-c-library\.sh "\$PLATFORM" "languages\/typescript\/packages\/protect-ffi\/platforms\/\$\{PLATFORM\}\/index\.node"/,
    )
  })
})
