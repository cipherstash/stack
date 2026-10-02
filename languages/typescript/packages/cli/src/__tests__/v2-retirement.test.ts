import { describe, expect, it } from 'vitest'
import { registry } from '../cli/registry.js'
import { validateInstallFlags } from '../commands/db/install.js'

const commands = registry.flatMap((group) => group.commands)

describe('EQL v2 CLI retirement', () => {
  it('removes Proxy configuration and v2 cutover commands from the manifest', () => {
    const names = commands.map((command) => command.name)

    expect(names).not.toContain('db push')
    expect(names).not.toContain('db activate')
    expect(names).not.toContain('encrypt cutover')
  })

  it('removes generation selection and release downloads from install and upgrade', () => {
    for (const name of ['eql install', 'eql upgrade']) {
      const command = commands.find((candidate) => candidate.name === name)
      const flags = command?.flags?.map((flag) => flag.name) ?? []

      expect(flags).not.toContain('--eql-version')
      expect(flags).not.toContain('--latest')
      expect(flags).not.toContain('--exclude-operator-family')
    }
  })

  it('leaves no consumer of the operator-family flag anywhere in the manifest', () => {
    // `db validate` was the last one: its v2 rule warned that an `ore` index
    // would not support ORDER BY without operator families. EQL v3's install
    // self-adapts, and `eql validate` reasons about the ORE domain instead —
    // so the flag has no remaining meaning on any command.
    for (const command of commands) {
      const flags = command.flags?.map((flag) => flag.name) ?? []
      expect(flags).not.toContain('--exclude-operator-family')
    }
  })

  it('moves validate into the EQL group, leaving `db validate` a hidden alias', () => {
    const names = commands.map((command) => command.name)

    expect(names).toContain('eql validate')
    // The `db` spelling still dispatches (with a deprecation warning), exactly
    // like `db install` / `db upgrade` / `db status` — but it is deliberately
    // absent from the registry, so help and `stash manifest --json` advertise
    // one name.
    expect(names).not.toContain('db validate')
  })

  it('removes the Proxy choice from init', () => {
    const init = commands.find((command) => command.name === 'init')
    const flags = init?.flags?.map((flag) => flag.name) ?? []

    expect(flags).not.toContain('--proxy')
    expect(flags).not.toContain('--no-proxy')
  })

  it('points legacy install requests at the upstream EQL 2.3.1 release', () => {
    const releaseUrl =
      'https://github.com/cipherstash/encrypt-query-language/releases/tag/eql-2.3.1'

    expect(validateInstallFlags({ eqlVersion: '2' })).toContain(releaseUrl)
    expect(validateInstallFlags({ latest: true })).toContain(releaseUrl)
  })

  it('rejects the obsolete operator-family flag because v3 self-adapts', () => {
    expect(validateInstallFlags({ excludeOperatorFamily: true })).toMatch(
      /self-adapts/,
    )
  })
})
