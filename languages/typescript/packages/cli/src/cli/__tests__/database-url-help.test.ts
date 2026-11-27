/**
 * Every command that takes `--database-url` must say, in its help, which value
 * wins when stash.config.ts sets a literal `databaseUrl`: the flag or the
 * config (#1980). The registry is plain data, so nothing else ties the help to
 * what each command does.
 *
 * `flag` commands never load the config when the flag is given. `config`
 * commands load stash.config.ts through `loadStashConfig`, and a literal
 * `databaseUrl` there replaces the resolver that reads the flag.
 */

import { describe, expect, it } from 'vitest'
import { registry } from '@/cli/registry.js'

type Winner = 'flag' | 'config'

const WINNER: Record<string, Winner> = {
  // main.ts passes `scaffoldConfig: 'skip'` with the flag, and
  // `resolveInstallContext` then never looks for a config.
  'eql install': 'flag',
  // `resolveRepairDatabaseUrl` reads only the flag and DATABASE_URL.
  'eql repair': 'flag',
  // `resolveDiagnosticDatabaseUrl` with `flagWins: true`.
  'eql verify': 'flag',
  // `resolveDiagnosticDatabaseUrl` with `flagWins: false`.
  'eql preflight': 'config',
  'eql upgrade': 'config',
  'eql status': 'config',
  'eql validate': 'config',
  'db test-connection': 'config',
  'schema build': 'config',
}

const CONFIG_WINS =
  'a hand-set literal databaseUrl in the config bypasses the resolver and wins over all of these'

const withFlag = registry
  .flatMap((group) => group.commands)
  .flatMap((command) => {
    const flag = command.flags?.find((f) => f.name === '--database-url')
    return flag ? [{ name: command.name, description: flag.description }] : []
  })

describe('--database-url help', () => {
  it('classifies every command that takes the flag', () => {
    expect(withFlag.map((c) => c.name).sort()).toEqual(
      Object.keys(WINNER).sort(),
    )
  })

  it.each(withFlag)(
    '$name states which value wins',
    ({ name, description }) => {
      if (WINNER[name] === 'config') {
        expect(description).toContain(CONFIG_WINS)
      } else {
        expect(description).not.toContain(CONFIG_WINS)
        expect(description).toMatch(
          /bypasses config loading entirely|never reads stash\.config\.ts/,
        )
      }
    },
  )
})
