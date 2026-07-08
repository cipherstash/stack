import { describe, expect, it } from 'vitest'
import { buildManifest } from '../manifest.js'
import { type CommandGroup, registry } from '../registry.js'

describe('buildManifest', () => {
  it('stamps the name and the passed-in version', () => {
    const m = buildManifest('9.9.9')
    expect(m.name).toBe('stash')
    expect(m.version).toBe('9.9.9')
  })

  it('emits every non-hidden command across all groups', () => {
    const m = buildManifest('0.0.0')
    const registryCount = registry
      .flatMap((g) => g.commands)
      .filter((c) => !c.hidden).length
    const manifestCount = m.groups.flatMap((g) => g.commands).length
    expect(manifestCount).toBe(registryCount)
    expect(m.groups.length).toBe(registry.length)
  })

  it('drops commands marked hidden', () => {
    // Drive the hidden filter with a stub so coverage doesn't depend on the
    // live registry happening to contain a hidden command (it currently
    // contains none — a real-registry assertion would be vacuously green).
    const groups: CommandGroup[] = [
      {
        title: 'T',
        commands: [
          { name: 'shown', summary: 's' },
          { name: 'gone', summary: 'g', hidden: true },
        ],
      },
    ]
    const names = buildManifest('0.0.0', groups)
      .groups.flatMap((g) => g.commands)
      .map((c) => c.name)
    expect(names).toEqual(['shown'])
  })

  it('carries examples through into the manifest', () => {
    // The one optional-field passthrough not covered by the auth-login (long +
    // flags) or wizard (all-undefined) cases.
    const init = buildManifest('0.0.0')
      .groups.flatMap((g) => g.commands)
      .find((c) => c.name === 'init')
    expect(init?.examples).toContain('init --supabase')
  })

  it('defensively copies flags so a consumer cannot corrupt the registry', () => {
    const dbUrlOf = (m: ReturnType<typeof buildManifest>) =>
      m.groups
        .flatMap((g) => g.commands)
        .flatMap((c) => c.flags ?? [])
        .find((f) => f.name === '--database-url')

    const first = dbUrlOf(buildManifest('0.0.0'))
    expect(first).toBeDefined()
    // Mutate a manifest flag; the shared registry singleton must be untouched.
    ;(first as { description: string }).description = 'MUTATED'
    expect(dbUrlOf(buildManifest('0.0.0'))?.description).not.toBe('MUTATED')
  })

  it('gives every command a non-empty name and summary', () => {
    for (const group of buildManifest('0.0.0').groups) {
      expect(group.title.length).toBeGreaterThan(0)
      for (const cmd of group.commands) {
        expect(cmd.name.length).toBeGreaterThan(0)
        expect(cmd.summary.length).toBeGreaterThan(0)
      }
    }
  })

  it('includes the worked-example auth login descriptor with its flags', () => {
    const cmds = buildManifest('0.0.0').groups.flatMap((g) => g.commands)
    const authLogin = cmds.find((c) => c.name === 'auth login')
    expect(authLogin).toBeDefined()
    expect(authLogin?.long).toContain('device authorization flow')
    const flagNames = authLogin?.flags?.map((f) => f.name) ?? []
    expect(flagNames).toContain('--region')
    expect(flagNames).toContain('--json')
    expect(flagNames).toContain('--no-open')
  })

  it('surfaces the shared --database-url flag with its env var', () => {
    const eqlInstall = buildManifest('0.0.0')
      .groups.flatMap((g) => g.commands)
      .find((c) => c.name === 'eql install')
    const dbUrl = eqlInstall?.flags?.find((f) => f.name === '--database-url')
    expect(dbUrl?.env).toBe('DATABASE_URL')
    expect(dbUrl?.value).toBe('<url>')
  })

  it('drops undefined optionals so the JSON round-trips cleanly', () => {
    const m = buildManifest('1.2.3')
    const json = JSON.stringify(m)
    expect(JSON.parse(json)).toEqual(m)
    // A summary-only command must not carry empty long/examples/flags keys.
    const wizard = m.groups
      .flatMap((g) => g.commands)
      .find((c) => c.name === 'wizard')
    expect(wizard).toEqual({
      name: 'wizard',
      summary: 'AI-guided encryption setup (reads your codebase)',
    })
  })
})
