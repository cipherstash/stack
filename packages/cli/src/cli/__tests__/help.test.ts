import { describe, expect, it } from 'vitest'
import { renderCommandHelp } from '../help.js'

const RUNNER = 'npx stash'

describe('renderCommandHelp', () => {
  it('renders full help for a leaf command with flags and examples', () => {
    const out = renderCommandHelp('eql install', RUNNER)
    expect(out).not.toBeNull()
    // Usage line names the specific command, not the global surface.
    expect(out).toContain('Usage: npx stash eql install [options]')
    // Summary + a representative flag from the descriptor.
    expect(out).toContain(
      'Scaffold stash.config.ts (if missing) and install EQL extensions',
    )
    expect(out).toContain('Options:')
    expect(out).toContain('--force')
    // Value-taking flag renders its placeholder + default annotation.
    expect(out).toContain('--eql-version <2|3>')
    expect(out).toContain('(default: 2)')
  })

  it('surfaces a flag env var alongside its description', () => {
    const out = renderCommandHelp('eql install', RUNNER)
    expect(out).toContain('--database-url <url>')
    expect(out).toContain('Also settable via DATABASE_URL.')
  })

  it('renders a group listing for a command prefix', () => {
    const out = renderCommandHelp('eql', RUNNER)
    expect(out).not.toBeNull()
    expect(out).toContain('Usage: npx stash eql <command> [options]')
    expect(out).toContain('Commands:')
    expect(out).toContain('eql install')
    expect(out).toContain('eql upgrade')
    expect(out).toContain('eql status')
    // Points the user at the per-command help.
    expect(out).toContain('Run `npx stash eql <command> --help`')
    // A group listing shows no Options/Examples block.
    expect(out).not.toContain('Options:')
  })

  it('renders the long description when present', () => {
    const out = renderCommandHelp('auth login', RUNNER)
    expect(out).toContain('device authorization flow')
    expect(out).toContain('Examples:')
    expect(out).toContain('npx stash auth login --region us-east-1 --json')
  })

  it('resolves a subcommand-bearing group prefix (auth)', () => {
    const out = renderCommandHelp('auth', RUNNER)
    expect(out).toContain('Usage: npx stash auth <command> [options]')
    expect(out).toContain('auth login')
    expect(out).toContain('auth regions')
  })

  it('renders a summary-only command without empty Options/Examples', () => {
    const out = renderCommandHelp('wizard', RUNNER)
    expect(out).toContain('Usage: npx stash wizard [options]')
    expect(out).toContain('AI-guided encryption setup')
    expect(out).not.toContain('Options:')
    expect(out).not.toContain('Examples:')
  })

  it('returns null for an unknown command so the caller can fall back', () => {
    expect(renderCommandHelp('bogus', RUNNER)).toBeNull()
    expect(renderCommandHelp('eql bogus', RUNNER)).toBeNull()
  })

  it('threads the package-manager runner into the rendered text', () => {
    const out = renderCommandHelp('init', 'pnpm dlx stash')
    expect(out).toContain('Usage: pnpm dlx stash init [options]')
    expect(out).toContain('pnpm dlx stash init --supabase')
  })
})
