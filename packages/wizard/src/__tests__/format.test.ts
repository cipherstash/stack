import pc from 'picocolors'
import { describe, expect, it } from 'vitest'
import { formatAgentOutput } from '../lib/format.js'

describe('formatAgentOutput', () => {
  it('renders h2 headings as bold cyan', () => {
    const result = formatAgentOutput('## Current Status')
    expect(result).toContain(pc.bold(pc.cyan('Current Status')))
    expect(result).not.toContain('##')
  })

  it('renders h1 headings as bold cyan', () => {
    const result = formatAgentOutput('# Title')
    expect(result).toContain(pc.bold(pc.cyan('Title')))
  })

  it('renders checkmarks with green tick', () => {
    const result = formatAgentOutput('✅ **Already configured:**')
    expect(result).toContain(pc.green('✔'))
    expect(result).toContain(pc.bold('Already configured:'))
  })

  it('renders bullet points with dim dot', () => {
    const result = formatAgentOutput('- CipherStash Stack is installed')
    expect(result).toContain(pc.dim('•'))
    expect(result).toContain('CipherStash Stack is installed')
  })

  it('renders bold bullet labels', () => {
    const result = formatAgentOutput('- **encrypt.ts** — Simple schema')
    expect(result).toContain(pc.bold('encrypt.ts'))
    expect(result).toContain('Simple schema')
  })

  it('renders numbered lists with dim numbers', () => {
    const result = formatAgentOutput('1. First step\n2. Second step')
    expect(result).toContain(pc.dim('1.'))
    expect(result).toContain(pc.dim('2.'))
  })

  it('renders inline code with cyan', () => {
    const result = formatAgentOutput('Run `npm install` to continue')
    expect(result).toContain(pc.cyan('npm install'))
  })

  it('renders bold text', () => {
    const result = formatAgentOutput('This is **important** text')
    expect(result).toContain(pc.bold('important'))
  })

  it('renders code blocks with dim borders', () => {
    const result = formatAgentOutput('```\nconst x = 1\n```')
    expect(result).toContain('┌─')
    expect(result).toContain('└─')
    expect(result).toContain('const x = 1')
  })

  it('handles plain text unchanged', () => {
    const result = formatAgentOutput('Just a regular sentence.')
    expect(result).toContain('Just a regular sentence.')
  })

  it('handles mixed content', () => {
    const input = [
      '## Status',
      '',
      '✅ **Configured:**',
      '- Database is connected',
      '- `stash.config.ts` exists',
      '',
      '## Next Steps',
      '',
      '1. Run `npx drizzle-kit generate`',
      '2. Run `npx stash db push`',
    ].join('\n')

    const result = formatAgentOutput(input)
    // Should contain styled elements, not raw markdown
    expect(result).toContain(pc.bold(pc.cyan('Status')))
    expect(result).toContain(pc.green('✔'))
    expect(result).toContain(pc.cyan('stash.config.ts'))
    expect(result).toContain(pc.bold(pc.cyan('Next Steps')))
    expect(result).toContain(pc.dim('1.'))
  })
})
