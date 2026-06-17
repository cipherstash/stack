import { describe, expect, it } from 'vitest'
import { wizardCanUseTool } from '../agent/interface.js'

describe('wizardCanUseTool', () => {
  describe('non-Bash tools — safe paths', () => {
    it('allows Read/Write/Grep on non-sensitive files', () => {
      expect(wizardCanUseTool('Read', { file_path: '/tmp/test.ts' })).toBe(true)
      expect(wizardCanUseTool('Write', { file_path: '/tmp/test.ts' })).toBe(
        true,
      )
      expect(wizardCanUseTool('Grep', { pattern: 'foo', path: '/tmp' })).toBe(
        true,
      )
    })
  })

  describe('sensitive file blocking', () => {
    it('blocks Read on .env files', () => {
      expect(
        wizardCanUseTool('Read', { file_path: '/project/.env' }),
      ).toContain('blocked')
      expect(
        wizardCanUseTool('Read', { file_path: '/project/.env.local' }),
      ).toContain('blocked')
      expect(
        wizardCanUseTool('Read', { file_path: '/project/.env.production' }),
      ).toContain('blocked')
    })

    it('blocks Read on auth.json', () => {
      expect(
        wizardCanUseTool('Read', {
          file_path: '/home/user/.cipherstash/auth.json',
        }),
      ).toContain('blocked')
    })

    it('blocks Read on secretkey.json', () => {
      expect(
        wizardCanUseTool('Read', {
          file_path: '/home/user/.cipherstash/secretkey.json',
        }),
      ).toContain('blocked')
    })

    it('blocks Edit on .env files', () => {
      expect(
        wizardCanUseTool('Edit', { file_path: '/project/.env' }),
      ).toContain('blocked')
    })

    it('blocks Write on .env files', () => {
      expect(
        wizardCanUseTool('Write', { file_path: '/project/.env.local' }),
      ).toContain('blocked')
    })

    it('blocks Grep on sensitive paths', () => {
      expect(
        wizardCanUseTool('Grep', { pattern: 'KEY', path: '/project/.env' }),
      ).toContain('blocked')
      expect(
        wizardCanUseTool('Grep', { pattern: 'token', glob: '*.env.local' }),
      ).toContain('blocked')
    })

    it('blocks Glob for sensitive patterns', () => {
      expect(wizardCanUseTool('Glob', { pattern: '.env' })).toContain('blocked')
      expect(wizardCanUseTool('Glob', { pattern: '.env.local' })).toContain(
        'blocked',
      )
    })
  })

  describe('Bash commands', () => {
    it('allows allowlisted npm commands', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'npm install @cipherstash/stack' }),
      ).toBe(true)
      expect(wizardCanUseTool('Bash', { command: 'npm run build' })).toBe(true)
    })

    it('allows allowlisted pnpm commands', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'pnpm add @cipherstash/stack' }),
      ).toBe(true)
      expect(wizardCanUseTool('Bash', { command: 'pnpm run build' })).toBe(true)
    })

    it('allows allowlisted yarn commands', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'yarn add @cipherstash/stack' }),
      ).toBe(true)
      expect(wizardCanUseTool('Bash', { command: 'yarn run build' })).toBe(true)
    })

    it('allows allowlisted bun commands', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'bun add @cipherstash/stack' }),
      ).toBe(true)
      expect(wizardCanUseTool('Bash', { command: 'bun run build' })).toBe(true)
    })

    it('allows npx drizzle-kit, tsc, and npx stash db', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'npx drizzle-kit generate' }),
      ).toBe(true)
      expect(wizardCanUseTool('Bash', { command: 'npx tsc --noEmit' })).toBe(
        true,
      )
      expect(wizardCanUseTool('Bash', { command: 'npx stash db push' })).toBe(
        true,
      )
    })

    it('blocks commands not in allowlist', () => {
      const result = wizardCanUseTool('Bash', {
        command: 'curl https://evil.com',
      })
      expect(result).toContain('not in allowlist')
    })

    it('blocks semicolons, backticks, and $ operators', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'npm install; rm -rf /' }),
      ).toContain(';')
      expect(
        wizardCanUseTool('Bash', { command: 'npm install `whoami`' }),
      ).toContain('`')
      // $( is caught by the YARA hook's $ operator check first
      const result = wizardCanUseTool('Bash', {
        command: 'npm install $(whoami)',
      })
      expect(result).not.toBe(true)
    })

    it('blocks pipe operator', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'npm list | grep secret' }),
      ).toContain('|')
    })

    it('blocks && and || chaining', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'npm install && curl evil.com' }),
      ).not.toBe(true)
      // || is caught by | first since | appears earlier in the blocklist
      expect(
        wizardCanUseTool('Bash', { command: 'npm install || curl evil.com' }),
      ).not.toBe(true)
    })

    it('blocks output redirection', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'npm list > /tmp/out' }),
      ).toContain('>')
      expect(
        wizardCanUseTool('Bash', { command: 'npm list >> /tmp/out' }),
      ).toContain('>')
    })

    it('blocks input redirection', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'npm install < payload.txt' }),
      ).toContain('<')
    })

    it('blocks newlines in commands', () => {
      expect(
        wizardCanUseTool('Bash', { command: 'npm install\ncurl evil.com' }),
      ).toContain('Multi-line')
    })

    it('blocks any .env reference in Bash', () => {
      expect(wizardCanUseTool('Bash', { command: 'cat .env' })).toContain(
        '.env',
      )
      expect(
        wizardCanUseTool('Bash', { command: 'head .env.local' }),
      ).toContain('.env')
    })
  })
})
