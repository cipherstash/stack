import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

type Pm = 'npm' | 'pnpm' | 'yarn' | 'bun'

function fromUserAgent(): Pm | undefined {
  const ua = process.env.npm_config_user_agent ?? ''
  if (ua.startsWith('bun/')) return 'bun'
  if (ua.startsWith('pnpm/')) return 'pnpm'
  if (ua.startsWith('yarn/')) return 'yarn'
  return undefined
}

function fromLockfile(cwd: string): Pm | undefined {
  if (
    existsSync(resolve(cwd, 'bun.lockb')) ||
    existsSync(resolve(cwd, 'bun.lock'))
  )
    return 'bun'
  if (existsSync(resolve(cwd, 'pnpm-lock.yaml'))) return 'pnpm'
  if (existsSync(resolve(cwd, 'yarn.lock'))) return 'yarn'
  if (existsSync(resolve(cwd, 'package-lock.json'))) return 'npm'
  return undefined
}

export function detectRunner(): string {
  const pm = fromUserAgent() ?? fromLockfile(process.cwd()) ?? 'npm'
  return pm === 'bun'
    ? 'bunx'
    : pm === 'pnpm'
      ? 'pnpm dlx'
      : pm === 'yarn'
        ? 'yarn dlx'
        : 'npx'
}
