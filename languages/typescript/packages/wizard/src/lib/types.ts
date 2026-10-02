export type Integration = 'drizzle' | 'supabase' | 'prisma' | 'generic'

/**
 * Setup-lifecycle phase the wizard runs in. `implement` (default) drives
 * the full setup flow; `plan` produces a reviewable `.cipherstash/plan.md`
 * with no code mutations. The CLI plumbs this through `--mode plan` /
 * `--mode implement` (or the `--plan` / `--implement` shortcuts), and the
 * gateway's `Mode` type is the public-API mirror of this same union.
 */
export type WizardMode = 'plan' | 'implement'

export type RunPhase =
  | 'idle'
  | 'detecting'
  | 'gathering'
  | 'running'
  | 'completed'
  | 'error'

export interface WizardSession {
  // CLI arguments
  cwd: string
  debug: boolean

  // Auto-detection
  detectedIntegration: Integration | undefined
  hasTypeScript: boolean
  detectedPackageManager: DetectedPackageManager | undefined

  // Resolved state
  selectedIntegration: Integration | undefined

  // Runtime
  phase: RunPhase

  // CipherStash credentials
  authenticated: boolean
  hasStashConfig: boolean
  hasEqlInstalled: boolean
}

export interface DetectedPackageManager {
  name: 'npm' | 'pnpm' | 'yarn' | 'bun'
  installCommand: string
  runCommand: string
  execCommand: string
}

export interface FrameworkConfig<
  TContext extends Record<string, unknown> = Record<string, unknown>,
> {
  metadata: {
    name: string
    integrationName: Integration
    documentationUrl: string
    gatherContext?: () => Promise<TContext>
  }
  detection: {
    packageName: string
    getVersion: () => Promise<string | undefined>
    installationCheck: () => Promise<boolean>
  }
  environment: {
    envVars: Array<{
      key: string
      description: string
    }>
  }
  analytics: {
    getTags: (context: TContext) => Record<string, string>
  }
  prompts: {
    projectTypeDetection: string
    packageInstallation: string
    contextLines: (context: TContext) => string[]
  }
  ui: {
    successMessage: string
    estimatedDuration: string
    nextSteps: (context: TContext) => string[]
  }
}

export interface HealthCheckResult {
  service: string
  status: 'up' | 'degraded' | 'down'
  message?: string
}

export type ReadinessResult = 'ready' | 'not_ready' | 'ready_with_warnings'

export const AgentSignals = {
  STATUS: 'wizard:status',
  ERROR_MCP_MISSING: 'wizard:error:mcp_missing',
  ERROR_RESOURCE_MISSING: 'wizard:error:resource_missing',
  ERROR_RATE_LIMIT: 'wizard:error:rate_limit',
  WIZARD_REMARK: 'wizard:remark',
} as const
