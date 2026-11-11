export interface FrictionItem {
  section: string
  issue: string
  actionable: boolean
  description: string
  workaround: string
}
export interface AccessEvent {
  actor: string
  decision: string
  result: string
  resource: string
  stage?: string
  pid?: number
  operation?: string
  syscall?: string
}
export interface OracleCheck {
  id: string
  passed: boolean
  cause?: string
}
export interface MigratorResult {
  runtime?: {
    provider: 'claude-code'
    version: string
    model: string
    numTurns: number
    permissionMode: 'acceptEdits'
  }
  exitCode: number
  limit?: string
  toolCalls?: Array<{ id: string; exitCode: number }>
}
export interface RunDriver {
  provision(): Promise<unknown>
  installUnmigrated(): Promise<unknown>
  initializeLegacyData(): Promise<unknown>
  snapshot(): Promise<unknown>
  migrate(): Promise<MigratorResult>
  friction(): Promise<unknown>
  installAppHost(): Promise<unknown>
  behaviour(): Promise<OracleCheck[]>
}
export interface Supervision {
  drain(): AccessEvent[] | Promise<AccessEvent[]>
  stop(): Promise<unknown>
}
export interface Forward {
  host: string
  port: number
  targetHost: string
  targetPort: number
  network?: string
}
export interface IsolationOptions {
  actor: string
  workspace: string
  env?: Record<string, string>
  command: string[]
  forwards?: Forward[]
  probe?: boolean
  canary?: string | null
  timeoutMs?: number
  testKillTracer?: boolean
}
export interface IsolationResult {
  exitCode: number
  stdout: string
  stderr: string
  timedOut?: boolean
}
export interface Manifest {
  procedure?: 'dynamodb' | 'postgres-v2-to-v3'
  sourceEqlGeneration?: number
  targetEqlGeneration?: number
  stack?: string
  guideHash: string | null
  guideSections?: string[]
  agents?: {
    limits?: { timeMs: number; turns?: number; toolCalls?: number }
    [key: string]: unknown
  }
  isolation?: unknown
  fixtureRevision?: string
  artifacts?: { transcript: string; diff?: string; snapshot: string }
  storeCapabilities?: unknown
  [key: string]: unknown
}
export interface StageFailure {
  stage: string
  category: string
  cause: string
  event?: AccessEvent
}
export interface EvidenceRecord {
  id: string
  stage: string
  kind: string
  checkId: string
  payload: unknown
  payloadDigest: string
  attributionUsable: boolean
  guideRevision: string | null
}
export interface RunReport {
  id: string
  manifest: Manifest
  stages: Array<{
    name: string
    status: string
    reason?: string
    cause?: string
  }>
  failures: StageFailure[]
  evidence: EvidenceRecord[]
  friction: FrictionItem[] | null
  migratorInvoked: boolean
  editorEligible: boolean
  outcome: string
}
