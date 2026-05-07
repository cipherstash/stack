/**
 * YARA-style security scanning hooks for the wizard agent.
 * Validates tool uses before and after execution.
 *
 * Follows the fail-closed pattern: scanner errors block rather than allow.
 */

interface ScanResult {
  blocked: boolean
  rule?: string
  reason?: string
}

// --- Pre-execution rules ---

export const DANGEROUS_BASH_OPERATORS = [
  ';',
  '`',
  '$',
  '(',
  ')',
  '|',
  '&&',
  '||',
  '>',
  '>>',
  '<',
]

const BLOCKED_BASH_PATTERNS = [
  {
    pattern: /rm\s+-rf/i,
    rule: 'destructive_rm',
    reason: 'Recursive force delete blocked',
  },
  {
    pattern: /git\s+push\s+--force/i,
    rule: 'git_force_push',
    reason: 'Force push blocked',
  },
  {
    pattern: /git\s+reset\s+--hard/i,
    rule: 'git_reset_hard',
    reason: 'Hard reset blocked',
  },
  {
    pattern: /curl.*\$.*KEY/i,
    rule: 'secret_exfiltration',
    reason: 'Potential secret exfiltration via curl',
  },
  {
    pattern: /cat.*\.env/i,
    rule: 'env_file_read',
    reason: 'Direct .env file read blocked — use wizard-tools MCP',
  },
]

/** Scan a Bash command before execution. */
export function scanPreToolUse(toolName: string, input: string): ScanResult {
  if (toolName !== 'Bash') return { blocked: false }

  // Block dangerous shell operators
  for (const op of DANGEROUS_BASH_OPERATORS) {
    if (input.includes(op)) {
      return {
        blocked: true,
        rule: 'dangerous_operator',
        reason: `Shell operator "${op}" is not allowed`,
      }
    }
  }

  // Block dangerous command patterns
  for (const { pattern, rule, reason } of BLOCKED_BASH_PATTERNS) {
    if (pattern.test(input)) {
      return { blocked: true, rule, reason }
    }
  }

  return { blocked: false }
}

// --- Post-execution rules ---

const PROMPT_INJECTION_PATTERNS = [
  {
    pattern: /ignore\s+previous\s+instructions/i,
    rule: 'prompt_injection_override',
    severity: 'critical' as const,
  },
  {
    pattern: /you\s+are\s+now\s+a\s+different/i,
    rule: 'prompt_injection_identity',
    severity: 'medium' as const,
  },
]

const SECRET_PATTERNS = [
  {
    pattern: /phc_[a-zA-Z0-9]{20,}/,
    rule: 'hardcoded_posthog_key',
    reason: 'PostHog API key in code',
  },
  {
    pattern: /sk_live_[a-zA-Z0-9]+/,
    rule: 'hardcoded_stripe_key',
    reason: 'Stripe live key in code',
  },
  {
    pattern: /password\s*=\s*['"][^'"]+['"]/i,
    rule: 'hardcoded_password',
    reason: 'Hardcoded password detected',
  },
]

/** Scan file content after a write/edit operation. */
export function scanPostToolUseWrite(content: string): ScanResult {
  // Truncate at 100KB for performance
  const truncated = content.slice(0, 100_000)

  for (const { pattern, rule, reason } of SECRET_PATTERNS) {
    if (pattern.test(truncated)) {
      return { blocked: true, rule, reason }
    }
  }

  return { blocked: false }
}

/** Scan file content after a read/grep for prompt injection. */
export function scanPostToolUseRead(content: string): ScanResult {
  const truncated = content.slice(0, 100_000)

  for (const { pattern, rule, severity } of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(truncated)) {
      return {
        blocked: severity === 'critical',
        rule,
        reason: `Prompt injection detected (${severity})`,
      }
    }
  }

  return { blocked: false }
}
