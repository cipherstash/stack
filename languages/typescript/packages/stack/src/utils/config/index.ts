import fs from 'node:fs'
import path from 'node:path'

/**
 * A lightweight function that parses a TOML-like string
 * and returns the `workspace_crn` value found under `[auth]`.
 *
 * @param tomlString The contents of the TOML file as a string.
 * @returns The workspace_crn if found, otherwise undefined.
 */
function getWorkspaceCrn(tomlString: string): string | undefined {
  let currentSection = ''
  let workspaceCrn: string | undefined

  const lines = tomlString.split(/\r?\n/)

  for (const line of lines) {
    const trimmedLine = line.trim()

    if (!trimmedLine || trimmedLine.startsWith('#')) {
      continue
    }

    const sectionMatch = trimmedLine.match(/^\[([^\]]+)\]$/)
    if (sectionMatch) {
      currentSection = sectionMatch[1]
      continue
    }

    const kvMatch = trimmedLine.match(/^(\w+)\s*=\s*"([^"]+)"$/)
    if (kvMatch) {
      const [_, key, value] = kvMatch

      if (currentSection === 'auth' && key === 'workspace_crn') {
        workspaceCrn = value
        break
      }
    }
  }

  return workspaceCrn
}

/**
 * Extracts the workspace ID from a CRN string.
 * CRN format: crn:region.aws:ID
 *
 * @param crn The CRN string to extract from
 * @returns The workspace ID portion of the CRN
 */
export function extractWorkspaceIdFromCrn(crn: string): string {
  const match = crn.match(/crn:[^:]+:([^:]+)$/)
  if (!match) {
    throw new Error('Invalid CRN format')
  }
  return match[1]
}

export function loadWorkSpaceId(suppliedCrn?: string): string {
  const configPath = path.join(process.cwd(), 'cipherstash.toml')

  if (suppliedCrn) {
    return extractWorkspaceIdFromCrn(suppliedCrn)
  }

  if (!fs.existsSync(configPath) && !process.env.CS_WORKSPACE_CRN) {
    throw new Error(
      'You have not defined a workspace CRN in your config file, or the CS_WORKSPACE_CRN environment variable.',
    )
  }

  // Environment variables take precedence over config files
  if (process.env.CS_WORKSPACE_CRN) {
    return extractWorkspaceIdFromCrn(process.env.CS_WORKSPACE_CRN)
  }

  if (!fs.existsSync(configPath)) {
    throw new Error(
      'You have not defined a workspace CRN in your config file, or the CS_WORKSPACE_CRN environment variable.',
    )
  }

  const tomlString = fs.readFileSync(configPath, 'utf8')
  const workspaceCrn = getWorkspaceCrn(tomlString)

  if (!workspaceCrn) {
    throw new Error(
      'You have not defined a workspace CRN in your config file, or the CS_WORKSPACE_CRN environment variable.',
    )
  }

  return extractWorkspaceIdFromCrn(workspaceCrn)
}
