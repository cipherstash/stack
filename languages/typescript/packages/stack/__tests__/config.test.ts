import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  extractWorkspaceIdFromCrn,
  loadWorkSpaceId,
} from '../src/utils/config/index.js'

// Mock the 'node:fs' module
vi.mock('node:fs', () => ({
  default: {
    existsSync: vi.fn(),
    readFileSync: vi.fn(),
  },
}))

// We need to dynamically import the mocked module to manipulate it
import fs from 'node:fs'

describe('config utilities', () => {
  // -------------------------------------------------------
  // extractWorkspaceIdFromCrn
  // -------------------------------------------------------
  describe('extractWorkspaceIdFromCrn', () => {
    it('extracts the workspace ID from a valid CRN', () => {
      const id = extractWorkspaceIdFromCrn('crn:ap-southeast-2:abc123')
      expect(id).toBe('abc123')
    })

    it('extracts a UUID workspace ID from a CRN', () => {
      const id = extractWorkspaceIdFromCrn(
        'crn:us-east-1:550e8400-e29b-41d4-a716-446655440000',
      )
      expect(id).toBe('550e8400-e29b-41d4-a716-446655440000')
    })

    it('extracts workspace ID with region containing dot', () => {
      const id = extractWorkspaceIdFromCrn(
        'crn:ap-southeast-2.aws:workspace123',
      )
      expect(id).toBe('workspace123')
    })

    it('throws on invalid CRN format (no crn prefix)', () => {
      expect(() => extractWorkspaceIdFromCrn('invalid-string')).toThrow(
        'Invalid CRN format',
      )
    })

    it('throws on empty string', () => {
      expect(() => extractWorkspaceIdFromCrn('')).toThrow('Invalid CRN format')
    })

    it('throws on CRN with missing workspace ID', () => {
      expect(() => extractWorkspaceIdFromCrn('crn:region:')).toThrow(
        'Invalid CRN format',
      )
    })

    it('throws on CRN with only prefix', () => {
      expect(() => extractWorkspaceIdFromCrn('crn:')).toThrow(
        'Invalid CRN format',
      )
    })
  })

  // -------------------------------------------------------
  // loadWorkSpaceId (tests getWorkspaceCrn indirectly)
  // -------------------------------------------------------
  describe('loadWorkSpaceId', () => {
    const originalEnv = process.env

    beforeEach(() => {
      vi.resetAllMocks()
      process.env = { ...originalEnv }
      delete process.env.CS_WORKSPACE_CRN
    })

    afterEach(() => {
      process.env = originalEnv
    })

    it('returns workspace ID from supplied CRN directly', () => {
      const result = loadWorkSpaceId('crn:ap-southeast-2:myWorkspace')
      expect(result).toBe('myWorkspace')
    })

    it('returns workspace ID from CS_WORKSPACE_CRN env variable', () => {
      process.env.CS_WORKSPACE_CRN = 'crn:us-east-1:envWorkspace'
      vi.mocked(fs.existsSync).mockReturnValue(false)

      const result = loadWorkSpaceId()
      expect(result).toBe('envWorkspace')
    })

    it('env variable takes precedence over config file', () => {
      process.env.CS_WORKSPACE_CRN = 'crn:us-east-1:envWorkspace'
      vi.mocked(fs.existsSync).mockReturnValue(true)
      vi.mocked(fs.readFileSync).mockReturnValue(
        '[auth]\nworkspace_crn = "crn:ap-southeast-2:fileWorkspace"',
      )

      const result = loadWorkSpaceId()
      expect(result).toBe('envWorkspace')
    })

    it('reads workspace CRN from TOML config file with [auth] section', () => {
      vi.mocked(fs.existsSync).mockReturnValue(true)
      vi.mocked(fs.readFileSync).mockReturnValue(
        '[auth]\nworkspace_crn = "crn:ap-southeast-2:fileWorkspace"',
      )

      const result = loadWorkSpaceId()
      expect(result).toBe('fileWorkspace')
    })

    it('reads workspace CRN from TOML with comments', () => {
      vi.mocked(fs.existsSync).mockReturnValue(true)
      vi.mocked(fs.readFileSync).mockReturnValue(
        '# Config file\n[auth]\n# This is the workspace CRN\nworkspace_crn = "crn:region:commentedWorkspace"\n',
      )

      const result = loadWorkSpaceId()
      expect(result).toBe('commentedWorkspace')
    })

    it('reads workspace CRN from TOML with multiple sections', () => {
      vi.mocked(fs.existsSync).mockReturnValue(true)
      vi.mocked(fs.readFileSync).mockReturnValue(
        '[general]\nname = "myapp"\n\n[auth]\nworkspace_crn = "crn:region:multiSectionWorkspace"\n\n[other]\nkey = "value"\n',
      )

      const result = loadWorkSpaceId()
      expect(result).toBe('multiSectionWorkspace')
    })

    it('throws when config file has no [auth] section and no env var', () => {
      vi.mocked(fs.existsSync).mockReturnValue(true)
      vi.mocked(fs.readFileSync).mockReturnValue('[general]\nname = "myapp"\n')

      expect(() => loadWorkSpaceId()).toThrow(
        'You have not defined a workspace CRN',
      )
    })

    it('throws when config file has [auth] but no workspace_crn and no env var', () => {
      vi.mocked(fs.existsSync).mockReturnValue(true)
      vi.mocked(fs.readFileSync).mockReturnValue(
        '[auth]\nother_key = "value"\n',
      )

      expect(() => loadWorkSpaceId()).toThrow(
        'You have not defined a workspace CRN',
      )
    })

    it('throws when config file has empty content and no env var', () => {
      vi.mocked(fs.existsSync).mockReturnValue(true)
      vi.mocked(fs.readFileSync).mockReturnValue('')

      expect(() => loadWorkSpaceId()).toThrow(
        'You have not defined a workspace CRN',
      )
    })

    it('throws when no config file exists and no env var', () => {
      vi.mocked(fs.existsSync).mockReturnValue(false)

      expect(() => loadWorkSpaceId()).toThrow(
        'You have not defined a workspace CRN',
      )
    })

    it('supplied CRN takes precedence over everything', () => {
      process.env.CS_WORKSPACE_CRN = 'crn:us-east-1:envWorkspace'
      vi.mocked(fs.existsSync).mockReturnValue(true)
      vi.mocked(fs.readFileSync).mockReturnValue(
        '[auth]\nworkspace_crn = "crn:ap-southeast-2:fileWorkspace"',
      )

      const result = loadWorkSpaceId('crn:eu-west-1:suppliedWorkspace')
      expect(result).toBe('suppliedWorkspace')
    })
  })
})
