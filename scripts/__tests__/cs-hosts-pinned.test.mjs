import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * Every job that hands the client a workspace CRN must also hand it the CTS
 * and ZeroKMS hosts, from the repo variables `CS_CTS_HOST` and
 * `CS_ZEROKMS_HOST`.
 *
 * Without them the client derives both hosts from the CRN's region, and for
 * the CI workspace that derivation is wrong: it is a us-east-1 workspace whose
 * access key was issued by the ap-southeast-2 CTS. A job that omits the hosts
 * asks the us-east-1 CTS, which answers `401 … Unknown credential` for a key
 * that is perfectly valid, and every live test in the job fails on auth.
 *
 * Literal host URLs are refused as well as missing ones. `tests.yml`'s
 * `e2e-tests` job hardcoded both to ap-southeast-2, which pointed ZeroKMS at
 * the wrong region the moment the workspace moved. Reading them from `vars`
 * keeps a workspace move a change to three repo variables, not to every
 * workflow.
 */
const CRN_EXPRESSION = /\$\{\{\s*vars\.CS_WORKSPACE_CRN\s*\}\}/
const CTS_EXPRESSION = /\$\{\{\s*vars\.CS_CTS_HOST\s*\}\}/
const ZEROKMS_EXPRESSION = /\$\{\{\s*vars\.CS_ZEROKMS_HOST\s*\}\}/
const LITERAL_HOST =
  /https:\/\/[a-z0-9-]+\.aws\.(?:cts|zerokms)\.cipherstashmanaged\.net/

function jobsWithCrn() {
  const found = []
  for (const relPath of workflowFiles()) {
    const wf = readWorkflow(relPath)
    for (const [jobName, job] of Object.entries(wf?.jobs ?? {})) {
      const text = JSON.stringify(job)
      if (!CRN_EXPRESSION.test(text)) continue
      found.push({ id: `${relPath} / ${jobName}`, text })
    }
  }
  return found
}

const JOBS = jobsWithCrn()

describe('credentialed jobs pin the CTS and ZeroKMS hosts', () => {
  it('finds credentialed jobs to check', () => {
    expect(JOBS.length).toBeGreaterThan(0)
  })

  it.each(JOBS.map((job) => [job.id, job]))(
    '%s reads CS_CTS_HOST and CS_ZEROKMS_HOST from vars',
    (_id, job) => {
      expect(job.text).toMatch(CTS_EXPRESSION)
      expect(job.text).toMatch(ZEROKMS_EXPRESSION)
    },
  )

  it('no workflow hardcodes a CTS or ZeroKMS host', () => {
    const offenders = workflowFiles().filter((relPath) =>
      LITERAL_HOST.test(JSON.stringify(readWorkflow(relPath))),
    )
    expect(offenders).toEqual([])
  })
})
