#!/usr/bin/env node
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import process from 'node:process'
import yaml from 'js-yaml'

const defaultWorkflowFiles = [
  '.github/workflows/release.yml',
  '.github/workflows/release-plz.yml',
]

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function stepLabel(file, jobName, index, step) {
  const name = step.name ? ` "${step.name}"` : ''
  const uses = step.uses ? ` (${step.uses})` : ''
  return `${file}: job ${jobName} step ${index + 1}${name}${uses}`
}

function readWorkflow(file) {
  return yaml.load(readFileSync(file, 'utf8'))
}

function isExplicitlyDisabled(value) {
  return value === false || value === 'false'
}

function isConfiguredAndNotDisabled(value) {
  return value !== undefined && !isExplicitlyDisabled(value)
}

function hasCacheInput(step, names) {
  const withBlock = step.with ?? {}
  return names.some((name) => Object.hasOwn(withBlock, name))
}

export function lintWorkflowDocument(document, file = '<workflow>') {
  const errors = []
  const jobs = document?.jobs ?? {}

  for (const [jobName, job] of Object.entries(jobs)) {
    for (const [index, step] of asArray(job?.steps).entries()) {
      if (!step || typeof step !== 'object' || !step.uses) continue

      const label = stepLabel(file, jobName, index, step)
      const action = String(step.uses).toLowerCase()
      const withBlock = step.with ?? {}

      if (action.startsWith('pnpm/action-setup@')) {
        if (!hasCacheInput(step, ['cache']) || !isExplicitlyDisabled(withBlock.cache)) {
          errors.push(`${label}: pnpm/action-setup must set with.cache: false in release workflows`)
        }
      }

      // mise-action restores an executable toolchain from cache — the same
      // poisoned-cache vector as node/pnpm dependency caches, running inside
      // jobs that hold npm/crates.io OIDC publishing power.
      if (action.startsWith('jdx/mise-action@')) {
        if (!hasCacheInput(step, ['cache']) || !isExplicitlyDisabled(withBlock.cache)) {
          errors.push(`${label}: jdx/mise-action must set with.cache: false in release workflows`)
        }
      }

      if (action.startsWith('actions/setup-node@')) {
        if (isConfiguredAndNotDisabled(withBlock.cache)) {
          errors.push(`${label}: actions/setup-node dependency cache must stay disabled`)
        }
        if (isConfiguredAndNotDisabled(withBlock['package-manager-cache'])) {
          errors.push(`${label}: actions/setup-node package-manager-cache must stay disabled`)
        }
      }

      if (action.startsWith('actions/cache@')) {
        errors.push(`${label}: actions/cache is not allowed in release workflows that install or publish packages`)
      }
    }
  }

  return errors
}

export function lintWorkflowFiles(files = defaultWorkflowFiles) {
  return files.flatMap((file) => lintWorkflowDocument(readWorkflow(file), file))
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const files = process.argv.slice(2).map((file) => resolve(file))
  const errors = lintWorkflowFiles(files.length > 0 ? files : defaultWorkflowFiles)

  for (const error of errors) {
    console.error(error)
  }

  process.exit(errors.length === 0 ? 0 : 1)
}
