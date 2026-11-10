import { execFile } from 'node:child_process'
import { cp, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { promisify } from 'node:util'

const exec = promisify(execFile)

/** @param {{fixture:string,workspace:string,guide:string,frictionPath:string}} options */
export async function prepareWorkspace({
  fixture,
  workspace,
  guide,
  frictionPath,
}) {
  await cp(fixture, workspace, { recursive: true })
  const template = await readFile(
    resolve(workspace, 'package.json.template'),
    'utf8',
  )
  await writeFile(resolve(workspace, 'package.json'), template)
  await cp(guide, resolve(workspace, 'migration-guide.md'))
  let readme = await readFile(resolve(workspace, 'README.md'), 'utf8')
  /** @param {string} from @param {string} to */
  function replace(from, to) {
    if (!readme.includes(from))
      throw Error('Fixture README is missing required harness instructions')
    readme = readme.replace(from, () => to)
  }
  replace(
    'Record unclear instructions and failed approaches in `friction.md`.',
    `Write a JSON Friction Log to HARNESS_FRICTION_LOG (${frictionPath}). Use [] for no friction. Each item has section (input guide heading slug), issue (lowercase ASCII hyphenated slug), actionable (boolean), description and workaround (strings).`,
  )
  replace(
    'use the harness acceptance command for those checks.',
    'exercise the public API against your assigned stores for those checks.',
  )
  await writeFile(resolve(workspace, 'README.md'), readme)
  await exec('git', ['init', '-q'], { cwd: workspace })
  await exec('git', ['add', '.'], { cwd: workspace })
  await exec(
    'git',
    [
      '-c',
      'user.name=Migration Harness',
      '-c',
      'user.email=harness@localhost',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '-qm',
      'Unmigrated Fixture App',
    ],
    { cwd: workspace },
  )
}
