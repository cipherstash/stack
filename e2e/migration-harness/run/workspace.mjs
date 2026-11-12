import { execFile } from 'node:child_process'
import { cp, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { promisify } from 'node:util'

const exec = promisify(execFile)

/** @param {{fixture:string,workspace:string,guide:string,frictionPath:string,guideSections:string[]}} options */
export async function prepareWorkspace({
  fixture,
  workspace,
  guide,
  frictionPath,
  guideSections,
}) {
  await cp(fixture, workspace, { recursive: true })
  const template = await readFile(
    resolve(workspace, 'package.json.template'),
    'utf8',
  )
  await writeFile(resolve(workspace, 'package.json'), template)
  await cp(guide, resolve(workspace, 'migration-guide.md'))
  await writeFile(
    resolve(workspace, 'friction-schema.json'),
    JSON.stringify(
      {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        type: 'array',
        items: {
          type: 'object',
          required: [
            'section',
            'issue',
            'actionable',
            'description',
            'workaround',
          ],
          properties: {
            section: { type: 'string', enum: guideSections },
            issue: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
            actionable: { type: 'boolean' },
            description: { type: 'string' },
            workaround: { type: 'string' },
          },
        },
      },
      null,
      2,
    ) + '\n',
  )
  let readme = await readFile(resolve(workspace, 'README.md'), 'utf8')
  /** @param {string} from @param {string} to */
  function replace(from, to) {
    if (!readme.includes(from))
      throw Error('Fixture README is missing required harness instructions')
    readme = readme.replace(from, () => to)
  }
  replace(
    'Record unclear instructions and failed approaches in `friction.md`.',
    `Write a JSON Friction Log to HARNESS_FRICTION_LOG (${frictionPath}). Use [] for no friction. Read friction-schema.json for the complete item schema and exact accepted section IDs; copy section verbatim from its enum instead of deriving a heading slug. Each item requires section, issue (lowercase ASCII hyphenated slug), actionable (boolean), description and workaround (strings). Write a regular UTF-8 JSON file of at most 1 MiB, not a symlink or hard link. The harness validates against its original section catalog even if workspace files are changed.`,
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
