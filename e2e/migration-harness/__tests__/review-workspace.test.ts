import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test } from 'vitest'
import { prepareWorkspace } from '../run/workspace.mjs'

test.each([
  'Record unclear instructions and failed approaches in `friction.md`.',
  'use the harness acceptance command for those checks.',
])(
  'F14 rejects a fixture README missing the expected phrase %s',
  async (missing) => {
    const root = await mkdtemp(join(tmpdir(), 'mh-readme-drift-'))
    try {
      const fixture = join(root, 'fixture')
      await mkdir(fixture)
      await writeFile(
        join(fixture, 'package.json.template'),
        '{"private":true}',
      )
      const phrases = [
        'Record unclear instructions and failed approaches in `friction.md`.',
        'use the harness acceptance command for those checks.',
      ]
      await writeFile(
        join(fixture, 'README.md'),
        phrases.filter((phrase) => phrase !== missing).join('\n'),
      )
      await writeFile(join(root, 'guide.md'), '# Guide')
      await expect(
        prepareWorkspace({
          fixture,
          workspace: join(root, 'workspace'),
          guide: join(root, 'guide.md'),
          frictionPath: '/workspace/friction.json',
        }),
      ).rejects.toThrow('Fixture README')
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  },
)
