import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

describe('Go binding script test flags', () => {
  for (const platform of ['Darwin', 'Linux']) {
    for (const producer of [false, true]) {
      it(`${platform}, artifact producer=${producer}`, () => {
        const root = mkdtempSync(join(tmpdir(), 'go-binding-script-'))
        try {
          const bin = join(root, 'bin')
          const module = join(root, 'module with spaces')
          const log = join(root, 'commands.log')
          mkdirSync(bin)
          mkdirSync(module)
          writeFileSync(join(module, 'guest.wasm'), 'test guest')
          writeFileSync(join(bin, 'gofmt'), '#!/bin/sh\nexit 0\n', {
            mode: 0o755,
          })
          writeFileSync(
            join(bin, 'uname'),
            `#!/bin/sh\nprintf '%s\\n' '${platform}'\n`,
            { mode: 0o755 },
          )
          writeFileSync(
            join(bin, 'go'),
            `#!/bin/sh
printf '%s|%s|%s\\n' "\${GOOS:-}" "\${GOARCH:-}" "$*" >> "$GO_BINDING_LOG"
`,
            { mode: 0o755 },
          )
          // /bin/bash is the CI shell, including Bash 3.2 on macOS. Do not
          // accidentally test only a newer Homebrew shell found on PATH.
          const result = spawnSync(
            '/bin/bash',
            [
              join(REPO_ROOT, 'scripts/go-binding-test.sh'),
              module,
              'guest.wasm',
            ],
            {
              env: {
                ...process.env,
                PATH: `${bin}:${process.env.PATH}`,
                GO_BINDING_LOG: log,
                GOOS: '',
                GOARCH: '',
                STACK_CONFORMANCE_OUTPUT: producer
                  ? join(root, 'artifact.json')
                  : '',
              },
              encoding: 'utf8',
            },
          )
          expect(result.status, result.stderr).toBe(0)
          const flags = producer ? '-count=1 ' : ''
          expect(readFileSync(log, 'utf8').trim().split('\n')).toEqual([
            '||vet ./...',
            '||test -v ./auth -run ^TestDeviceRefresh',
            `||test ${flags}./...`,
            platform === 'Linux'
              ? `linux|386|test ${flags}./...`
              : 'linux|386|vet ./...',
          ])
        } finally {
          rmSync(root, { recursive: true, force: true })
        }
      })
    }
  }
})
