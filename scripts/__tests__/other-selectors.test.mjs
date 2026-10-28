import { describe, expect, it } from 'vitest'
import { readSelectorJob, selectedJobs } from './lib/selector.mjs'

/**
 * What the selector jobs of the release lint, the musl image build, CodeQL and
 * OSV-Scanner decide for a pull request.
 *
 * CodeQL analyses JavaScript and TypeScript only, so its trigger paths are the
 * file types the JavaScript extractor reads. OSV-Scanner reads dependencies
 * from lockfiles and manifests, so its trigger paths are those files.
 */

const WORKFLOWS = {
  lintRelease: '.github/workflows/lint-release.yml',
  musl: '.github/workflows/musl-build-image.yml',
  codeql: '.github/workflows/codeql.yml',
  osv: '.github/workflows/osv-scanner.yml',
}

const runs = (relPath, job, file) => selectedJobs(relPath, [file]).includes(job)

describe('the other pull request workflows', () => {
  it.each(Object.values(WORKFLOWS))('%s has a selector job', (relPath) => {
    expect(readSelectorJob(relPath)).not.toBeNull()
  })
})

describe('the release lint selector', () => {
  it('runs for the release workflows and the scripts it checks', () => {
    for (const file of [
      '.github/workflows/release.yml',
      '.github/actionlint.yaml',
      'packages/eql/tasks/release/prepare-bindings-assets.sh',
    ]) {
      expect(runs(WORKFLOWS.lintRelease, 'lint', file), file).toBe(true)
    }
    expect(
      runs(WORKFLOWS.lintRelease, 'lint', 'scripts/release-gate.mjs'),
    ).toBe(false)
  })
})

describe('the musl image selector', () => {
  it('builds the image for a change to the Dockerfile only', () => {
    expect(
      runs(WORKFLOWS.musl, 'build', '.github/docker/musl-build/Dockerfile'),
    ).toBe(true)
    expect(runs(WORKFLOWS.musl, 'build', 'Cargo.lock')).toBe(false)
  })
})

describe('the CodeQL selector', () => {
  it('runs the analysis for JavaScript, TypeScript and the files they read', () => {
    for (const file of [
      'languages/typescript/packages/stack/src/index.ts',
      'scripts/release-gate.mjs',
      'languages/typescript/packages/stack/package.json',
      '.github/workflows/codeql.yml',
    ]) {
      expect(runs(WORKFLOWS.codeql, 'analyze', file), file).toBe(true)
    }
  })

  it('skips the analysis for Rust, Go, SQL and Markdown', () => {
    for (const file of [
      'packages/stack-encrypt/src/lib.rs',
      'languages/golang/encrypt/encrypt.go',
      'packages/eql/src/v3/schema.sql',
      'README.md',
    ]) {
      expect(runs(WORKFLOWS.codeql, 'analyze', file), file).toBe(false)
    }
  })
})

describe('the OSV-Scanner selector', () => {
  it('runs the scan for a lockfile or manifest anywhere in the tree', () => {
    for (const file of [
      'pnpm-lock.yaml',
      'Cargo.lock',
      'packages/eql/Cargo.lock',
      'languages/golang/go.mod',
      '.github/impact-gate/requirements.txt',
      'languages/typescript/examples/deno/deno.lock',
    ]) {
      expect(runs(WORKFLOWS.osv, 'osv-scan', file), file).toBe(true)
    }
  })

  it('skips the scan for source code', () => {
    expect(
      runs(
        WORKFLOWS.osv,
        'osv-scan',
        'languages/typescript/packages/stack/src/index.ts',
      ),
    ).toBe(false)
    expect(runs(WORKFLOWS.osv, 'osv-scan', 'Cargo.toml')).toBe(false)
  })
})
