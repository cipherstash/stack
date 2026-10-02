import { spawnSync } from 'node:child_process'
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * `scripts/check-c-library.sh` is the one copy of the rules for which C
 * library each Linux release binary must link. It used to be three copies, in
 * `_build-auth-artifacts.yml`, `auth-preflight.yml` and `ffi-preflight.yml`,
 * and nothing kept them the same.
 *
 * THE FIXTURES ARE WRITTEN HERE, NOT COMPILED AND NOT CHECKED IN. No musl
 * compiler is on the CI runners or on a developer's machine, and a checked-in
 * binary is a file no reviewer can read. The script reads one thing from a
 * binary, the NEEDED entries of its dynamic section, and it reads them through
 * the real `readelf`. So a minimal ELF file whose dynamic section names the
 * libraries a real gnu or musl build names is the same input to it, and every
 * byte of it is in `elf()` below.
 */

const SCRIPT = join(REPO_ROOT, 'scripts/check-c-library.sh')

/**
 * A minimal 64-bit little-endian x86-64 ELF file.
 *
 * With `needed`, a shared object whose dynamic section lists those libraries,
 * as a native module does. With `needed: null`, an executable with no dynamic
 * section at all, which is what a statically linked binary has.
 *
 * One loadable segment maps the whole file at address 0, so every address in
 * the dynamic section equals its file offset. readelf resolves the NEEDED
 * names through DT_STRTAB, and falls back to the `.dynstr` section header.
 */
function elf({ needed }) {
  const EHDR = 64
  const PHDR = 56
  const SHDR = 64
  const align8 = (n) => Math.ceil(n / 8) * 8
  const dynamic = needed !== null

  const dynstr = Buffer.from(`\0${needed?.join('\0') ?? ''}\0`)
  const names = ['', '.dynstr', '.dynamic', '.shstrtab']
  const sections = dynamic ? names : ['', '.shstrtab']
  const shstrtab = Buffer.from(`${sections.join('\0')}\0`)
  const nameOffset = (name) => shstrtab.indexOf(`\0${name}\0`) + 1

  const phnum = dynamic ? 2 : 1
  const dynstrOff = EHDR + PHDR * phnum
  const dynOff = align8(dynstrOff + (dynamic ? dynstr.length : 0))
  const entries = dynamic
    ? [
        ...needed.map((lib) => [1n, BigInt(dynstr.indexOf(`\0${lib}\0`) + 1)]),
        [5n, BigInt(dynstrOff)], // DT_STRTAB
        [10n, BigInt(dynstr.length)], // DT_STRSZ
        [0n, 0n], // DT_NULL
      ]
    : []
  const dynSize = entries.length * 16
  const shstrOff = dynOff + dynSize
  const shOff = align8(shstrOff + shstrtab.length)
  const shnum = sections.length
  const file = Buffer.alloc(shOff + SHDR * shnum)

  // ELF header
  file.write('\x7fELF', 0, 'latin1')
  file[4] = 2 // ELFCLASS64
  file[5] = 1 // ELFDATA2LSB
  file[6] = 1 // EV_CURRENT
  file.writeUInt16LE(dynamic ? 3 : 2, 16) // ET_DYN or ET_EXEC
  file.writeUInt16LE(62, 18) // EM_X86_64
  file.writeUInt32LE(1, 20)
  file.writeBigUInt64LE(BigInt(EHDR), 32) // e_phoff
  file.writeBigUInt64LE(BigInt(shOff), 40) // e_shoff
  file.writeUInt16LE(EHDR, 52)
  file.writeUInt16LE(PHDR, 54)
  file.writeUInt16LE(phnum, 56)
  file.writeUInt16LE(SHDR, 58)
  file.writeUInt16LE(shnum, 60)
  file.writeUInt16LE(shnum - 1, 62) // e_shstrndx: .shstrtab is last

  const phdr = (i, { type, flags, offset, size, align }) => {
    const at = EHDR + PHDR * i
    file.writeUInt32LE(type, at)
    file.writeUInt32LE(flags, at + 4)
    file.writeBigUInt64LE(BigInt(offset), at + 8) // p_offset
    file.writeBigUInt64LE(BigInt(offset), at + 16) // p_vaddr
    file.writeBigUInt64LE(BigInt(offset), at + 24) // p_paddr
    file.writeBigUInt64LE(BigInt(size), at + 32) // p_filesz
    file.writeBigUInt64LE(BigInt(size), at + 40) // p_memsz
    file.writeBigUInt64LE(BigInt(align), at + 48)
  }
  // PT_LOAD, readable, over the whole file.
  phdr(0, { type: 1, flags: 4, offset: 0, size: file.length, align: 0x1000 })

  const shdr = (
    i,
    { name, type, flags, offset, size, link, align, entsize },
  ) => {
    const at = shOff + SHDR * i
    file.writeUInt32LE(nameOffset(name), at)
    file.writeUInt32LE(type, at + 4)
    file.writeBigUInt64LE(BigInt(flags), at + 8)
    file.writeBigUInt64LE(BigInt(flags & 2 ? offset : 0), at + 16) // sh_addr
    file.writeBigUInt64LE(BigInt(offset), at + 24)
    file.writeBigUInt64LE(BigInt(size), at + 32)
    file.writeUInt32LE(link, at + 40)
    file.writeBigUInt64LE(BigInt(align), at + 48)
    file.writeBigUInt64LE(BigInt(entsize), at + 56)
  }

  if (dynamic) {
    dynstr.copy(file, dynstrOff)
    entries.forEach(([tag, value], i) => {
      file.writeBigInt64LE(tag, dynOff + 16 * i)
      file.writeBigUInt64LE(value, dynOff + 16 * i + 8)
    })
    // PT_DYNAMIC, readable and writable.
    phdr(1, { type: 2, flags: 6, offset: dynOff, size: dynSize, align: 8 })
    // SHT_STRTAB, SHF_ALLOC
    shdr(1, {
      name: '.dynstr',
      type: 3,
      flags: 2,
      offset: dynstrOff,
      size: dynstr.length,
      link: 0,
      align: 1,
      entsize: 0,
    })
    // SHT_DYNAMIC, SHF_WRITE | SHF_ALLOC, linked to .dynstr
    shdr(2, {
      name: '.dynamic',
      type: 6,
      flags: 3,
      offset: dynOff,
      size: dynSize,
      link: 1,
      align: 8,
      entsize: 16,
    })
  }
  shstrtab.copy(file, shstrOff)
  shdr(shnum - 1, {
    name: '.shstrtab',
    type: 3,
    flags: 0,
    offset: shstrOff,
    size: shstrtab.length,
    link: 0,
    align: 1,
    entsize: 0,
  })
  return file
}

const dir = mkdtempSync(join(tmpdir(), 'check-c-library-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))

/** The libraries a Rust cdylib names on each C library, as readelf lists them. */
const FIXTURES = {
  gnu: ['libgcc_s.so.1', 'libm.so.6', 'libc.so.6', 'ld-linux-x86-64.so.2'],
  musl: ['libgcc_s.so.1', 'libc.musl-x86_64.so.1'],
  // A binary with a dynamic section that names no C library: a C library
  // linked in statically, with only libgcc left dynamic.
  'no-libc': ['libgcc_s.so.1'],
  // No dynamic section at all.
  static: null,
}
const fixture = Object.fromEntries(
  Object.entries(FIXTURES).map(([name, needed]) => {
    const path = join(dir, `${name}.node`)
    writeFileSync(path, elf({ needed }))
    return [name, path]
  }),
)

function check(...args) {
  const result = spawnSync(SCRIPT, args, { encoding: 'utf8' })
  return {
    status: result.status,
    output: `${result.stdout}${result.stderr}`,
  }
}

// readelf is GNU binutils, which every Linux runner has and macOS does not.
// Skipped only outside CI, so CI cannot pass by checking nothing.
const hasReadelf = spawnSync('readelf', ['--version']).status === 0

describe.skipIf(!hasReadelf && !process.env.CI)('check-c-library.sh', () => {
  it('reads the fixtures the way it reads a real binary', () => {
    const gnu = spawnSync('readelf', ['-d', fixture.gnu], { encoding: 'utf8' })
    expect(gnu.status).toBe(0)
    for (const lib of FIXTURES.gnu) {
      expect(gnu.stdout).toMatch(
        new RegExp(`\\(NEEDED\\)\\s+Shared library: \\[${lib}\\]`),
      )
    }
    const stat = spawnSync('readelf', ['-d', fixture.static], {
      encoding: 'utf8',
    })
    expect(stat.status).toBe(0)
    expect(stat.stdout).toContain('There is no dynamic section in this file.')
  })

  const ACCEPTS = {
    'linux-x64-gnu': 'gnu',
    'linux-arm64-gnu': 'gnu',
    'linux-x64-musl': 'musl',
  }

  const cases = Object.entries(ACCEPTS).flatMap(([platform, accepted]) =>
    Object.keys(FIXTURES).map((binary) => ({
      platform,
      binary,
      ok: binary === accepted,
    })),
  )

  it.each(cases)(
    '$platform with the $binary binary: accepted is $ok',
    ({ platform, binary, ok }) => {
      const { status, output } = check(platform, fixture[binary])
      if (ok) {
        expect(status, output).toBe(0)
        expect(output).toContain(`${platform}: links the expected C library`)
      } else {
        expect(status, output).toBe(1)
        // A failure names its cause in the job log, as an annotation.
        expect(output).toMatch(new RegExp(`^::error::.*${platform}`, 'm'))
      }
    },
  )

  it('names the cause of each musl rejection', () => {
    expect(check('linux-x64-musl', fixture.gnu).output).toContain('links glibc')
    for (const binary of ['static', 'no-libc']) {
      expect(check('linux-x64-musl', fixture[binary]).output).toContain(
        'linked statically',
      )
    }
  })

  it.each([
    'darwin-x64',
    'win32-x64-msvc',
    'linux-arm64-musl',
    'linux-x64',
    'linux-x64-gnu ',
  ])('rejects %j, which has no rule, whatever the binary', (platform) => {
    for (const binary of ['gnu', 'musl']) {
      const { status, output } = check(platform, fixture[binary])
      expect(status, output).toBe(1)
      expect(output).toContain(`::error::no C library rule for ${platform}`)
    }
  })

  it('fails when the binary is missing or is not an ELF file', () => {
    const notElf = join(dir, 'not-elf.node')
    writeFileSync(notElf, 'not an ELF file\n')
    for (const binary of [join(dir, 'absent.node'), notElf]) {
      expect(check('linux-x64-gnu', binary).status).not.toBe(0)
    }
  })

  it('fails when an argument is missing', () => {
    expect(check().status).not.toBe(0)
    expect(check('linux-x64-gnu').output).toContain('usage:')
  })

  it('has a rule for every Linux platform package that the release publishes', () => {
    // Each platform name ends in its C library, so a new Linux platform
    // package is checked here against the binary it must accept.
    const linux = ['auth', 'protect-ffi'].flatMap((pkg) =>
      readdirSync(
        join(REPO_ROOT, 'languages/typescript/packages', pkg, 'platforms'),
      ).filter((name) => name.startsWith('linux-')),
    )
    expect(linux.length).toBeGreaterThan(0)
    for (const platform of new Set(linux)) {
      const libc = platform.split('-').at(-1)
      const { status, output } = check(platform, fixture[libc])
      expect(status, output).toBe(0)
    }
  })
})

describe('the workflows that check a Linux binary', () => {
  const CALLERS = [
    '.github/workflows/_build-auth-artifacts.yml',
    '.github/workflows/auth-preflight.yml',
    '.github/workflows/ffi-preflight.yml',
  ]

  const runs = (file) =>
    Object.values(readWorkflow(file)?.jobs ?? {}).flatMap((job) =>
      (job?.steps ?? []).map((step) => String(step?.run ?? '')),
    )

  it.each(CALLERS)('%s calls the script', (file) => {
    expect(runs(file).some((run) => run.includes('check-c-library.sh'))).toBe(
      true,
    )
  })

  it('keep no copy of the rules of their own', () => {
    // Discovery, not the list above: a copy added to any workflow fails here.
    const copies = workflowFiles().filter((file) =>
      runs(file).some((run) =>
        /\breadelf\s+-|libc\\?\.musl|libc\\?\.so\\?\.6/.test(run),
      ),
    )
    expect(copies).toEqual([])
  })

  it('is executable, so a workflow can run it by path', () => {
    // A CI checkout takes the mode from git, so this reads the committed mode.
    expect(statSync(SCRIPT).mode & 0o111).toBe(0o111)
    expect(readFileSync(SCRIPT, 'utf8')).toMatch(/^#!\/usr\/bin\/env bash\n/)
  })
})
