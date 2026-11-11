import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { expect, test } from 'vitest'

const exec = promisify(execFile)
const supervisor = fileURLToPath(
  new URL('../isolation/supervise.py', import.meta.url),
)

// Execute the production supervisor functions, replacing only Linux process and
// filesystem boundaries so these regressions need neither Docker nor ptrace.
const runner = String.raw`
import ast, base64, builtins, io, json, os, pathlib, subprocess, sys, tempfile
from unittest.mock import patch
source = pathlib.Path(sys.argv[1])
scenario = json.loads(sys.argv[2])
module = ast.parse(source.read_text(), filename=str(source))
module.body = [node for node in module.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
scope = {}
exec(compile(module, str(source), 'exec'), scope)
frames = []
sys.stdin = io.TextIOWrapper(io.BytesIO())
scope.update(config={'uid': 1000, 'gid': 1000, 'env': scenario.get('env', {}), 'forwards': []}, actor='migrator', emit=lambda kind, **fields: frames.append(dict(kind=kind, **fields)))
real_open = os.open
real_builtin_open = builtins.open
actor_fd = None
invocation = 0
streams = []
with tempfile.TemporaryDirectory() as directory:
    def open_fd(path, flags, mode=0o777, **kwargs):
        global actor_fd
        if path == '/trace/actor-stderr':
            actor_fd = real_open(os.path.join(directory, 'actor-stderr'), flags, mode, **kwargs)
            return actor_fd
        return real_open(path, flags, mode, **kwargs)
    def open_file(path, *args, **kwargs):
        if str(path).startswith('/proc/') and str(path).endswith('/children'):
            return io.StringIO('42')
        return real_builtin_open(path, *args, **kwargs)
    class Process:
        pid = 41
        def __init__(self, *args, **kwargs):
            global invocation
            current = scenario['invocations'][invocation]
            invocation += 1
            os.write(actor_fd, current.get('stderr', '').encode())
            self.stdin = io.BytesIO()
            self.stdout = tempfile.TemporaryFile()
            streams.append(self.stdout)
            calls = current.get('trace', ['[pid 42] ' + call for call in current.get('calls', [])] + ['[pid 42] +++ exited with 0 +++'])
            self.stderr = io.BytesIO(('\n'.join(calls) + '\n').encode())
        def poll(self): return 0
        def wait(self): return 0
    with patch('os.open', open_fd), patch('os.dup2'), patch('builtins.open', open_file), patch('subprocess.Popen', Process), patch('os.killpg'):
        for current in scenario['invocations']:
            scope['invoke'](['true'], current['stage'])
    for stream in streams: stream.close()
print(json.dumps(frames))
`

interface Frame {
  kind: string
  data?: string
  error?: string
  event?: {
    pid: number
    operation: string
    resource: string
    decision: string
    result: string
  }
}

async function observe(
  invocations: Array<{
    stage: string
    stderr?: string
    calls?: string[]
    trace?: string[]
  }>,
  env: Record<string, string> = {},
): Promise<Frame[]> {
  const { stdout } = await exec('python3', [
    '-c',
    runner,
    supervisor,
    JSON.stringify({ invocations, env }),
  ])
  return JSON.parse(stdout)
}

test('trusted events omit subprocess argument credentials while retaining access identity', async () => {
  const secret = 'SYNTHETIC-ARGV-CREDENTIAL'
  const frames = await observe([
    {
      stage: 'command',
      calls: [
        `execve("/usr/bin/printf", ["printf", "${secret}"], 0x1 /* 1 var */) = 0`,
      ],
    },
  ])
  const event = frames.find((frame) => frame.kind === 'event')?.event
  expect(event).toMatchObject({
    operation: 'execve',
    resource: '/usr/bin/printf',
    decision: 'allowed',
    result: 'success',
  })
  expect(event).not.toHaveProperty('syscall')
  expect(JSON.stringify(frames)).not.toContain(secret)
})

test('trusted resources do not preserve network payloads or credential-bearing paths', async () => {
  const secret = 'SYNTHETIC-RESOURCE-CREDENTIAL'
  const frames = await observe(
    [
      {
        stage: 'command',
        calls: [
          `sendto(3, "${secret}", 29, 0, NULL, 0) = -1 EACCES (Permission denied)`,
          `openat(AT_FDCWD</workspace>, "${secret}.txt", O_RDONLY) = -1 ENOENT (No such file or directory)`,
        ],
      },
    ],
    { CS_CLIENT_KEY: secret },
  )
  expect(frames.filter((frame) => frame.kind === 'event')).toHaveLength(2)
  expect(JSON.stringify(frames)).not.toContain(secret)
})

test('each invocation emits only its own stderr after a longer startup diagnostic', async () => {
  const frames = await observe([
    { stage: 'startup-probe', stderr: 'long startup diagnostic' },
    { stage: 'command', stderr: 'x' },
  ])
  const stderr = frames
    .filter((frame) => frame.kind === 'stderr')
    .map((frame) => Buffer.from(frame.data ?? '', 'base64').toString())
  expect(stderr).toEqual(['long startup diagnostic', 'x'])
})

test('redacting a database password in a resource preserves a forbidden access decision', async () => {
  const password = 'SYNTHETIC-DB-PASSWORD'
  const frames = await observe(
    [
      {
        stage: 'command',
        calls: [
          `openat(AT_FDCWD, "/protected/${password}", O_RDONLY) = -1 EACCES (Permission denied)`,
        ],
      },
    ],
    { DATABASE_URL: `postgresql://role:${password}@database.local/records` },
  )
  const event = frames.find((frame) => frame.kind === 'event')?.event
  expect(event).toMatchObject({
    operation: 'openat',
    resource: '/protected/[redacted]',
    decision: 'forbidden',
    result: 'denied',
  })
  expect(JSON.stringify(frames)).not.toContain(password)
})

// strace 6.1's non-leader exec format: tests/threads-execve.c and src/strace.c.
test('observer joins exec continuation after a non-leader thread takes the process PID', async () => {
  const frames = await observe([
    {
      stage: 'command',
      trace: [
        '[pid 43] execve("/usr/bin/node", ["node"], 0x1 /* 1 var */ <pid changed to 42 ...>',
        '[pid 42] +++ superseded by execve in pid 43 +++',
        '[pid 42] <... execve resumed>) = 0',
        '[pid 42] +++ exited with 0 +++',
      ],
    },
  ])
  expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
  expect(frames.find((frame) => frame.kind === 'event')?.event).toMatchObject({
    operation: 'execve',
    resource: '/usr/bin/node',
    result: 'success',
  })
  expect(frames.some((frame) => frame.kind === 'actor-exit')).toBe(true)
})

test('observer transfers an interleaved unfinished exec and preserves forbidden access evidence', async () => {
  const frames = await observe([
    {
      stage: 'command',
      trace: [
        '[pid 43] execve("/protected/tool", ["tool"], 0x1 /* 1 var */ <unfinished ...>',
        '[pid 42] +++ superseded by execve in pid 43 +++',
        '[pid 42] <... execve resumed>) = 0',
        '[pid 42] +++ exited with 0 +++',
      ],
    },
  ])
  expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
  expect(frames.find((frame) => frame.kind === 'event')?.event).toMatchObject({
    operation: 'execve',
    resource: '/protected/tool',
    decision: 'forbidden',
    result: 'success',
  })
})

// strace 6.1 printleader (src/strace.c) prints the [pid N] prefix only while
// more than one tracee is attached. A descendant that outlives the actor is the
// sole tracee, so its lines are unprefixed until it creates another process.
test('observer attributes unprefixed lines to the sole surviving tracee, not the actor', async () => {
  const frames = await observe([
    {
      stage: 'command',
      trace: [
        '[pid 42] clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x1) = 46',
        '[pid 42] +++ exited with 0 +++',
        'vfork( <unfinished ...>',
        '[pid 47] execve("/usr/bin/true", ["true"], 0x1 /* 1 var */) = 0',
        '[pid 46] <... vfork resumed>) = 47',
        '[pid 47] +++ exited with 0 +++',
        'openat(AT_FDCWD, "/protected/file", O_RDONLY) = -1 EACCES (Permission denied)',
        '+++ exited with 1 +++',
      ],
    },
  ])
  expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
  const events = frames
    .filter((frame) => frame.kind === 'event')
    .map((frame) => frame.event)
  expect(events).toContainEqual(
    expect.objectContaining({ pid: 46, operation: 'vfork' }),
  )
  expect(events).toContainEqual(
    expect.objectContaining({
      pid: 46,
      operation: 'openat',
      resource: '/protected/file',
      decision: 'forbidden',
      result: 'denied',
    }),
  )
  expect(frames).toContainEqual(
    expect.objectContaining({ kind: 'actor-exit', exitCode: 0 }),
  )
})

test.each([
  [
    'unmatched ptrace syscall continuation',
    ['[pid 42] <... openat resumed>) = 3</workspace/file>'],
  ],
  [
    'mismatched ptrace syscall continuation',
    [
      '[pid 42] openat(AT_FDCWD, "/workspace/file", O_RDONLY <unfinished ...>',
      '[pid 42] <... execve resumed>) = 0',
    ],
  ],
  [
    'missing ptrace exec PID transition',
    [
      '[pid 42] +++ superseded by execve in pid 43 +++',
      '[pid 42] <... execve resumed>) = 0',
    ],
  ],
  [
    'ptrace observer ended without the actor exit record',
    [
      '[pid 42] openat(AT_FDCWD, "/workspace/file", O_RDONLY) = 3</workspace/file>',
    ],
  ],
])('observer still fails closed on %s', async (message, trace) => {
  const frames = await observe([{ stage: 'command', trace }])
  expect(frames).toContainEqual({
    kind: 'stream-error',
    error: expect.stringContaining(message),
  })
})
