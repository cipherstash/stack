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
            return io.StringIO('' if scenario.get('actorPid', 42) is None else str(scenario.get('actorPid', 42)))
        return real_builtin_open(path, *args, **kwargs)
    class Process:
        pid = 41
        def __init__(self, *args, **kwargs):
            global invocation
            frames.append(dict(kind='observer-command', command=args[0]))
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
  command?: string[]
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
  actorPid: number | null = 42,
): Promise<Frame[]> {
  const { stdout } = await exec('python3', [
    '-c',
    runner,
    supervisor,
    JSON.stringify({ invocations, env, actorPid }),
  ])
  return JSON.parse(stdout)
}

test('supervisor requests PID-prefixed shared output and preserves numeric-PID lifecycle evidence', async () => {
  const frames = await observe([
    {
      stage: 'command',
      trace: [
        '42 clone(child_stack=NULL, flags=SIGCHLD) = 46',
        '42 +++ exited with 0 +++',
        '46 vfork( <unfinished ...>',
        '47 execve("/usr/bin/true", ["true"], 0x1) = 0',
        '47 +++ exited with 0 +++',
        '46 <... vfork resumed>) = 47',
        '46 openat(AT_FDCWD, "/protected/file", O_RDONLY) = -1 EACCES (Permission denied)',
        '46 +++ exited with 1 +++',
      ],
    },
  ])
  // strace 6.1 -f prints every PID only with a shared -o destination. Keep
  // that output on the trusted stderr pipe rather than reconstructing identity
  // from whether strace happened to omit the prefix at a lifecycle boundary.
  const command =
    frames.find((frame) => frame.kind === 'observer-command')?.command ?? []
  expect(command[0]).toBe('strace')
  expect(command).toContain('-f')
  const output = command.indexOf('-o')
  expect(
    output,
    'strace must use shared output mode to prefix every PID',
  ).toBeGreaterThan(0)
  expect(command[output + 1]).toBe('/dev/stderr')
  expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
  expect(frames).toContainEqual(
    expect.objectContaining({
      event: expect.objectContaining({ pid: 46, operation: 'vfork' }),
    }),
  )
  expect(frames).toContainEqual(
    expect.objectContaining({
      event: expect.objectContaining({
        pid: 46,
        operation: 'openat',
        resource: '/protected/file',
        decision: 'forbidden',
        result: 'denied',
      }),
    }),
  )
  expect(frames).toContainEqual(
    expect.objectContaining({ kind: 'actor-exit', exitCode: 0 }),
  )
})

test('observer identifies a fast actor from its initial numeric exec when proc discovery misses it', async () => {
  const frames = await observe(
    [
      {
        stage: 'command',
        trace: [
          '42 execve("/usr/bin/setpriv", ["setpriv"], 0x1) = 0',
          '42 clone(child_stack=NULL, flags=SIGCHLD) = 45',
          '42 +++ exited with 0 +++',
          '45 openat(AT_FDCWD, "/protected/file", O_RDONLY) = -1 EACCES (Permission denied)',
          '45 +++ exited with 1 +++',
        ],
      },
    ],
    {},
    null,
  )
  expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
  expect(frames).toContainEqual(
    expect.objectContaining({ kind: 'actor-exit', exitCode: 0 }),
  )
  expect(frames).toContainEqual(
    expect.objectContaining({
      event: expect.objectContaining({
        pid: 45,
        operation: 'openat',
        decision: 'forbidden',
        result: 'denied',
      }),
    }),
  )
})

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
test.each(['bracket', 'numeric'])(
  'observer joins exec continuation after a non-leader thread takes the process PID (%s)',
  async (prefix) => {
    const frames = await observe([
      {
        stage: 'command',
        trace: [
          '[pid 43] execve("/usr/bin/node", ["node"], 0x1 /* 1 var */ <pid changed to 42 ...>',
          '[pid 42] +++ superseded by execve in pid 43 +++',
          '[pid 42] <... execve resumed>) = 0',
          '[pid 42] +++ exited with 0 +++',
        ].map((line) =>
          prefix === 'numeric' ? line.replace(/^\[pid (\d+)\] /, '$1 ') : line,
        ),
      },
    ])
    expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
    expect(frames.find((frame) => frame.kind === 'event')?.event).toMatchObject(
      {
        operation: 'execve',
        resource: '/usr/bin/node',
        result: 'success',
      },
    )
    expect(frames.some((frame) => frame.kind === 'actor-exit')).toBe(true)
  },
)

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

// Python's startup checks its standard streams with newfstatat(fd, "",
// AT_EMPTY_PATH). With -yy strace decodes fd 2 as the supervisor's capture file,
// but the call names no path: it reads metadata of a descriptor already held.
test('observer allows metadata reads of a held descriptor but still forbids a named lookup', async () => {
  const frames = await observe([
    {
      stage: 'command',
      calls: [
        'newfstatat(2</trace/actor-stderr>, "", {st_mode=S_IFREG|0600, st_size=0, ...}, AT_EMPTY_PATH) = 0',
        'statx(2</trace/actor-stderr>, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {stx_mask=STATX_BASIC_STATS, ...}) = 0',
        'newfstatat(AT_FDCWD</workspace>, "/trace/actor-stderr", 0xffffc0de, 0) = 0',
      ],
    },
  ])
  expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
  const events = frames
    .filter((frame) => frame.kind === 'event')
    .map((frame) => frame.event)
  expect(events.slice(0, 2)).toEqual([
    expect.objectContaining({ operation: 'newfstatat', decision: 'allowed' }),
    expect.objectContaining({ operation: 'statx', decision: 'allowed' }),
  ])
  expect(events[2]).toMatchObject({
    operation: 'newfstatat',
    resource: '/trace/actor-stderr',
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

test.each(['+++ exited with 0 +++', '+++ killed by SIGTERM +++'])(
  'observer does not resurrect a child whose %s precedes the parent fork return',
  async (terminal) => {
    const frames = await observe([
      {
        stage: 'command',
        trace: [
          '[pid 42] clone(child_stack=NULL, flags=SIGCHLD) = 45',
          '[pid 42] +++ exited with 0 +++',
          'vfork( <unfinished ...>',
          '[pid 46] execve("/usr/bin/true", ["true"], 0x1) = 0',
          `[pid 46] ${terminal}`,
          '<... vfork resumed>) = 46',
          'vfork( <unfinished ...>',
          '[pid 47] execve("/usr/bin/true", ["true"], 0x1) = 0',
          '[pid 45] <... vfork resumed>) = 47',
          '[pid 47] +++ exited with 0 +++',
          'openat(AT_FDCWD, "/protected/file", O_RDONLY) = -1 EACCES (Permission denied)',
          '+++ exited with 1 +++',
        ],
      },
    ])
    expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
    expect(
      frames
        .filter((frame) => frame.event?.operation === 'vfork')
        .map((frame) => frame.event?.pid),
    ).toEqual([45, 45])
    expect(frames).toContainEqual(
      expect.objectContaining({
        kind: 'event',
        event: expect.objectContaining({
          pid: 45,
          operation: 'openat',
          resource: '/protected/file',
          decision: 'forbidden',
          result: 'denied',
        }),
      }),
    )
    expect(frames).toContainEqual(
      expect.objectContaining({ kind: 'actor-exit', exitCode: 0 }),
    )
  },
)

test.each([false, true])(
  'observer tracks a reused child PID after its old process exits (resumed=%s)',
  async (resumed) => {
    const frames = await observe([
      {
        stage: 'command',
        trace: [
          '[pid 42] clone(child_stack=NULL, flags=SIGCHLD) = 45',
          '[pid 45] +++ exited with 0 +++',
          ...(resumed
            ? [
                'clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>',
                '[pid 42] <... clone resumed>) = 45',
              ]
            : ['clone(child_stack=NULL, flags=SIGCHLD) = 45']),
          '[pid 42] +++ exited with 0 +++',
          'openat(AT_FDCWD, "/protected/file", O_RDONLY) = -1 EACCES (Permission denied)',
          '+++ exited with 1 +++',
        ],
      },
    ])
    expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
    expect(frames).toContainEqual(
      expect.objectContaining({
        kind: 'event',
        event: expect.objectContaining({
          pid: 45,
          operation: 'openat',
          resource: '/protected/file',
          decision: 'forbidden',
          result: 'denied',
        }),
      }),
    )
    expect(frames).toContainEqual(
      expect.objectContaining({ kind: 'actor-exit', exitCode: 0 }),
    )
  },
)

// The actor ignores SIGCHLD, so exited children are auto-reaped. sigaction is
// outside the supervisor's traced syscall classes; PID reuse may therefore
// happen while another clone is outstanding without a wait syscall in the log.
// Unrelated process churn that wraps the PID allocator is omitted here.
test('observer tracks a child PID reused after an older child exits during clone', async () => {
  const frames = await observe([
    {
      stage: 'command',
      trace: [
        '[pid 42] clone(child_stack=NULL, flags=SIGCHLD) = 45',
        '[pid 42] clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>',
        '[pid 45] +++ exited with 0 +++',
        '[pid 42] <... clone resumed>) = 45',
        '[pid 42] +++ exited with 0 +++',
        'vfork( <unfinished ...>',
        '[pid 46] execve("/usr/bin/true", ["true"], 0x1) = 0',
        '[pid 45] <... vfork resumed>) = 46',
        '[pid 46] +++ exited with 0 +++',
        'openat(AT_FDCWD, "/protected/file", O_RDONLY) = -1 EACCES (Permission denied)',
        '+++ exited with 1 +++',
      ],
    },
  ])
  expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
  expect(frames).toContainEqual(
    expect.objectContaining({
      event: expect.objectContaining({
        pid: 45,
        operation: 'openat',
        decision: 'forbidden',
        result: 'denied',
      }),
    }),
  )
  expect(frames).toContainEqual(
    expect.objectContaining({ kind: 'actor-exit', exitCode: 0 }),
  )
})

test('observer does not resurrect a reused child that also exits before clone resumes', async () => {
  const frames = await observe([
    {
      stage: 'command',
      trace: [
        '[pid 42] clone(child_stack=NULL, flags=SIGCHLD) = 43',
        '[pid 42] clone(child_stack=NULL, flags=SIGCHLD) = 45',
        '[pid 42] clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>',
        '[pid 45] +++ exited with 0 +++',
        '[pid 45] execve("/usr/bin/true", ["true"], 0x1) = 0',
        '[pid 45] +++ exited with 0 +++',
        '[pid 42] <... clone resumed>) = 45',
        '[pid 42] +++ exited with 0 +++',
        'openat(AT_FDCWD, "/protected/file", O_RDONLY) = -1 EACCES (Permission denied)',
        '+++ exited with 1 +++',
      ],
    },
  ])
  expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
  expect(frames).toContainEqual(
    expect.objectContaining({
      event: expect.objectContaining({
        pid: 43,
        operation: 'openat',
        decision: 'forbidden',
        result: 'denied',
      }),
    }),
  )
  expect(frames).toContainEqual(
    expect.objectContaining({ kind: 'actor-exit', exitCode: 0 }),
  )
})

test.each(['ECONNREFUSED', 'ETIMEDOUT', '111'])(
  'observer treats SO_ERROR %s as a failed connection despite successful getsockopt',
  async (error) => {
    const frames = await observe([
      {
        stage: 'startup-probe',
        calls: [
          'connect(18<TCP:[127.0.0.1:49000]>, {sa_family=AF_INET, sin_port=htons(32768), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)',
          `getsockopt(18<TCP:[127.0.0.1:49000->127.0.0.1:32768]>, SOL_SOCKET, SO_ERROR, [${error}], [4]) = 0`,
        ],
      },
    ])
    expect(frames.filter((frame) => frame.kind === 'stream-error')).toEqual([])
    expect(
      frames.find((frame) => frame.event?.operation === 'getsockopt')?.event,
    ).toMatchObject({
      resource: '127.0.0.1:32768',
      decision: 'forbidden',
      result: 'denied',
    })
    expect(frames).toContainEqual(
      expect.objectContaining({ kind: 'actor-exit', exitCode: 0 }),
    )
  },
)

test.each([
  ['SO_ERROR', '[0]'],
  ['SO_ERROR', '[UNKNOWN]'],
  ['SO_ERROR', '0xffffdead'],
  ['SO_TYPE', '[SOCK_STREAM]'],
])(
  'observer keeps successful forbidden-peer getsockopt %s %s fail-closed',
  async (option, value) => {
    const frames = await observe([
      {
        stage: 'startup-probe',
        calls: [
          `getsockopt(18<TCP:[127.0.0.1:49000->127.0.0.1:32768]>, SOL_SOCKET, ${option}, ${value}, [4]) = 0`,
        ],
      },
    ])
    expect(
      frames.find((frame) => frame.event?.operation === 'getsockopt')?.event,
    ).toMatchObject({
      resource: '127.0.0.1:32768',
      decision: 'forbidden',
      result: 'success',
    })
    expect(frames.some((frame) => frame.kind === 'actor-exit')).toBe(false)
  },
)

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
