"""Trusted PID-1 supervisor. Actor bytes never enter the trace channel.

The Docker namespace supplies enforcement; strace supplies ptrace events for
descendants, including npm lifecycle scripts. Trace files are root-only.
"""
import base64
import errno
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from urllib.parse import unquote, urlsplit

lock = threading.Lock()
def emit(kind, **fields):
    with lock:
        print(json.dumps(dict(kind=kind, **fields)), flush=True)

config = json.loads(base64.b64decode(os.environ['HARNESS_CONFIG']))
actor = config['actor']
if os.environ.get('HARNESS_MODEL_CANARY') != config['modelCanary']:
    emit('stream-error', error='Root model credential canary was not provisioned')
    os._exit(1)
os.makedirs('/trace', mode=0o700, exist_ok=True)
os.chmod('/trace', 0o700)
for forward in config.get('forwards', []):
    subprocess.Popen(['socat', 'TCP4-LISTEN:%s,bind=%s,reuseaddr,fork' %
                      (forward['port'], forward['address']),
                      'UNIX-CONNECT:/forwards/%s.sock' % forward['index']],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def credential_redactions(env):
    """Collect configured credentials and URL passwords before exporting paths."""
    values = set()
    for key, value in env.items():
        if not isinstance(value, str) or not value:
            continue
        if key.startswith('CS_') or key == 'DATABASE_URL':
            values.add(value)
        if key == 'DATABASE_URL':
            password = urlsplit(value).password
            if password:
                values.update((password, unquote(password)))
    # strace quotes filesystem strings; match their escaped spelling too.
    values.update(json.dumps(value)[1:-1] for value in tuple(values))
    return sorted(values, key=len, reverse=True)


def resource_identity(resource, redactions):
    """Retain the resource location without configured secrets or URL userinfo."""
    for value in redactions:
        resource = resource.replace(value, '[redacted]')
    return re.sub(r'([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@', r'\1[redacted]@', resource)


def invoke(argv, stage):
    # Only configured application credentials enter the actor. In particular no
    # Docker, model, host HOME, or supervisor configuration environment is inherited.
    env = dict({key: value for key, value in config.get('env', {}).items() if key.startswith(('CS_', 'HARNESS_')) or key == 'DATABASE_URL'}, PATH='/usr/local/bin:/usr/bin:/bin',
               HOME='/tmp', TMPDIR='/tmp')
    env.pop('HARNESS_CONFIG', None)
    env.pop('HARNESS_MODEL_CANARY', None)
    redactions = credential_redactions(env)
    if stage == 'startup-probe':
        env['HARNESS_STARTUP_TARGETS'] = json.dumps(config.get('forbiddenTargets', []))
    # Shared -o output makes strace prefix every line with its PID, including
    # sole survivors. Keep it on the trusted stderr pipe; actor stderr uses fd 3.
    command = ['strace', '-f', '-o', '/dev/stderr', '-q', '-yy', '-s', '4096', '-e',
               'trace=%file,%network,%process',
               'setpriv', '--reuid=%s' % config['uid'], '--regid=%s' % config['gid'], '--clear-groups',
               '--inh-caps=-all', '--ambient-caps=-all', '--bounding-set=-all',
               '--no-new-privs', '--', '/bin/sh', '-c', 'exec 2>&3; exec 3>&-; exec \"$@\"', 'actor'] + argv
    actor_stderr = os.open('/trace/actor-stderr', os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
    # fd 3 is reserved for actor diagnostics; the ptrace observer owns stderr.
    if actor_stderr != 3:
        os.dup2(actor_stderr, 3)
    process = subprocess.Popen(command, cwd='/workspace', env=env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True, pass_fds=(3,))
    actor_pid = None
    for _ in range(200):
        try:
            with open('/proc/%s/task/%s/children' % (process.pid, process.pid)) as children:
                child_pids = children.read().split()
            if child_pids:
                actor_pid = int(child_pids[0])
                break
        except FileNotFoundError:
            break
        time.sleep(.005)
    stopped = threading.Event()
    def stop():
        stopped.set()
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
    if stage == 'command' and config.get('testKillTracer'):
        # Host-selected capability fault injection, never application controlled.
        threading.Timer(.1, lambda: os.kill(process.pid, signal.SIGKILL)).start()

    def copy_output(stream, kind):
        while True:
            chunk = os.read(stream.fileno(), 16384)
            if not chunk: break
            emit(kind, data=base64.b64encode(chunk).decode())
    threads = []
    for stream, kind in ([(process.stdout, 'stdout')] if stage == 'command' else []):
        thread = threading.Thread(target=copy_output, args=(stream, kind), daemon=True)
        thread.start()
        threads.append(thread)

    def copy_input():
        try:
            for line in sys.stdin.buffer:
                if stopped.is_set(): break
                process.stdin.write(line)
                process.stdin.flush()
        except (BrokenPipeError, ValueError): pass
        finally:
            try: process.stdin.close()
            except (BrokenPipeError, ValueError): pass
    if stage == 'command':
        threading.Thread(target=copy_input, daemon=True).start()
    else:
        process.stdin.close()

    allowed = ['/workspace', '/usr', '/lib', '/lib64', '/bin', '/sbin',
               '/etc', '/tmp', '/dev', '/proc', '/sys', '/var', '/run', '/opt', '/home']
    def permitted(path):
        return path in ['/', '/harness'] or path in ['/harness/app-host.mjs', '/harness/startup.mjs'] or any(path == root or path.startswith(root + '/') for root in allowed)

    def trace():
        nonlocal actor_pid
        pending = {}
        pending_forks = {}
        exec_moves = {}
        # strace prefixes a line with [pid N] only while more than one tracee is
        # attached. Track attached tracees so an unprefixed line is attributed to
        # the sole survivor, which is not the actor once a descendant outlives it.
        live = {str(actor_pid)} if actor_pid is not None else set()
        actor_exit = None
        source = process.stderr
        if source is not None:
            while True:
                line = source.readline().decode()
                if not line:
                    if process.poll() is not None: break
                    time.sleep(.005)
                    continue
                match = re.match(r'(?:\[pid\s+(\d+)\]\s+|\s*(\d+)\s+)?(.*)', line)
                if not match: continue
                first, second, call = match.groups()
                prefixed = first is not None or second is not None
                if prefixed:
                    pid = first or second
                elif len(live) == 1:
                    pid = next(iter(live))
                else:
                    pid = str(actor_pid or process.pid)
                if actor_pid is None and prefixed and not live and actor_exit is None:
                    # A fast actor may finish before /proc discovery sees it.
                    # The first trusted record is the initial exec launched by
                    # strace; never substitute a later descendant's exit PID.
                    if not call.startswith('execve('):
                        raise RuntimeError('ptrace stream lacks initial actor exec record')
                    actor_pid = int(pid)
                exited = re.fullmatch(r'\+\+\+ exited with (\d+) \+\+\+', call)
                killed = re.fullmatch(r'\+\+\+ killed by (SIG\w+)(?: \(core dumped\))? \+\+\+', call)
                if exited or killed:
                    live.discard(pid)
                    # A child can finish before its parent's creation syscall
                    # resumes. An older process with that PID can also exit
                    # during the call, before the PID is reused for its child.
                    # Distinguish that older generation from the new child.
                    for creation in pending_forks.values():
                        if pid in creation['existing']:
                            creation['existing'].remove(pid)
                        else:
                            creation['exited'].add(pid)
                    pending_forks.pop(pid, None)
                    if (int(pid) == actor_pid) if actor_pid is not None else not prefixed:
                        actor_exit = int(exited.group(1)) if exited else -getattr(signal, killed.group(1))
                    continue
                live.add(pid)
                # A non-leader exec takes the thread group's PID. strace 6.1
                # terminates its printed entry with this marker instead of
                # <unfinished ...>, then resumes under the replacement PID.
                moved = re.fullmatch(r'(.*) <pid changed to (\d+) \.\.\.>', call)
                if moved:
                    entry, replacement = moved.groups()
                    if not entry.startswith(('execve(', 'execveat(')) or replacement == pid:
                        raise RuntimeError('invalid ptrace exec PID transition')
                    pending.pop(pid, None)
                    pending_forks.pop(pid, None)
                    pending_forks.pop(replacement, None)
                    for creation in pending_forks.values():
                        creation['existing'].discard(pid)
                        creation['existing'].discard(replacement)
                    pending[replacement] = entry
                    exec_moves[pid] = replacement
                    continue
                superseded = re.fullmatch(r'\+\+\+ superseded by execve in pid (\d+) \+\+\+', call)
                if superseded:
                    former = superseded.group(1)
                    live.discard(former)
                    pending_forks.pop(former, None)
                    pending_forks.pop(pid, None)
                    for creation in pending_forks.values():
                        creation['existing'].discard(former)
                        creation['existing'].discard(pid)
                    if exec_moves.pop(former, None) == pid:
                        if not pending.get(pid, '').startswith(('execve(', 'execveat(')):
                            raise RuntimeError('missing ptrace exec PID transition')
                    else:
                        # Interleaving may have already printed <unfinished ...>
                        # for the old thread before strace observes its exec.
                        entry = pending.pop(former, None)
                        if not entry or not entry.startswith(('execve(', 'execveat(')):
                            raise RuntimeError('missing ptrace exec PID transition')
                        pending[pid] = entry
                    continue
                if '<unfinished ...>' in call:
                    pending[pid] = call.split('<unfinished ...>')[0]
                    if call.startswith(('clone(', 'clone3(', 'fork(', 'vfork(')):
                        pending_forks[pid] = {'existing': set(live), 'exited': set()}
                    continue
                exited_children = ()
                if call.startswith('<... '):
                    resumed = re.match(r'<\.\.\. (\w+) resumed>(.*)', call)
                    if not resumed or pid not in pending:
                        raise RuntimeError('unmatched ptrace syscall continuation (pid=%s, syscall=%s, pending=%s)' % (pid, resumed.group(1) if resumed else 'invalid', len(pending)))
                    entry = pending.pop(pid)
                    if entry.split('(', 1)[0] != resumed.group(1):
                        raise RuntimeError('mismatched ptrace syscall continuation')
                    creation = pending_forks.pop(pid, None)
                    exited_children = creation['exited'] if creation else ()
                    call = entry + resumed.group(2)
                if ' = ' not in call: continue
                operation, result = call.rsplit(' = ', 1)
                if operation.startswith(('clone(', 'clone3(', 'fork(', 'vfork(')):
                    child = re.match(r'(\d+)\b', result)
                    if child and int(child.group(1)) > 0 and child.group(1) not in exited_children:
                        live.add(child.group(1))
                # Canonical paths returned by the kernel are decoded by strace -yy.
                # Raw arguments are used only to decide access, never exported.
                canonical = re.match(r'\d+<(/[^>]+)>', result)
                path = canonical.group(1) if canonical else None
                # newfstatat/statx(fd, "", AT_EMPTY_PATH) reads metadata of a
                # descriptor the actor already holds (Python checks its stdio
                # this way). -yy decodes the fd's path, but nothing is looked up
                # by name, so the access was decided when the fd was opened.
                held_descriptor = bool(re.match(r'(?:newfstatat|statx|fstatat64)\(\d+<[^>]*>, "",', operation)
                                       and 'AT_EMPTY_PATH' in operation)
                if path is None:
                    raw = re.search(r'\"(/[^\"]*)\"', operation)
                    path = raw.group(1) if raw else None
                    if path is None:
                        relative = re.search(r'(?:AT_FDCWD|\d+)<(/[^>]+)>, \"([^\"]*)\"', operation)
                        if relative:
                            path = os.path.normpath(os.path.join(relative.group(1), relative.group(2)))
                    if path is not None:
                        path = os.path.normpath(path)
                denied = result.startswith('-1 ')
                # Nonblocking connect reports its failure through SO_ERROR.
                # getsockopt itself succeeds when it reads that error; its zero
                # return value is not evidence of a successful connection.
                socket_error = re.fullmatch(r'getsockopt\(\d+(?:<[^,]*>)?, SOL_SOCKET, SO_ERROR, \[(E[A-Z0-9_]+|[0-9]+)\], \[4\]\)', operation)
                if result == '0' and socket_error:
                    value = socket_error.group(1)
                    if value in errno.errorcode.values() or (value.isdecimal() and int(value) > 0):
                        denied = True
                operation_name = operation.split('(', 1)[0]
                resource = path or 'syscall:' + operation_name
                forbidden = bool(path and not permitted(path) and not held_descriptor)
                if operation.startswith(('connect(', 'sendto(', 'sendmsg(', 'sendmmsg(', 'recvfrom(', 'recvmsg(', 'recvmmsg(', 'getsockopt(')):
                    endpoint = re.search(r'sin_port=htons\((\d+)\).*sin_addr=inet_addr\("([^"]+)"\)', operation)
                    kernel_route = ('<NETLINK:[ROUTE:' in operation
                                    and 'sa_family=AF_NETLINK, nl_pid=0' in operation)
                    if kernel_route and operation.startswith(('recvmsg(', 'recvfrom(')):
                        # Interface replies can contain AF_INET6 metadata; that
                        # payload is not the socket's address family.
                        resource = 'kernel:route-interface-reply'
                        forbidden = False
                    elif endpoint:
                        port, address = endpoint.groups()
                        resource = '%s:%s' % (address, port)
                        forbidden = not any(f['address'] == address and f['port'] == int(port)
                                            for f in config.get('forwards', []))
                    else:
                        peer = re.search(r'<(?:TCP|UDP):\[[^]]*->([^]]+)\]>', operation)
                        if peer:
                            resource = peer.group(1)
                            forbidden = not any(resource == '%s:%s' % (f['address'], f['port'])
                                                for f in config.get('forwards', []))
                        elif 'AF_UNIX' in operation or 'AF_INET6' in operation:
                            forbidden = True
                        elif ('<NETLINK:[ROUTE:' in operation
                              and 'sa_family=AF_NETLINK' in operation
                              and re.search(r'nlmsg_type=RTM_GET(?:LINK|ADDR)\b', operation)
                              and operation.startswith(('sendto(', 'sendmsg('))):
                            # Node queries interface metadata through the kernel's
                            # route netlink socket. This read-only query has no
                            # remote peer; do not treat it as an unknown datagram.
                            resource = 'kernel:route-interface-query'
                            forbidden = False
                        elif operation.startswith(('sendto(', 'sendmsg(', 'sendmmsg(')):
                            # Unknown datagram destinations cannot be authenticated.
                            forbidden = True
                event = dict(actor=actor, stage=stage, pid=int(pid), operation=operation_name,
                             resource=resource_identity(resource, redactions),
                             decision='forbidden' if forbidden else 'allowed',
                             result='denied' if denied else 'success')
                emit('event', event=event)
                if forbidden and not denied:
                    stop()
                    break
        if actor_exit is None and not stopped.is_set():
            raise RuntimeError('ptrace observer ended without the actor exit record')
        return actor_exit

    try:
        actor_exit = trace()
        if not stopped.is_set() and actor_exit != process.wait():
            raise RuntimeError('ptrace observer exit disagrees with the actor exit record')
        if actor_exit is not None:
            emit('actor-exit', actor=actor, stage=stage, exitCode=actor_exit)
    except Exception as error:
        emit('stream-error', error=str(error))
        stop()
    code = process.wait()
    for thread in threads: thread.join(timeout=2)
    os.lseek(actor_stderr, 0, os.SEEK_SET)
    errors = os.read(actor_stderr, 1024 * 1024)
    if errors: emit('stderr', data=base64.b64encode(errors).decode())
    return code

with open('/trace/canary', 'w') as canary:
    canary.write('SYNTHETIC-NOT-A-SECRET')
os.chmod('/trace/canary', 0o600)
with open('/trace/model-credential', 'w') as credential:
    credential.write(config['modelCanary'])
os.chmod('/trace/model-credential', 0o600)
startup = invoke(['node', '/harness/startup.mjs'], 'startup-probe')
if startup != 0:
    emit('stream-error', error='Per-invocation startup capability probes failed')
    emit('stream-end')
    emit('exit', exitCode=startup)
    os._exit(1)
code = invoke(config['command'], 'command')
emit('stream-end')
emit('exit', exitCode=code)
os._exit(0)
