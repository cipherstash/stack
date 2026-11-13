"""Child process of `test_concurrency_live.py`: a fork, and a call in the
forked child. Prints what the child did as JSON.

`after` forks after the first call, so the parent's client exists: the
child must be refused, with no wait. `before` forks before any call, so no
client exists: the child must build its own and work. `during` forks while
another thread is building the client: the child holds a copy of the build
lock that no thread will release, and must be refused, not wait on it.

The child's result comes back through a pipe. The parent waits at most 30
seconds, so a child that never returns shows as "hang" and does not stop
the test run.
"""

import json
import os
import sys
import threading
import time

from _sync_contract import User, user

from stackencrypt import Cipher, StashError, _engine

mode = sys.argv[1]
cipher = Cipher(User)
if mode == "after":
    cipher.encrypt([user(1)])
    assert _engine.client_builds() == 1
if mode == "during":
    builder = threading.Thread(target=cipher.encrypt, args=([user(1)],))
    builder.start()
    time.sleep(0.05)
    # The build loads the keyset over the network, which takes far longer
    # than 50 ms. A build already done would make this the `after` case.
    if _engine.client_builds() != 0 or not builder.is_alive():
        print(json.dumps({"child": "the build finished before the fork"}))
        raise SystemExit(0)

read_end, write_end = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(read_end)
    try:
        rows = cipher.encrypt([user(2)])
        opened = cipher.decrypt(rows)
        result = {"child": "ok" if opened == [user(2)] else "wrong"}
    except StashError as error:
        result = {"child": error.code}
    except BaseException as error:  # noqa: BLE001  Reported to the parent.
        result = {"child": f"error: {type(error).__name__}"}
    os.write(write_end, json.dumps(result).encode())
    os._exit(0)

os.close(write_end)
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    done, status = os.waitpid(pid, os.WNOHANG)
    if done:
        break
    time.sleep(0.05)
else:
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    print(json.dumps({"child": "hang"}))
    raise SystemExit(0)

print(os.read(read_end, 4096).decode() or json.dumps({"child": f"no result, status {status}"}))
