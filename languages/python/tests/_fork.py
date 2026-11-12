"""Child process of `test_concurrency_live.py`: one call, then a fork, then a
call in the forked child. Prints what the child did as JSON.

The child's result comes back through a pipe. The parent waits at most 30
seconds, so a child that never returns shows as "hang" and does not stop
the test run.
"""

import json
import os
import time

from _sync_contract import User, user

from stackencrypt import Cipher, _engine

cipher = Cipher(User)
cipher.encrypt([user(1)])
assert _engine.client_builds() == 1

read_end, write_end = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(read_end)
    try:
        rows = cipher.encrypt([user(2)])
        opened = cipher.decrypt(rows)
        result = {
            "child": "ok" if opened == [user(2)] else "wrong",
            "builds": _engine.client_builds(),
        }
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
