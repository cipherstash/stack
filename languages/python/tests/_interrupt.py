"""Child process of `test_concurrency_live.py`: SIGINT during a 5000-value
`encrypt`. Prints what happened as JSON.

A reference call is timed first, as the gate test knows its call takes one
second. The signal is sent a quarter of the way into the second call. A
call cut short would raise at that quarter. A call that waits raises after
it returns, near the reference time.
"""

import json
import time

from _sync_contract import User, send_sigint_later, user, wait_for_the_interrupt

from stackencrypt import Cipher

cipher = Cipher(User)
# Load the keyset first, so both timed calls are the 5000 values alone.
cipher.encrypt([user(0)])
models = [user(n) for n in range(5000)]

started = time.monotonic()
cipher.encrypt(models)
reference = time.monotonic() - started

interrupts = 0
arrived = None
rows = None
timer = send_sigint_later(reference / 4)
started = time.monotonic()
try:
    rows = cipher.encrypt(models)
    wait_for_the_interrupt()
except KeyboardInterrupt:
    interrupts += 1
    arrived = time.monotonic() - started
timer.join()

# Python checks for signals many times in the code below. A second
# interrupt would raise in it, and the process would exit with an error.
after = cipher.encrypt([user(1)])
print(
    json.dumps(
        {
            "reference": reference,
            "arrived": arrived,
            "interrupts": interrupts,
            "rows": None if rows is None else len(rows),
            "after": len(after),
        }
    )
)
