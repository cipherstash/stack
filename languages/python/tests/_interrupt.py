"""Child process of `test_concurrency_live.py`: SIGINT during a long
`encrypt`. Prints what happened as JSON.

A reference time is measured first, as the gate test knows its call takes
one second. It is the fastest of three calls, so a slow one cannot raise
it. The call starts at 5000 values and doubles until the reference is long
enough to send a signal into. The signal is sent a quarter of the way into
one more call. A call cut short would raise at that quarter. A call that
waits raises after it returns, near the reference time.
"""

import json
import time

from _sync_contract import User, send_sigint_later, user, wait_for_the_interrupt

from stackencrypt import Cipher

LONG_ENOUGH = 0.4
MOST_VALUES = 80_000


def timed(call):
    started = time.monotonic()
    call()
    return time.monotonic() - started


cipher = Cipher(User)
# Load the keyset first, so the timed calls are the values alone.
cipher.encrypt([user(0)])

values = 5000
while True:
    models = [user(n) for n in range(values)]
    reference = min(timed(lambda: cipher.encrypt(models)) for _ in range(3))
    if reference >= LONG_ENOUGH or values >= MOST_VALUES:
        break
    values *= 2

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
            "values": values,
            "reference": reference,
            "arrived": arrived,
            "interrupts": interrupts,
            "rows": None if rows is None else len(rows),
            "after": len(after),
        }
    )
)
