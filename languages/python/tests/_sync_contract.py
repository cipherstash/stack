"""The parts of the sync contract tests that more than one file uses: the
model, the threads, and the interrupt.

The users are `tests/test_concurrency_live.py`, the deterministic copy in
`tests_deterministic/test_concurrency.py`, the two child scripts
`_first_call.py` and `_interrupt.py`, and the gate test
`test_gate_keyboard_interrupt.py`. Not a test file: pytest collects
nothing here.
"""

import dataclasses
import os
import signal
import threading
import time
import traceback
from typing import Annotated, Dict, List

import stackencrypt
from stackencrypt import Cipher, Passthrough, TextEq

THREADS = 8
PER_THREAD = 100


@stackencrypt.model("users")
@dataclasses.dataclass
class User:
    id: Annotated[int, Passthrough]
    email: Annotated[str, TextEq]


def user(n: int) -> User:
    return User(id=n, email=f"user{n}@example.com")


def encrypt_from_threads(cipher: Cipher, per_thread: int) -> List[Dict[str, object]]:
    """Release ``THREADS`` threads at once, each to encrypt ``per_thread``
    users one call at a time. Returns every row, in user order. Raises if
    any call failed."""
    sealed: List[List[Dict[str, object]]] = [[] for _ in range(THREADS)]
    failures: List[str] = []
    # A timeout, so one thread that never arrives fails the test, not hangs it.
    start = threading.Barrier(THREADS, timeout=30)

    def encrypt_many(t: int) -> None:
        try:
            start.wait()
            for n in range(per_thread):
                sealed[t].extend(cipher.encrypt([user(t * per_thread + n)]))
        except Exception:
            failures.append(f"thread {t}: {traceback.format_exc()}")

    threads = [threading.Thread(target=encrypt_many, args=(t,)) for t in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == [], failures
    return [row for rows in sealed for row in rows]


def decrypt_from_threads(cipher: Cipher, rows: List[Dict[str, object]]) -> List[User]:
    """Release ``THREADS`` threads at once, each to decrypt its own slice of
    ``rows`` one call at a time. Returns every user, in row order. Raises if
    any call failed."""
    per_thread = -(-len(rows) // THREADS)
    opened: List[List[User]] = [[] for _ in range(THREADS)]
    failures: List[str] = []
    start = threading.Barrier(THREADS, timeout=30)

    def decrypt_many(t: int) -> None:
        try:
            start.wait()
            for row in rows[t * per_thread : (t + 1) * per_thread]:
                opened[t].extend(cipher.decrypt([row]))
        except Exception:
            failures.append(f"thread {t}: {traceback.format_exc()}")

    threads = [threading.Thread(target=decrypt_many, args=(t,)) for t in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == [], failures
    return [model for models in opened for model in models]


def send_sigint_later(seconds: float) -> threading.Timer:
    """Send SIGINT to this process after ``seconds``."""
    timer = threading.Timer(seconds, os.kill, (os.getpid(), signal.SIGINT))
    timer.start()
    return timer


def wait_for_the_interrupt() -> None:
    """Python raises a pending interrupt at its next check after a call. The
    loop gives it that check, and ends if it never comes."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        # A short sleep still returns to Python, which then checks for the
        # signal, and it does not keep a core busy.
        time.sleep(0.01)
