"""The sync contract from the spec in #1341, held against ZeroKMS: one engine
client per process, shared by every thread, and a ``KeyboardInterrupt``
that waits for the call.

These tests need the four CipherStash credentials. Without them every test
here skips. The first-call test and the interrupt test run in a new Python
process each: the client of this one is already built, and the interrupt
is for the whole process.
"""

import dataclasses
import json
import os
import subprocess
import sys
import textwrap
import threading
from typing import Annotated

import pytest

import stackencrypt
from stackencrypt import Cipher, Passthrough, TextEq
from stackencrypt import _engine

CREDENTIALS = ("CS_CLIENT_ACCESS_KEY", "CS_WORKSPACE_CRN", "CS_CLIENT_ID", "CS_CLIENT_KEY")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not all(os.environ.get(name) for name in CREDENTIALS),
        reason="needs CS_CLIENT_ACCESS_KEY, CS_WORKSPACE_CRN, CS_CLIENT_ID and CS_CLIENT_KEY",
    ),
]

THREADS = 8
PER_THREAD = 100

# The model of both scripts below, and of the test in this process.
MODEL = """
import dataclasses
from typing import Annotated

import stackencrypt
from stackencrypt import Passthrough, TextEq


@stackencrypt.model("users")
@dataclasses.dataclass
class User:
    id: Annotated[int, Passthrough]
    email: Annotated[str, TextEq]
"""


@stackencrypt.model("users")
@dataclasses.dataclass
class User:
    id: Annotated[int, Passthrough]
    email: Annotated[str, TextEq]


def run_python(script):
    """Run ``script`` in a new Python process with this one's environment,
    and return what it printed last, as JSON."""
    done = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(MODEL) + textwrap.dedent(script)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_threads_making_their_first_call_at_once_build_one_client():
    counts = run_python(
        f"""
        import json
        import threading

        from stackencrypt import Cipher, _engine

        assert _engine.client_builds() == 0
        cipher = Cipher(User)
        start = threading.Barrier({THREADS})
        failures = []

        def first_call(n):
            start.wait()
            try:
                cipher.encrypt([User(id=n, email=f"user{{n}}@example.com")])
            except Exception as error:
                failures.append(repr(error))

        threads = [threading.Thread(target=first_call, args=(n,)) for n in range({THREADS})]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        print(json.dumps({{
            "failures": failures,
            "builds": _engine.client_builds(),
            "keyset_loads": _engine.keyset_loads(),
        }}))
        """
    )

    assert counts == {"failures": [], "builds": 1, "keyset_loads": 1}


def test_threads_encrypt_at_once_and_every_row_opens():
    cipher = Cipher(User)
    sealed = [[] for _ in range(THREADS)]
    failures = []
    start = threading.Barrier(THREADS)

    def encrypt_many(t):
        start.wait()
        try:
            sealed[t].extend(
                cipher.encrypt([User(id=t * PER_THREAD + n, email=f"t{t}-n{n}@example.com")])[0]
                for n in range(PER_THREAD)
            )
        except Exception as error:
            failures.append(repr(error))

    threads = [threading.Thread(target=encrypt_many, args=(t,)) for t in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []

    rows = [row for rows in sealed for row in rows]
    opened = cipher.decrypt(rows)

    assert opened == [
        User(id=i, email=f"t{i // PER_THREAD}-n{i % PER_THREAD}@example.com")
        for i in range(THREADS * PER_THREAD)
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT is sent with os.kill")
def test_an_interrupt_during_encrypt_waits_for_it_and_the_cipher_still_works():
    result = run_python(
        """
        import json
        import os
        import signal
        import threading
        import time

        from stackencrypt import Cipher

        cipher = Cipher(User)
        # Load the keyset first, so the timed call is the 5000 values alone.
        cipher.encrypt([User(id=0, email="warm@example.com")])
        models = [User(id=n, email=f"user{n}@example.com") for n in range(5000)]

        sent = []

        def interrupt():
            sent.append(time.monotonic())
            os.kill(os.getpid(), signal.SIGINT)

        interrupts = 0
        rows = None
        returned = None
        timer = threading.Timer(0.2, interrupt)
        started = time.monotonic()
        timer.start()
        try:
            rows = cipher.encrypt(models)
            returned = time.monotonic()
            # Python raises the interrupt at its next check after the call.
            # The loop gives it that check, and ends if it never comes.
            while time.monotonic() < returned + 5:
                pass
        except KeyboardInterrupt:
            interrupts += 1
        timer.join()

        # A second interrupt would end this process with an error.
        after = cipher.encrypt([User(id=1, email="after@example.com")])
        end = time.monotonic() + 0.5
        while time.monotonic() < end:
            pass

        print(json.dumps({
            "interrupts": interrupts,
            "sent_during_call": returned is None or sent[0] < returned,
            "call_seconds": None if returned is None else returned - started,
            "rows": None if rows is None else len(rows),
            "after": len(after),
        }))
        """
    )

    assert result["interrupts"] == 1
    # The signal arrived while the call ran, and the interrupt still waited
    # for the call to return.
    assert result["sent_during_call"], result
    # The call returned all its rows, or the interrupt came before the
    # assignment and left nothing: never part of a result.
    assert result["rows"] in (None, 5000)
    assert result["after"] == 1
