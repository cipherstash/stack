"""The sync contract from the spec in #1341, held against ZeroKMS: one engine
client per process, shared by every thread, and a ``KeyboardInterrupt``
that waits for the call.

These tests need the four CipherStash credentials. Without them every test
here skips. The first-call test and the interrupt test each run a script in
a new Python process: the client of this one is already built, and the
interrupt is for the whole process.
"""

import json
import os
import pathlib
import subprocess
import sys

import pytest
from _sync_contract import PER_THREAD, THREADS, User, encrypt_from_threads, user

from stackencrypt import Cipher

CREDENTIALS = ("CS_CLIENT_ACCESS_KEY", "CS_WORKSPACE_CRN", "CS_CLIENT_ID", "CS_CLIENT_KEY")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not all(os.environ.get(name) for name in CREDENTIALS),
        reason="needs CS_CLIENT_ACCESS_KEY, CS_WORKSPACE_CRN, CS_CLIENT_ID and CS_CLIENT_KEY",
    ),
]


def run_child(script):
    """Run ``script``, beside this file, in a new Python process with this
    one's environment. Returns the JSON it printed last."""
    done = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).with_name(script))],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_threads_making_their_first_call_at_once_build_one_client():
    assert run_child("_first_call.py") == {"builds": 1, "keyset_loads": 1}


def test_threads_encrypt_at_once_and_every_row_opens():
    cipher = Cipher(User)

    rows = encrypt_from_threads(cipher, PER_THREAD)

    assert cipher.decrypt(rows) == [user(n) for n in range(THREADS * PER_THREAD)]


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT is sent with os.kill")
def test_an_interrupt_during_encrypt_waits_for_it_and_the_cipher_still_works():
    result = run_child("_interrupt.py")

    # The signal is sent at a quarter of the reference time. Below this,
    # there is too little time to send it inside the call.
    assert result["reference"] >= 0.2, result
    assert result["interrupts"] == 1, result
    # A call cut short raises at the quarter. A call that waits raises
    # after it returns, near the reference time.
    assert result["arrived"] >= result["reference"] / 2, result
    # All the rows, or the interrupt came before the assignment and left
    # nothing: never part of a result.
    assert result["rows"] in (None, 5000), result
    assert result["after"] == 1, result
