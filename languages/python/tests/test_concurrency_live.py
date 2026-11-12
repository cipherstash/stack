"""The sync contract from the spec in #1341, held against ZeroKMS: one engine
client per process, shared by every thread, and a ``KeyboardInterrupt``
that waits for the call.

These tests need the four CipherStash credentials. Without them every test
here skips. The first-call test and the interrupt test each run a script in
a new Python process: the client of this one is already built, and the
interrupt is for the whole process.
"""

import pathlib
import sys

import pytest
from _live import LIVE, run_python
from _sync_contract import (
    PER_THREAD,
    THREADS,
    User,
    decrypt_from_threads,
    encrypt_from_threads,
    user,
)

from stackencrypt import Cipher

pytestmark = LIVE

HERE = pathlib.Path(__file__).parent


def test_threads_making_their_first_call_at_once_build_one_client():
    assert run_python([str(HERE / "_first_call.py")]) == {"builds": 1, "keyset_loads": 1}


def test_threads_encrypt_at_once_and_every_row_opens():
    cipher = Cipher(User)

    rows = encrypt_from_threads(cipher, PER_THREAD)

    assert cipher.decrypt(rows) == [user(n) for n in range(THREADS * PER_THREAD)]


def test_threads_decrypt_at_once_and_every_row_opens():
    cipher = Cipher(User)
    rows = encrypt_from_threads(cipher, PER_THREAD)

    assert decrypt_from_threads(cipher, rows) == [user(n) for n in range(THREADS * PER_THREAD)]


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT is sent with os.kill")
def test_an_interrupt_during_encrypt_waits_for_it_and_the_cipher_still_works():
    result = run_python([str(HERE / "_interrupt.py")])

    # The script grows the call until it takes 0.4 seconds, up to 80,000
    # values. Below 0.2, there is too little time to send a signal into it.
    assert result["reference"] >= 0.2, result
    assert result["interrupts"] == 1, result
    # A call cut short raises at a quarter of the reference. A call that
    # waits raises after it returns, near the reference time.
    assert result["arrived"] >= result["reference"] / 2, result
    # All the rows, or the interrupt came before the assignment and left
    # nothing: never part of a result.
    assert result["rows"] in (None, result["values"]), result
    assert result["after"] == 1, result
