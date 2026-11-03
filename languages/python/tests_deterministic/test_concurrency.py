"""The concurrency test of `tests/test_concurrency_live.py`, with no
credentials: threads that encrypt at once on the one client all succeed,
and every row opens. It runs on every pull request, a fork's included.

The model and the threads are `tests/_sync_contract.py`, shared with the
live test.
"""

import sys
from pathlib import Path

from stackencrypt import Cipher

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from _sync_contract import PER_THREAD, THREADS, User, encrypt_from_threads, user  # noqa: E402


def test_threads_encrypt_at_once_and_every_row_opens():
    cipher = Cipher(User)

    rows = encrypt_from_threads(cipher, PER_THREAD)

    assert cipher.decrypt(rows) == [user(n) for n in range(THREADS * PER_THREAD)]
