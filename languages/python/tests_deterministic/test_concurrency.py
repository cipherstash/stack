"""The concurrency test of `tests/test_concurrency_live.py`, with no
credentials: threads that encrypt at once on the one client all succeed,
and every row opens. It runs on every pull request that starts
`tests-python.yml`, a fork's included.

The model and the threads are `tests/_sync_contract.py`, shared with the
live test. pyproject.toml puts `tests/` on the path.
"""

from _sync_contract import (
    PER_THREAD,
    THREADS,
    User,
    decrypt_from_threads,
    encrypt_from_threads,
    user,
)

from stackencrypt import Cipher


def test_threads_encrypt_at_once_and_every_row_opens():
    cipher = Cipher(User)

    rows = encrypt_from_threads(cipher, PER_THREAD)

    assert cipher.decrypt(rows) == [user(n) for n in range(THREADS * PER_THREAD)]


def test_threads_decrypt_at_once_and_every_row_opens():
    cipher = Cipher(User)
    rows = encrypt_from_threads(cipher, PER_THREAD)

    assert decrypt_from_threads(cipher, rows) == [user(n) for n in range(THREADS * PER_THREAD)]
