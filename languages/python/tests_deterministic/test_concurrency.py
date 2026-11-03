"""The concurrency contract from the spec in #1341, with no credentials:
threads that encrypt at once on the one client all succeed, and every row
opens.

`tests/test_concurrency_live.py` runs the same test against ZeroKMS. This
copy runs on every pull request, a fork's included.
"""

import dataclasses
import threading
from typing import Annotated

import stackencrypt
from stackencrypt import Cipher, Passthrough, TextEq

THREADS = 8
PER_THREAD = 100


@stackencrypt.model("users")
@dataclasses.dataclass
class User:
    id: Annotated[int, Passthrough]
    email: Annotated[str, TextEq]


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
