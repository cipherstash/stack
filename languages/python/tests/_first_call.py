"""Child process of `test_concurrency_live.py`: the threads make the first
call of this process together. Prints the counts as JSON."""

import json

from _sync_contract import User, encrypt_from_threads

from stackencrypt import Cipher, _engine

assert _engine.client_builds() == 0
encrypt_from_threads(Cipher(User), per_thread=1)
print(json.dumps({"builds": _engine.client_builds(), "keyset_loads": _engine.keyset_loads()}))
