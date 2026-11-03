"""What every live test file shares: the credential and database checks, and
a runner for a child Python process. Not a test file: pytest collects
nothing here."""

import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

import pytest

CREDENTIALS = ("CS_CLIENT_ACCESS_KEY", "CS_WORKSPACE_CRN", "CS_CLIENT_ID", "CS_CLIENT_KEY")
DATABASE_URL = os.environ.get("EQL_TEST_DATABASE_URL", "")

# A live test file sets `pytestmark = LIVE`. Without the credentials, every
# test in it skips, and `mise run test:live` fails on the skip.
LIVE = [
    pytest.mark.live,
    pytest.mark.skipif(
        not all(os.environ.get(name) for name in CREDENTIALS),
        reason="needs CS_CLIENT_ACCESS_KEY, CS_WORKSPACE_CRN, CS_CLIENT_ID and CS_CLIENT_KEY",
    ),
]

needs_database = pytest.mark.skipif(not DATABASE_URL, reason="needs EQL_TEST_DATABASE_URL")


def run_python(args: List[str], env: Optional[Dict[str, str]] = None) -> Any:
    """Run Python with ``args`` in a new process, with this one's
    environment and ``env`` on top. Fails unless it exits with 0. Returns
    the JSON it printed last."""
    done = subprocess.run(
        [sys.executable, *args],
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])
