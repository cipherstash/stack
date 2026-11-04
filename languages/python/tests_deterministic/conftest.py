"""Every test here runs against the `deterministic-kms` test build.

`mise run test:deterministic` builds the extension with that feature and runs
this folder in its own pytest process. The session switches the process to
the deterministic client before any test runs: its keys come from a seed
through stack-kms's `DeterministicSource`, not from ZeroKMS. So no test here
needs credentials or makes a request.

The seed is the one the Go SDK's frozen rows were sealed under, so rows the
Go SDK stored open here. The switch is for the whole process, which is why
this folder is not under `tests/`.
"""

import json
import os
from pathlib import Path

import pytest

from stackencrypt import _engine

REPO = Path(__file__).resolve().parents[3]
# The Go SDK's EQL fixtures, all sealed under one seed.
FIXTURES = REPO / "packages/eql/tests/encryption/fixtures"


def pytest_sessionstart(session):
    use = getattr(_engine, "_use_deterministic_keys", None)
    if use is None:
        pytest.exit(
            "the extension was built without the deterministic-kms feature; "
            "run `mise run test:deterministic`",
            returncode=2,
        )
    # Cipher checks that credentials are present before it builds a plan.
    # These parse, and the deterministic client never uses them.
    os.environ["CS_CLIENT_ACCESS_KEY"] = "CSAKtestKeyId.testKeySecret"
    os.environ["CS_WORKSPACE_CRN"] = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"
    frozen = json.loads((FIXTURES / "stored_v4_rows_v1.json").read_text())
    use(frozen["seed"].encode())
