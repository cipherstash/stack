"""The fixtures every offline test module uses.

One copy, so that a variable added here is cleared for every module. A
variable left set in one module could let its tests reach the network.
"""

import pytest

from stackencrypt import _engine

ACCESS_KEY = "CSAKtestKeyId.testKeySecret"
WORKSPACE_CRN = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"

# Every variable the engine client reads: the credentials, the client key,
# and the service hosts.
CS_VARIABLES = (
    "CS_CLIENT_ACCESS_KEY",
    "CS_WORKSPACE_CRN",
    "CS_CLIENT_ID",
    "CS_CLIENT_KEY",
    "CS_CTS_HOST",
    "CS_ZEROKMS_HOST",
    "CS_VITUR_HOST",
)


@pytest.fixture
def no_credentials(monkeypatch, tmp_path):
    """No CipherStash variable in the environment, and an empty profile store."""
    for name in CS_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CS_CONFIG_PATH", str(tmp_path / "no-profile"))


@pytest.fixture
def credentials(monkeypatch, no_credentials):
    """Credentials that parse, so ``Cipher`` builds, and no client key. A
    call that gets past every check fails building the engine client, with
    no request.

    The engine client is shared by the whole process. Once a live test has
    built it, a call here would reach ZeroKMS instead of failing, so the
    test is skipped. ``mise run test`` and ``-m live`` run the two kinds of
    test in separate processes, and skip nothing.
    """
    if _engine.client_builds() > 0:
        pytest.skip(
            "a live test built the shared engine client earlier in this "
            "process; run the offline tests in a process of their own"
        )
    monkeypatch.setenv("CS_CLIENT_ACCESS_KEY", ACCESS_KEY)
    monkeypatch.setenv("CS_WORKSPACE_CRN", WORKSPACE_CRN)


@pytest.fixture
def untouched():
    """Fails the test if the shared client was built or a request was sent."""
    builds, requests = _engine.client_builds(), _engine.request_count()
    yield
    assert _engine.client_builds() == builds
    assert _engine.request_count() == requests
