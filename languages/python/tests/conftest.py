"""Shared fixtures.

The live gate is "does the engine construct", not "are the CS_* variables
set". Credentials come from either `CS_CLIENT_ID` + `CS_CLIENT_KEY` or the
profile `stash auth login` writes (decision 10), and the engine's
`AutoStrategy` is what decides between them — so a check on the environment
alone would skip a session whose profile works perfectly well.
"""

import os

import pytest

from stackencrypt import _engine


@pytest.fixture(scope="session")
def live():
    """Skip unless an engine handle can actually be built.

    Constructing one is the whole check: it resolves credentials and talks
    to ZeroKMS, so if it succeeds the live tests can run, and if it fails
    the reason is worth printing rather than guessing at.
    """
    try:
        return _engine.Engine()
    except Exception as error:  # noqa: BLE001 — the reason is the message
        pytest.skip(f"no working credentials: {error}")


@pytest.fixture(scope="session")
def database_url(live):
    """Skip unless a Postgres with EQL v3 is pointed at."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.skip("no DATABASE_URL")
    return url
