"""Gate fact 2 (#1384): a KeyboardInterrupt sent during a call that released
the GIL is raised only after that call returns.

Runs only against a wheel built with the `gate-probe` cargo feature; see
docs/gate-facts/keyboard-interrupt.md. Skipped otherwise.
"""

import sys
import time

import pytest
from _sync_contract import send_sigint_later, wait_for_the_interrupt

from stackencrypt import _engine

probe = getattr(_engine, "_probe_detached_sleep", None)

pytestmark = [
    pytest.mark.skipif(probe is None, reason="built without the gate-probe feature"),
    pytest.mark.skipif(sys.platform == "win32", reason="SIGINT is sent with os.kill"),
]

CALL_MS = 1000
SIGNAL_AT_S = 0.2


def call_then_wait_for_the_interrupt():
    probe(CALL_MS)
    wait_for_the_interrupt()


def test_interrupt_waits_for_the_detached_call_to_return():
    timer = send_sigint_later(SIGNAL_AT_S)
    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        call_then_wait_for_the_interrupt()
    raised_after_s = time.monotonic() - started
    timer.join()

    # The signal was sent at 0.2 s. If the call had been cut short, the
    # interrupt would arrive then. It must arrive after the call's full second.
    assert raised_after_s >= CALL_MS / 1000


def test_the_extension_is_usable_after_an_interrupt():
    timer = send_sigint_later(SIGNAL_AT_S)
    with pytest.raises(KeyboardInterrupt):
        call_then_wait_for_the_interrupt()
    timer.join()

    assert probe(10) >= 10
