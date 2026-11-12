"""The refusals of the switch to the deterministic client.

conftest.py has switched this process once, before any test. A second
switch is refused, and a seed that is not 32 bytes is refused before any
switch is tried.
"""

import pytest

from stackencrypt import StashError, _engine


def test_a_second_switch_is_refused():
    with pytest.raises(StashError) as raised:
        _engine._use_deterministic_keys(bytes(32))
    assert raised.value.code == "stack_test_build"


@pytest.mark.parametrize("length", [0, 31, 33])
def test_a_seed_that_is_not_32_bytes_is_refused(length):
    with pytest.raises(ValueError):
        _engine._use_deterministic_keys(bytes(length))
