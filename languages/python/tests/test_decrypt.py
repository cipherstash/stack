"""``Cipher.decrypt`` before any request: the row checks and the empty list.

Every row is checked before the shared client is built: its shape, its
columns, each EQL value's JSON and the table and column it names, and each
passthrough value's type. So these tests need fake credentials only, and
make no request. The live round trip is in ``test_encrypt_live.py``.
"""

import dataclasses
import json
from typing import Annotated

import pytest

import stackencrypt
from stackencrypt import (
    Cipher,
    DecryptError,
    InvalidValueError,
    Passthrough,
    StashError,
    TextEq,
)
from stackencrypt import _engine

# The `i` of a value stored under users.email, and the rest of an EQL value
# left out: the checks before any request read only `i`.
STORED = json.dumps({"i": {"t": "users", "c": "email"}, "v": 2})


@pytest.fixture(autouse=True)
def credentials(monkeypatch, tmp_path):
    """Credentials that parse, so ``Cipher`` builds. Nothing here sends them."""
    for name in ("CS_CLIENT_ID", "CS_CLIENT_KEY", "CS_CTS_HOST", "CS_ZEROKMS_HOST", "CS_VITUR_HOST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CS_CLIENT_ACCESS_KEY", "CSAKtestKeyId.testKeySecret")
    monkeypatch.setenv("CS_WORKSPACE_CRN", "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY")
    monkeypatch.setenv("CS_CONFIG_PATH", str(tmp_path / "no-profile"))


@pytest.fixture
def untouched():
    """Fails the test if the shared client was built or a request was sent."""
    builds, requests = _engine.client_builds(), _engine.request_count()
    yield
    assert _engine.client_builds() == builds
    assert _engine.request_count() == requests


@stackencrypt.model("users")
@dataclasses.dataclass
class User:
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]


def refused(rows, error=DecryptError):
    with pytest.raises(error) as raised:
        Cipher(User).decrypt(rows)
    return raised.value


def test_an_empty_list_is_an_empty_list_with_no_request(untouched):
    assert Cipher(User).decrypt([]) == []


def test_a_decrypt_error_is_a_stash_error():
    assert issubclass(DecryptError, StashError)


def test_a_tuple_row_is_the_wrong_shape_and_names_dict_row(untouched):
    error = refused([(STORED, 3)])
    assert error.code == "decrypt_row_shape"
    assert "dict_row" in error.message


def test_a_row_without_a_declared_column_names_it(untouched):
    error = refused([{"email": STORED}])
    assert error.code == "decrypt_missing_column"
    assert error.field == "age"


@pytest.mark.parametrize(
    "stored",
    [
        json.dumps({"i": {"t": "users", "c": "login"}}),
        json.dumps({"i": {"t": "accounts", "c": "email"}}),
    ],
    ids=["another-column", "another-table"],
)
def test_a_value_stored_under_another_column_is_a_foreign_row(untouched, stored):
    error = refused([{"email": stored, "age": 3}])
    assert error.code == "decrypt_foreign_row"
    assert error.field == "email"


@pytest.mark.parametrize(
    "value",
    [STORED.encode(), json.loads(STORED)],
    ids=["bytes", "dict"],
)
def test_bytes_and_dict_values_are_read_as_eql_json(untouched, value):
    # Each form reaches the same checks as the str: the row is refused for
    # its passthrough, after the EQL value was read and accepted.
    error = refused([{"email": value, "age": "3"}], InvalidValueError)
    assert error.field == "age"


@pytest.mark.parametrize(
    "value",
    [STORED[: len(STORED) // 2], b"\xff\xfe", 42, None, "[]"],
    ids=["truncated", "not-utf-8", "int", "null", "not-an-object"],
)
def test_a_value_that_is_not_eql_json_is_malformed(untouched, value):
    error = refused([{"email": value, "age": 3}])
    assert error.code == "decrypt_malformed"
    assert error.field == "email"


def test_a_passthrough_int_that_arrives_as_str_is_the_wrong_type(untouched):
    error = refused([{"email": STORED, "age": "3"}], InvalidValueError)
    assert error.code == "value_wrong_type"
    assert error.field == "age"
    assert error.reason == "passthrough"


def test_a_null_passthrough_is_refused(untouched):
    error = refused([{"email": STORED, "age": None}], InvalidValueError)
    assert error.code == "value_none"
    assert error.field == "age"


def test_one_bad_row_in_ten_fails_the_call_before_any_request(untouched):
    rows = [{"email": STORED, "age": i} for i in range(9)] + [{"email": STORED}]
    error = refused(rows)
    assert error.code == "decrypt_missing_column"
    assert "row 9" in error.message


def test_extra_columns_are_not_read(untouched):
    # The extra column holds what every check would refuse. The row is
    # refused for its passthrough instead, so the extra column was not read.
    error = refused([{"email": STORED, "age": "3", "id": object()}], InvalidValueError)
    assert error.field == "age"


def test_a_row_that_passes_every_check_reaches_the_engine():
    # Refused later by the engine for want of a client key, not by the row
    # checks: they passed.
    with pytest.raises(StashError) as raised:
        Cipher(User).decrypt([{"email": STORED, "age": 3}])
    assert not isinstance(raised.value, (DecryptError, InvalidValueError))
