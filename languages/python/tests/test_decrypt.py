"""``Cipher.decrypt`` before any request: the row checks and the empty list.

Every row is checked before the shared client is built: its shape, its
columns, each EQL value's JSON and the table and column it names, and each
passthrough value's type. So these tests need fake credentials only, and
make no request. The live round trip is in ``test_encrypt_live.py``.
"""

import dataclasses
import datetime
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

# The `i` of a value stored under users.email, and the rest of an EQL value
# left out: the checks before any request read only `i`.
STORED = json.dumps({"i": {"t": "users", "c": "email"}, "v": 2})


pytestmark = pytest.mark.usefixtures("credentials")


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


def test_one_row_on_its_own_is_refused_as_one_row(untouched):
    # As from cursor.fetchone(): list() of a dict is its column names.
    error = refused({"email": STORED, "age": 3})
    assert error.code == "decrypt_row_shape"
    assert "not one row" in error.message


def test_a_dict_that_is_not_json_is_malformed(untouched):
    # A set has no JSON form: json.dumps raises TypeError.
    value = {"i": {"t": "users", "c": "email"}, "v": {1, 2}}
    error = refused([{"email": value, "age": 3}])
    assert error.code == "decrypt_malformed"
    assert error.field == "email"
    assert "row 0" in error.message


def test_a_str_that_is_not_valid_utf8_is_malformed(untouched):
    # A lone surrogate: a str Python holds, with no UTF-8 encoding.
    error = refused([{"email": "\ud800", "age": 3}])
    assert error.code == "decrypt_malformed"
    assert error.field == "email"


class Boom(Exception):
    """An error that is not about the input's JSON or type."""


class ExplodingDict(dict):
    """A dict whose items, which json.dumps reads, raise Boom."""

    def items(self):
        raise Boom("not about the JSON")


def test_an_error_that_is_not_about_the_json_propagates(untouched):
    with pytest.raises(Boom):
        Cipher(User).decrypt([{"email": ExplodingDict(i={}), "age": 3}])


class NoOffset(datetime.tzinfo):
    def utcoffset(self, dt):
        return None


class RaisingOffset(datetime.tzinfo):
    def utcoffset(self, dt):
        raise Boom("the user's own tzinfo")


@stackencrypt.model("visits")
@dataclasses.dataclass
class Visit:
    email: Annotated[str, TextEq]
    seen: Annotated[datetime.datetime, Passthrough]


VISIT_STORED = json.dumps({"i": {"t": "visits", "c": "email"}, "v": 2})


def test_a_passthrough_datetime_whose_tzinfo_gives_no_offset_is_naive(untouched):
    seen = datetime.datetime(2026, 1, 1, tzinfo=NoOffset())
    with pytest.raises(InvalidValueError) as raised:
        Cipher(Visit).decrypt([{"email": VISIT_STORED, "seen": seen}])
    assert raised.value.code == "value_naive_datetime"
    assert raised.value.field == "seen"


def test_an_error_from_a_passthrough_value_propagates(untouched):
    seen = datetime.datetime(2026, 1, 1, tzinfo=RaisingOffset())
    with pytest.raises(Boom):
        Cipher(Visit).decrypt([{"email": VISIT_STORED, "seen": seen}])


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


@pytest.mark.parametrize("value", [None, ""], ids=["null", "empty"])
def test_a_malformed_value_names_its_row(untouched, value):
    rows = [{"email": STORED, "age": i} for i in range(2)] + [{"email": value, "age": 2}]
    error = refused(rows)
    assert error.code == "decrypt_malformed"
    assert "row 2" in error.message


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
