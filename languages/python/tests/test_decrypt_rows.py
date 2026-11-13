"""``Cipher.decrypt_rows`` before any request: the row rules.

These tests need fake credentials only, and make no request. The live round
trip is in ``test_encrypt_live.py``.
"""

import dataclasses
import json
from typing import Annotated

import pytest

import stackencrypt
from stackencrypt import (
    Cipher,
    DecryptError,
    Ignore,
    InvalidValueError,
    Passthrough,
    StashError,
    Text,
    TextEq,
)

# The `i` of a value stored under people.email, and the rest of an EQL value
# left out: the checks before any request read only `i`.
STORED = json.dumps({"i": {"t": "people", "c": "email"}, "v": 2})

pytestmark = pytest.mark.usefixtures("credentials")


@stackencrypt.model("people")
@dataclasses.dataclass
class Person:
    email: Annotated[str, TextEq]
    name: Annotated[str, Text]
    age: Annotated[int, Passthrough]
    id: Annotated[int, Ignore] = 0


@pytest.fixture
def people():
    return Cipher(Person)


def refused(cipher, rows, error=DecryptError):
    with pytest.raises(error) as raised:
        cipher.decrypt_rows(rows)
    return raised.value


def test_an_empty_list_is_an_empty_list_with_no_request(people, untouched):
    assert people.decrypt_rows([]) == []


def test_rows_with_no_declared_field_come_back_unchanged_with_no_request(people, untouched):
    rows = [{"people_id": 1}, {"people_id": 2, "id": 7}]
    assert people.decrypt_rows(rows) == rows


def test_one_row_on_its_own_is_refused_as_one_row(people, untouched):
    error = refused(people, {"email": STORED, "age": 3})
    assert error.code == "decrypt_row_shape"
    assert "not one row" in error.message


def test_one_tuple_row_on_its_own_is_refused_as_one_row(people, untouched):
    # A tuple row is a sequence of its column values. Passed alone, each
    # EQL value would be read as a row with no declared field, and come
    # back unchanged with no error.
    value = json.loads(STORED)
    error = refused(people, (value, value))
    assert error.code == "decrypt_row_shape"
    assert "one EQL value" in error.message


def test_a_sqlalchemy_row_on_its_own_is_refused(people, untouched):
    from sqlalchemy import create_engine, text

    with create_engine("sqlite://").connect() as connection:
        row = connection.execute(text("SELECT 1 AS age")).first()
    error = refused(people, row)
    assert error.code == "decrypt_row_shape"
    assert "_mapping" in error.message


def test_a_row_that_is_not_a_mapping_is_refused(people, untouched):
    error = refused(people, [{"email": STORED}, (STORED,)])
    assert error.code == "decrypt_row_shape"
    assert "row 1" in error.message


def test_rows_with_different_fields_are_refused(people, untouched):
    error = refused(people, [{"email": STORED}, {"email": STORED, "age": 3}])
    assert error.code == "decrypt_row_shape"
    assert "row 1" in error.message


@pytest.mark.parametrize("value", [STORED[:10], 42, None], ids=["truncated", "int", "null"])
def test_a_value_that_is_not_eql_json_is_malformed(people, untouched, value):
    error = refused(people, [{"email": value}])
    assert error.code == "decrypt_malformed"
    assert error.field == "email"


def test_a_value_stored_under_another_column_is_a_foreign_row(people, untouched):
    error = refused(people, [{"name": STORED}])
    assert error.code == "decrypt_foreign_row"
    assert error.field == "name"


def test_a_passthrough_of_the_wrong_type_is_refused(people, untouched):
    error = refused(people, [{"email": STORED, "age": "3"}], InvalidValueError)
    assert error.field == "age"


def test_a_row_that_passes_every_check_reaches_the_engine(people):
    # Refused later by the engine for want of a client key, not by the row
    # checks: they passed.
    with pytest.raises(StashError) as raised:
        people.decrypt_rows([{"email": STORED, "people_id": 1}])
    assert not isinstance(raised.value, (DecryptError, InvalidValueError))
