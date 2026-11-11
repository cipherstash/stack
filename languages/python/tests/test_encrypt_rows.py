"""``Cipher.encrypt_rows`` before any request: the row rules.

These tests need fake credentials only, and make no request. The live round
trip is in ``test_encrypt_live.py``.
"""

import dataclasses
from typing import Annotated

import pytest

import stackencrypt
from stackencrypt import Cipher, Ignore, InvalidValueError, Passthrough, Text, TextEq

SECRET = "secret@example.com"

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


def refused(cipher, rows, error=InvalidValueError):
    with pytest.raises(error) as raised:
        cipher.encrypt_rows(rows)
    assert SECRET not in str(raised.value)
    return raised.value


def test_an_empty_list_is_an_empty_list_with_no_request(people, untouched):
    assert people.encrypt_rows([]) == []


def test_rows_with_no_declared_field_come_back_unchanged_with_no_request(people, untouched):
    rows = [{"people_id": 1}, {"people_id": 2, "id": 7}]
    assert people.encrypt_rows(rows) == rows


def test_a_row_that_is_not_a_mapping_is_refused(people, untouched):
    error = refused(people, [{"email": SECRET}, ("email", SECRET)])
    assert error.code == "value_row_shape"
    assert "row 1" in error.message


def test_rows_with_different_fields_are_refused(people, untouched):
    error = refused(people, [{"email": SECRET}, {"email": SECRET, "name": "Ann"}])
    assert error.code == "value_row_shape"
    assert "row 1" in error.message


def test_a_value_of_the_wrong_type_names_the_field(people, untouched):
    error = refused(people, [{"email": SECRET, "age": "3"}])
    assert error.code == "value_wrong_type"
    assert error.field == "age"


def test_a_none_value_is_refused(people, untouched):
    error = refused(people, [{"email": None}])
    assert error.code == "value_none"
    assert error.field == "email"


def test_the_input_rows_are_not_changed(people, untouched):
    rows = [{"email": SECRET, "age": "3"}]
    refused(people, rows)
    assert rows == [{"email": SECRET, "age": "3"}]
