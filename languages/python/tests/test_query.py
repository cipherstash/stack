"""``Cipher.query`` before any request: the field checks and the value checks.

A name that is not a declared field, a field that answers no query, and a
value that does not fit are all refused before the shared client is built.
So these tests need fake credentials only, and make no request. The live
search, the index, and the request count are in ``test_encrypt_live.py``.
"""

import dataclasses
from typing import Annotated

import pytest

import stackencrypt
from stackencrypt import (
    Cipher,
    IntegerEq,
    InvalidValueError,
    Passthrough,
    QueryError,
    StashError,
    Text,
    TextEq,
)

pytestmark = pytest.mark.usefixtures("credentials")


@stackencrypt.model("users")
@dataclasses.dataclass
class User:
    email: Annotated[str, TextEq]
    bio: Annotated[str, Text]
    age: Annotated[int, Passthrough]
    rank: Annotated[int, IntegerEq]


def refused(field, value, error=QueryError):
    with pytest.raises(error) as raised:
        Cipher(User).query(field, value)
    return raised.value


def test_a_query_error_is_a_stash_error():
    assert issubclass(QueryError, StashError)


def test_an_unknown_name_lists_the_fields_with_a_query(untouched):
    error = refused("emial", "a@example.com")
    assert error.code == "query_unknown_field"
    assert error.field == "emial"
    assert "'emial'" in error.message
    assert "Fields with a query: 'email', 'rank'." in error.message


def test_a_field_that_is_not_a_str_is_an_unknown_name(untouched):
    error = refused(None, "a@example.com")
    assert error.code == "query_unknown_field"
    assert error.field is None


def test_a_text_field_answers_no_query(untouched):
    error = refused("bio", "hello")
    assert error.code == "query_unsupported"
    assert error.field == "bio"
    assert error.reason == "Text"


def test_a_passthrough_field_answers_no_query(untouched):
    error = refused("age", 3)
    assert error.code == "query_unsupported"
    assert error.field == "age"
    assert error.reason == "Passthrough"


def test_a_class_with_no_queryable_field_says_so(untouched):
    @stackencrypt.model("notes")
    @dataclasses.dataclass
    class Note:
        body: Annotated[str, Text]

    with pytest.raises(QueryError) as raised:
        Cipher(Note).query("body", "x")
    assert "The class has no field with a query." in raised.value.message


def test_a_value_of_another_type_is_the_wrong_type(untouched):
    error = refused("email", 3, InvalidValueError)
    assert error.code == "value_wrong_type"
    assert error.field == "email"
    assert error.reason == "string"


def test_a_bool_on_an_integer_field_is_the_wrong_type(untouched):
    error = refused("rank", True, InvalidValueError)
    assert error.code == "value_wrong_type"
    assert error.field == "rank"


def test_none_is_refused(untouched):
    error = refused("email", None, InvalidValueError)
    assert error.code == "value_none"


def test_a_value_out_of_range_is_refused(untouched):
    error = refused("rank", 2**31, InvalidValueError)
    assert error.code == "value_out_of_range"
    assert error.reason == "int32"


def test_the_message_never_contains_the_value(untouched):
    error = refused("email", 123456789, InvalidValueError)
    assert "123456789" not in str(error)


def test_a_query_that_passes_every_check_reaches_the_engine():
    # Refused later by the engine for want of a client key, not by the
    # checks: they passed.
    with pytest.raises(StashError) as raised:
        Cipher(User).query("email", "a@example.com")
    assert not isinstance(raised.value, (QueryError, InvalidValueError))
