"""The query methods before any request: the field checks and the value checks.

``eq``, ``lt``, ``lte``, ``gt``, ``gte`` and ``matches`` (ADR-0003). A name that is not a
declared field, a field that does not support the operator, and a value that
does not fit are all refused before the shared client is built.
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
    IntegerOrd,
    InvalidValueError,
    Passthrough,
    QueryError,
    StashError,
    Text,
    TextEq,
    TextMatch,
)

pytestmark = pytest.mark.usefixtures("credentials")


@stackencrypt.model("users")
@dataclasses.dataclass
class User:
    email: Annotated[str, TextEq]
    bio: Annotated[str, Text]
    age: Annotated[int, Passthrough]
    rank: Annotated[int, IntegerEq]
    level: Annotated[int, IntegerOrd]
    notes: Annotated[str, TextMatch]


ORDER = ["lt", "lte", "gt", "gte"]


def refused(field, value, error=QueryError, op="eq"):
    with pytest.raises(error) as raised:
        getattr(Cipher(User), op)(field, value)
    return raised.value


def test_query_is_gone():
    # ADR-0003: one method for each operator, and no second way to make an
    # equality term.
    assert not hasattr(Cipher, "query")


def test_a_query_error_is_a_stash_error():
    assert issubclass(QueryError, StashError)


def test_an_unknown_name_lists_the_fields_with_a_query(untouched):
    error = refused("emial", "a@example.com")
    assert error.code == "query_unknown_field"
    assert error.field == "emial"
    assert "'emial'" in error.message
    assert "Fields that support eq: 'email', 'rank'." in error.message


def test_a_field_that_is_not_a_str_is_an_unknown_name(untouched):
    error = refused(None, "a@example.com")
    assert error.code == "query_unknown_field"
    assert error.field is None


def test_an_unknown_name_lists_the_fields_with_the_operator(untouched):
    error = refused("lvl", 3, op="gte")
    assert error.code == "query_unknown_field"
    assert "Fields that support gte: 'level'." in error.message


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


@pytest.mark.parametrize(
    ("field", "value", "marker"),
    [("level", 3, "IntegerOrd"), ("notes", "hello", "TextMatch")],
)
def test_a_field_with_a_query_type_but_no_eq_index_answers_no_eq(
    untouched, field, value, marker
):
    # The marker has a query type, for order or match. The engine answers
    # eq through the eq index alone.
    error = refused(field, value)
    assert error.code == "query_unsupported"
    assert error.field == field
    assert error.reason == marker
    assert "does not support eq" in error.message


@pytest.mark.parametrize("op", ORDER)
@pytest.mark.parametrize(
    ("field", "value", "marker"),
    [("email", "a@example.com", "TextEq"), ("notes", "hello", "TextMatch")],
)
def test_a_field_with_no_order_index_answers_no_order_operator(
    untouched, op, field, value, marker
):
    error = refused(field, value, op=op)
    assert error.code == "query_unsupported"
    assert error.field == field
    assert error.reason == marker
    assert f"does not support {op}" in error.message


@pytest.mark.parametrize("op", ORDER)
def test_a_passthrough_field_answers_no_order_operator(untouched, op):
    error = refused("age", 3, op=op)
    assert error.code == "query_unsupported"
    assert error.reason == "Passthrough"


@pytest.mark.parametrize("op", ORDER)
def test_an_order_value_of_another_type_is_the_wrong_type(untouched, op):
    error = refused("level", "3", InvalidValueError, op=op)
    assert error.code == "value_wrong_type"
    assert error.field == "level"


def test_a_class_with_no_queryable_field_says_so(untouched):
    @stackencrypt.model("notes")
    @dataclasses.dataclass
    class Note:
        body: Annotated[str, Text]

    with pytest.raises(QueryError) as raised:
        Cipher(Note).eq("body", "x")
    assert "The class has no field that supports eq." in raised.value.message


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


@pytest.mark.parametrize(
    ("field", "value", "marker"),
    [("email", "a@example.com", "TextEq"), ("level", 3, "IntegerOrd")],
)
def test_a_field_with_no_match_index_answers_no_matches(untouched, field, value, marker):
    error = refused(field, value, op="matches")
    assert error.code == "query_unsupported"
    assert error.reason == marker
    assert "does not support matches" in error.message
    assert "Fields that support matches: 'notes'." in error.message


def test_matches_takes_text_only(untouched):
    error = refused("notes", 3, InvalidValueError, op="matches")
    assert error.code == "value_wrong_type"
    assert error.field == "notes"


def test_matches_message_never_contains_the_text(untouched):
    error = refused("email", "zebracorn", op="matches")
    assert "zebracorn" not in str(error)


@pytest.mark.parametrize(
    ("op", "field", "value"),
    [("eq", "email", "a@example.com"), ("matches", "notes", "hello")]
    + [(op, "level", 3) for op in ORDER],
)
def test_a_query_that_passes_every_check_reaches_the_engine(op, field, value):
    # Refused later by the engine for want of a client key, not by the
    # checks: they passed.
    with pytest.raises(StashError) as raised:
        getattr(Cipher(User), op)(field, value)
    assert not isinstance(raised.value, (QueryError, InvalidValueError))
