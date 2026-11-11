"""A field declared ``Optional``, before any request: ``None`` passes the
checks of ``encrypt``, ``decrypt`` and the ``*_rows`` methods, and a query
term refuses it.

These tests need fake credentials only. A call that passes every check
fails building the engine client, with no request. The round trip is in
``test_encrypt_live.py``.
"""

import dataclasses
import json
from typing import Annotated, Optional

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

pytestmark = pytest.mark.usefixtures("credentials")


@stackencrypt.model("places")
@dataclasses.dataclass
class Place:
    name: Annotated[str, TextEq]
    city: Annotated[Optional[str], TextEq]
    note: Annotated[Optional[str], Passthrough]


STORED = json.dumps({"i": {"t": "places", "c": "name"}, "v": 2})


def reaches_the_engine(call):
    # Refused later by the engine for want of a client key, not by the
    # value checks: they passed.
    with pytest.raises(StashError) as raised:
        call()
    assert not isinstance(raised.value, (InvalidValueError, DecryptError))


def test_none_in_an_optional_field_passes_the_encrypt_checks():
    reaches_the_engine(lambda: Cipher(Place).encrypt([Place(name="a", city=None, note=None)]))


def test_none_in_a_field_that_is_not_optional_is_still_refused(untouched):
    with pytest.raises(InvalidValueError) as raised:
        Cipher(Place).encrypt([Place(name=None, city="Leeds", note=None)])
    assert raised.value.code == "value_none"
    assert raised.value.field == "name"


def test_none_in_an_optional_field_passes_the_encrypt_rows_checks():
    reaches_the_engine(lambda: Cipher(Place).encrypt_rows([{"city": None, "note": None}]))


def test_a_null_column_of_an_optional_field_passes_the_decrypt_checks():
    reaches_the_engine(lambda: Cipher(Place).decrypt([{"name": STORED, "city": None, "note": None}]))


def test_a_null_column_of_a_field_that_is_not_optional_is_still_refused(untouched):
    with pytest.raises(DecryptError) as raised:
        Cipher(Place).decrypt([{"name": None, "city": None, "note": None}])
    assert raised.value.code == "decrypt_malformed"
    assert raised.value.field == "name"


def test_a_query_term_for_none_is_refused_and_points_to_is_null(untouched):
    with pytest.raises(InvalidValueError) as raised:
        Cipher(Place).eq("city", None)
    assert raised.value.code == "value_none"
    assert raised.value.field == "city"
    assert "IS NULL" in raised.value.message
