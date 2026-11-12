"""``Cipher.encrypt`` before any request: the value rules and the empty list.

Every value is checked while the models are written into the engine's input
frame, before the shared client is built. So these tests need fake
credentials only, and make no request. The live round trip is in
``test_encrypt_live.py``.
"""

import dataclasses
import datetime
import decimal
import math
from typing import Annotated

import pytest

import stackencrypt
from stackencrypt import (
    Bigint,
    Cipher,
    Date,
    Double,
    InvalidValueError,
    Numeric,
    Passthrough,
    Real,
    Smallint,
    StashError,
    TextEq,
    Timestamp,
)

SECRET = "secret@example.com"


pytestmark = pytest.mark.usefixtures("credentials")


def cipher_for(**fields):
    """A Cipher for a dataclass with ``email: TextEq`` and ``fields``."""
    annotations = {"email": Annotated[str, TextEq], **fields}
    cls = dataclasses.make_dataclass("User", annotations.items())
    return Cipher(stackencrypt.model("users")(cls)), cls


def refused(cipher, model):
    with pytest.raises(InvalidValueError) as raised:
        cipher.encrypt([model])
    error = raised.value
    assert SECRET not in str(error)
    return error


def test_an_empty_list_is_an_empty_list_with_no_request(untouched):
    cipher, _ = cipher_for()
    assert cipher.encrypt([]) == []


def test_an_invalid_value_error_is_a_stash_error_and_a_value_error():
    assert issubclass(InvalidValueError, StashError)
    assert issubclass(InvalidValueError, ValueError)


def test_a_bool_on_an_int_field_is_the_wrong_type(untouched):
    cipher, User = cipher_for(age=Annotated[int, Bigint])
    error = refused(cipher, User(email=SECRET, age=True))
    assert error.code == "value_wrong_type"
    assert error.field == "age"
    assert error.reason == "int64"
    assert "bool" in error.message


def test_a_datetime_on_a_date_field_is_the_wrong_type(untouched):
    cipher, User = cipher_for(born=Annotated[datetime.date, Date])
    now = datetime.datetime.now(datetime.timezone.utc)
    error = refused(cipher, User(email=SECRET, born=now))
    assert error.code == "value_wrong_type"
    assert error.field == "born"


def test_none_on_a_sealed_field_is_refused(untouched):
    cipher, User = cipher_for()
    error = refused(cipher, User(email=None))
    assert error.code == "value_none"
    assert error.field == "email"
    assert error.reason == "string"


def test_none_on_a_passthrough_field_is_refused(untouched):
    cipher, User = cipher_for(age=Annotated[int, Passthrough])
    error = refused(cipher, User(email=SECRET, age=None))
    assert error.code == "value_none"
    assert error.reason == "passthrough"


def test_a_passthrough_value_of_another_type_is_refused(untouched):
    cipher, User = cipher_for(age=Annotated[int, Passthrough])
    error = refused(cipher, User(email=SECRET, age="3"))
    assert error.code == "value_wrong_type"
    assert error.field == "age"


def test_an_int_outside_its_kind_is_out_of_range(untouched):
    cipher, User = cipher_for(rank=Annotated[int, Smallint])
    error = refused(cipher, User(email=SECRET, rank=40_000))
    assert error.code == "value_out_of_range"
    assert error.field == "rank"
    assert error.reason == "int16"


def test_an_int_wider_than_128_bits_is_out_of_range(untouched):
    cipher, User = cipher_for(age=Annotated[int, Passthrough])
    error = refused(cipher, User(email=SECRET, age=2**200))
    assert error.code == "value_out_of_range"


def test_a_float_that_float32_cannot_hold_is_not_representable(untouched):
    cipher, User = cipher_for(score=Annotated[float, Real])
    error = refused(cipher, User(email=SECRET, score=0.1))
    assert error.code == "value_not_representable"
    assert error.reason == "float32"


def test_a_float64_takes_any_float(untouched):
    # Refused later by the engine for want of credentials, not by the value
    # rules: the value check passed.
    cipher, User = cipher_for(score=Annotated[float, Double])
    with pytest.raises(StashError) as raised:
        cipher.encrypt([User(email=SECRET, score=0.1)])
    assert not isinstance(raised.value, InvalidValueError)


@pytest.mark.parametrize(
    "value",
    [decimal.Decimal("NaN"), decimal.Decimal("Infinity"), decimal.Decimal("1e-29")],
    ids=["nan", "infinity", "scale-29"],
)
def test_a_decimal_outside_the_engines_bounds_is_not_representable(untouched, value):
    cipher, User = cipher_for(price=Annotated[decimal.Decimal, Numeric])
    error = refused(cipher, User(email=SECRET, price=value))
    assert error.code == "value_not_representable"
    assert error.reason == "decimal"


def test_a_naive_datetime_is_refused(untouched):
    cipher, User = cipher_for(seen=Annotated[datetime.datetime, Timestamp])
    error = refused(cipher, User(email=SECRET, seen=datetime.datetime(2026, 1, 1)))
    assert error.code == "value_naive_datetime"
    assert "tzinfo" in error.message


class NoOffset(datetime.tzinfo):
    """A tzinfo that gives no offset: Python counts its datetime as naive."""

    def utcoffset(self, dt):
        return None


def test_a_datetime_whose_tzinfo_gives_no_offset_is_naive(untouched):
    cipher, User = cipher_for(seen=Annotated[datetime.datetime, Timestamp])
    seen = datetime.datetime(2026, 1, 1, tzinfo=NoOffset())
    error = refused(cipher, User(email=SECRET, seen=seen))
    assert error.code == "value_naive_datetime"


def test_a_model_of_another_class_is_the_wrong_type(untouched):
    # Contact has the same field names, so every getattr would succeed.
    cipher, _ = cipher_for(age=Annotated[int, Passthrough])
    Contact = dataclasses.make_dataclass("Contact", [("email", str), ("age", int)])
    error = refused(cipher, Contact(email=SECRET, age=3))
    assert error.code == "value_wrong_type"
    assert "model 0 is a Contact" in error.message


def test_every_model_is_checked_before_any_request(untouched):
    # The bad value is in the last model of many.
    cipher, User = cipher_for(age=Annotated[int, Bigint])
    models = [User(email=SECRET, age=i) for i in range(100)] + [User(email=SECRET, age=math.pi)]
    with pytest.raises(InvalidValueError) as raised:
        cipher.encrypt(models)
    assert raised.value.field == "age"


def test_a_property_that_raises_propagates_unchanged(untouched):
    @stackencrypt.model("users")
    class User:
        email: Annotated[str, TextEq]

        def __init__(self, email):
            self._email = email

        @property
        def email(self):
            raise LookupError("the user's own error")

    with pytest.raises(LookupError, match="the user's own error"):
        Cipher(User).encrypt([User(email=SECRET)])


def test_a_zero_decimal_with_a_huge_exponent_passes_the_value_check():
    # The read is constant time: a loop per unit of exponent would hang here.
    # The call then fails building the client, with no client key set.
    cipher, User = cipher_for(price=Annotated[decimal.Decimal, Numeric])
    with pytest.raises(StashError) as raised:
        cipher.encrypt([User(email=SECRET, price=decimal.Decimal("0E+999999999999999999"))])
    assert not isinstance(raised.value, InvalidValueError)


def test_a_bad_zerokms_host_is_refused_naming_it(monkeypatch, untouched):
    monkeypatch.setenv("CS_ZEROKMS_HOST", "not a url")
    cipher, User = cipher_for()
    with pytest.raises(StashError) as raised:
        cipher.encrypt([User(email=SECRET)])
    assert raised.value.code == "stack_kms_invalid_endpoint"
    assert "CS_ZEROKMS_HOST" in str(raised.value)
