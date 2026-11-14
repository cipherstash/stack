"""The value rules, through ``encrypt`` and ``eq`` alike.

Every value is checked by exact type and range before any request, by one
function that both calls use. Each case here runs through both, and the
``untouched`` fixture fails a case that built the client or sent a request.

A value that passes every check reaches the engine. With fake credentials
and no client key, the engine then fails to build its client: that failure
is a ``StashError`` that is not an ``InvalidValueError``, which shows the
checks passed. The round trip of each value is in ``test_encrypt_live.py``.
"""

import dataclasses
import datetime
import decimal
import math
from typing import Annotated, Any, List, Tuple

import pytest

import stackencrypt
from stackencrypt import (
    BigintEq,
    Boolean,
    Cipher,
    DateEq,
    DeclarationError,
    DoubleEq,
    IntegerEq,
    InvalidValueError,
    NumericEq,
    QueryError,
    RealEq,
    SmallintEq,
    StashError,
    TextEq,
    TimestampEq,
)

pytestmark = pytest.mark.usefixtures("credentials")

UTC = datetime.timezone.utc
TEN_HOURS_AHEAD = datetime.timezone(datetime.timedelta(hours=10))

# The Python type each marker's field is declared with.
PYTHON_TYPE = {
    SmallintEq: int,
    IntegerEq: int,
    BigintEq: int,
    RealEq: float,
    DoubleEq: float,
    NumericEq: decimal.Decimal,
    Boolean: bool,
    DateEq: datetime.date,
    TimestampEq: datetime.datetime,
    TextEq: str,
}


def declared(marker: Any) -> Tuple[Cipher, Any]:
    """A cipher for a class with one field ``x`` of ``marker``. Built
    outside ``pytest.raises``, so a refused declaration fails the test."""
    cls = dataclasses.make_dataclass(
        "Row", [("x", Annotated[PYTHON_TYPE[marker], marker])]
    )
    return Cipher(stackencrypt.model("rows")(cls)), cls


def through_encrypt(cipher: Cipher, cls: Any, value: Any) -> None:
    cipher.encrypt([cls(x=value)])


def through_eq(cipher: Cipher, cls: Any, value: Any) -> None:
    cipher.eq("x", value)


def calls(cases: List[Tuple[Any, ...]]) -> List[Any]:
    """Each case through ``encrypt``, and through ``eq`` where the
    marker has an ``eq`` index. ``Boolean`` has none."""
    return [
        pytest.param(call, *case, id=f"{call.__name__}-{case[0].__name__}-{case[1]!r}")
        for case in cases
        for call in (through_encrypt, through_eq)
        if call is through_encrypt or "eq" in case[0].indexes
    ]


# (marker, value, code, reason): one value per refusal the rules make.
REFUSED: List[Tuple[Any, Any, str, str]] = [
    (BigintEq, 2**63, "value_out_of_range", "int64"),
    (BigintEq, -(2**63) - 1, "value_out_of_range", "int64"),
    (IntegerEq, 2**31, "value_out_of_range", "int32"),
    (IntegerEq, -(2**31) - 1, "value_out_of_range", "int32"),
    (SmallintEq, 2**15, "value_out_of_range", "int16"),
    (SmallintEq, -(2**15) - 1, "value_out_of_range", "int16"),
    (RealEq, 0.1, "value_not_representable", "float32"),
    (RealEq, 1e39, "value_not_representable", "float32"),
    (NumericEq, decimal.Decimal("NaN"), "value_not_representable", "decimal"),
    # One past the largest 96-bit mantissa, on each side.
    (NumericEq, decimal.Decimal("79228162514264337593543950336"), "value_not_representable", "decimal"),
    (NumericEq, decimal.Decimal("-79228162514264337593543950336"), "value_not_representable", "decimal"),
    (NumericEq, decimal.Decimal("Infinity"), "value_not_representable", "decimal"),
    (NumericEq, decimal.Decimal("1e-29"), "value_not_representable", "decimal"),
    (TimestampEq, datetime.datetime(2024, 1, 1), "value_naive_datetime", "timestamp"),
    (TextEq, None, "value_none", "string"),
    (BigintEq, None, "value_none", "int64"),
    (BigintEq, True, "value_wrong_type", "int64"),
    (IntegerEq, 1.0, "value_wrong_type", "int32"),
    (DoubleEq, 1, "value_wrong_type", "float64"),
    (NumericEq, 1.5, "value_wrong_type", "decimal"),
    (DateEq, datetime.datetime(2024, 1, 1, tzinfo=UTC), "value_wrong_type", "date"),
    (TextEq, b"bytes", "value_wrong_type", "string"),
    (Boolean, 1, "value_wrong_type", "bool"),
]


@pytest.mark.parametrize(("call", "marker", "value", "code", "reason"), calls(REFUSED))
def test_a_value_that_does_not_fit_is_refused_before_any_request(
    untouched, call, marker, value, code, reason
):
    cipher, cls = declared(marker)
    with pytest.raises(InvalidValueError) as raised:
        call(cipher, cls, value)

    assert raised.value.code == code
    assert raised.value.field == "x"
    assert raised.value.reason == reason


# (marker, value): values at the edge of what each rule accepts.
ACCEPTED: List[Tuple[Any, Any]] = [
    (BigintEq, 2**63 - 1),
    (BigintEq, -(2**63)),
    (IntegerEq, 2**31 - 1),
    (IntegerEq, -(2**31)),
    (SmallintEq, 2**15 - 1),
    (SmallintEq, -(2**15)),
    (RealEq, 0.5),
    (RealEq, math.nan),
    (RealEq, math.inf),
    (RealEq, -math.inf),
    (RealEq, -0.0),
    (DoubleEq, 0.1),
    (DoubleEq, math.nan),
    (DoubleEq, -math.inf),
    (NumericEq, decimal.Decimal("-79228162514264337593543950335")),
    (NumericEq, decimal.Decimal("1e-28")),
    (Boolean, False),
    (DateEq, datetime.date(1, 1, 1)),
    (TimestampEq, datetime.datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)),
    (TimestampEq, datetime.datetime(2024, 1, 1, tzinfo=TEN_HOURS_AHEAD)),
    (TextEq, ""),
]


@pytest.mark.parametrize(("call", "marker", "value"), calls(ACCEPTED))
def test_a_value_at_the_edge_passes_every_check(call, marker, value):
    cipher, cls = declared(marker)
    with pytest.raises(StashError) as raised:
        call(cipher, cls, value)

    # Only the failure to build the client shows that every check passed.
    refused = (InvalidValueError, QueryError, DeclarationError)
    assert not isinstance(raised.value, refused), raised.value
