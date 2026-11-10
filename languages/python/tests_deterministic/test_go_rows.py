"""Python against the EQL rows the Go SDK stored, under the same seed.

Every fixture here is in `packages/eql/tests/encryption/fixtures/`, written by
the Go SDK's generated code over the deterministic EQL guest. Each model
declares the same table, columns and EQL types as its Go type in
`languages/golang/encrypt/internal/testusers/`.

- `stored_v4_rows_v1.json` is FROZEN: nothing writes it again. Go
  (`TestFrozenV4RowsStillOpen`) and Rust (`tests/v4_types.rs`) check it too.
  A build that cannot open it is red.
- `v4_ordered_rows.json`, `v4_smallint_rows.json` and `v4_ledger_rows.json`
  are regenerated when the stored format changes on purpose. They hold what
  the Go SDK seals today, for the types the frozen file lacks: the order
  terms, `Smallint`, dates, timestamps and decimals.

For each, Python opens the rows Go stored, and seals the same plaintexts to
the same stored values apart from each ciphertext `c`. The equality, order
and match terms are deterministic, so they must be byte-identical. Python's
equality query term for each value must be the term Go stored.
"""

import dataclasses
import datetime
import decimal
import json
import struct
from pathlib import Path
from typing import Annotated

import pytest

import stackencrypt
from stackencrypt import (
    Bigint,
    BigintEq,
    BigintOrd,
    BigintOrdOpe,
    Boolean,
    Cipher,
    Date,
    DateEq,
    DecryptError,
    Double,
    DoubleEq,
    DoubleOrd,
    DoubleOrdOpe,
    Integer,
    IntegerEq,
    IntegerOrd,
    IntegerOrdOpe,
    Numeric,
    NumericEq,
    Passthrough,
    Real,
    RealEq,
    RealOrd,
    RealOrdOpe,
    Smallint,
    SmallintEq,
    Text,
    TextEq,
    TextMatch,
    TextOrd,
    TextOrdOpe,
    Timestamp,
    TimestampEq,
)


@stackencrypt.model("profiles")
@dataclasses.dataclass
class Profile:
    id: Annotated[int, Passthrough]
    visits: Annotated[int, Integer]
    balance: Annotated[int, Bigint]
    active: Annotated[bool, Boolean]
    ratio: Annotated[float, Real]
    score: Annotated[float, Double]
    note: Annotated[str, Text]
    name: Annotated[str, TextMatch]
    age: Annotated[int, IntegerEq]
    rank: Annotated[int, BigintEq]
    weight: Annotated[float, RealEq]
    price: Annotated[float, DoubleEq]
    email: Annotated[str, TextEq]


@stackencrypt.model("rankings")
@dataclasses.dataclass
class Ranking:
    id: Annotated[int, Passthrough]
    level: Annotated[int, IntegerOrd]
    floor: Annotated[int, IntegerOrdOpe]
    points: Annotated[int, BigintOrd]
    total: Annotated[int, BigintOrdOpe]
    speed: Annotated[float, RealOrd]
    pace: Annotated[float, RealOrdOpe]
    score: Annotated[float, DoubleOrd]
    mean: Annotated[float, DoubleOrdOpe]
    title: Annotated[str, TextOrd]
    handle: Annotated[str, TextOrdOpe]


@stackencrypt.model("profiles")
@dataclasses.dataclass
class Tally:
    id: Annotated[int, Passthrough]
    small: Annotated[int, Smallint]
    tally: Annotated[int, SmallintEq]
    wide: Annotated[int, SmallintEq]


@stackencrypt.model("profiles")
@dataclasses.dataclass
class Ledger:
    id: Annotated[int, Passthrough]
    opened: Annotated[datetime.date, Date]
    due: Annotated[datetime.date, DateEq]
    created: Annotated[datetime.datetime, Timestamp]
    posted: Annotated[datetime.datetime, TimestampEq]
    total: Annotated[decimal.Decimal, Numeric]
    amount: Annotated[decimal.Decimal, NumericEq]


# The Go SDK's EQL fixtures. Not imported from conftest.py: `from conftest`
# resolves to whichever conftest.py is first on sys.path.
FIXTURES = Path(__file__).resolve().parents[3] / "packages/eql/tests/encryption/fixtures"

# (fixture, model, the row ids Python's types can hold). Ledger rows 1 and 2
# hold years past Python's 1 to 9999 and nanosecond timestamps: the tests
# at the end check each refusal on its own.
CASES = [
    ("stored_v4_rows_v1.json", Profile, [1, 2]),
    ("v4_ordered_rows.json", Ranking, [1, 2, 3]),
    ("v4_smallint_rows.json", Tally, [1, 2, 3]),
    ("v4_ledger_rows.json", Ledger, [3]),
]
IDS = [fixture for fixture, _, _ in CASES]


def rows_of(fixture, ids):
    rows = json.loads((FIXTURES / fixture).read_text())["rows"]
    assert set(ids) <= {row["id"] for row in rows}, (fixture, ids)
    return [row for row in rows if row["id"] in ids]


def sealed_fields(cls):
    return [field for field in dataclasses.fields(cls) if field.name != "id"]


def value_of(python_type, plaintext):
    """A Go fixture's JSON plaintext as the field's Python value."""
    if python_type is datetime.datetime:
        return datetime.datetime.fromisoformat(plaintext.replace("Z", "+00:00"))
    if python_type is datetime.date:
        return datetime.date.fromisoformat(plaintext)
    if python_type is decimal.Decimal:
        return decimal.Decimal(plaintext)
    # JSON gives 0 for a float field whose value is zero.
    return python_type(plaintext)


def model_of(cls, row):
    values = {
        field.name: value_of(field.type.__origin__, row["plaintext"][field.name])
        for field in sealed_fields(cls)
    }
    return cls(id=row["id"], **values)


def stored_row(cls, row):
    """The row as psycopg's dict_row gives it: EQL values as JSON text."""
    return {
        "id": row["id"],
        **{f.name: json.dumps(row["stored"][f.name]) for f in sealed_fields(cls)},
    }


def exact(value):
    """A form whose == also compares a float's sign, a Decimal's scale, the
    type (True is not 1), and an instant whatever its zone."""
    if isinstance(value, float):
        return struct.pack("<d", value)
    if isinstance(value, decimal.Decimal):
        return value.as_tuple()
    if isinstance(value, datetime.datetime):
        assert value.utcoffset() is not None, value
        return value.astimezone(datetime.timezone.utc)
    return (type(value), value)


def without_ciphertext(value):
    stored = json.loads(value) if isinstance(value, str) else dict(value)
    stored.pop("c", None)
    return stored


@pytest.mark.parametrize(("fixture", "cls", "ids"), CASES, ids=IDS)
def test_python_opens_the_rows_the_go_sdk_stored(fixture, cls, ids):
    rows = rows_of(fixture, ids)

    opened = Cipher(cls).decrypt([stored_row(cls, row) for row in rows])

    for row, model in zip(rows, opened):
        expected = model_of(cls, row)
        for field in dataclasses.fields(cls):
            got, want = getattr(model, field.name), getattr(expected, field.name)
            assert exact(got) == exact(want), (row["id"], field.name)


@pytest.mark.parametrize(("fixture", "cls", "ids"), CASES, ids=IDS)
def test_python_seals_what_the_go_sdk_sealed_apart_from_each_ciphertext(fixture, cls, ids):
    rows = rows_of(fixture, ids)

    sealed = Cipher(cls).encrypt([model_of(cls, row) for row in rows])

    for row, columns in zip(rows, sealed):
        for field in sealed_fields(cls):
            assert without_ciphertext(columns[field.name]) == without_ciphertext(
                row["stored"][field.name]
            ), (row["id"], field.name)


@pytest.mark.parametrize(("fixture", "cls", "ids"), CASES, ids=IDS)
def test_each_equality_term_is_the_term_the_go_sdk_stored(fixture, cls, ids):
    cipher = Cipher(cls)
    queried = [
        f for f in sealed_fields(cls) if "eq" in f.type.__metadata__[0].indexes
    ]

    for row in rows_of(fixture, ids):
        model = model_of(cls, row)
        for field in queried:
            term = json.loads(cipher.eq(field.name, getattr(model, field.name)))
            assert term["hm"] == row["stored"][field.name]["hm"], (row["id"], field.name)


def test_every_case_compares_terms():
    """The seal comparison is not vacuous: between them, the fixtures store
    equality, order and match terms."""
    terms = set()
    for fixture, cls, ids in CASES:
        for row in rows_of(fixture, ids):
            for field in sealed_fields(cls):
                terms |= set(without_ciphertext(row["stored"][field.name])) - {"i", "v"}
    assert terms == {"hm", "op", "bf"}


@stackencrypt.model("profiles")
@dataclasses.dataclass
class Opened:
    id: Annotated[int, Passthrough]
    opened: Annotated[datetime.date, Date]


@stackencrypt.model("profiles")
@dataclasses.dataclass
class Created:
    id: Annotated[int, Passthrough]
    created: Annotated[datetime.datetime, Timestamp]


@pytest.mark.parametrize("row_id", [1, 2])
def test_a_date_outside_pythons_years_is_refused(row_id):
    # -262143-01-01 and +262142-12-31: datetime holds years 1 to 9999.
    [row] = rows_of("v4_ledger_rows.json", [row_id])

    with pytest.raises(DecryptError) as raised:
        Cipher(Opened).decrypt([stored_row(Opened, row)])

    assert raised.value.code == "decrypt_not_representable"
    assert raised.value.field == "opened"
    assert "year" in raised.value.message


@pytest.mark.parametrize("row_id", [1, 2])
def test_a_timestamp_with_nanoseconds_is_refused_not_rounded(row_id):
    # 1969-12-31T23:59:59.999999999Z and 2024-02-29T12:34:56.123456789Z:
    # years datetime holds, with nanoseconds it does not. Rounded, a value
    # would seal to another equality term than the one Go stored.
    [row] = rows_of("v4_ledger_rows.json", [row_id])
    assert row["plaintext"]["created"].endswith("9Z")

    with pytest.raises(DecryptError) as raised:
        Cipher(Created).decrypt([stored_row(Created, row)])

    assert raised.value.code == "decrypt_not_representable"
    assert raised.value.field == "created"
    assert "nanoseconds" in raised.value.message


def test_a_timestamp_in_whole_microseconds_opens():
    [row] = rows_of("v4_ledger_rows.json", [3])

    [created] = Cipher(Created).decrypt([stored_row(Created, row)])

    assert created.created == datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
