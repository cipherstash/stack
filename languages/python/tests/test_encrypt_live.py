"""``Cipher.encrypt``, ``Cipher.decrypt`` and ``Cipher.query`` against ZeroKMS
and a PostgreSQL with the EQL v4 bundle.

These tests need CipherStash credentials (``CS_CLIENT_ACCESS_KEY``,
``CS_WORKSPACE_CRN``, ``CS_CLIENT_ID``, ``CS_CLIENT_KEY``) and a database
URL in ``EQL_TEST_DATABASE_URL`` whose database has the EQL v4 bundle
installed. Without them every test here skips. ``mise run test:live``
installs the bundle and runs them, and fails if any skips.
"""

import dataclasses
import datetime
import decimal
import json
import math
import struct
from typing import Annotated, List, NamedTuple

import attrs
import pydantic
import pytest
from _live import DATABASE_URL, LIVE, needs_database
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

import stackencrypt
from stackencrypt import Cipher, DecryptError, Ignore, Passthrough, TextEq
from stackencrypt import _engine, _eql

pytestmark = LIVE


@stackencrypt.model("users")
@dataclasses.dataclass
class User:
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]


@stackencrypt.model("contacts")
@dataclasses.dataclass
class Contact:
    email: Annotated[str, TextEq]


@needs_database
def test_an_encrypted_row_inserts_with_a_plain_parameter():
    psycopg = pytest.importorskip("psycopg")
    rows = Cipher(User).encrypt([User(email="a@example.com", age=3)])

    assert set(rows[0]) == {"email", "age"}
    assert isinstance(rows[0]["email"], str)
    assert rows[0]["age"] == 3
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
        cur.execute(
            "CREATE TEMPORARY TABLE users (email public.eql_v4_text_eq, age int)"
        )
        # The README's insert: a plain %s, no cast. Postgres infers the
        # domain from the column for a str parameter.
        cur.execute(
            "INSERT INTO users (email, age) VALUES (%s, %s)",
            (rows[0]["email"], rows[0]["age"]),
        )
        cur.execute("SELECT email IS NOT NULL, pg_typeof(email)::text, age FROM users")
        assert cur.fetchone() == (True, "eql_v4_text_eq", 3)


def test_the_plaintext_is_not_in_the_encrypted_column():
    rows = Cipher(User).encrypt([User(email="hidden@example.com", age=3)])
    assert "hidden@example.com" not in rows[0]["email"]


def test_1001_one_field_models_make_three_key_requests():
    cipher = Cipher(Contact)
    # The first call in the process may load the keyset. Warm the client up
    # first, so the count below is the key requests alone.
    cipher.encrypt([Contact(email="warm@example.com")])
    before = _engine.request_count()

    cipher.encrypt([Contact(email=f"user{i}@example.com") for i in range(1001)])

    # ceil(1001 / 500): stack-kms's 500 keys per request.
    assert _engine.request_count() - before == 3


def test_two_ciphers_share_one_engine_client():
    Cipher(User).encrypt([User(email="a@example.com", age=1)])
    # Read after the first call: an earlier test may have loaded the keyset
    # more than once, if a load failed and the next call loaded it again.
    loads = _engine.requests().get("load-keyset")

    Cipher(Contact).encrypt([Contact(email="b@example.com")])

    assert _engine.client_builds() == 1
    assert _engine.requests().get("load-keyset") == loads


@stackencrypt.model("prices")
@dataclasses.dataclass
class Price:
    sku: Annotated[str, TextEq]
    amount: Annotated[decimal.Decimal, Passthrough]


def test_a_decimal_passthrough_comes_back_as_the_same_decimal():
    rows = Cipher(Price).encrypt([Price(sku="a", amount=decimal.Decimal("19.50"))])
    amount = rows[0]["amount"]
    assert type(amount) is decimal.Decimal
    # The scale is kept: 19.50, not 19.5.
    assert str(amount) == "19.50"


# The five class kinds, each with one TextEq, one Passthrough and one Ignore.


@stackencrypt.model("users")
@dataclasses.dataclass
class DataclassUser:
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]
    note: Annotated[str, Ignore] = ""


@stackencrypt.model("users")
@attrs.define
class AttrsUser:
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]
    note: Annotated[str, Ignore] = ""


@stackencrypt.model("users")
class PydanticUser(pydantic.BaseModel):
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]
    note: Annotated[str, Ignore] = ""


class TupleUser(NamedTuple):
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]
    note: Annotated[str, Ignore] = ""


stackencrypt.model("users")(TupleUser)


class Base(DeclarativeBase):
    pass


class Post(Base):
    __tablename__ = "posts"
    id: Mapped[Annotated[int, Passthrough]] = mapped_column(primary_key=True)
    user_id: Mapped[Annotated[int, Passthrough]] = mapped_column(ForeignKey("users.id"))


@stackencrypt.model("users")
class SqlAlchemyUser(Base):
    __tablename__ = "users"
    id: Mapped[Annotated[int, Passthrough]] = mapped_column(primary_key=True)
    email: Mapped[Annotated[str, TextEq]]
    age: Mapped[Annotated[int, Passthrough]]
    # SQLAlchemy does not look inside Annotated for the target, so the
    # relationship names it. Without "Post", the first instance fails to
    # configure the mapper. posts is still not a list: see spec #1341, the
    # note on the Ignore relationship form.
    posts: Mapped[Annotated[List["Post"], Ignore]] = relationship("Post")


def build(cls, at):
    """The model for row ``at``: an id only where the class declares one."""
    fields = {"email": f"user{at}@example.com", "age": 30 + at}
    if cls is SqlAlchemyUser:
        fields["id"] = at + 1
    return cls(**fields)


def fields(model):
    return {name: getattr(model, name) for name in ("email", "age")}


CLASS_KINDS = [DataclassUser, AttrsUser, PydanticUser, TupleUser, SqlAlchemyUser]


@needs_database
@pytest.mark.parametrize("cls", CLASS_KINDS, ids=lambda cls: cls.__name__)
def test_rows_read_back_with_dict_row_decrypt_into_the_models(cls):
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    cipher = Cipher(cls)
    models = [build(cls, at) for at in range(3)]
    rows = cipher.encrypt(models)
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "CREATE TEMPORARY TABLE users "
            "(id serial PRIMARY KEY, email public.eql_v4_text_eq, age int)"
        )
        for row in rows:
            cur.execute("INSERT INTO users (email, age) VALUES (%s, %s)", (row["email"], row["age"]))
        # SELECT *: the id column is extra for every class but SQLAlchemy's,
        # and is ignored.
        cur.execute("SELECT * FROM users ORDER BY id")
        decrypted = cipher.decrypt(cur.fetchall())

    assert [type(model) for model in decrypted] == [cls] * 3
    assert [fields(model) for model in decrypted] == [fields(model) for model in models]


def test_str_bytes_and_dict_forms_decrypt_to_the_same_value():
    cipher = Cipher(User)
    [row] = cipher.encrypt([User(email="forms@example.com", age=3)])
    forms = [row["email"], row["email"].encode(), json.loads(row["email"])]

    decrypted = cipher.decrypt([{"email": form, "age": 3} for form in forms])

    assert [user.email for user in decrypted] == ["forms@example.com"] * 3


def test_a_value_encrypted_for_another_column_is_a_foreign_row():
    [row] = Cipher(Contact).encrypt([Contact(email="a@example.com")])
    with pytest.raises(DecryptError) as raised:
        Cipher(User).decrypt([{"email": row["email"], "age": 3}])
    assert raised.value.code == "decrypt_foreign_row"
    assert raised.value.field == "email"


def test_a_sqlalchemy_class_is_built_without_its_ignored_relationship():
    cipher = Cipher(SqlAlchemyUser)
    rows = cipher.encrypt([build(SqlAlchemyUser, 0)])

    [user] = cipher.decrypt(rows)

    assert (user.id, user.email, user.age) == (1, "user0@example.com", 30)
    assert "posts" not in user.__dict__


def test_1001_rows_open_with_three_key_requests():
    cipher = Cipher(Contact)
    rows = cipher.encrypt([Contact(email=f"user{i}@example.com") for i in range(1001)])
    before = _engine.request_count()

    decrypted = cipher.decrypt(rows)

    # ceil(1001 / 500): the keys for the whole list, 500 per request.
    assert _engine.request_count() - before == 3
    assert decrypted[1000].email == "user1000@example.com"


@needs_database
def test_a_query_term_finds_the_one_matching_row():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    cipher = Cipher(User)
    rows = cipher.encrypt(
        [User(email="a@example.com", age=1), User(email="b@example.com", age=2)]
    )
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("CREATE TEMPORARY TABLE users (email public.eql_v4_text_eq, age int)")
        for row in rows:
            cur.execute("INSERT INTO users (email, age) VALUES (%s, %s)", (row["email"], row["age"]))
        # The README's query: the term cast to the marker's query domain.
        cur.execute(
            f"SELECT * FROM users WHERE email = %s::{TextEq.query_sql_domain}",
            (cipher.query("email", "a@example.com"),),
        )
        found = cipher.decrypt(cur.fetchall())

    assert found == [User(email="a@example.com", age=1)]


@needs_database
def test_a_query_uses_the_eq_term_index():
    psycopg = pytest.importorskip("psycopg")

    cipher = Cipher(User)
    rows = cipher.encrypt([User(email=f"user{i}@example.com", age=i) for i in range(20)])
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
        cur.execute("CREATE TEMPORARY TABLE users (email public.eql_v4_text_eq, age int)")
        # The README's index.
        cur.execute("CREATE INDEX users_email_eq ON users USING hash (eql_v4.eq_term(email))")
        for row in rows:
            cur.execute("INSERT INTO users (email, age) VALUES (%s, %s)", (row["email"], row["age"]))
        cur.execute("ANALYZE users")
        # A table this small is cheaper to scan, so the planner is told not
        # to. The test is that the index can answer the query at all.
        cur.execute("SET LOCAL enable_seqscan = off")
        cur.execute(
            "EXPLAIN SELECT * FROM users WHERE email = %s::eql_v4.query_text_eq",
            (cipher.query("email", "user7@example.com"),),
        )
        plan = "\n".join(line for (line,) in cur.fetchall())

    assert "users_email_eq" in plan, plan


def test_100_queries_make_no_request():
    cipher = Cipher(User)
    # The first call in the process may build the client and load the
    # keyset. Warm it up first, so the count below is the queries alone.
    cipher.query("email", "warm@example.com")
    before = _engine.request_count()

    terms = {cipher.query("email", f"user{i}@example.com") for i in range(100)}

    assert _engine.request_count() == before
    assert len(terms) == 100


# One field per producible type. JsonSearch is out of scope: the json kind
# has no Python type in this version, and the decorator refuses it.
PRODUCIBLE = [m for m in _eql.TYPES if m.producible and m.name != "JsonSearch"]

# A value and its Python type for each plaintext kind, near the edge of
# what the kind holds.
KIND_VALUES = {
    "string": (str, "héllo\x00wörld"),
    "int16": (int, -(2**15)),
    "int32": (int, 2**31 - 1),
    "int64": (int, -(2**63)),
    "float32": (float, 1.5),
    "float64": (float, 0.1),
    "bool": (bool, True),
    "date": (datetime.date, datetime.date(2024, 2, 29)),
    "timestamp": (
        datetime.datetime,
        datetime.datetime(
            2024, 2, 29, 23, 59, 59, 999999,
            tzinfo=datetime.timezone(datetime.timedelta(hours=10)),
        ),
    ),
    "decimal": (decimal.Decimal, decimal.Decimal("-1234.5600")),
}


def every_type_model():
    cls = dataclasses.make_dataclass(
        "EveryType",
        [(m.name.lower(), Annotated[KIND_VALUES[m.plaintext][0], m]) for m in PRODUCIBLE],
    )
    return stackencrypt.model("every_type")(cls)


def test_every_producible_type_except_json_search_is_covered():
    assert {m.plaintext for m in PRODUCIBLE} == set(KIND_VALUES)
    assert len(PRODUCIBLE) == 49


@needs_database
def test_every_producible_type_round_trips_through_postgres():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    cls = every_type_model()
    cipher = Cipher(cls)
    model = cls(**{m.name.lower(): KIND_VALUES[m.plaintext][1] for m in PRODUCIBLE})
    [row] = cipher.encrypt([model])
    columns = [m.name.lower() for m in PRODUCIBLE]
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "CREATE TEMPORARY TABLE every_type ("
            + ", ".join(f"{m.name.lower()} {m.sql_domain}" for m in PRODUCIBLE)
            + ")"
        )
        cur.execute(
            f"INSERT INTO every_type ({', '.join(columns)}) "
            f"VALUES ({', '.join(['%s'] * len(columns))})",
            [row[column] for column in columns],
        )
        cur.execute("SELECT * FROM every_type")
        [decrypted] = cipher.decrypt(cur.fetchall())

    for marker in PRODUCIBLE:
        name = marker.name.lower()
        assert exact(getattr(decrypted, name)) == exact(getattr(model, name)), name


def exact(value):
    """A value in a form whose == also compares what Python's == does not:
    a Decimal's scale (1.50 == 1.5 in Python), a float's sign (-0.0 == 0.0),
    and a datetime's instant with no tzinfo dropped."""
    if isinstance(value, decimal.Decimal):
        return value.as_tuple()
    if isinstance(value, float):
        return struct.pack("<d", value)
    if isinstance(value, datetime.datetime):
        assert value.utcoffset() is not None, value
        # The same instant, whatever zone it comes back in.
        return value.astimezone(datetime.timezone.utc)
    return (type(value), value)


@stackencrypt.model("floats")
@dataclasses.dataclass
class Floats:
    real: Annotated[float, stackencrypt.RealOrdOre]
    double: Annotated[float, stackencrypt.DoubleEq]


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, -0.0], ids=repr)
def test_nan_infinity_and_negative_zero_round_trip(value):
    cipher = Cipher(Floats)

    [floats] = cipher.decrypt(cipher.encrypt([Floats(real=value, double=value)]))

    for opened in (floats.real, floats.double):
        if math.isnan(value):
            assert math.isnan(opened)
        else:
            assert opened == value
            assert math.copysign(1.0, opened) == math.copysign(1.0, value)
