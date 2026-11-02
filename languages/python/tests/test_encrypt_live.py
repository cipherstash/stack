"""``Cipher.encrypt`` and ``Cipher.decrypt`` against ZeroKMS and a PostgreSQL
with the EQL v4 bundle.

These tests need CipherStash credentials (``CS_CLIENT_ACCESS_KEY``,
``CS_WORKSPACE_CRN``, ``CS_CLIENT_ID``, ``CS_CLIENT_KEY``) and a database
URL in ``EQL_TEST_DATABASE_URL`` whose database has the EQL v4 bundle
installed. Without them every test here skips. ``mise run test:live``
installs the bundle and runs them, and fails if any skips.
"""

import dataclasses
import decimal
import json
import os
from typing import Annotated, List, NamedTuple

import attrs
import pydantic
import pytest
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

import stackencrypt
from stackencrypt import Cipher, DecryptError, Ignore, Passthrough, TextEq
from stackencrypt import _engine

CREDENTIALS = ("CS_CLIENT_ACCESS_KEY", "CS_WORKSPACE_CRN", "CS_CLIENT_ID", "CS_CLIENT_KEY")
DATABASE_URL = os.environ.get("EQL_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not all(os.environ.get(name) for name in CREDENTIALS),
        reason="needs CS_CLIENT_ACCESS_KEY, CS_WORKSPACE_CRN, CS_CLIENT_ID and CS_CLIENT_KEY",
    ),
]

needs_database = pytest.mark.skipif(not DATABASE_URL, reason="needs EQL_TEST_DATABASE_URL")


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
    Cipher(Contact).encrypt([Contact(email="b@example.com")])
    assert _engine.client_builds() == 1


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
    posts: Mapped[Annotated[List["Post"], Ignore]] = relationship()


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
