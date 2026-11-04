"""``Cipher.encrypt`` against ZeroKMS and a PostgreSQL with the EQL v4 bundle.

These tests need CipherStash credentials (``CS_CLIENT_ACCESS_KEY``,
``CS_WORKSPACE_CRN``, ``CS_CLIENT_ID``, ``CS_CLIENT_KEY``) and a database
URL in ``EQL_TEST_DATABASE_URL`` whose database has the EQL v4 bundle
installed. Without them every test here skips. ``mise run test:live``
installs the bundle and runs them, and fails if any skips.
"""

import dataclasses
import decimal
import os
from typing import Annotated

import pytest

import stackencrypt
from stackencrypt import Cipher, Passthrough, TextEq
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
