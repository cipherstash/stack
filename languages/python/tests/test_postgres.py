"""The whole path: declare, encrypt a batch, insert into EQL v3 columns,
query by the encrypted field, decrypt the batch. Needs live ZeroKMS and a
Postgres with EQL v3 installed (`DATABASE_URL`).

No EQL domain name is written here. The column's type and the query cast
come from `PlanSpec.domains`, which the engine's resolver filled: Python
states what the field holds and what a query must do, and the engine says
which EQL type that is (G1, at the SQL layer).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import psycopg
import pytest

from stackencrypt import EQL, Cipher, Equality, Int64, Passthrough, Plan, Text


@dataclass
class User:
    email: Annotated[str, Text, EQL(Equality)]
    age: Annotated[int, Int64, Passthrough()]


@pytest.fixture(scope="module")
def plan():
    return Plan.of(User).context("users").build()


@pytest.fixture(scope="module")
def cipher(live, plan):
    return Cipher(plan, engine=live)


def eql(value: bytes) -> str:
    """A stored EQL value as the text Postgres parses into `jsonb`.

    The engine returns the EQL JSON as bytes; psycopg would send bytes as
    `bytea`, which no EQL domain accepts. The text goes as `text` and the SQL
    casts it `::jsonb`, so Postgres does the parsing and the bytes are
    neither inspected nor reshaped on the way (G1). NOT `Jsonb(text)`: that
    wraps a Python *string* as the JSON value, Postgres receives a JSON
    string literal, `jsonb_typeof` is `'string'`, and the domain's check
    fails — which is how this test first failed.
    """
    return value.decode()


@pytest.fixture
def table(database_url, plan):
    """A table whose encrypted column takes the domain the engine named."""
    domain = plan.domains["email"]["sql_domain"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute("drop table if exists py_users")
        connection.execute(
            f"create table py_users (id bigserial primary key, "
            f"email {domain}, age bigint)"
        )
        yield connection
        connection.execute("drop table if exists py_users")


def test_insert_query_and_decrypt(cipher, plan, table):
    users = [User(email=f"p{n}@example.com", age=20 + n) for n in range(4)]

    records = cipher.encrypt(users)
    with table.cursor() as cursor:
        cursor.executemany(
            "insert into py_users (email, age) values (%s::jsonb, %s)",
            [(eql(record["email"]), record["age"]) for record in records],
        )

    # The query term, cast to the query domain the engine named.
    term = cipher.query("email", "p2@example.com")
    query_domain = plan.domains["email"]["query_sql_domain"]
    with table.cursor() as cursor:
        cursor.execute(
            f"select email::text, age from py_users where email = %s::jsonb::{query_domain}",
            (eql(term),),
        )
        found = cursor.fetchall()

    assert len(found) == 1
    [(stored_email, stored_age)] = found

    [user] = cipher.decrypt([{"email": stored_email.encode(), "age": stored_age}])
    assert user.email == "p2@example.com"
    assert user.age == 22


def test_a_term_for_a_value_that_is_not_stored_finds_nothing(cipher, plan, table):
    [record] = cipher.encrypt([User(email="present@example.com", age=1)])
    with table.cursor() as cursor:
        cursor.execute(
            "insert into py_users (email, age) values (%s::jsonb, %s)",
            (eql(record["email"]), record["age"]),
        )

    term = cipher.query("email", "absent@example.com")
    query_domain = plan.domains["email"]["query_sql_domain"]
    with table.cursor() as cursor:
        cursor.execute(
            f"select count(*) from py_users where email = %s::jsonb::{query_domain}",
            (eql(term),),
        )
        [[count]] = cursor.fetchall()

    # A zero here is the right answer. It is also what a type mismatch looks
    # like, which is why the test above asserts a positive match first.
    assert count == 0


def test_the_whole_batch_reads_back_in_one_call(cipher, plan, table):
    users = [User(email=f"b{n}@example.com", age=n) for n in range(3)]
    records = cipher.encrypt(users)
    with table.cursor() as cursor:
        cursor.executemany(
            "insert into py_users (email, age) values (%s::jsonb, %s)",
            [(eql(record["email"]), record["age"]) for record in records],
        )
        cursor.execute("select email::text, age from py_users order by id")
        rows = cursor.fetchall()

    before = cipher.key_requests
    back = cipher.decrypt([{"email": email.encode(), "age": age} for email, age in rows])

    assert [user.email for user in back] == [user.email for user in users]
    assert cipher.key_requests - before == 1
