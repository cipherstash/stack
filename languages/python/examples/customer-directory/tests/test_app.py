"""Live tests for the customer directory: real ZeroKMS, real PostgreSQL.

Run them with `mise run test`, after `mise run setup`. They empty the
`customers` table.
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import psycopg
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.exc import DataError
from sqlalchemy.orm import Session

import app as psycopg_app
import app_sqlalchemy as sqlalchemy_app

DATABASE_URL = os.environ["DATABASE_URL"]
EMAIL = "ada@example.com"
NAME = "Ada Lovelace"


def customer(email=EMAIL, name=NAME, plan="free"):
    return {"email": email, "name": name, "plan": plan}


def empty_the_table():
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("TRUNCATE customers")


@pytest.fixture(params=[psycopg_app, sqlalchemy_app], ids=["psycopg", "sqlalchemy"])
def module(request):
    return request.param


@pytest.fixture
def client(module):
    empty_the_table()
    # The `with` form keeps one event loop for the whole test, so concurrent
    # requests run on the same thread pool, as they do under Uvicorn.
    with TestClient(module.app) as test_client:
        yield test_client


def test_a_new_customer_is_found_by_exact_email(client):
    assert client.post("/customers", json=customer()).status_code == 201

    response = client.post("/customers/search", json={"email": EMAIL})

    assert response.status_code == 200
    found = response.json()
    assert (found["email"], found["name"], found["plan"]) == (EMAIL, NAME, "free")
    assert found["created_at"].endswith("Z")


def test_a_different_email_is_not_found(client):
    client.post("/customers", json=customer())

    response = client.post("/customers/search", json={"email": "ADA@example.com"})

    assert response.status_code == 404


def test_the_database_stores_no_plaintext_email_or_name(client):
    client.post("/customers", json=customer())

    with psycopg.connect(DATABASE_URL) as conn:
        stored = conn.execute("SELECT email::text, name::text FROM customers").fetchone()

    assert EMAIL not in stored[0]
    assert NAME not in stored[1]


def test_a_second_customer_with_the_same_email_is_refused(client):
    client.post("/customers", json=customer())

    response = client.post("/customers", json=customer(name="Someone Else"))

    assert response.status_code == 409


def test_the_list_decrypts_customers_up_to_the_limit(client):
    for number in range(3):
        client.post("/customers", json=customer(email=f"user{number}@example.com"))

    response = client.get("/customers", params={"limit": 2})

    assert response.status_code == 200
    assert [row["email"] for row in response.json()] == [
        "user0@example.com",
        "user1@example.com",
    ]


def test_a_naive_created_at_is_refused(client):
    body = {**customer(), "created_at": "2026-01-01T00:00:00"}

    response = client.post("/customers", json=body)

    assert response.status_code == 422


def test_error_logs_contain_no_plaintext(client, caplog):
    client.post("/customers", json=customer())
    naive = {**customer(), "created_at": "2026-01-01T00:00:00"}

    with caplog.at_level(logging.INFO):
        client.post("/customers", json=customer())
        client.post("/customers", json=naive)

    assert "customer_error" in caplog.text
    assert EMAIL not in caplog.text
    assert NAME not in caplog.text


def test_a_rejected_request_does_not_repeat_the_input(client):
    body = {**customer(), "created_at": f"not a date {EMAIL}"}

    response = client.post("/customers", json=body)

    assert response.status_code == 422
    assert EMAIL not in response.text


@pytest.mark.parametrize(
    "body", [psycopg_app.Customer, sqlalchemy_app.CustomerBody], ids=["psycopg", "sqlalchemy"]
)
def test_a_pydantic_error_does_not_print_the_input(body):
    with pytest.raises(ValidationError) as caught:
        body(email=EMAIL, name=NAME, plan="free", created_at=f"not a date {EMAIL}")

    assert EMAIL not in str(caught.value)


def test_an_unexpected_error_gives_a_fixed_500(client, module, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError(f"contains {EMAIL}")

    monkeypatch.setattr(module.cipher, "encrypt", fail)

    with caplog.at_level(logging.INFO):
        response = client.post("/customers", json=customer())

    assert response.status_code == 500
    assert EMAIL not in response.text
    assert "RuntimeError" in caplog.text
    assert EMAIL not in caplog.text


def test_one_cipher_serves_concurrent_requests(client):
    emails = [f"user{number}@example.com" for number in range(20)]

    def add_then_find(email):
        added = client.post("/customers", json=customer(email=email))
        found = client.post("/customers/search", json={"email": email})
        return added.status_code, found.status_code, found.json()["email"]

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(add_then_find, emails))

    assert results == [(201, 200, email) for email in emails]


def test_each_app_reads_what_the_other_wrote():
    empty_the_table()
    with TestClient(psycopg_app.app) as first, TestClient(sqlalchemy_app.app) as second:
        first.post("/customers", json=customer(email="first@example.com"))
        second.post("/customers", json=customer(email="second@example.com"))

        from_second = second.post("/customers/search", json={"email": "first@example.com"})
        from_first = first.post("/customers/search", json={"email": "second@example.com"})

    assert (from_second.status_code, from_second.json()["name"]) == (200, NAME)
    assert (from_first.status_code, from_first.json()["name"]) == (200, NAME)


def test_a_session_cannot_store_a_plaintext_object():
    empty_the_table()
    plaintext = sqlalchemy_app.Customer(
        email=EMAIL, name=NAME, plan="free", created_at=datetime.now(timezone.utc)
    )

    with pytest.raises(DataError) as caught:
        with Session(sqlalchemy_app.engine) as session:
            session.add(plaintext)
            session.commit()

    assert EMAIL not in str(caught.value)
    with psycopg.connect(DATABASE_URL) as conn:
        assert conn.execute("SELECT count(*) FROM customers").fetchone() == (0,)
