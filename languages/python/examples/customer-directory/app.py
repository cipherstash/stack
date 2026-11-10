"""A customer directory: a FastAPI service that stores encrypted customers.

`email` is encrypted and searchable by exact match. `name` is encrypted with
no search. `plan` and `created_at` are stored as plaintext.

The handlers are plain `def` functions. FastAPI runs them on a thread pool, so
requests share the one `Cipher` below at the same time.
"""

import os
from datetime import datetime, timezone
from typing import Annotated, List, Optional

import psycopg
import stackencrypt
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field
from stackencrypt import Passthrough, Text, TextEq

from errors import install_error_handlers, log_error, problem

DATABASE_URL = os.environ["DATABASE_URL"]
SELECT_CUSTOMER = "SELECT email, name, plan, created_at FROM customers"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@stackencrypt.model("customers")
class Customer(BaseModel):
    # A Pydantic error prints the input by default, and the input is plaintext.
    model_config = ConfigDict(hide_input_in_errors=True)

    email: Annotated[str, TextEq]
    name: Annotated[str, Text]
    plan: Annotated[str, Passthrough]
    created_at: Annotated[datetime, Passthrough] = Field(default_factory=utc_now)


class Search(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    email: str


# One Cipher for the process: making one checks the model and the credentials.
cipher = stackencrypt.Cipher(Customer)

app = FastAPI(title="Customer directory")


install_error_handlers(app)


@app.exception_handler(psycopg.errors.UniqueViolation)
def duplicate(request: Request, error: psycopg.errors.UniqueViolation) -> JSONResponse:
    log_error(error)
    return problem(409, "A customer with this email already exists.")


@app.post("/customers", status_code=201, response_model=Customer)
def add_customer(customer: Customer) -> Customer:
    row = cipher.encrypt([customer])[0]
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute(
            "INSERT INTO customers (email, name, plan, created_at)"
            " VALUES (%(email)s, %(name)s, %(plan)s, %(created_at)s)",
            row,
        )
    return customer


@app.post("/customers/search", response_model=Customer)
def find_customer(search: Search) -> Customer:
    # The email is in the body so that it stays out of URLs and access logs.
    term = cipher.eq("email", search.email)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"{SELECT_CUSTOMER} WHERE email = %s::eql_v4.query_text_eq", (term,))
            found: Optional[dict] = cur.fetchone()
    if found is None:
        raise HTTPException(status_code=404, detail="No customer has this email.")
    return cipher.decrypt([found])[0]


@app.get("/customers", response_model=List[Customer])
def list_customers(limit: int = Query(default=100, ge=1, le=500)) -> List[Customer]:
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"{SELECT_CUSTOMER} ORDER BY id LIMIT %s", (limit,))
            return cipher.decrypt(cur.fetchall())
