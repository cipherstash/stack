"""The customer directory again, with the model declared in SQLAlchemy.

It uses the table of `app.py`, so the two apps share rows.

A SQLAlchemy object contains plaintext, and the columns must receive
ciphertext. So the app calls `encrypt` before an INSERT and `decrypt` after a
SELECT. It does not use `Session`.
"""

import os
from datetime import datetime, timezone
from typing import Annotated, List, Optional

import sqlalchemy as sa
import stackencrypt
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import UserDefinedType
from stackencrypt import Ignore, Passthrough, Text, TextEq

from errors import install_error_handlers, log_error, problem

# hide_parameters leaves the bound values out of SQLAlchemy's error text.
# PostgreSQL's own detail can still quote the start of a rejected value.
engine = sa.create_engine(
    os.environ["DATABASE_URL"].replace("postgresql://", "postgresql+psycopg://", 1),
    hide_parameters=True,
)


class EqlType(UserDefinedType):
    """An EQL column type. The tests fail with `sa.Text`, `sa.String`, or `sa.JSON`."""

    cache_ok = True

    def __init__(self, sql_name: str) -> None:
        self.sql_name = sql_name

    def get_col_spec(self, **kwargs) -> str:
        return self.sql_name


class Base(DeclarativeBase):
    pass


@stackencrypt.model("customers")
class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[Annotated[int, Ignore]] = mapped_column(
        sa.BigInteger, sa.Identity(always=True), primary_key=True
    )
    email: Mapped[Annotated[str, TextEq]] = mapped_column(EqlType("public.eql_v4_text_eq"))
    name: Mapped[Annotated[str, Text]] = mapped_column(EqlType("public.eql_v4_text"))
    plan: Mapped[Annotated[str, Passthrough]]
    created_at: Mapped[Annotated[datetime, Passthrough]] = mapped_column(
        sa.DateTime(timezone=True)
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CustomerBody(BaseModel):
    """The JSON shape of a customer, for requests and responses."""

    # A Pydantic error prints the input by default, and the input is plaintext.
    model_config = ConfigDict(hide_input_in_errors=True, from_attributes=True)

    email: str
    name: str
    plan: str
    created_at: datetime = Field(default_factory=utc_now)


class Search(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    email: str


# `id` is left out: the model marks it Ignore, and `decrypt` does not want it.
COLUMNS = (Customer.email, Customer.name, Customer.plan, Customer.created_at)

# One Cipher for the process: making one checks the model and the credentials.
cipher = stackencrypt.Cipher(Customer)

app = FastAPI(title="Customer directory (SQLAlchemy)")
install_error_handlers(app)


@app.exception_handler(IntegrityError)
def integrity_error(request: Request, error: IntegrityError) -> JSONResponse:
    log_error(error)
    if isinstance(error.orig, UniqueViolation):
        return problem(409, "A customer with this email already exists.")
    return problem(500, "The request failed.")


@app.post("/customers", status_code=201, response_model=CustomerBody)
def add_customer(body: CustomerBody) -> CustomerBody:
    rows = cipher.encrypt([Customer(**body.model_dump())])
    with engine.begin() as conn:
        conn.execute(sa.insert(Customer.__table__), rows)
    return body


@app.post("/customers/search", response_model=CustomerBody)
def find_customer(search: Search) -> Customer:
    # The email is in the body so that it stays out of URLs and access logs.
    term = sa.literal(cipher.eq("email", search.email), sa.Text)
    query = sa.select(*COLUMNS).where(
        Customer.email == sa.cast(term, EqlType("eql_v4.query_text_eq"))
    )
    with engine.connect() as conn:
        found: Optional[sa.RowMapping] = conn.execute(query).mappings().first()
    if found is None:
        raise HTTPException(status_code=404, detail="No customer has this email.")
    return cipher.decrypt([found])[0]


@app.get("/customers", response_model=List[CustomerBody])
def list_customers(limit: int = Query(default=100, ge=1, le=500)) -> List[Customer]:
    query = sa.select(*COLUMNS).order_by(Customer.id).limit(limit)
    with engine.connect() as conn:
        return cipher.decrypt(conn.execute(query).mappings().all())
