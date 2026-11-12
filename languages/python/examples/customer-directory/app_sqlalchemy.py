"""The customer directory again, with the model declared in SQLAlchemy.

It uses the table of `app.py`, so the two apps share rows.

`configure_encryption` makes the ORM encrypt and decrypt: a flush encrypts
the encrypted fields, and a query decrypts the objects it loads. So the
endpoints use `Session` as any SQLAlchemy app does, with no SDK calls.
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
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from stackencrypt import Ignore, Passthrough, Text, TextEq
from stackencrypt.sqlalchemy import configure_encryption, eql_type_map

from errors import install_error_handlers, log_error, problem

# hide_parameters leaves the bound values out of SQLAlchemy's error text.
# PostgreSQL's own detail can still quote the start of a rejected value.
# make_url reads both postgresql:// and postgres://, as app.py accepts both.
# The URL object, not its str(), which writes the password as ***.
engine = sa.create_engine(
    sa.engine.make_url(os.environ["DATABASE_URL"]).set(drivername="postgresql+psycopg"),
    hide_parameters=True,
)


class Base(DeclarativeBase):
    # Gives each encrypted field its EQL column type, from its marker.
    type_annotation_map = eql_type_map


@stackencrypt.model("customers")
class Customer(Base):
    __tablename__ = "customers"
    # As schema.sql makes it. A btree, because PostgreSQL cannot make a hash
    # index unique. It also serves the email search, so the SDK adds no
    # index of its own on this term.
    __table_args__ = (
        sa.Index("customers_email_unique", sa.text("eql_v4.eq_term(email)"), unique=True),
    )

    id: Mapped[Annotated[int, Ignore]] = mapped_column(
        sa.BigInteger, sa.Identity(always=True), primary_key=True
    )
    email: Mapped[Annotated[str, TextEq]]
    name: Mapped[Annotated[str, Text]]
    plan: Mapped[Annotated[str, Passthrough]] = mapped_column(sa.Text)
    created_at: Mapped[Annotated[datetime, Passthrough]] = mapped_column(
        sa.DateTime(timezone=True)
    )


# Once for the process, before the first request. Every engine is covered.
configure_encryption([Customer])


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
    with Session(engine) as session:
        session.add(Customer(**body.model_dump()))
        session.commit()
    return body


@app.post("/customers/search", response_model=CustomerBody)
def find_customer(search: Search) -> Customer:
    # The email is in the body so that it stays out of URLs and access logs.
    query = sa.select(Customer).where(Customer.email == search.email)
    with Session(engine) as session:
        found: Optional[Customer] = session.scalars(query).first()
    if found is None:
        raise HTTPException(status_code=404, detail="No customer has this email.")
    return found


@app.get("/customers", response_model=List[CustomerBody])
def list_customers(limit: int = Query(default=100, ge=1, le=500)) -> List[Customer]:
    query = sa.select(Customer).order_by(Customer.id).limit(limit)
    with Session(engine) as session:
        return list(session.scalars(query).all())
