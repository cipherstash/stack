"""``stackencrypt.sqlalchemy.configure_encryption`` before any query: the
class checks.

These tests need fake credentials only. They use an SQLite engine that no
test connects to. The hooks run against PostgreSQL in
``test_sqlalchemy_live.py``.
"""

import dataclasses
from typing import Annotated

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

import stackencrypt
from stackencrypt import DeclarationError, Ignore, Passthrough, TextEq
from stackencrypt.sqlalchemy import configure_encryption

pytestmark = pytest.mark.usefixtures("credentials")


class Base(DeclarativeBase):
    pass


@stackencrypt.model("customers")
class Customer(Base):
    __tablename__ = "customers"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    email: Mapped[Annotated[str, TextEq]]
    plan: Mapped[Annotated[str, Passthrough]]


@pytest.fixture
def engine():
    return create_engine("sqlite://")


def refused(engine, classes):
    with pytest.raises(DeclarationError) as raised:
        configure_encryption(engine, classes)
    return raised.value


def test_a_class_sqlalchemy_does_not_map_is_refused(engine):
    @stackencrypt.model("contacts")
    @dataclasses.dataclass
    class Contact:
        email: Annotated[str, TextEq]

    error = refused(engine, [Contact])
    assert error.code == "declaration_not_mapped"
    assert "Contact" in error.message


def test_a_class_not_declared_is_refused(engine):
    class Plain(Base):
        __tablename__ = "plain"
        id: Mapped[int] = mapped_column(primary_key=True)

    error = refused(engine, [Plain])
    assert error.code == "declaration_not_decorated"


def test_a_declared_table_that_is_not_the_mapped_table_is_refused(engine):
    @stackencrypt.model("people")
    class Person(Base):
        __tablename__ = "persons"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    error = refused(engine, [Person])
    assert error.code == "declaration_table_mismatch"
    assert "people" in error.message
    assert "persons" in error.message


def test_a_field_whose_column_has_another_name_is_refused(engine):
    @stackencrypt.model("accounts")
    class Account(Base):
        __tablename__ = "accounts"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]] = mapped_column("email_address")

    error = refused(engine, [Account])
    assert error.code == "declaration_column_name"
    assert error.field == "email"
    assert "email_address" in error.message


def test_a_class_configured_twice_is_refused(engine):
    @stackencrypt.model("members")
    class Member(Base):
        __tablename__ = "members"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    configure_encryption(engine, [Member])
    error = refused(create_engine("sqlite://"), [Member])
    assert error.code == "declaration_already_configured"


def test_a_refused_list_configures_none_of_its_classes(engine):
    @stackencrypt.model("guests")
    class Guest(Base):
        __tablename__ = "guests"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    @stackencrypt.model("visitors")
    class Visitor(Base):
        __tablename__ = "visits"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    refused(engine, [Guest, Visitor])
    # Guest was not configured by the refused call, so it can be now.
    configure_encryption(engine, [Guest])


def test_a_declared_mapped_class_is_accepted_with_no_request(engine, untouched):
    configure_encryption(engine, [Customer])


def test_a_sealed_value_inside_the_sql_is_refused_and_not_stored(untouched):
    from sqlalchemy import insert, select, update

    @stackencrypt.model("leads")
    class Lead(Base):
        __tablename__ = "leads"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    engine = create_engine("sqlite://")
    Lead.__table__.create(engine)
    configure_encryption(engine, [Lead])

    for statement in [
        insert(Lead).values(email="secret@example.com"),
        update(Lead).where(Lead.id == 1).values(email="secret@example.com"),
    ]:
        with engine.begin() as conn, pytest.raises(DeclarationError) as raised:
            conn.execute(statement)
        assert raised.value.code == "declaration_inline_value"
        assert raised.value.field == "email"
        assert "secret@example.com" not in str(raised.value)

    with engine.connect() as conn:
        assert conn.execute(select(Lead.__table__)).all() == []
