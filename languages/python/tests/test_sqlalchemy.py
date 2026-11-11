"""``stackencrypt.sqlalchemy`` before any request: the type map, the class
checks of ``configure_encryption``, and the operators a query refuses.

These tests need fake credentials only. They use an SQLite engine that no
test connects to. The hooks run against PostgreSQL in
``test_sqlalchemy_live.py``.
"""

import dataclasses
from typing import Annotated, Optional

import pytest
from sqlalchemy import String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

import stackencrypt
from stackencrypt import DeclarationError, Ignore, InvalidValueError, Passthrough, TextEq
from stackencrypt import IntegerOrd, QueryError, Text, _eql
from stackencrypt.sqlalchemy import EqlType, configure_encryption, eql_type_map

pytestmark = pytest.mark.usefixtures("credentials")


class Base(DeclarativeBase):
    type_annotation_map = eql_type_map


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


def test_a_unique_encrypted_column_is_refused(engine):
    @stackencrypt.model("logins")
    class Login(Base):
        __tablename__ = "logins"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]] = mapped_column(unique=True)

    error = refused(engine, [Login])
    assert error.code == "declaration_unique_column"
    assert error.field == "email"
    assert "eql_v4.eq_term(email)" in error.message


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
    # SQLite has no EQL types, and the refusal comes before the database.
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE leads (id INTEGER PRIMARY KEY, email TEXT)")
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


# The type map.


def test_the_type_map_gives_every_declarable_marker_its_eql_type():
    declarable = [m for m in _eql.TYPES if m.producible and m.plaintext != "json"]
    assert declarable
    for marker in declarable:
        # Two hints for each marker: the value type, and Optional of it.
        types = [t for hint, t in eql_type_map.items() if hint.__metadata__ == (marker,)]
        assert len(types) == 2
        for column_type in types:
            assert isinstance(column_type, EqlType)
            assert column_type.marker is marker
            assert column_type.get_col_spec() == marker.sql_domain


def test_an_optional_field_gets_a_nullable_eql_column():
    @stackencrypt.model("places")
    class Place(Base):
        __tablename__ = "places"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        name: Mapped[Annotated[str, TextEq]]
        city: Mapped[Annotated[Optional[str], TextEq]]
        note: Mapped[Annotated[Optional[str], Passthrough]]

    columns = Place.__table__.c
    assert (repr(columns.city.type), columns.city.nullable) == ("EqlType(TextEq)", True)
    assert columns.name.nullable is False
    assert columns.note.nullable is True


def test_a_column_of_another_type_is_refused(engine):
    @stackencrypt.model("tickets")
    class Ticket(Base):
        __tablename__ = "tickets"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]] = mapped_column(String)

    error = refused(engine, [Ticket])
    assert error.code == "declaration_column_type"
    assert error.field == "email"
    assert "eql_v4_text_eq" in error.message


# The operators a query refuses, before any request.


@stackencrypt.model("scores")
class Score(Base):
    __tablename__ = "scores"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    level: Mapped[Annotated[int, IntegerOrd]]
    note: Mapped[Annotated[str, Text]]


@pytest.fixture(scope="module")
def scores():
    configure_encryption(create_engine("sqlite://"), [Score])


@pytest.mark.parametrize(
    "build",
    [
        lambda: Score.note.like("%secret%"),
        lambda: Score.note.contains("secret"),
        lambda: Score.note.in_(select(Score.note).scalar_subquery()),
        lambda: Score.level.between(1, 9),
        lambda: Score.level + 1,
    ],
    ids=["like", "contains", "in-a-subquery", "between", "add"],
)
def test_an_operator_that_would_send_the_value_is_refused(scores, untouched, build):
    with pytest.raises(QueryError) as raised:
        build()
    assert raised.value.code == "query_unsupported"
    assert "secret" not in str(raised.value)


@pytest.mark.parametrize(
    "build",
    [
        lambda: Score.note.is_(None),
        lambda: Score.note.is_not(None),
        lambda: Score.note == None,  # noqa: E711
        lambda: Score.note != None,  # noqa: E711
        lambda: Score.note.in_([]),
        lambda: Score.note.not_in([]),
        lambda: Score.level.asc(),
        lambda: Score.level.desc(),
    ],
    ids=["is-null", "is-not-null", "equals-none", "not-equals-none", "in-nothing", "not-in-nothing", "asc", "desc"],
)
def test_an_operator_that_sends_no_value_is_allowed_with_no_request(scores, untouched, build):
    build()


def test_a_comparison_on_a_class_not_configured_is_refused(untouched):
    @stackencrypt.model("drafts")
    class Draft(Base):
        __tablename__ = "drafts"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        note: Mapped[Annotated[str, Text]]

    with pytest.raises(QueryError) as raised:
        Draft.note == "secret"  # noqa: B015
    assert raised.value.code == "query_not_configured"
    assert "secret" not in str(raised.value)


# Passthrough values on writes.


def test_a_passthrough_value_is_checked_on_a_flush(untouched):
    import datetime

    from sqlalchemy.orm import Session

    @stackencrypt.model("trips")
    class Visit(Base):
        __tablename__ = "trips"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]
        at: Mapped[Annotated[datetime.datetime, Passthrough]]

    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE trips (id INTEGER PRIMARY KEY, email TEXT, at TEXT)")
    configure_encryption(engine, [Visit])

    with Session(engine) as session, pytest.raises(InvalidValueError) as raised:
        session.add(Visit(email="secret@example.com", at=datetime.datetime(2026, 1, 1)))
        session.commit()

    assert raised.value.code == "value_naive_datetime"
    assert raised.value.field == "at"
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT count(*) FROM trips").scalar() == 0


# ORDER BY an encrypted column.


def order_sql(statement):
    from sqlalchemy.dialects import postgresql

    sql = str(statement.compile(dialect=postgresql.dialect()))
    return " ".join(sql.split("ORDER BY", 1)[1].split())


def test_asc_and_desc_on_an_order_column_sort_by_its_order_term(scores, untouched):
    assert order_sql(select(Score).order_by(Score.level.asc())) == "eql_v4.ord_term(scores.level) ASC"
    assert order_sql(select(Score).order_by(Score.level.desc().nulls_last())) == (
        "eql_v4.ord_term(scores.level) DESC NULLS LAST"
    )


def test_sorting_a_column_with_no_order_index_is_refused(scores, untouched):
    with pytest.raises(QueryError) as raised:
        Score.note.asc()
    assert raised.value.code == "query_unsupported"
    assert "order index" in raised.value.message


def test_a_bare_order_by_is_sorted_by_the_order_term_in_a_session(untouched):
    from sqlalchemy import asc
    from sqlalchemy.orm import Session

    @stackencrypt.model("laps")
    class Lap(Base):
        __tablename__ = "laps"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        seconds: Mapped[Annotated[int, IntegerOrd]]
        note: Mapped[Annotated[str, Text]]

    engine = create_engine("sqlite://")
    seen = []
    from sqlalchemy import event

    @event.listens_for(engine, "before_cursor_execute")
    def capture(conn, cursor, statement, parameters, context, executemany):
        seen.append(statement)

    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE laps (id INTEGER PRIMARY KEY, seconds TEXT, note TEXT)")
    configure_encryption(engine, [Lap])

    with Session(engine) as session:
        for statement in (select(Lap).order_by(Lap.seconds), select(Lap).order_by(asc(Lap.seconds))):
            try:
                session.execute(statement)
            except Exception:
                pass  # SQLite has no eql_v4 functions: only the SQL matters here.
        with pytest.raises(QueryError) as raised:
            session.execute(select(Lap).order_by(Lap.note))
    assert all("ORDER BY eql_v4.ord_term(laps.seconds)" in sql for sql in seen[-2:]), seen
    assert raised.value.code == "query_unsupported"
