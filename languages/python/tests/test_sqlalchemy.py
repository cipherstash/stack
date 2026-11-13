"""``stackencrypt.sqlalchemy`` before any request: the type map, the class
checks of ``configure_encryption``, and the operators a query refuses.

These tests need fake credentials only. They use an SQLite engine that no
test connects to. The hooks run against PostgreSQL in
``test_sqlalchemy_live.py``.
"""

import dataclasses
from typing import Annotated, Optional

import pytest
from sqlalchemy import ForeignKey, String, UniqueConstraint, create_engine, func, literal, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

import stackencrypt
from stackencrypt import DeclarationError, Ignore, InvalidValueError, Passthrough, TextEq
from stackencrypt import IntegerOrd, QueryError, StashError, Text, _eql
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


def refused(classes):
    with pytest.raises(DeclarationError) as raised:
        configure_encryption(classes)
    return raised.value


def test_a_class_sqlalchemy_does_not_map_is_refused(engine):
    @stackencrypt.model("contacts")
    @dataclasses.dataclass
    class Contact:
        email: Annotated[str, TextEq]

    error = refused([Contact])
    assert error.code == "declaration_not_mapped"
    assert "Contact" in error.message


def test_a_class_not_declared_is_refused(engine):
    class Plain(Base):
        __tablename__ = "plain"
        id: Mapped[int] = mapped_column(primary_key=True)

    error = refused([Plain])
    assert error.code == "declaration_not_decorated"


def test_a_declared_table_that_is_not_the_mapped_table_is_refused(engine):
    @stackencrypt.model("people")
    class Person(Base):
        __tablename__ = "persons"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    error = refused([Person])
    assert error.code == "declaration_table_mismatch"
    assert "people" in error.message
    assert "persons" in error.message


def test_a_field_whose_column_has_another_name_is_refused(engine):
    @stackencrypt.model("accounts")
    class Account(Base):
        __tablename__ = "accounts"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]] = mapped_column("email_address")

    error = refused([Account])
    assert error.code == "declaration_column_name"
    assert error.field == "email"
    assert "email_address" in error.message


def test_a_unique_encrypted_column_is_refused(engine):
    @stackencrypt.model("logins")
    class Login(Base):
        __tablename__ = "logins"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]] = mapped_column(unique=True)

    error = refused([Login])
    assert error.code == "declaration_unique_column"
    assert error.field == "email"
    assert "eql_v4.eq_term(email)" in error.message


def test_an_encrypted_column_in_a_unique_constraint_is_refused(engine):
    @stackencrypt.model("seats")
    class Seat(Base):
        __tablename__ = "seats"
        __table_args__ = (UniqueConstraint("venue", "holder"),)
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        venue: Mapped[Annotated[int, Ignore]]
        holder: Mapped[Annotated[str, TextEq]]

    error = refused([Seat])
    assert error.code == "declaration_unique_column"
    assert error.field == "holder"


def test_a_unique_plaintext_column_beside_an_encrypted_one_is_accepted(untouched):
    @stackencrypt.model("passes")
    class Pass(Base):
        __tablename__ = "passes"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        code: Mapped[Annotated[str, Ignore]] = mapped_column(unique=True)
        holder: Mapped[Annotated[str, TextEq]]

    configure_encryption([Pass])


def test_a_repeat_call_for_a_configured_class_does_nothing(untouched):
    @stackencrypt.model("members")
    class Member(Base):
        __tablename__ = "members"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    configure_encryption([Member])
    configure_encryption([Member])
    configure_encryption([Member, Member])


def test_a_class_whose_declaration_changed_is_refused_on_a_repeat_call():
    @stackencrypt.model("pilots")
    class Pilot(Base):
        __tablename__ = "pilots"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    configure_encryption([Pilot])
    Pilot.__repr__ = lambda self: "Pilot(...)"

    assert refused([Pilot]).code == "declaration_class_changed"


def test_another_class_that_maps_a_configured_table_is_refused():
    @stackencrypt.model("crews")
    class Crew(Base):
        __tablename__ = "crews"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    class OtherBase(DeclarativeBase):
        type_annotation_map = eql_type_map

    @stackencrypt.model("crews")
    class CrewAgain(OtherBase):
        __table__ = Crew.__table__
        id: Mapped[Annotated[int, Ignore]]
        email: Mapped[Annotated[str, TextEq]]

    configure_encryption([Crew])
    error = refused([CrewAgain])

    assert error.code == "declaration_already_configured"
    assert "Crew" in error.message


def test_an_engine_made_after_the_call_is_encrypted_too(untouched):
    import datetime

    from sqlalchemy.orm import Session

    @stackencrypt.model("flights")
    class Flight(Base):
        __tablename__ = "flights"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]
        at: Mapped[Annotated[datetime.datetime, Passthrough]]

    configure_encryption([Flight])
    later = create_engine("sqlite://")
    with later.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE flights (id INTEGER PRIMARY KEY, email TEXT, at TEXT)")

    # The write hook runs on the new engine: it checks the passthrough value.
    with Session(later) as session, pytest.raises(InvalidValueError) as raised:
        session.add(Flight(email="secret@example.com", at=datetime.datetime(2026, 1, 1)))
        session.commit()
    assert raised.value.code == "value_naive_datetime"


def test_a_table_of_the_same_name_that_is_not_configured_is_left_alone(untouched):
    from sqlalchemy import Column, Integer, MetaData, Table, insert

    @stackencrypt.model("tickets_seen")
    class Seen(Base):
        __tablename__ = "tickets_seen"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]

    configure_encryption([Seen])
    # Another database's table, with the same name, and no encryption.
    other = Table("tickets_seen", MetaData(), Column("id", Integer, primary_key=True), Column("email", String))
    engine = create_engine("sqlite://")
    other.create(engine)

    with engine.begin() as conn:
        conn.execute(insert(other), [{"email": "plain@example.com"}])
        assert conn.execute(other.select()).one().email == "plain@example.com"


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

    refused([Guest, Visitor])
    # Guest was not configured by the refused call, so it can be now.
    configure_encryption([Guest])


def test_a_declared_mapped_class_is_accepted_with_no_request(engine, untouched):
    configure_encryption([Customer])


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
    configure_encryption([Lead])

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

    error = refused([Ticket])
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


@pytest.fixture
def scores(credentials):
    # Function scope, so that the fake credentials are set first. A repeat
    # call for a configured class does nothing.
    configure_encryption([Score])


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
    configure_encryption([Visit])

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
    configure_encryption([Lap])

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


# A comparison with a SQL expression, not a Python value.


@pytest.mark.parametrize(
    "build",
    [
        lambda: Score.note == literal("secret"),
        lambda: Score.note == func.lower("secret"),
        lambda: Score.level > literal(3) + 1,
    ],
    ids=["literal", "function-of-a-value", "expression-of-a-value"],
)
def test_a_comparison_with_an_expression_that_holds_a_value_is_refused(scores, untouched, build):
    with pytest.raises(QueryError) as raised:
        build()
    assert raised.value.code == "query_unsupported"
    assert "secret" not in str(raised.value)


def test_a_comparison_with_another_column_sends_no_value(scores, untouched):
    from sqlalchemy.dialects import postgresql

    sql = str((Score.note == Score.note).compile(dialect=postgresql.dialect()))

    assert sql == "scores.note = scores.note"


def test_a_labelled_column_in_order_by_is_sorted_by_the_order_term(untouched):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    @stackencrypt.model("splits")
    class Split(Base):
        __tablename__ = "splits"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        seconds: Mapped[Annotated[int, IntegerOrd]]

    engine = create_engine("sqlite://")
    sent = []
    event.listen(engine, "before_cursor_execute", lambda conn, cur, sql, *a: sent.append(sql))
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE splits (id INTEGER PRIMARY KEY, seconds TEXT)")
    configure_encryption([Split])
    secs = Split.seconds.label("secs")

    with Session(engine) as session:
        for statement in (
            select(secs).order_by(secs),
            select(secs).order_by("secs"),
            select(secs).order_by(secs.desc()),
        ):
            try:
                session.execute(statement)
            except Exception:
                pass  # SQLite has no eql_v4 functions: only the SQL matters here.

    sorts = [sql.split("ORDER BY", 1)[1].strip() for sql in sent[-3:]]
    assert sorts == [
        "eql_v4.ord_term(splits.seconds)",
        "eql_v4.ord_term(splits.seconds)",
        "eql_v4.ord_term(splits.seconds) DESC",
    ]


def test_a_column_named_by_a_string_in_order_by_is_sorted_by_the_order_term(untouched):
    from sqlalchemy import desc, event
    from sqlalchemy.orm import Session

    @stackencrypt.model("legs")
    class Leg(Base):
        __tablename__ = "legs"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        seconds: Mapped[Annotated[int, IntegerOrd]]

    engine = create_engine("sqlite://")
    sent = []
    event.listen(engine, "before_cursor_execute", lambda conn, cur, sql, *a: sent.append(sql))
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE legs (id INTEGER PRIMARY KEY, seconds TEXT)")
    configure_encryption([Leg])
    statements = [
        select(Leg.seconds).order_by("seconds"),
        select(Leg.seconds).order_by(desc("seconds")),
        select(Leg).order_by("seconds"),
        select(Leg.__table__).order_by("seconds"),
    ]

    with Session(engine) as session:
        for statement in statements:
            try:
                session.execute(statement)
            except Exception:
                pass  # SQLite has no eql_v4 functions: only the SQL matters here.

    sorts = [sql.split("ORDER BY", 1)[1].strip() for sql in sent[-4:]]
    assert sorts == [
        "eql_v4.ord_term(legs.seconds)",
        "eql_v4.ord_term(legs.seconds) DESC",
        "eql_v4.ord_term(legs.seconds)",
        "eql_v4.ord_term(legs.seconds)",
    ]


def test_a_string_naming_an_encrypted_column_that_is_not_selected_is_sorted_or_refused(untouched):
    from sqlalchemy import event
    from sqlalchemy.orm import Session, aliased

    @stackencrypt.model("stages")
    class Stage(Base):
        __tablename__ = "stages"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        name: Mapped[Annotated[str, Passthrough]]
        seconds: Mapped[Annotated[int, IntegerOrd]]

    engine = create_engine("sqlite://")
    sent = []
    event.listen(engine, "before_cursor_execute", lambda conn, cur, sql, *a: sent.append(sql))
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE stages (id INTEGER PRIMARY KEY, name TEXT, seconds TEXT)")
    configure_encryption([Stage])
    other = aliased(Stage)

    with Session(engine) as session:
        try:
            session.execute(select(Stage.name).order_by("seconds"))
        except Exception:
            pass  # SQLite has no eql_v4 functions: only the SQL matters here.
        with pytest.raises(QueryError) as raised:
            session.execute(select(Stage.name, other.name).join(other, other.id == Stage.id).order_by("seconds"))

    assert sent[-1].split("ORDER BY", 1)[1].strip() == "eql_v4.ord_term(stages.seconds)"
    assert raised.value.code == "query_unsupported"
    assert "seconds" in raised.value.message


def test_a_plaintext_label_with_an_encrypted_columns_name_is_left_alone(untouched):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    @stackencrypt.model("heats")
    class Heat(Base):
        __tablename__ = "heats"
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        rank: Mapped[Annotated[int, Passthrough]]
        seconds: Mapped[Annotated[int, IntegerOrd]]

    engine = create_engine("sqlite://")
    sent = []
    event.listen(engine, "before_cursor_execute", lambda conn, cur, sql, *a: sent.append(sql))
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE heats (id INTEGER PRIMARY KEY, rank INTEGER, seconds TEXT)")
    configure_encryption([Heat])

    with Session(engine) as session:
        # The label "seconds" names the plaintext rank, so the sort is by rank.
        session.execute(select(Heat.rank.label("seconds")).order_by("seconds"))
        try:
            session.execute(select(Heat.rank, Heat.seconds.label("rank")).order_by("rank"))
        except Exception:
            pass  # SQLite has no eql_v4 functions: only the SQL matters here.

    assert sent[-2].split("ORDER BY", 1)[1].strip() == "seconds"
    # Here the label "rank" names the encrypted column, so the sort is its term.
    assert sent[-1].split("ORDER BY", 1)[1].strip() == "eql_v4.ord_term(heats.seconds)"


# A sealed value the statement carries itself, in any form the hook does not
# encrypt.

SECRET = "secret@example.com"


@stackencrypt.model("inline_leads")
class InlineLead(Base):
    __tablename__ = "inline_leads"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    email: Mapped[Annotated[str, TextEq]]


@pytest.fixture
def leads(credentials):
    """An SQLite engine with a configured ``inline_leads`` table, and its class."""
    Lead = InlineLead
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE inline_leads (id INTEGER PRIMARY KEY, email TEXT)")
    configure_encryption([Lead])
    return engine, Lead


def _inline_writes(Lead):
    from sqlalchemy import bindparam, case, insert, update
    from sqlalchemy.dialects import sqlite

    upsert = sqlite.insert(Lead).values(id=1, email=None)
    return {
        "multi-row values": (insert(Lead).values([{"email": SECRET}, {"email": SECRET}]), None),
        "a function of a value": (insert(Lead).values(email=func.lower(SECRET)), None),
        "a bindparam of another name": (
            insert(Lead).values(email=bindparam("new_email")),
            [{"new_email": SECRET}, {"new_email": SECRET}],
        ),
        "a case with a value": (
            update(Lead).values(email=case((Lead.id == 1, SECRET), else_=SECRET)),
            None,
        ),
        "an on-conflict set": (
            upsert.on_conflict_do_update(index_elements=["id"], set_={"email": SECRET}),
            None,
        ),
    }


@pytest.mark.parametrize(
    "form",
    ["multi-row values", "a function of a value", "a bindparam of another name", "a case with a value", "an on-conflict set"],
)
def test_a_sealed_value_in_any_form_of_the_statement_is_refused(leads, untouched, form):
    engine, Lead = leads
    statement, rows = _inline_writes(Lead)[form]
    with engine.begin() as conn, pytest.raises(DeclarationError) as raised:
        conn.execute(statement, rows) if rows else conn.execute(statement)
    assert raised.value.code == "declaration_inline_value"
    assert raised.value.field == "email"
    assert SECRET not in str(raised.value)
    with engine.connect() as conn:
        assert conn.execute(select(Lead.__table__)).all() == []


def test_an_on_conflict_set_from_the_excluded_row_is_encrypted_not_refused(leads):
    from sqlalchemy.dialects import sqlite

    engine, Lead = leads
    statement = sqlite.insert(Lead)
    statement = statement.on_conflict_do_update(
        index_elements=["id"], set_={"email": statement.excluded.email}
    )
    # Past the refusal, the hook encrypts the row: with no client key, that
    # fails building the client, before the database.
    with engine.begin() as conn, pytest.raises(StashError) as raised:
        conn.execute(statement, [{"id": 1, "email": SECRET}])
    assert not isinstance(raised.value, DeclarationError)


# The session hook reads rows as the app asks for them.


class Shelf(Base):
    __tablename__ = "plain_shelves"
    id: Mapped[int] = mapped_column(primary_key=True)
    boxes: Mapped[list["Box"]] = relationship()


class Box(Base):
    __tablename__ = "plain_boxes"
    id: Mapped[int] = mapped_column(primary_key=True)
    shelf_id: Mapped[int] = mapped_column(ForeignKey("plain_shelves.id"))


@pytest.fixture
def shelves(untouched):
    """Two shelves of two boxes in SQLite, with the hooks installed."""
    from sqlalchemy.orm import Session

    configure_encryption([Customer])  # installs the hooks, if no test did
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[Shelf.__table__, Box.__table__])
    with Session(engine) as session:
        session.add_all([Shelf(id=1, boxes=[Box(id=1), Box(id=2)]), Shelf(id=2, boxes=[Box(id=3), Box(id=4)])])
        session.commit()
    return engine


def test_a_joined_eager_load_of_two_entities_with_unique_works(shelves):
    from sqlalchemy.orm import Session, joinedload

    with Session(shelves) as session:
        rows = (
            session.execute(select(Shelf, Box).join(Shelf.boxes).options(joinedload(Shelf.boxes)))
            .unique()
            .all()
        )
    assert len(rows) == 4


def test_a_joined_eager_load_with_no_unique_is_still_refused_by_sqlalchemy(shelves):
    from sqlalchemy.exc import InvalidRequestError
    from sqlalchemy.orm import Session, joinedload

    with Session(shelves) as session, pytest.raises(InvalidRequestError, match="unique"):
        session.execute(select(Shelf).options(joinedload(Shelf.boxes))).all()


def test_yield_per_reads_the_rows_a_chunk_at_a_time(shelves):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    loaded = []
    listener = lambda target, context: loaded.append(target.id)  # noqa: E731
    event.listen(Box, "load", listener)
    try:
        with Session(shelves) as session:
            result = session.execute(select(Box).order_by(Box.id).execution_options(yield_per=1))
            first = next(iter(result.scalars()))
            assert first.id == 1
            assert loaded == [1]
            result.close()
    finally:
        event.remove(Box, "load", listener)


# A single-table subclass of a configured class.


@stackencrypt.model("members_plus")
class MemberPlus(Base):
    __tablename__ = "members_plus"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    kind: Mapped[Annotated[str, Passthrough]]
    email: Mapped[Annotated[str, TextEq]]
    __mapper_args__ = {"polymorphic_on": "kind", "polymorphic_identity": "member"}


class GoldMember(MemberPlus):
    __mapper_args__ = {"polymorphic_identity": "gold"}


def test_a_subclass_on_its_bases_table_is_accepted_when_its_base_is_configured(untouched):
    configure_encryption([MemberPlus])
    configure_encryption([GoldMember])
    configure_encryption([MemberPlus, GoldMember])


def test_a_subclass_load_is_decrypted_like_its_base(untouched):
    from sqlalchemy.orm import Session

    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE members_plus (id INTEGER PRIMARY KEY, kind TEXT, email TEXT)")
        conn.exec_driver_sql("""INSERT INTO members_plus VALUES (1, 'gold', '{"i": {"t": "members_plus", "c": "email"}, "v": 2, "c": "x"}')""")
    configure_encryption([MemberPlus])
    # The hook tries to decrypt the stored value: with no client key, that
    # fails, instead of returning the stored JSON as the email.
    with Session(engine) as session, pytest.raises(StashError):
        session.execute(select(GoldMember)).scalars().all()


# Unique indexes and primary keys on an encrypted column.


def test_an_encrypted_column_in_a_unique_index_is_refused(engine):
    from sqlalchemy import Index

    @stackencrypt.model("tags")
    class Tag(Base):
        __tablename__ = "tags"
        __table_args__ = (Index("ux_tags_label", "label", unique=True),)
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        label: Mapped[Annotated[str, TextEq]]

    error = refused([Tag])
    assert error.code == "declaration_unique_column"
    assert error.field == "label"


def test_an_encrypted_primary_key_is_refused(engine):
    @stackencrypt.model("badges")
    class Badge(Base):
        __tablename__ = "badges"
        code: Mapped[Annotated[str, TextEq]] = mapped_column(primary_key=True)

    error = refused([Badge])
    assert error.code == "declaration_unique_column"
    assert error.field == "code"


# ORDER BY outside a select's own ORDER BY.


@pytest.mark.parametrize(
    "build",
    [
        lambda: select(Score.id).union(select(Score.id)).order_by(Score.level),
        lambda: select(func.row_number().over(order_by=Score.level)),
        lambda: select(func.percentile_disc(0.5).within_group(Score.level)),
        lambda: select(_aggregate_order_by(func.array_agg(Score.id), Score.level)),
    ],
    ids=["union", "over", "within_group", "aggregate_order_by"],
)
def test_a_bare_encrypted_column_sorted_where_the_hooks_cannot_rewrite_it_is_refused(scores, untouched, build):
    with create_engine("sqlite://").connect() as conn, pytest.raises(QueryError) as raised:
        conn.execute(build())
    assert raised.value.code == "query_unsupported"
    assert raised.value.reason == "order"


def test_a_window_sorted_by_asc_of_an_encrypted_column_uses_its_order_term(scores, untouched):
    statement = select(func.row_number().over(order_by=Score.level.asc()))
    from sqlalchemy.dialects import postgresql

    assert "eql_v4.ord_term(scores.level)" in str(statement.compile(dialect=postgresql.dialect()))


def _aggregate_order_by(target, order_by):
    from sqlalchemy.dialects.postgresql import aggregate_order_by

    return aggregate_order_by(target, order_by)


# Index names.


def test_an_index_name_longer_than_postgres_allows_is_shortened():
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateIndex

    class Event(Base):
        __tablename__ = "customer_subscription_events"
        id: Mapped[int] = mapped_column(primary_key=True)
        billing_contact_email_address: Mapped[Annotated[str, TextEq]]

    names = [index.name for index in Event.__table__.indexes]
    assert len(names) == 1
    assert len(names[0]) <= 63
    for index in Event.__table__.indexes:
        CreateIndex(index).compile(dialect=postgresql.dialect())


def test_a_mixed_case_columns_own_index_on_its_term_is_kept_alone():
    from sqlalchemy import Index, text

    class Contact(Base):
        __tablename__ = "mixed_contacts"
        __table_args__ = (Index("ux_mixed_email", text('eql_v4.eq_term("Email")'), unique=True),)
        id: Mapped[int] = mapped_column(primary_key=True)
        Email: Mapped[Annotated[str, TextEq]]

    assert [index.name for index in Contact.__table__.indexes] == ["ux_mixed_email"]
