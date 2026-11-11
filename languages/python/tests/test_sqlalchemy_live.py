"""``configure_encryption`` against ZeroKMS and a PostgreSQL with the EQL v4
bundle: the app writes and reads plaintext attributes, and the tables hold
EQL values.

These tests need the CipherStash credentials and ``EQL_TEST_DATABASE_URL``,
as ``test_encrypt_live.py`` does. Each test makes its own tables in a schema
of its own, and drops the schema afterwards.
"""

import decimal
import uuid
from typing import Annotated, List, Optional

import pytest
from _live import DATABASE_URL, LIVE, needs_database
from sqlalchemy import ForeignKey, and_, create_engine, delete, desc, func, not_, or_, select, text, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

import stackencrypt
from stackencrypt import Ignore, IntegerOrd, MatchQuery, NumericOrd, Passthrough, QueryError, Text, TextEq, TextMatch, _engine
from stackencrypt.sqlalchemy import configure_encryption, eql_type_map

pytestmark = [*LIVE, needs_database]


class Base(DeclarativeBase):
    type_annotation_map = eql_type_map


@stackencrypt.model("customers")
class Customer(Base):
    __tablename__ = "customers"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    email: Mapped[Annotated[str, TextEq]]
    name: Mapped[Annotated[str, Text]]
    plan: Mapped[Annotated[str, Passthrough]]
    # A relationship needs no marker: it is never a column.
    orders: Mapped[List["Order"]] = relationship(back_populates="customer")


@stackencrypt.model("orders")
class Order(Base):
    __tablename__ = "orders"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    customer_id: Mapped[Annotated[int, Ignore]] = mapped_column(ForeignKey("customers.id"))
    note: Mapped[Annotated[str, Text]]
    customer: Mapped["Customer"] = relationship(back_populates="orders")


@stackencrypt.model("profiles")
class Profile(Base):
    __tablename__ = "profiles"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    bio: Mapped[Annotated[str, TextMatch]]
    plan: Mapped[Annotated[str, Passthrough]]


@stackencrypt.model("venues")
class Venue(Base):
    __tablename__ = "venues"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    name: Mapped[Annotated[str, TextEq]]
    city: Mapped[Annotated[Optional[str], TextEq]]
    visits: Mapped[Annotated[Optional[int], Passthrough]]


@stackencrypt.model("trips")
class Trip(Base):
    __tablename__ = "trips"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    name: Mapped[Annotated[str, TextMatch]]
    town: Mapped[Annotated[str, TextMatch]]
    city: Mapped[Annotated[Optional[str], TextMatch]]


@stackencrypt.model("guides")
class Guide(Base):
    __tablename__ = "guides"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    trip_id: Mapped[Annotated[int, Ignore]] = mapped_column(ForeignKey("trips.id"))
    bio: Mapped[Annotated[str, TextMatch]]


@stackencrypt.model("runs")
class Run(Base):
    __tablename__ = "runs"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    label: Mapped[Annotated[str, Passthrough]]
    average_hr: Mapped[Annotated[Optional[int], IntegerOrd]]
    pace: Mapped[Annotated[Optional[decimal.Decimal], NumericOrd]]


@stackencrypt.model("players")
class Player(Base):
    __tablename__ = "players"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    level: Mapped[Annotated[int, IntegerOrd]]


@pytest.fixture(scope="module")
def engine():
    schema = f"sa_{uuid.uuid4().hex[:12]}"
    url = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
    # The EQL types are in `public` and the functions in `eql_v4`, so both
    # stay on the search path after the test schema.
    engine = create_engine(
        url,
        connect_args={"options": f"-c search_path={schema},public"},
        hide_parameters=True,
    )
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    Base.metadata.create_all(engine)
    configure_encryption(engine, [Customer, Order, Player, Profile, Venue, Trip, Guide, Run])
    yield engine
    with engine.begin() as conn:
        conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
    engine.dispose()


@pytest.fixture(autouse=True)
def empty(engine):
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE orders, customers, players, profiles, venues, guides, trips, runs RESTART IDENTITY"))


def stored(engine, sql):
    with engine.connect() as conn:
        return conn.execute(text(sql)).all()


def add_ann(engine):
    with Session(engine) as session:
        ann = Customer(email="ann@example.com", name="Ann", plan="free")
        ann.orders = [Order(note="first order"), Order(note="second order")]
        session.add(ann)
        session.commit()


def test_an_added_object_is_stored_encrypted_and_keeps_its_plaintext(engine):
    with Session(engine, expire_on_commit=False) as session:
        ann = Customer(email="ann@example.com", name="Ann", plan="free")
        session.add(ann)
        session.commit()

        assert (ann.email, ann.name, ann.plan) == ("ann@example.com", "Ann", "free")
        assert not session.dirty
    [(email, name, plan)] = stored(engine, "SELECT email::text, name::text, plan FROM customers")
    assert "ann@example.com" not in email
    assert "Ann" not in name
    assert '"c"' in email
    assert plan == "free"


def test_a_query_decrypts_the_objects_it_loads(engine):
    add_ann(engine)
    with Session(engine) as session:
        [ann] = session.scalars(select(Customer)).all()

        assert (ann.email, ann.name, ann.plan) == ("ann@example.com", "Ann", "free")
        assert not session.dirty


def test_an_update_of_one_field_is_stored_encrypted(engine):
    add_ann(engine)
    with Session(engine) as session:
        ann = session.scalars(select(Customer)).one()
        ann.email = "ann@new.example.com"
        session.commit()
    [(email,)] = stored(engine, "SELECT email::text FROM customers")
    assert "new.example.com" not in email
    with Session(engine) as session:
        ann = session.scalars(select(Customer)).one()
        assert (ann.email, ann.name) == ("ann@new.example.com", "Ann")


def test_a_relationship_load_decrypts_the_related_objects(engine):
    add_ann(engine)
    with Session(engine) as session:
        ann = session.scalars(select(Customer)).one()
        assert sorted(order.note for order in ann.orders) == ["first order", "second order"]


def test_an_attribute_read_after_commit_is_decrypted(engine):
    add_ann(engine)
    with Session(engine) as session:
        ann = session.scalars(select(Customer)).one()
        ann.plan = "pro"
        session.commit()  # expires every attribute

        assert ann.email == "ann@example.com"
        assert not session.dirty


def test_100_objects_make_one_key_request_to_insert_and_one_to_load(engine):
    add_ann(engine)  # warms up the client: the first call may load the keyset
    with Session(engine) as session:
        session.add_all(
            [Customer(email=f"user{i}@example.com", name=f"User {i}", plan="free") for i in range(100)]
        )
        before = _engine.request_count()
        session.commit()
        inserted = _engine.request_count() - before
    with Session(engine) as session:
        before = _engine.request_count()
        customers = session.scalars(select(Customer).where(Customer.plan == "free")).all()
        loaded = _engine.request_count() - before

    # 100 objects of 2 sealed fields: 200 values, one request of up to 500 keys.
    assert (inserted, loaded) == (1, 1)
    assert sorted(c.email for c in customers)[0] == "ann@example.com"


def test_an_equality_search_finds_the_one_matching_row(engine):
    add_ann(engine)
    with Session(engine) as session:
        session.add(Customer(email="bob@example.com", name="Bob", plan="free"))
        session.commit()
    with Session(engine) as session:
        found = session.scalars(select(Customer).where(Customer.email == "bob@example.com")).all()

    assert [(c.email, c.name) for c in found] == [("bob@example.com", "Bob")]


def test_order_searches_find_the_rows_on_each_side(engine):
    with Session(engine) as session:
        session.add_all([Player(level=level) for level in (1, 3, 5, 7)])
        session.commit()
    with Session(engine) as session:
        high = session.scalars(select(Player).where(Player.level >= 5)).all()
        low = session.scalars(select(Player).where(Player.level < 3)).all()
        middle = session.scalars(
            select(Player).where(Player.level > 1, Player.level <= 5).order_by(Player.id)
        ).all()

    assert sorted(p.level for p in high) == [5, 7]
    assert [p.level for p in low] == [1]
    assert [p.level for p in middle] == [3, 5]


def test_an_order_search_on_an_equality_field_is_unsupported(engine):
    with pytest.raises(QueryError) as raised:
        select(Customer).where(Customer.email > "a@example.com")
    assert raised.value.code == "query_unsupported"


def test_not_equal_and_in_find_the_right_rows(engine):
    with Session(engine) as session:
        session.add_all(
            [Customer(email=f"{name}@example.com", name=name, plan="free") for name in ("ann", "bob", "cy")]
        )
        session.commit()
    with Session(engine) as session:
        def names(*where):
            return sorted(c.name for c in session.scalars(select(Customer).where(*where)))

        assert names(Customer.email != "bob@example.com") == ["ann", "cy"]
        assert names(Customer.email.in_(["ann@example.com", "cy@example.com"])) == ["ann", "cy"]
        assert names(Customer.email.not_in(["ann@example.com"])) == ["bob", "cy"]
        assert names(Customer.email.in_([])) == []


def test_an_update_of_a_passthrough_field_only_makes_no_key_request(engine):
    add_ann(engine)  # warms up the client
    with Session(engine) as session:
        ann = session.scalars(select(Customer)).one()
        ann.plan = "pro"
        before = _engine.request_count()
        session.commit()
        assert _engine.request_count() - before == 0
    with Session(engine) as session:
        assert session.scalars(select(Customer)).one().plan == "pro"


def test_a_query_of_columns_decrypts_the_encrypted_ones(engine):
    add_ann(engine)
    with Session(engine) as session:
        rows = session.execute(select(Customer.email, Customer.name, Customer.plan)).all()
        labelled = session.execute(select(Customer.email.label("address"))).all()
        both = session.execute(select(Customer, Customer.name)).all()

    assert [tuple(row) for row in rows] == [("ann@example.com", "Ann", "free")]
    assert [row.address for row in labelled] == ["ann@example.com"]
    [(ann, name)] = both
    assert (ann.email, name) == ("ann@example.com", "Ann")


def test_100_rows_of_columns_make_one_key_request(engine):
    with Session(engine) as session:
        session.add_all(
            [Customer(email=f"user{i}@example.com", name=f"User {i}", plan="free") for i in range(100)]
        )
        session.commit()
    with Session(engine) as session:
        before = _engine.request_count()
        rows = session.execute(select(Customer.email, Customer.name)).all()
        assert _engine.request_count() - before == 1
    assert sorted(row.email for row in rows)[0] == "user0@example.com"


def test_a_core_query_on_a_connection_returns_eql_values(engine):
    add_ann(engine)
    with engine.connect() as conn:
        [email] = conn.execute(select(Customer.__table__.c.email)).scalars().all()
    # Left to the app: cipher.decrypt_rows opens it.
    assert "ann@example.com" not in str(email)
    [opened] = stackencrypt.Cipher(Customer).decrypt_rows([{"email": email}])
    assert opened == {"email": "ann@example.com"}


# .match() on a TextMatch field.

BIOS = ["Alice Smith", "Natalie Wood", "Bob Jones"]


def add_profiles(engine):
    with Session(engine) as session:
        session.add_all([Profile(bio=bio, plan="free") for bio in BIOS])
        session.commit()


def test_a_match_search_returns_the_rows_that_hold_the_text(engine):
    add_profiles(engine)
    with Session(engine) as session:
        found = session.scalars(select(Profile).where(Profile.bio.match("ali"))).all()

    assert sorted(p.bio for p in found) == ["Alice Smith", "Natalie Wood"]


def test_rows_that_fail_verify_are_dropped(engine, monkeypatch):
    add_profiles(engine)
    verify = MatchQuery.verify
    # A false match of the Bloom filter cannot be made on purpose. So
    # verify refuses one row that the database returns.
    monkeypatch.setattr(
        MatchQuery, "verify", lambda q, values: [v != "Natalie Wood" and ok for v, ok in zip(values, verify(q, values))]
    )
    with Session(engine) as session:
        found = session.scalars(
            select(Profile).where(Profile.bio.match("ali"), Profile.plan == "free")
        ).all()

    assert [p.bio for p in found] == ["Alice Smith"]


def test_a_limit_can_return_fewer_rows_than_match(engine, monkeypatch):
    add_profiles(engine)
    verify = MatchQuery.verify
    monkeypatch.setattr(
        MatchQuery, "verify", lambda q, values: [v != "Alice Smith" and ok for v, ok in zip(values, verify(q, values))]
    )
    with Session(engine) as session:
        found = session.scalars(
            select(Profile).where(Profile.bio.match("ali")).order_by(Profile.id).limit(1)
        ).all()

    # The database's one row was Alice, which verify refused. Natalie also
    # matches, but was past the limit.
    assert found == []


@pytest.mark.parametrize(
    "statement",
    [
        lambda: select(Profile).where(or_(Profile.bio.match("ali"), Profile.plan == "pro")),
        lambda: select(Profile).where(not_(Profile.bio.match("ali"))),
        lambda: select(Profile.plan).where(Profile.bio.match("ali")),
        lambda: select(func.count()).select_from(Profile).where(Profile.bio.match("ali")),
        lambda: update(Profile).where(Profile.bio.match("ali")).values(plan="pro"),
        lambda: delete(Profile).where(Profile.bio.match("ali")),
    ],
    ids=["in-an-or", "in-a-not", "object-not-selected", "count", "update", "delete"],
)
def test_a_match_that_rows_cannot_be_checked_for_is_refused(engine, statement):
    add_profiles(engine)
    with Session(engine) as session, pytest.raises(QueryError) as raised:
        session.execute(statement())
    assert raised.value.code == "query_unsupported"
    assert "A match index can return rows" in raised.value.message
    assert "ali" not in str(raised.value)
    with Session(engine) as session:
        assert sorted((p.bio, p.plan) for p in session.scalars(select(Profile))) == sorted(
            (bio, "free") for bio in BIOS
        )


def test_a_match_on_a_connection_is_refused(engine):
    add_profiles(engine)
    with engine.connect() as conn, pytest.raises(QueryError) as raised:
        conn.execute(select(Profile.__table__).where(Profile.bio.match("ali")))
    assert raised.value.code == "query_unsupported"
    assert "is not run through a session" in raised.value.message


def test_a_match_on_a_field_with_no_match_index_is_unsupported(engine):
    with pytest.raises(QueryError) as raised:
        Customer.email.match("ali")
    assert raised.value.code == "query_unsupported"


# A field declared Optional.


def test_an_optional_field_stores_null_reads_none_and_is_found_with_is_null(engine):
    with Session(engine) as session:
        session.add_all([Venue(name="hall", city=None, visits=None), Venue(name="park", city="Leeds", visits=2)])
        session.commit()
    with Session(engine) as session:
        missing = session.scalars(select(Venue).where(Venue.city.is_(None))).all()
        leeds = session.scalars(select(Venue).where(Venue.city == "Leeds")).all()
        cities = session.execute(select(Venue.name, Venue.city).order_by(Venue.id)).all()

    assert [(v.name, v.city, v.visits) for v in missing] == [("hall", None, None)]
    assert [(v.name, v.city, v.visits) for v in leeds] == [("park", "Leeds", 2)]
    assert [tuple(row) for row in cities] == [("hall", None), ("park", "Leeds")]


def test_an_optional_field_can_be_set_to_none_and_back(engine):
    with Session(engine) as session:
        session.add(Venue(name="hall", city="York", visits=1))
        session.commit()
    with Session(engine) as session:
        hall = session.scalars(select(Venue)).one()
        hall.city = None
        session.commit()
        assert hall.city is None
    with Session(engine) as session:
        hall = session.scalars(select(Venue)).one()
        assert hall.city is None
        hall.city = "Bath"
        session.commit()
    with Session(engine) as session:
        assert session.scalars(select(Venue).where(Venue.city == "Bath")).one().name == "hall"


# An or_ whose branches are all match searches.

TRIPS = [
    ("Morning run", "Hove", "Brighton"),
    ("Evening ride", "Leeds", None),
    ("Hill walk", "Keswick", "Carlisle"),
]


def add_trips(engine):
    with Session(engine) as session:
        session.add_all([Trip(name=n, town=t, city=c) for n, t, c in TRIPS])
        session.commit()


def names(engine, *where):
    with Session(engine) as session:
        return sorted(t.name for t in session.scalars(select(Trip).where(*where)))


def any_field(text):
    return or_(Trip.name.match(text), Trip.town.match(text), Trip.city.match(text))


def test_an_or_of_matches_returns_the_rows_that_hold_the_text_in_any_field(engine):
    add_trips(engine)

    assert names(engine, any_field("run")) == ["Morning run"]
    assert names(engine, any_field("leeds")) == ["Evening ride"]
    assert names(engine, any_field("brighton")) == ["Morning run"]
    assert names(engine, any_field("hove")) == ["Morning run"]


def test_a_null_field_fails_its_branch_only(engine):
    add_trips(engine)

    # Evening ride has no city; its town still matches.
    assert names(engine, or_(Trip.city.match("leeds"), Trip.town.match("leeds"))) == ["Evening ride"]


def test_a_branch_can_be_an_and_of_matches(engine):
    add_trips(engine)

    where = or_(and_(Trip.name.match("hill"), Trip.town.match("keswick")), Trip.city.match("brighton"))
    assert names(engine, where) == ["Hill walk", "Morning run"]


def test_a_false_match_in_one_branch_is_removed_and_another_branch_keeps_the_row(engine, monkeypatch):
    add_trips(engine)
    verify = MatchQuery.verify
    # A false match of the Bloom filter cannot be made on purpose. So verify
    # refuses Hove as a town: Morning run must then be kept by its name.
    monkeypatch.setattr(
        MatchQuery, "verify", lambda q, values: [v != "Hove" and ok for v, ok in zip(values, verify(q, values))]
    )

    assert names(engine, or_(Trip.town.match("hove"), Trip.name.match("run"))) == ["Morning run"]
    assert names(engine, or_(Trip.town.match("hove"), Trip.name.match("walk"))) == ["Hill walk"]


def test_two_or_groups_joined_with_and_keep_the_rows_that_pass_both(engine):
    add_trips(engine)

    where = (
        or_(Trip.name.match("run"), Trip.name.match("ride")),
        or_(Trip.town.match("leeds"), Trip.city.match("carlisle")),
    )
    assert names(engine, *where) == ["Evening ride"]


@pytest.mark.parametrize(
    "where",
    [
        lambda: or_(Trip.name.match("run"), Trip.id == 1),
        lambda: or_(not_(Trip.name.match("run")), Trip.town.match("hove")),
        lambda: not_(or_(Trip.name.match("run"), Trip.town.match("hove"))),
        lambda: or_(and_(Trip.name.match("run"), Trip.id == 1), Trip.town.match("hove")),
    ],
    ids=["mixed", "not-in-a-branch", "or-in-a-not", "mixed-and-in-a-branch"],
)
def test_an_or_that_is_not_only_matches_is_refused(engine, where):
    add_trips(engine)
    with Session(engine) as session, pytest.raises(QueryError) as raised:
        session.execute(select(Trip).where(where()))
    assert raised.value.code == "query_unsupported"
    assert "A match index can return rows" in raised.value.message


def test_an_or_across_an_outer_join_fails_the_branch_of_a_missing_object(engine):
    add_trips(engine)
    with Session(engine) as session:
        # Only Hill walk (id 3) has a guide.
        session.add(Guide(trip_id=3, bio="Mountain leader"))
        session.commit()
    with Session(engine) as session:
        statement = (
            select(Trip, Guide)
            .outerjoin(Guide, Guide.trip_id == Trip.id)
            .where(or_(Trip.name.match("run"), Guide.bio.match("mountain")))
            .order_by(Trip.id)
        )
        found = [(trip.name, guide and guide.bio) for trip, guide in session.execute(statement)]

    # Morning run has no guide: its Guide branch fails, and its name keeps it.
    assert found == [("Morning run", None), ("Hill walk", "Mountain leader")]


# ORDER BY an encrypted column with an order index.

RUNS = [
    ("a", 150, decimal.Decimal("5.30")),
    ("b", None, decimal.Decimal("4.75")),
    ("c", 120, None),
    ("d", 175, decimal.Decimal("6.10")),
    ("e", 98, decimal.Decimal("4.80")),
]


def labels(engine, *order):
    with Session(engine) as session:
        return [r.label for r in session.scalars(select(Run).order_by(*order))]


@pytest.fixture
def runs(engine):
    with Session(engine) as session:
        session.add_all([Run(label=l, average_hr=hr, pace=p) for l, hr, p in RUNS])
        session.commit()


def test_order_by_an_integer_ord_column(engine, runs):
    assert labels(engine, Run.average_hr.asc().nulls_last()) == ["e", "c", "a", "d", "b"]
    assert labels(engine, Run.average_hr.desc().nulls_last()) == ["d", "a", "c", "e", "b"]


def test_order_by_a_numeric_ord_column(engine, runs):
    assert labels(engine, Run.pace.asc().nulls_last()) == ["b", "e", "a", "d", "c"]
    assert labels(engine, Run.pace.desc().nulls_last()) == ["d", "a", "e", "b", "c"]


def test_nulls_first_puts_the_missing_values_first(engine, runs):
    assert labels(engine, Run.average_hr.asc().nulls_first())[0] == "b"
    assert labels(engine, Run.pace.desc().nulls_first())[0] == "c"


def test_order_by_with_a_limit_pages_in_order(engine, runs):
    with Session(engine) as session:
        page = session.scalars(
            select(Run).order_by(Run.average_hr.desc().nulls_last()).limit(2).offset(1)
        ).all()
    assert [r.label for r in page] == ["a", "c"]



def test_a_bare_order_by_and_sqlalchemy_asc_sort_by_the_plaintext(engine, runs):
    from sqlalchemy import asc, desc

    assert labels(engine, Run.average_hr) == ["e", "c", "a", "d", "b"]
    assert labels(engine, asc(Run.pace)) == ["b", "e", "a", "d", "c"]
    assert labels(engine, desc(Run.average_hr).nulls_last()) == ["d", "a", "c", "e", "b"]


def test_an_order_by_on_a_connection_sorts_by_the_plaintext(engine, runs):
    table = Run.__table__
    with engine.connect() as conn:
        found = conn.execute(select(table.c.label).order_by(table.c.average_hr.asc().nulls_last())).scalars().all()
        bare = conn.execute(select(table.c.label).order_by(table.c.pace)).scalars().all()

    assert found == ["e", "c", "a", "d", "b"]
    assert bare == ["b", "e", "a", "d", "c"]


def test_an_orm_select_on_a_connection_sorts_by_the_plaintext(engine, runs):
    # select(Run.label) names a mapped attribute, so SQLAlchemy marks it as
    # an ORM statement, even when it runs on a connection.
    from sqlalchemy import asc

    with engine.connect() as conn:
        bare = conn.execute(select(Run.label).order_by(Run.average_hr)).scalars().all()
        function = conn.execute(select(Run.label).order_by(asc(Run.pace))).scalars().all()

    assert bare == ["e", "c", "a", "d", "b"]
    assert function == ["b", "e", "a", "d", "c"]


@pytest.fixture
def sent(engine):
    """The SQL the engine sends while a test runs. A wrong sort gives a
    random order, which can be the right one by chance, so a sort test
    also checks the SQL."""
    from sqlalchemy import event

    statements = []

    def record(conn, cursor, statement, *args):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    yield statements
    event.remove(engine, "before_cursor_execute", record)


def test_a_bare_order_by_on_an_aliased_class_sorts_by_the_plaintext(engine, runs, sent):
    from sqlalchemy.orm import aliased

    other = aliased(Run)
    found = labels_of(engine, select(other).order_by(other.average_hr))

    assert found == ["e", "c", "a", "d", "b"]
    assert "ORDER BY eql_v4.ord_term(runs_1.average_hr)" in sent[-1], sent[-1]


def test_a_bare_order_by_in_a_subquery_sorts_by_the_plaintext(engine, runs, sent):
    # The three lowest heart rates, then their labels in the outer query.
    lowest = select(Run.label, Run.average_hr).order_by(Run.average_hr).limit(3).subquery()
    with Session(engine) as session:
        found = session.execute(select(lowest.c.label)).scalars().all()
    with engine.connect() as conn:
        on_a_connection = conn.execute(select(lowest.c.label)).scalars().all()

    assert sorted(found) == ["a", "c", "e"]
    assert sorted(on_a_connection) == ["a", "c", "e"]
    assert all("ORDER BY eql_v4.ord_term(runs.average_hr)" in sql for sql in sent[-2:]), sent[-2:]


def labels_of(engine, statement):
    with Session(engine) as session:
        return [r.label for r in session.scalars(statement)]


def test_a_labelled_column_in_order_by_sorts_by_the_plaintext(engine, runs, sent):
    hr = Run.average_hr.label("hr")
    with Session(engine) as session:
        by_label = session.execute(select(Run.label, hr).order_by(hr)).all()
        by_name = session.execute(select(Run.label, hr).order_by("hr")).all()

    assert [row.label for row in by_label] == ["e", "c", "a", "d", "b"]
    assert [row.label for row in by_name] == ["e", "c", "a", "d", "b"]
    assert all("ORDER BY eql_v4.ord_term(runs.average_hr)" in sql for sql in sent[-2:]), sent[-2:]
    # The selected column is still the decrypted value, under its label.
    assert [row.hr for row in by_label] == [98, 120, 150, 175, None]


def test_a_column_named_by_a_string_in_order_by_sorts_by_the_plaintext(engine, runs, sent):
    from sqlalchemy import desc

    assert labels_of(engine, select(Run).order_by("average_hr")) == ["e", "c", "a", "d", "b"]
    assert labels_of(engine, select(Run).order_by(desc("pace").nulls_last())) == ["d", "a", "e", "b", "c"]
    assert "ORDER BY eql_v4.ord_term(runs.average_hr)" in sent[-2], sent[-2]
    assert "ORDER BY eql_v4.ord_term(runs.pace) DESC NULLS LAST" in sent[-1], sent[-1]


def test_a_plaintext_label_with_an_encrypted_columns_name_sorts_by_the_plaintext(engine, runs, sent):
    # The label "average_hr" names the plaintext label column.
    renamed = Run.label.label("average_hr")
    with Session(engine) as session:
        found = session.execute(select(renamed).order_by(desc("average_hr"))).scalars().all()

    assert found == ["e", "d", "c", "b", "a"]
    assert "ord_term" not in sent[-1], sent[-1]
