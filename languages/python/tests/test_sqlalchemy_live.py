"""``configure_encryption`` against ZeroKMS and a PostgreSQL with the EQL v4
bundle: the app writes and reads plaintext attributes, and the tables hold
EQL values.

These tests need the CipherStash credentials and ``EQL_TEST_DATABASE_URL``,
as ``test_encrypt_live.py`` does. Each test makes its own tables in a schema
of its own, and drops the schema afterwards.
"""

import uuid
from typing import Annotated

import pytest
from _live import DATABASE_URL, LIVE, needs_database
from sqlalchemy import ForeignKey, create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

import stackencrypt
from stackencrypt import Ignore, IntegerOrd, Passthrough, QueryError, Text, TextEq, _engine
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
    orders = relationship("Order", back_populates="customer")  # a list of Order


@stackencrypt.model("orders")
class Order(Base):
    __tablename__ = "orders"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    customer_id: Mapped[Annotated[int, Ignore]] = mapped_column(ForeignKey("customers.id"))
    note: Mapped[Annotated[str, Text]]
    customer: Mapped[Annotated["Customer", Ignore]] = relationship(back_populates="orders")


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
    configure_encryption(engine, [Customer, Order, Player])
    yield engine
    with engine.begin() as conn:
        conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
    engine.dispose()


@pytest.fixture(autouse=True)
def empty(engine):
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE orders, customers, players RESTART IDENTITY"))


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
