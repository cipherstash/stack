"""An Alembic migration of an existing table to encrypted columns, against
PostgreSQL with the EQL v4 bundle: ``alembic revision --autogenerate`` and
``alembic upgrade``, through an ``env.py`` that uses the two hooks of
``stackencrypt.sqlalchemy``.

These tests need ``EQL_TEST_DATABASE_URL``, and the CipherStash credentials
for the searches. Each test makes its own schema, and drops it afterwards.
"""

import pathlib
import sys
import textwrap
import uuid
from urllib.parse import quote

import pytest
from _live import DATABASE_URL, LIVE, needs_database
from sqlalchemy import create_engine, text

pytestmark = [*LIVE, needs_database]

alembic_command = pytest.importorskip("alembic.command")
from alembic.config import Config  # noqa: E402

MODELS = '''
from typing import Annotated

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

import stackencrypt
from stackencrypt import Ignore, IntegerOrd, Passthrough, TextEq, TextMatch
from stackencrypt.sqlalchemy import eql_type_map


class Base(DeclarativeBase):
    type_annotation_map = eql_type_map


@stackencrypt.model("accounts")
class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    email: Mapped[Annotated[str, TextEq]]        # was text: changed in place
    level: Mapped[Annotated[int, IntegerOrd]]    # new
    bio: Mapped[Annotated[str, TextMatch]]       # new
    plan: Mapped[Annotated[str, Passthrough]]    # unchanged; `note` is removed
'''

# Only `email` changes, so the USING cast is the first step that meets a row.
EMAIL_ONLY = '''
from typing import Annotated

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

import stackencrypt
from stackencrypt import Ignore, Passthrough, TextEq
from stackencrypt.sqlalchemy import eql_type_map


class Base(DeclarativeBase):
    type_annotation_map = eql_type_map


@stackencrypt.model("accounts")
class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    email: Mapped[Annotated[str, TextEq]]
    note: Mapped[Annotated[str, Passthrough]] = mapped_column(nullable=True)
    plan: Mapped[Annotated[str, Passthrough]]
'''

ENV = '''
from alembic import context
from sqlalchemy import create_engine

from models import Base
from stackencrypt.sqlalchemy import process_revision_directives, render_item

engine = create_engine(context.config.get_main_option("sqlalchemy.url"))
with engine.connect() as connection:
    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        render_item=render_item,
        process_revision_directives=process_revision_directives,
    )
    with context.begin_transaction():
        context.run_migrations()
'''

SCRIPT = '''"""${message}"""
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}


def upgrade():
    ${upgrades if upgrades else "pass"}


def downgrade():
    ${downgrades if downgrades else "pass"}
'''


@pytest.fixture
def project(tmp_path, monkeypatch, request):
    """An Alembic project in ``tmp_path`` with the models above, on a schema
    of its own that holds the existing table. A test can name other models
    with ``@pytest.mark.models(...)``."""
    marker = request.node.get_closest_marker("models")
    models = marker.args[0] if marker else MODELS
    schema = f"mig_{uuid.uuid4().hex[:12]}"
    url = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
    url += ("&" if "?" in url else "?") + "options=" + quote(f"-csearch_path={schema},public")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
        conn.execute(
            text(
                "CREATE TABLE accounts (id serial PRIMARY KEY, email text NOT NULL, "
                "note text, plan varchar NOT NULL)"
            )
        )
    (tmp_path / "versions").mkdir()
    (tmp_path / "models.py").write_text(textwrap.dedent(models))
    (tmp_path / "env.py").write_text(textwrap.dedent(ENV))
    (tmp_path / "script.py.mako").write_text(SCRIPT)
    monkeypatch.syspath_prepend(str(tmp_path))
    # env.py imports `models`: each test needs its own file, not the one an
    # earlier test imported.
    monkeypatch.delitem(sys.modules, "models", raising=False)
    config = Config()
    config.set_main_option("script_location", str(tmp_path))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    yield config, engine
    with engine.begin() as conn:
        conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
    engine.dispose()


def generate(config, message):
    script = alembic_command.revision(config, message=message, autogenerate=True)
    return pathlib.Path(script.path).read_text()


def body(migration, function):
    """The lines of ``function`` in a migration file, comments left out."""
    lines = migration.split(f"def {function}():\n", 1)[1].split("\n\n\ndef ", 1)[0]
    return [line.strip() for line in lines.splitlines() if line.strip() and not line.strip().startswith("#")]


def test_autogenerate_writes_the_columns_the_indexes_and_the_using_cast(project):
    config, _ = project

    migration = generate(config, "encrypt accounts")

    assert "import stackencrypt.sqlalchemy" in migration
    assert (
        "ALTER TABLE accounts ALTER COLUMN email TYPE public.eql_v4_text_eq "
        "USING email::jsonb::public.eql_v4_text_eq"
    ) in migration
    assert "stackencrypt.sqlalchemy.EqlType(stackencrypt.IntegerOrd)" in migration
    assert "stackencrypt.sqlalchemy.EqlType(stackencrypt.TextMatch)" in migration
    assert "op.drop_column('accounts', 'note')" in migration
    for index in ("ix_accounts_email_eq", "ix_accounts_level_ope", "ix_accounts_bio_match"):
        assert f"op.create_index('{index}'" in migration


def test_the_upgrade_makes_the_columns_and_indexes_and_a_second_autogenerate_finds_nothing(project):
    config, engine = project
    generate(config, "encrypt accounts")

    alembic_command.upgrade(config, "head")

    with engine.connect() as conn:
        columns = dict(
            conn.execute(
                text(
                    "SELECT attname, format_type(atttypid, atttypmod) FROM pg_attribute "
                    "WHERE attrelid = 'accounts'::regclass AND attnum > 0 AND NOT attisdropped"
                )
            ).all()
        )
        indexes = dict(
            conn.execute(
                text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'accounts'")
            ).all()
        )
    assert columns == {
        "id": "integer",
        "email": "eql_v4_text_eq",
        "level": "eql_v4_integer_ord",
        "bio": "eql_v4_text_match",
        "plan": "character varying",
    }
    assert "USING hash (eql_v4.eq_term(email))" in indexes["ix_accounts_email_eq"]
    assert "USING btree (eql_v4.ord_term(level))" in indexes["ix_accounts_level_ope"]
    assert "USING gin (eql_v4.match_term(bio))" in indexes["ix_accounts_bio_match"]

    second = generate(config, "nothing to do")
    assert body(second, "upgrade") == ["pass"]
    assert body(second, "downgrade") == ["pass"]


@pytest.mark.models(EMAIL_ONLY)
def test_the_upgrade_refuses_a_column_with_plaintext_rows_and_keeps_them(project):
    config, engine = project
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO accounts (email, plan) VALUES ('a@example.com', 'free')"))
    migration = generate(config, "encrypt email")
    assert body(migration, "upgrade")[0].startswith("op.execute('ALTER TABLE accounts ALTER COLUMN email")

    with pytest.raises(Exception) as raised:
        alembic_command.upgrade(config, "head")

    assert "invalid input syntax for type json" in str(raised.value)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT email, plan FROM accounts")).all() == [("a@example.com", "free")]


def test_postgresql_uses_each_index_for_its_search(project):
    config, engine = project
    generate(config, "encrypt accounts")
    alembic_command.upgrade(config, "head")
    import models

    from stackencrypt import Cipher

    accounts = Cipher(models.Account)
    searches = {
        "ix_accounts_email_eq": (
            "email = CAST(:term AS eql_v4.query_text_eq)",
            accounts.eq("email", "a@example.com"),
        ),
        "ix_accounts_level_ope": (
            "level >= CAST(:term AS eql_v4.query_integer_ord)",
            accounts.gte("level", 3),
        ),
        "ix_accounts_bio_match": (
            "bio @@ CAST(:term AS eql_v4.query_text_match)",
            accounts.matches("bio", "hello").term,
        ),
    }
    with engine.begin() as conn:
        # With no rows, PostgreSQL would read the table rather than an index.
        conn.execute(text("SET LOCAL enable_seqscan = off"))
        for index, (where, term) in searches.items():
            plan = conn.execute(
                text(f"EXPLAIN SELECT id FROM accounts WHERE {where}"), {"term": term}
            ).scalars().all()
            assert any(index in line for line in plan), (index, plan)
