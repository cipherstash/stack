"""The database indexes and the Alembic migration code that
``stackencrypt.sqlalchemy`` gives an encrypted column, with no database.

``test_sqlalchemy_live.py`` runs a generated migration against PostgreSQL.
"""

import datetime
from typing import Annotated

import pytest
from alembic.autogenerate import render_python_code
from alembic.operations import ops
from alembic.autogenerate.api import AutogenContext
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Column, Index, Integer, MetaData, String, Table, Text, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.schema import CreateIndex

import stackencrypt
from stackencrypt import Ignore, IntegerOrd, Passthrough, TextEq, TextSearch, _eql
from stackencrypt.sqlalchemy import (
    EqlType,
    eql_type_map,
    process_revision_directives,
    render_item,
)

# The index each kind of EQL index needs, as PostgreSQL prints it.
INDEX_SQL = {
    "eq": "USING hash (eql_v4.eq_term({col}))",
    "ope": "USING btree (eql_v4.ord_term({col}))",
    "ore_block": "USING btree (eql_v4.ord_term_ore({col}))",
    "match": "USING gin (eql_v4.match_term({col}))",
}


class Base(DeclarativeBase):
    type_annotation_map = eql_type_map


@stackencrypt.model("people")
class Person(Base):
    __tablename__ = "people"
    id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
    email: Mapped[Annotated[str, TextEq]]
    bio: Mapped[Annotated[str, TextSearch]]
    level: Mapped[Annotated[int, IntegerOrd]]
    plan: Mapped[Annotated[str, Passthrough]]


def index_sql(index):
    return " ".join(str(CreateIndex(index).compile(dialect=postgresql.dialect())).split())


@pytest.mark.parametrize(
    "marker",
    [m for m in _eql.TYPES if m.producible and m.plaintext in ("string", "int32", "date")],
    ids=lambda m: m.__name__,
)
def test_each_eql_index_of_a_marker_gets_its_database_index(marker):
    python_type = {"string": str, "int32": int, "date": datetime.date}[marker.plaintext]
    cls = type(
        f"T{marker.__name__}",
        (Base,),
        {
            "__tablename__": f"t_{marker.__name__.lower()}",
            "__annotations__": {
                "id": Mapped[int],
                "v": Mapped[Annotated[python_type, marker]],
            },
            "id": mapped_column(primary_key=True),
        },
    )
    table = cls.__table__.name

    made = {index.name: index_sql(index) for index in cls.__table__.indexes}

    assert made == {
        f"ix_{table}_v_{kind}": f"CREATE INDEX ix_{table}_v_{kind} ON {table} "
        + INDEX_SQL[kind].format(col="v")
        for kind in marker.indexes
    }


def test_an_index_the_model_declares_on_the_same_term_replaces_the_sdk_index():
    @stackencrypt.model("members")
    class Member(Base):
        __tablename__ = "members"
        # Unique, so a btree: PostgreSQL cannot make a hash index unique.
        __table_args__ = (Index("members_email_unique", text("eql_v4.eq_term(email)"), unique=True),)
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextSearch]]

    assert sorted(index.name for index in Member.__table__.indexes) == [
        "ix_members_email_match",
        "ix_members_email_ope",
        "members_email_unique",
    ]


def test_an_index_on_another_column_does_not_replace_the_sdk_index():
    @stackencrypt.model("guests")
    class Guest(Base):
        __tablename__ = "guests"
        __table_args__ = (Index("guests_name_eq", text("eql_v4.eq_term(name)")),)
        id: Mapped[Annotated[int, Ignore]] = mapped_column(primary_key=True)
        email: Mapped[Annotated[str, TextEq]]
        name: Mapped[Annotated[str, TextEq]]

    assert sorted(index.name for index in Guest.__table__.indexes) == [
        "guests_name_eq",
        "ix_guests_email_eq",
    ]


def test_a_table_that_is_not_mapped_gets_no_index():
    # As Alembic's add_column builds one: its indexes would be created twice.
    table = Table("t", MetaData(), Column("id", Integer, primary_key=True), Column("v", EqlType(TextEq)))

    assert table.indexes == set()


def test_a_model_gets_one_index_for_each_eql_index_of_each_encrypted_field():
    assert sorted(index.name for index in Person.__table__.indexes) == [
        "ix_people_bio_eq",
        "ix_people_bio_match",
        "ix_people_bio_ope",
        "ix_people_email_eq",
        "ix_people_level_ope",
    ]


def migration_code(*operations):
    context = MigrationContext.configure(dialect_name="postgresql")
    return render_python_code(
        ops.UpgradeOps(ops=list(operations)), render_item=render_item, migration_context=context
    )


def test_a_generated_migration_names_the_eql_type_by_its_module():
    code = migration_code(ops.CreateTableOp.from_table(Person.__table__))

    assert "stackencrypt.sqlalchemy.EqlType(stackencrypt.TextEq)" in code
    assert "stackencrypt.sqlalchemy.EqlType(stackencrypt.IntegerOrd)" in code


def test_render_item_adds_the_imports_the_type_needs():
    autogen = AutogenContext(MigrationContext.configure(dialect_name="postgresql"))

    render_item("type", EqlType(TextEq), autogen)

    assert {"import stackencrypt", "import stackencrypt.sqlalchemy"} <= autogen.imports


def test_render_item_names_a_marker_the_package_does_not_export_by_its_module(monkeypatch):
    # A marker the engine cannot produce stays in _eql only. The catalog has
    # none now, so Json stands in for one.
    monkeypatch.delattr(stackencrypt, "Json", raising=False)
    autogen = AutogenContext(MigrationContext.configure(dialect_name="postgresql"))

    rendered = render_item("type", EqlType(_eql.Json), autogen)

    assert rendered == "stackencrypt.sqlalchemy.EqlType(stackencrypt._eql.Json)"
    namespace = {}
    exec("import stackencrypt\nimport stackencrypt.sqlalchemy\nt = " + rendered, namespace)
    assert namespace["t"].marker is _eql.Json


def test_render_item_leaves_other_items_to_alembic():
    autogen = AutogenContext(MigrationContext.configure(dialect_name="postgresql"))

    assert render_item("type", Integer(), autogen) is False
    assert autogen.imports == set()


def test_a_generated_migration_creates_the_indexes():
    index = next(i for i in Person.__table__.indexes if i.name == "ix_people_email_eq")

    code = migration_code(ops.CreateIndexOp.from_index(index))

    assert "op.create_index('ix_people_email_eq', 'people'" in code
    assert "eql_v4.eq_term(email)" in code
    assert "postgresql_using='hash'" in code


def test_the_generated_code_runs_with_those_imports():
    code = migration_code(ops.CreateTableOp.from_table(Person.__table__))
    calls = []
    namespace = {"op": type("Op", (), {"create_table": staticmethod(lambda *a, **k: calls.append(a))})}
    exec("import sqlalchemy as sa\nimport stackencrypt\nimport stackencrypt.sqlalchemy\n", namespace)

    exec("def upgrade():\n" + code + "\nupgrade()\n", namespace)

    [(name, *columns)] = calls
    assert name == "people"
    email = next(c for c in columns if getattr(c, "name", None) == "email")
    assert email.type.marker is TextEq


# process_revision_directives: a type change to an EQL type.


def script_with(*operations):
    return ops.MigrationScript(
        rev_id="1",
        upgrade_ops=ops.UpgradeOps(ops=[ops.ModifyTableOps("accounts", list(operations))]),
        downgrade_ops=ops.DowngradeOps(ops=[]),
    )


def rewrite(*operations):
    script = script_with(*operations)
    context = MigrationContext.configure(dialect_name="postgresql")
    process_revision_directives(context, ("head",), [script])
    return script.upgrade_ops.ops[0].ops


def test_a_type_change_to_an_eql_type_becomes_an_alter_with_a_using_cast():
    [statement] = rewrite(
        ops.AlterColumnOp("accounts", "email", existing_type=Text(), modify_type=EqlType(TextEq))
    )

    assert isinstance(statement, ops.ExecuteSQLOp)
    assert statement.sqltext == (
        "ALTER TABLE accounts ALTER COLUMN email TYPE public.eql_v4_text_eq "
        "USING email::jsonb::public.eql_v4_text_eq"
    )


def test_the_table_schema_and_quoted_names_are_kept():
    script = ops.MigrationScript(
        rev_id="1",
        upgrade_ops=ops.UpgradeOps(
            ops=[
                ops.ModifyTableOps(
                    "Accounts",
                    [
                        ops.AlterColumnOp(
                            "Accounts",
                            "Email",
                            schema="app",
                            existing_type=Text(),
                            modify_type=EqlType(TextEq),
                        )
                    ],
                    schema="app",
                )
            ]
        ),
        downgrade_ops=ops.DowngradeOps(ops=[]),
    )
    process_revision_directives(MigrationContext.configure(dialect_name="postgresql"), ("head",), [script])

    [statement] = script.upgrade_ops.ops[0].ops
    assert statement.sqltext == (
        'ALTER TABLE app."Accounts" ALTER COLUMN "Email" TYPE public.eql_v4_text_eq '
        'USING "Email"::jsonb::public.eql_v4_text_eq'
    )


def test_other_changes_of_the_same_column_are_kept():
    statement, alter = rewrite(
        ops.AlterColumnOp(
            "accounts",
            "email",
            existing_type=Text(),
            modify_type=EqlType(TextEq),
            existing_nullable=True,
            modify_nullable=False,
        )
    )

    assert isinstance(statement, ops.ExecuteSQLOp)
    assert alter.modify_type is None
    assert alter.modify_nullable is False


def test_a_type_change_to_another_type_is_left_to_alembic():
    alter = ops.AlterColumnOp("accounts", "plan", existing_type=Text(), modify_type=String())

    assert rewrite(alter) == [alter]


def test_the_rewritten_migration_renders_as_op_execute():
    script = script_with(
        ops.AlterColumnOp("accounts", "email", existing_type=Text(), modify_type=EqlType(TextEq))
    )
    process_revision_directives(MigrationContext.configure(dialect_name="postgresql"), ("head",), [script])

    code = render_python_code(script.upgrade_ops, render_item=render_item)

    assert "op.execute('ALTER TABLE accounts ALTER COLUMN email TYPE public.eql_v4_text_eq" in code
    assert "alter_column" not in code


def test_a_type_change_between_the_same_eql_type_is_dropped_in_both_directions():
    # As the database gives the type of an EQL column back to Alembic.
    reflected = postgresql.DOMAIN("eql_v4_text_eq", JSONB(), create_type=False)
    script = ops.MigrationScript(
        rev_id="1",
        upgrade_ops=ops.UpgradeOps(
            ops=[
                ops.ModifyTableOps(
                    "accounts",
                    [ops.AlterColumnOp("accounts", "email", existing_type=reflected, modify_type=EqlType(TextEq))],
                )
            ]
        ),
        downgrade_ops=ops.DowngradeOps(
            ops=[
                ops.ModifyTableOps(
                    "accounts",
                    [ops.AlterColumnOp("accounts", "email", existing_type=EqlType(TextEq), modify_type=reflected)],
                )
            ]
        ),
    )

    process_revision_directives(MigrationContext.configure(dialect_name="postgresql"), ("head",), [script])

    assert script.upgrade_ops.is_empty()
    assert script.downgrade_ops.is_empty()


def test_a_change_to_another_eql_type_is_kept():
    reflected = postgresql.DOMAIN("eql_v4_text", JSONB(), create_type=False)
    alter = ops.AlterColumnOp("accounts", "email", existing_type=reflected, modify_type=EqlType(TextEq))

    assert rewrite(alter) == [alter]
