"""Encryption for SQLAlchemy ORM models, with no SDK call in the app's code::

    from stackencrypt.sqlalchemy import configure_encryption

    engine = create_engine(DATABASE_URL)
    configure_encryption(engine, [Customer, Order])

After that, a flush encrypts the declared fields of the listed classes, and a
query decrypts them. The app reads and writes plaintext attributes.

- Writes: a ``before_execute`` hook on the engine. For each INSERT or UPDATE
  on a listed table, it encrypts the parameters of all the statement's rows
  with one ``Cipher.encrypt_rows`` call.
- Reads: the ``load`` and ``refresh`` events of each listed class record the
  objects a query builds. A ``do_orm_execute`` hook then decrypts them, with
  one ``Cipher.decrypt_rows`` call for each class and set of fields. The
  plaintext is set with ``set_committed_value``, so the objects are not
  marked as changed.

Only the sealed fields go through the hooks. A passthrough field is stored
as SQLAlchemy writes it.

- Indexes: a mapped class's table gets a database index for each EQL index
  of each encrypted column, such as ``hash (eql_v4.eq_term(email))`` for ``TextEq``.
  So ``create_all`` and Alembic's ``autogenerate`` create them.
- Migrations: two hooks for ``context.configure`` in Alembic's ``env.py``.
  ``render_item`` writes an ``EqlType`` into a migration file with its
  imports. ``process_revision_directives`` writes a change of an existing
  column to an EQL type as an ALTER with a USING cast.
- Search: the column type that ``eql_type_map`` gives each encrypted field
  turns ``==``, ``<``, ``<=``, ``>`` and ``>=`` into a comparison with a query
  term, made by ``Cipher.eq``, ``lt``, ``lte``, ``gt`` or ``gte``. Any other
  operator that would send a value raises ``QueryError`` when the query is
  built, because the value would reach the database as plaintext.

This module imports SQLAlchemy. The rest of the package does not.
"""

from typing import Annotated, Any, Callable, Dict, FrozenSet, List, Sequence, Tuple, Type

from sqlalchemy import Index, String, Table, cast, event, func, inspect, literal
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapper, Session
from sqlalchemy.orm.attributes import set_committed_value
from sqlalchemy.sql import operators
from sqlalchemy.sql.dml import Insert, Update
from sqlalchemy.types import UserDefinedType

from stackencrypt import _eql
from stackencrypt._cipher import Cipher
from stackencrypt._declaration import _KIND_TYPES
from stackencrypt._errors import DeclarationError, QueryError
from stackencrypt._markers import Marker, Passthrough

__all__ = [
    "EqlType",
    "configure_encryption",
    "eql_type_map",
    "process_revision_directives",
    "render_item",
]


class EqlType(UserDefinedType):  # type: ignore[type-arg]
    """The column type of an encrypted field: its marker's EQL type, such as
    ``public.eql_v4_text_eq`` for ``TextEq``. ``eql_type_map`` gives it to
    each field, so a model does not name it."""

    cache_ok = True

    def __init__(self, marker: Type[Marker]) -> None:
        self.marker = marker

    def get_col_spec(self, **kwargs: Any) -> str:
        return self.marker.sql_domain

    def __repr__(self) -> str:
        return f"EqlType({self.marker.__name__})"

    class comparator_factory(UserDefinedType.Comparator):  # type: ignore[type-arg]
        def operate(self, op: Any, *other: Any, **kwargs: Any) -> Any:
            if op in _NO_VALUE or (op is operators.eq and other == (None,)):
                return super().operate(op, *other, **kwargs)
            method = _COMPARISONS.get(op)
            if method is None or len(other) != 1:
                raise _refused(self.expr, op)
            return super().operate(op, _term(self.expr, method, other[0]), **kwargs)

        def reverse_operate(self, op: Any, other: Any, **kwargs: Any) -> Any:
            raise _refused(self.expr, op)


class _QueryType(UserDefinedType):  # type: ignore[type-arg]
    """The type a query term is cast to, such as ``eql_v4.query_text_eq``."""

    cache_ok = True

    def __init__(self, sql_name: str) -> None:
        self.sql_name = sql_name

    def get_col_spec(self, **kwargs: Any) -> str:
        return self.sql_name


# For a DeclarativeBase's `type_annotation_map`: every marker the decorator
# accepts, under the hint a model writes for it, such as
# Annotated[str, TextEq].
eql_type_map: Dict[Any, EqlType] = {
    Annotated[_KIND_TYPES[marker.plaintext], marker]: EqlType(marker)  # type: ignore[valid-type]
    for marker in _eql.TYPES
    if marker.producible and marker.plaintext in _KIND_TYPES
}

# The comparisons a query term answers, and the Cipher method that makes it.
_COMPARISONS: Dict[Any, str] = {
    operators.eq: "eq",
    operators.lt: "lt",
    operators.le: "lte",
    operators.gt: "gt",
    operators.ge: "gte",
}

# The operators that send no value to the database.
_NO_VALUE = frozenset(
    {
        operators.is_,
        operators.is_not,
        operators.asc_op,
        operators.desc_op,
        operators.nulls_first_op,
        operators.nulls_last_op,
    }
)

# The database index for each kind of EQL index: the EQL function the index
# is on, and the index method.
_INDEXES: Dict[str, Tuple[str, str]] = {
    "eq": ("eq_term", "hash"),
    "ope": ("ord_term", "btree"),
    "ore_block": ("ord_term_ore", "btree"),
    "match": ("match_term", "gin"),
}


@event.listens_for(Mapper, "instrument_class")
def _add_indexes(mapper: Any, cls: type) -> None:
    """Give a mapped class's table a database index for each EQL index of
    each ``EqlType`` column, named ``ix_<table>_<column>_<kind>``.

    It runs when SQLAlchemy maps the class, not when a column joins a table:
    Alembic's ``add_column`` puts the new column on a temporary table and
    creates every index of that table, so an index added there would be
    created twice."""
    table = mapper.local_table
    if not isinstance(table, Table):
        return
    for column in table.columns:
        if not isinstance(column.type, EqlType):
            continue
        for kind in column.type.marker.indexes:
            if kind not in _INDEXES:
                continue
            function, method = _INDEXES[kind]
            name = f"ix_{table.name}_{column.name}_{kind}"
            if any(index.name == name for index in table.indexes):
                continue
            Index(name, getattr(func.eql_v4, function)(column), postgresql_using=method)


def render_item(type_: str, obj: Any, autogen_context: Any) -> Any:
    """For Alembic's ``context.configure(render_item=render_item)`` in
    ``env.py``. Writes an ``EqlType`` column type into a migration as
    ``stackencrypt.sqlalchemy.EqlType(stackencrypt.TextEq)``, and adds the
    imports it needs. Returns ``False`` for anything else, so that Alembic
    writes it as usual."""
    if type_ == "type" and isinstance(obj, EqlType):
        autogen_context.imports.add("import stackencrypt")
        autogen_context.imports.add("import stackencrypt.sqlalchemy")
        return f"stackencrypt.sqlalchemy.EqlType(stackencrypt.{obj.marker.__name__})"
    return False


def process_revision_directives(context: Any, revision: Any, directives: List[Any]) -> None:
    """For Alembic's ``context.configure(process_revision_directives=...)``
    in ``env.py``. Rewrites each upgrade step that changes an existing
    column to an EQL type.

    Alembic writes that change as ``op.alter_column(..., type_=EqlType(...))``,
    and PostgreSQL refuses it: there is no cast from a column's old type to
    an EQL type. The step becomes ``op.execute`` of an ALTER with
    ``USING <column>::jsonb::<EQL type>``. That changes the type of a column
    with no rows. A column with rows that are not EQL values fails the
    migration, and keeps its rows. Any other change to the same column, such
    as to ``nullable``, is kept as Alembic wrote it.

    The downgrade steps are not changed.
    """
    from alembic.operations import ops

    preparer = context.dialect.identifier_preparer
    for script in directives:
        for container, rewrite in (
            (script.upgrade_ops, lambda step: _rewrite_type_change(ops, preparer, step)),
            (script.downgrade_ops, lambda step: [step]),
        ):
            kept = []
            for table_ops in container.ops:
                if isinstance(table_ops, ops.ModifyTableOps):
                    table_ops.ops = [
                        step
                        for operation in table_ops.ops
                        for unchanged in _drop_same_eql_type(ops, operation)
                        for step in rewrite(unchanged)
                    ]
                    if not table_ops.ops:
                        continue
                kept.append(table_ops)
            container.ops = kept


def _drop_same_eql_type(ops: Any, operation: Any) -> List[Any]:
    """Alembic compares a column's type as text: the database gives an EQL
    column's type as ``eql_v4_text_eq``, and ``EqlType`` as
    ``public.eql_v4_text_eq``. So it finds a change where there is none.
    Drop that type change, and the step if it changes nothing else."""
    if not isinstance(operation, ops.AlterColumnOp) or operation.modify_type is None:
        return [operation]
    if not _same_eql_type(operation.existing_type, operation.modify_type):
        return [operation]
    operation.modify_type = None
    return [operation] if operation.has_changes() else []


def _same_eql_type(a: Any, b: Any) -> bool:
    for eql, other in ((a, b), (b, a)):
        if isinstance(eql, EqlType):
            name = eql.marker.sql_domain.rsplit(".", 1)[-1]
            if isinstance(other, EqlType):
                return other.marker is eql.marker
            return getattr(other, "name", None) == name and getattr(other, "schema", None) in (
                None,
                "public",
            )
    return False


def _rewrite_type_change(ops: Any, preparer: Any, operation: Any) -> List[Any]:
    if not (
        isinstance(operation, ops.AlterColumnOp)
        and isinstance(operation.modify_type, EqlType)
        and not _is_eql(operation.existing_type)
    ):
        return [operation]
    table = preparer.quote(operation.table_name)
    if operation.schema:
        table = f"{preparer.quote_schema(operation.schema)}.{table}"
    column = preparer.quote(operation.column_name)
    domain = operation.modify_type.marker.sql_domain
    steps = [
        ops.ExecuteSQLOp(
            f"ALTER TABLE {table} ALTER COLUMN {column} TYPE {domain} "
            f"USING {column}::jsonb::{domain}"
        )
    ]
    operation.existing_type = operation.modify_type
    operation.modify_type = None
    if operation.has_changes():
        steps.append(operation)
    return steps


def _is_eql(column_type: Any) -> bool:
    """An EQL type, from the model or as the database gives it."""
    if isinstance(column_type, EqlType):
        return True
    return str(getattr(column_type, "name", "")).startswith("eql_v4_")


# The configured tables, for the comparisons: a Table to its cipher.
_TABLES: Dict[Table, Cipher] = {}

# The objects a load built or refreshed, and which attributes, waiting for
# the do_orm_execute hook. Kept in each session's `info`.
_PENDING = "stackencrypt_pending"

# Every class configured in this process, with its cipher and sealed fields.
_CONFIGURED: Dict[type, Tuple[Cipher, FrozenSet[str]]] = {}


def configure_encryption(engine: Engine, classes: Sequence[type]) -> None:
    """Encrypt and decrypt the declared fields of ``classes`` when the ORM
    writes them through ``engine`` and reads them in any session.

    Each class must be declared with ``stackencrypt.model`` and mapped by
    SQLAlchemy. Its declared table must be its ``__tablename__``, and each
    sealed field's column must have the field's name. A class can be
    configured once in a process.

    Every class is checked first. A class that fails raises
    ``DeclarationError``, and none of the classes is configured. The check
    makes no request.
    """
    checked = [_check(cls) for cls in classes]
    for cls, _, _ in checked:
        if cls in _CONFIGURED:
            raise DeclarationError(
                "declaration_already_configured",
                f"{cls.__qualname__} is configured for encryption already. "
                "Configure each class once, with every engine it writes through.",
            )
    if len({cls for cls, _, _ in checked}) != len(checked):
        raise DeclarationError(
            "declaration_already_configured",
            "the list names a class more than once.",
        )
    tables: Dict[str, Tuple[Cipher, FrozenSet[str]]] = {}
    for cls, cipher, sealed in checked:
        _CONFIGURED[cls] = (cipher, sealed)
        _TABLES[inspect(cls).local_table] = cipher
        tables[cipher.declaration.table] = (cipher, sealed)
        event.listen(cls, "load", _remember_load)
        event.listen(cls, "refresh", _remember_refresh)
    event.listen(engine, "before_execute", _encrypter(tables), retval=True)
    if not event.contains(Session, "do_orm_execute", _decrypt_loaded):
        event.listen(Session, "do_orm_execute", _decrypt_loaded)


def _check(cls: type) -> Tuple[type, Cipher, FrozenSet[str]]:
    cipher = Cipher(cls)  # refuses a class that is not declared
    mapper = inspect(cls, raiseerr=False) if isinstance(cls, type) else None
    if mapper is None or not hasattr(mapper, "columns"):
        raise DeclarationError(
            "declaration_not_mapped",
            f"{cls.__qualname__} is not mapped by SQLAlchemy. configure_encryption "
            "takes ORM classes. Use Cipher directly for other classes.",
        )
    table = cipher.declaration.table
    mapped = getattr(mapper.local_table, "name", None)
    if mapped != table:
        raise DeclarationError(
            "declaration_table_mismatch",
            f"{cls.__qualname__} is declared for table {table!r}, but SQLAlchemy "
            f"maps it to {mapped!r}. Use the same name in stackencrypt.model and "
            "__tablename__.",
        )
    sealed = frozenset(
        field.name for field in cipher.declaration.fields if field.marker is not Passthrough
    )
    for name in sorted(sealed):
        column = mapper.columns.get(name)
        if column is None or column.name != name or column.key != name:
            found = None if column is None else column.name
            raise DeclarationError(
                "declaration_column_name",
                f"field {name!r} of {cls.__qualname__} is stored in column {found!r}. "
                "configure_encryption needs each encrypted field's column to have "
                "the field's name.",
                field=name,
            )
    for field in cipher.declaration.fields:
        if field.marker is Passthrough:
            continue
        column_type = mapper.columns[field.name].type
        if not (isinstance(column_type, EqlType) and column_type.marker is field.marker):
            raise DeclarationError(
                "declaration_column_type",
                f"field {field.name!r} of {cls.__qualname__} is declared "
                f"{field.marker.__name__}, so its column must be "
                f"{field.marker.sql_domain}, but SQLAlchemy maps it as {column_type!r}. "
                "Set `type_annotation_map = eql_type_map` on the declarative base, "
                "and give the column no type of its own.",
                field=field.name,
            )
    return cls, cipher, sealed


def _encrypter(tables: Dict[str, Tuple[Cipher, FrozenSet[str]]]) -> Any:
    def encrypt_parameters(conn, clause, multiparams, params, execution_options):  # type: ignore[no-untyped-def]
        if not isinstance(clause, (Insert, Update)):
            return clause, multiparams, params
        configured = tables.get(getattr(clause.table, "name", None))
        if configured is None:
            return clause, multiparams, params
        cipher, sealed = configured
        rows = [dict(row) for row in multiparams] if multiparams else [dict(params or {})]
        _refuse_inline_values(conn, clause, sealed, rows)
        names = sealed.intersection(rows[0])
        if not names:
            return clause, multiparams, params
        encrypted = cipher.encrypt_rows([{name: row[name] for name in names} for row in rows])
        for row, values in zip(rows, encrypted):
            row.update(values)
        if multiparams:
            return clause, rows, params
        return clause, multiparams, rows[0]

    return encrypt_parameters


def _refuse_inline_values(conn, clause, sealed: FrozenSet[str], rows: List[Dict[str, Any]]) -> None:  # type: ignore[no-untyped-def]
    """Refuse a statement that carries a sealed value in its SQL, such as
    ``insert(table).values(email=...)``: the hook can only change the
    parameters passed beside the statement, so the value would be stored
    as plaintext."""
    inline = clause.compile(dialect=conn.dialect).params
    for name in sorted(sealed):
        if inline.get(name) is not None and not any(name in row for row in rows):
            raise DeclarationError(
                "declaration_inline_value",
                f"the statement writes {name!r} of table {clause.table.name!r} as a value "
                "inside the SQL, so it cannot be encrypted. Pass the values as "
                "parameters, as session.add and session.execute(insert(...), rows) do.",
                field=name,
            )


def _remember_load(target: object, context: object) -> None:
    _remember(target, None)


def _remember_refresh(target: object, context: object, attrs: Any) -> None:
    _remember(target, attrs)


def _remember(target: object, attrs: Any) -> None:
    session = Session.object_session(target)
    if session is not None:
        names = None if attrs is None else frozenset(attrs)
        session.info.setdefault(_PENDING, []).append((target, names))


def _decrypt_loaded(state: Any) -> Any:
    if not state.is_select:
        return None
    # Freezing reads every row, so every load and refresh event has fired.
    result = state.invoke_statement().freeze()
    pending = state.session.info.pop(_PENDING, [])
    groups: Dict[Tuple[type, FrozenSet[str]], List[object]] = {}
    for target, names in pending:
        cipher, sealed = _CONFIGURED[type(target)]
        loaded = target.__dict__
        fields = frozenset(
            name
            for name in (sealed if names is None else sealed.intersection(names))
            if loaded.get(name) is not None
        )
        if fields:
            groups.setdefault((type(target), fields), []).append(target)
    for (cls, fields), targets in groups.items():
        cipher, _ = _CONFIGURED[cls]
        opened = cipher.decrypt_rows(
            [{name: target.__dict__[name] for name in fields} for target in targets]
        )
        for target, values in zip(targets, opened):
            for name, value in values.items():
                set_committed_value(target, name, value)
    return result()


def _term(column: Any, method: str, value: object) -> Any:
    """``value`` as the query term that ``method`` makes for ``column``,
    cast to the column marker's query type."""
    cipher = _TABLES.get(getattr(column, "table", None))
    if cipher is None:
        raise QueryError(
            "query_not_configured",
            f"column {_column_name(column)} is encrypted, but its class is not configured. "
            "Call configure_encryption with the class before you build a query on it.",
        )
    term = getattr(cipher, method)(column.key, value)
    return cast(literal(term, String()), _QueryType(column.type.marker.query_sql_domain))


def _refused(column: Any, op: Callable[..., Any]) -> QueryError:
    name = getattr(op, "__name__", repr(op)).removesuffix("_op")
    return QueryError(
        "query_unsupported",
        f"{name} is not supported on the encrypted column {_column_name(column)}. "
        "It would send the value to the database as plaintext. Use ==, <, <=, >, or >= "
        "where the column's marker supports it.",
        field=getattr(column, "key", None),
        reason=name,
    )


def _column_name(column: Any) -> str:
    table = getattr(getattr(column, "table", None), "name", "?")
    return f"{table}.{getattr(column, 'name', '?')}"
