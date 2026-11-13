"""Encryption for SQLAlchemy ORM models, with no SDK call in the app's code::

    from stackencrypt.sqlalchemy import configure_encryption

    configure_encryption([Customer, Order])

After that, a flush encrypts the declared fields of the listed classes, and a
query decrypts them. The app reads and writes plaintext attributes.

- Writes: a ``before_execute`` hook on SQLAlchemy's ``Engine`` class, so
  every engine runs it. For each INSERT or UPDATE on the Table object of a
  listed class, it encrypts the parameters of all the statement's rows with
  one ``Cipher.encrypt_rows`` call.
- Reads: the ``load`` and ``refresh`` events of each listed class, and of
  its single-table subclasses, record the objects a query builds. A
  ``do_orm_execute`` hook then decrypts them, with one
  ``Cipher.decrypt_rows`` call for each class and set of fields in each
  chunk of rows the ORM builds: one chunk for ``.all()``, one for each
  ``yield_per`` batch. The plaintext is set with ``set_committed_value``,
  so the objects are not marked as changed.

On a write, every declared field goes through ``encrypt_rows``, so a
passthrough value is checked as ``encrypt`` checks it, and stored unchanged.
On a read, only the encrypted fields are decrypted.

- Indexes: a mapped class's table gets a database index for each EQL index
  of each encrypted column, such as ``hash (eql_v4.eq_term(email))`` for ``TextEq``.
  So ``create_all`` and Alembic's ``autogenerate`` create them.
- Migrations: two hooks for ``context.configure`` in Alembic's ``env.py``.
  ``render_item`` writes an ``EqlType`` into a migration file with its
  imports. ``process_revision_directives`` writes a change of an existing
  column to an EQL type as an ALTER with a USING cast.
- Match: ``.match(text)`` on a field with a match index is ``col @@ term``.
  The session hook runs ``verify`` on the rows and removes those that fail.
  It works only in a session's select, with whole objects of the class in
  the result. The match must be a condition of the WHERE joined with AND,
  or a branch of an ``or_`` of match searches only. Anything else raises
  ``QueryError``. A LIMIT can return fewer rows than it names.
- Sorting: ``order_by`` on an encrypted column sorts by its order term, such
  as ``eql_v4.ord_term(col)``, in both hooks. A bare ``ORDER BY col`` on an
  EQL v4 column sorts the stored JSON, in a wrong order (ADR-0004, decision
  9). A column with no order index cannot be sorted. A bare encrypted
  column in an ORDER BY the hooks do not rewrite, such as a window's or a
  UNION's, raises ``QueryError``.
- Search: the column type that ``eql_type_map`` gives each encrypted field
  turns ``==``, ``<``, ``<=``, ``>`` and ``>=`` into a comparison with a query
  term, made by ``Cipher.eq``, ``lt``, ``lte``, ``gt`` or ``gte``. Any other
  operator that would send a value raises ``QueryError`` when the query is
  built, because the value would reach the database as plaintext.

This module imports SQLAlchemy. The rest of the package does not.
"""

import hashlib
import itertools
from typing import Annotated, Any, Callable, Dict, FrozenSet, List, Optional, Sequence, Tuple, Type

from sqlalchemy import (
    Index,
    PrimaryKeyConstraint,
    String,
    Table,
    UniqueConstraint,
    cast,
    event,
    false,
    func,
    inspect,
    literal,
    not_,
    or_,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Engine, Row
from sqlalchemy.orm import Mapper, Session
from sqlalchemy.orm.attributes import set_committed_value
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.elements import (
    BindParameter,
    BooleanClauseList,
    ClauseElement,
    ColumnClause,
    Grouping,
    Label,
    _anonymous_label,
    _label_reference,
    _textual_label_reference,
)
from sqlalchemy.sql.dml import Insert, Update
from sqlalchemy.sql.functions import FunctionElement
from sqlalchemy.sql.selectable import CompoundSelect, Select
from sqlalchemy.types import UserDefinedType

import stackencrypt
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
            if op in _SORTS:
                # Sorted by the order term: EQL v4 gives its column types no
                # sort order of their own (see _sort_key).
                return getattr(_sort_key(self.expr), _SORTS[op])()
            # `is None`: `other == (None,)` would compare a SQL expression,
            # which has no truth value.
            if op in _NO_VALUE or (
                op in (operators.eq, operators.ne) and len(other) == 1 and other[0] is None
            ):
                return super().operate(op, *other, **kwargs)
            if (op in _COMPARISONS or op is operators.ne) and len(other) == 1:
                expression = other[0]
                if hasattr(expression, "__clause_element__"):  # an ORM attribute
                    expression = expression.__clause_element__()
                if isinstance(expression, ClauseElement):
                    # A SQL expression that holds a Python value, such as
                    # literal("x") or func.lower("x"), would send it to the
                    # database as plaintext.
                    if any(isinstance(e, BindParameter) for e in visitors.iterate(expression)):
                        raise _refused(self.expr, op)
                    # Another column: no value is sent. SQLAlchemy also
                    # compares columns this way when it copies a statement.
                    return super().operate(op, expression, **kwargs)
            if op is operators.ne and len(other) == 1:
                # NOT (col = term): a NULL column matches neither, as with !=.
                return not_(self.operate(operators.eq, other[0]))
            if op in (operators.in_op, operators.not_in_op) and len(other) == 1:
                values = other[0]
                if not isinstance(values, (list, tuple, set, frozenset)):
                    raise _refused(self.expr, op)
                # One equality term for each value. An empty list matches no row.
                found = or_(false(), *[self.operate(operators.eq, value) for value in values])
                return found if op is operators.in_op else not_(found)
            if op is operators.match_op and len(other) == 1:
                query = _cipher_of(self.expr).matches(self.expr.key, other[0])
                term = cast(
                    literal(query.term, String()),
                    _QueryType(self.expr.type.marker.query_sql_domain),
                )
                found = super().operate(_MATCHES, term)
                # The session hook finds the search by this annotation, to
                # check where it is and to verify the rows.
                return found._annotate({_MATCH: (self.expr, query)})
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
# Annotated[str, TextEq], and Annotated[Optional[str], TextEq] for a field
# that can be missing: SQLAlchemy looks up the whole hint, and makes the
# column nullable for the Optional one.
eql_type_map: Dict[Any, EqlType] = {
    hint: EqlType(marker)
    for marker in _eql.TYPES
    if marker.producible and marker.plaintext in _KIND_TYPES
    for hint in (
        Annotated[_KIND_TYPES[marker.plaintext], marker],  # type: ignore[valid-type]
        Annotated[Optional[_KIND_TYPES[marker.plaintext]], marker],  # type: ignore[valid-type]
    )
}

# The comparisons a query term answers, and the Cipher method that makes it.
_COMPARISONS: Dict[Any, str] = {
    operators.eq: "eq",
    operators.lt: "lt",
    operators.le: "lte",
    operators.gt: "gt",
    operators.ge: "gte",
}

# A match search: `col @@ term`, and the annotation that marks it.
_MATCHES = operators.custom_op("@@", is_comparison=True)
_MATCH = "stackencrypt_match"

# The execution option the session hook sets on a statement whose match
# searches it checked and verifies.
_VERIFIED = "stackencrypt_match_verified"

# The execution option the session hook sets on a select it has checked and
# sorted, so that the engine hook does not walk it again.
_SCANNED = "stackencrypt_scanned"

# The operators that send no value to the database.
_NO_VALUE = frozenset({operators.is_, operators.is_not})

# The sort operators, and the method that applies each to a sort key.
_SORTS = {
    operators.asc_op: "asc",
    operators.desc_op: "desc",
    operators.nulls_first_op: "nulls_first",
    operators.nulls_last_op: "nulls_last",
}

# The order term for each kind of order index.
_ORDER_TERMS = {"ope": "ord_term", "ore_block": "ord_term_ore"}

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
    declared = {_index_term(expression) for index in table.indexes for expression in index.expressions}
    for column in table.columns:
        if not isinstance(column.type, EqlType):
            continue
        for kind in column.type.marker.indexes:
            if kind not in _INDEXES:
                continue
            function, method = _INDEXES[kind]
            name = _index_name(f"ix_{table.name}_{column.name}_{kind}")
            if any(index.name == name for index in table.indexes):
                continue
            # The model declares an index on this term itself, such as a
            # unique btree on eq_term: that one serves the search. Compared
            # as _index_term writes it: with no quotes, in lower case.
            if f"eql_v4.{function}({column.name})".lower() in declared:
                continue
            Index(name, getattr(func.eql_v4, function)(column), postgresql_using=method)


# PostgreSQL's longest identifier, in bytes.
_MAX_NAME = 63


def _index_name(name: str) -> str:
    """``name``, or, when PostgreSQL would refuse it as too long, its start
    and a short hash of the whole of it, so that two long names still
    differ."""
    if len(name.encode()) <= _MAX_NAME:
        return name
    digest = hashlib.sha256(name.encode()).hexdigest()[:8]
    start = name.encode()[: _MAX_NAME - len(digest) - 1].decode(errors="ignore")
    return f"{start}_{digest}"


def _index_term(expression: Any) -> str:
    """An index expression as SQL, with no spaces or quotes, such as
    ``eql_v4.eq_term(email)``."""
    try:
        sql = str(expression.compile(dialect=postgresql.dialect()))
    except Exception:  # an expression only its own dialect compiles
        return ""
    return "".join(sql.split()).replace('"', "").lower()


def render_item(type_: str, obj: Any, autogen_context: Any) -> Any:
    """For Alembic's ``context.configure(render_item=render_item)`` in
    ``env.py``. Writes an ``EqlType`` column type into a migration as
    ``stackencrypt.sqlalchemy.EqlType(stackencrypt.TextEq)``, and adds the
    imports it needs. Returns ``False`` for anything else, so that Alembic
    writes it as usual."""
    if type_ == "type" and isinstance(obj, EqlType):
        autogen_context.imports.add("import stackencrypt")
        autogen_context.imports.add("import stackencrypt.sqlalchemy")
        name = obj.marker.__name__
        # A marker the package does not export, such as Json, is in _eql.
        module = "stackencrypt" if hasattr(stackencrypt, name) else "stackencrypt._eql"
        return f"stackencrypt.sqlalchemy.EqlType({module}.{name})"
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

# The configured tables, by their Table object: the class configured for each.
_TABLE_CLASSES: Dict[Table, type] = {}

# The objects a load built or refreshed, and which attributes, waiting for
# the do_orm_execute hook. Kept in each session's `info`.
_PENDING = "stackencrypt_pending"

# Every class configured in this process, with its cipher and sealed fields.
_CONFIGURED: Dict[type, Tuple[Cipher, FrozenSet[str]]] = {}


def configure_encryption(classes: Sequence[type]) -> None:
    """Encrypt and decrypt the declared fields of ``classes`` when the ORM
    writes them through any engine, and reads them in any session.

    Each class must be declared with ``stackencrypt.model`` and mapped by
    SQLAlchemy. Its declared table must be its ``__tablename__``, and each
    sealed field's column must have the field's name.

    The hooks are installed once in a process, on SQLAlchemy's ``Engine``
    and ``Session`` classes, so every engine gets them, including one made
    later, such as a test's. A write is encrypted when its table is the
    ``Table`` object of a configured class.

    A repeat call for a class that is already configured does nothing.
    It still raises ``DeclarationError`` when the class changed since it
    was declared, or when another class is configured for its table.

    A subclass that SQLAlchemy maps to its base's table, by single-table
    inheritance, is encrypted and decrypted as its base is. It needs no
    declaration of its own, and listing it with its base, or after it, does
    nothing.

    Every class is checked first. A class that fails raises
    ``DeclarationError``, and none of the classes is configured. The check
    makes no request.
    """
    listed = set(classes)
    checked = [
        _check(cls)  # refuses a changed class too
        for cls in classes
        if _covering_class(cls, listed) is None
    ]
    owners = dict(_TABLE_CLASSES)
    new = []
    for cls, cipher, sealed in checked:
        table = inspect(cls).local_table
        owner = owners.get(table)
        if owner is not None and owner is not cls:
            raise DeclarationError(
                "declaration_already_configured",
                f"{cls.__qualname__} maps table {table.name!r}, and "
                f"{owner.__qualname__} is configured for that table already. "
                "Configure one class for each table.",
            )
        if owner is None:
            owners[table] = cls
            new.append((cls, cipher, sealed, table))
    for cls, cipher, sealed, table in new:
        _CONFIGURED[cls] = (cipher, sealed)
        _TABLES[table] = cipher
        _TABLE_CLASSES[table] = cls
        # propagate: a single-table subclass's objects are loaded as its own.
        event.listen(cls, "load", _remember_load, propagate=True)
        event.listen(cls, "refresh", _remember_refresh, propagate=True)
    if not event.contains(Engine, "before_execute", _encrypt_parameters):
        event.listen(Engine, "before_execute", _encrypt_parameters, retval=True)
    if not event.contains(Session, "do_orm_execute", _decrypt_loaded):
        event.listen(Session, "do_orm_execute", _decrypt_loaded)


def _covering_class(cls: type, listed: Any = ()) -> Optional[type]:
    """The configured or listed base class whose table ``cls`` is mapped to,
    by single-table inheritance, or ``None``."""
    mapper = inspect(cls, raiseerr=False) if isinstance(cls, type) else None
    table = getattr(mapper, "local_table", None)
    for base in cls.__mro__[1:] if isinstance(cls, type) else ():
        if base in _CONFIGURED or base in listed:
            base_mapper = inspect(base, raiseerr=False)
            if table is not None and getattr(base_mapper, "local_table", None) is table:
                return base
    return None


def _configured_for(cls: type) -> Tuple[Cipher, FrozenSet[str]]:
    """The cipher and sealed fields of ``cls``, or of the configured base
    that a single-table subclass is mapped as."""
    for base in cls.__mro__:
        if base in _CONFIGURED:
            return _CONFIGURED[base]
    raise KeyError(cls)


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
        column = mapper.columns[field.name]
        table = mapper.local_table
        unique = (
            column.unique
            or column.primary_key
            or any(
                # contains_column, not `in`: a column collection takes only
                # a string key with `in`, and raises ArgumentError for a
                # Column. A primary key is a unique constraint too.
                isinstance(constraint, (UniqueConstraint, PrimaryKeyConstraint))
                and constraint.columns.contains_column(column)
                for constraint in table.constraints
            )
            # An index on the column itself, not on a term of it.
            or any(
                index.unique and any(expression is column for expression in index.expressions)
                for index in table.indexes
            )
        )
        if unique:
            raise DeclarationError(
                "declaration_unique_column",
                f"field {field.name!r} of {cls.__qualname__} is an encrypted column in a "
                "primary key, or with a unique constraint or index. Each EQL value contains "
                "new random ciphertext, so the database never finds a duplicate. Use a "
                "unique index on its equality term instead: "
                f"Index(..., text(\"eql_v4.eq_term({field.name})\"), unique=True) in "
                "__table_args__.",
                field=field.name,
            )
        column_type = column.type
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


def _encrypt_parameters(conn, clause, multiparams, params, execution_options):  # type: ignore[no-untyped-def]
    """The write hook, on SQLAlchemy's ``Engine`` class: every engine runs it."""
    if execution_options.get(_SCANNED):
        # A select the session hook checked and sorted already.
        return clause, multiparams, params
    matches, sorted_ = _scan(clause)
    if matches and not execution_options.get(_VERIFIED):
        column, _ = matches[0]._annotations[_MATCH]
        raise _match_refused(column, "is not run through a session.")
    if isinstance(clause, (Select, CompoundSelect)):
        # Every select, ORM-marked or not. SQLAlchemy marks a select as
        # ORM when it names a mapped class or attribute, even when it
        # runs on a connection, where the session hook does not run.
        return (_sorted_by_terms(clause) if sorted_ else clause), multiparams, params
    if not isinstance(clause, (Insert, Update)):
        return clause, multiparams, params
    cls = _configured_class(clause.table)
    if cls is None:
        return clause, multiparams, params
    cipher, sealed = _CONFIGURED[cls]
    rows = [dict(row) for row in multiparams] if multiparams else [dict(params or {})]
    _refuse_inline_values(clause, sealed, rows)
    # Passthrough fields too: encrypt_rows checks them as encrypt does,
    # and returns them unchanged.
    names = _declared(cipher).intersection(rows[0])
    if not names:
        return clause, multiparams, params
    encrypted = cipher.encrypt_rows([{name: row[name] for name in names} for row in rows])
    for row, values in zip(rows, encrypted):
        row.update(values)
    if multiparams:
        return clause, rows, params
    return clause, multiparams, rows[0]


def _configured_class(table: Any) -> Any:
    """The class configured for ``table``, found by its Table object, not
    its name: another database's table of the same name is not encrypted.
    An ORM statement can carry an annotated copy of the Table, so the copy
    is also looked up as its original."""
    found = _TABLE_CLASSES.get(table)
    if found is None and hasattr(table, "_deannotate"):
        found = _TABLE_CLASSES.get(table._deannotate())
    return found


def _declared(cipher: Cipher) -> FrozenSet[str]:
    return frozenset(field.name for field in cipher.declaration.fields)


def _refuse_inline_values(clause: Any, sealed: FrozenSet[str], rows: List[Dict[str, Any]]) -> None:
    """Refuse a statement that carries a sealed value in its own SQL, in any
    form: ``values(email=...)``, a list of rows in ``values([...])``, a SQL
    expression that holds a value, such as ``func.lower(...)`` or ``case``,
    a ``bindparam`` of another name, or the SET of an ON CONFLICT. The hook
    encrypts only the parameters passed beside the statement under the
    field's own name, so any other value would be stored as plaintext.

    The statement's values are read as it holds them, not compiled: a
    compile here would run outside SQLAlchemy's compiled cache."""
    for name, value, own_name in _written_values(clause):
        if name not in sealed:
            continue
        overridden = own_name and any(name in row for row in rows)
        if not overridden and _sends_value(value, name if own_name else None):
            raise DeclarationError(
                "declaration_inline_value",
                f"the statement writes {name!r} of table {clause.table.name!r} as a value "
                "inside the SQL, so it cannot be encrypted. Pass the values as "
                "parameters, as session.add and session.execute(insert(...), rows) do.",
                field=name,
            )


def _written_values(clause: Any) -> List[Tuple[str, Any, bool]]:
    """Each value the statement holds itself, as its column's name, the value,
    and whether the parameter of the field's own name sets it: that is true
    of ``values(...)`` with one row, whose parameter takes the column's name,
    and of nothing else."""
    found: List[Tuple[str, Any, bool]] = []
    columns = list(clause.table.columns)

    def name_of(key: Any) -> str:
        return key if isinstance(key, str) else getattr(key, "key", str(key))

    for key, value in (getattr(clause, "_values", None) or {}).items():
        found.append((name_of(key), value, True))
    for key, value in getattr(clause, "_ordered_values", None) or ():
        found.append((name_of(key), value, True))
    for rows in getattr(clause, "_multi_values", None) or ():
        for row in rows:
            items = row.items() if isinstance(row, dict) else zip(columns, row)
            for key, value in items:
                found.append((name_of(key), value, False))
    # The SET of an ON CONFLICT DO UPDATE, on PostgreSQL and SQLite.
    on_conflict = getattr(clause, "_post_values_clause", None)
    sets = getattr(on_conflict, "update_values_to_set", None) or {}
    for key, value in sets.items() if isinstance(sets, dict) else sets:
        found.append((name_of(key), value, False))
    return found


def _sends_value(value: Any, own_name: Optional[str]) -> bool:
    """Whether ``value`` puts a Python value into the SQL. A NULL does not,
    and neither does a column, such as ``excluded.email``. Where the
    field's own parameter sets the value, ``own_name`` is the field's name,
    and ``bindparam(own_name)`` takes that parameter, which the hook
    encrypts."""
    if not isinstance(value, ClauseElement):
        return value is not None
    for element in visitors.iterate(value):
        if not isinstance(element, BindParameter):
            continue
        if element.callable is not None or element.value is not None:
            return True
        # A placeholder of its own name would take a parameter the hook
        # does not encrypt. An anonymous one is a NULL.
        if not isinstance(element.key, _anonymous_label) and not (element is value and element.key == own_name):
            return True
    return False


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
    matches, sorted_ = _scan(state.statement)
    if matches and not state.is_select:
        column, _ = matches[0]._annotations[_MATCH]
        raise _match_refused(column, "is in an UPDATE or a DELETE, so it would change rows that do not hold the text.")
    if not state.is_select:
        return None
    searches = _checked_matches(state.statement, matches)
    if sorted_:
        state.statement = _sorted_by_terms(state.statement)
    # The engine hook need not scan the statement again.
    options: Dict[str, Any] = {_SCANNED: True}
    if searches:
        options[_VERIFIED] = True
    result = state.invoke_statement(execution_options=options)
    positions = _encrypted_columns(state.statement)
    chunks = getattr(result, "chunks", None)
    if chunks is None:
        # Not the ORM's own result, such as one another hook made: read it
        # whole.
        frozen = result.freeze()
        rows = _opened(state.session, positions, searches, list(frozen.data))
        return frozen.with_new_rows([_as_tuple(row) for row in rows])()

    # The ORM builds the rows a chunk at a time, as the app reads them: all
    # of them for .all(), and yield_per's number under yield_per. Each
    # chunk's objects are decrypted when the chunk is built, after their
    # load events have fired and before the app sees them. Uniqueness, and
    # SQLAlchemy's refusal of a joined eager load with no .unique(), still
    # apply to the rows as the ORM gives them.
    def opened_chunks(size: Optional[int]) -> Any:
        for rows in chunks(size):
            yield _opened(state.session, positions, searches, list(rows))

    result.chunks = opened_chunks
    result.iterator = itertools.chain.from_iterable(opened_chunks(result._yield_per))
    return result


def _as_tuple(row: Any) -> Any:
    return row if isinstance(row, (tuple, Row)) else (row,)


def _opened(session: Any, positions: Dict[Cipher, Dict[int, str]], searches: List[Any], rows: List[Any]) -> List[Any]:
    """``rows`` with the objects loaded for them decrypted, the encrypted
    result columns decrypted, and the rows that fail a match search
    removed."""
    pending = session.info.pop(_PENDING, [])
    groups: Dict[Tuple[type, FrozenSet[str]], List[object]] = {}
    for target, names in pending:
        cipher, sealed = _configured_for(type(target))
        loaded = target.__dict__
        fields = frozenset(
            name
            for name in (sealed if names is None else sealed.intersection(names))
            if loaded.get(name) is not None
        )
        if fields:
            groups.setdefault((type(target), fields), []).append(target)
    for (cls, fields), targets in groups.items():
        cipher, _ = _configured_for(cls)
        opened = cipher.decrypt_rows(
            [{name: target.__dict__[name] for name in fields} for target in targets]
        )
        for target, values in zip(targets, opened):
            for name, value in values.items():
                set_committed_value(target, name, value)
    if positions:
        rows = _decrypt_columns(positions, rows)
    if searches:
        rows = _verify(searches, rows)
    return rows


# A match search the hook verifies: the result position of its class's
# objects, the field, and the MatchQuery.
_Search = Tuple[int, str, Any]
# A condition of the WHERE, joined to the others with AND: an OR of
# branches, each an AND of searches. A plain match is one branch of one.
_Condition = List[List[_Search]]


def _checked_matches(statement: Any, matches: List[Any]) -> List[_Condition]:
    """The match searches of ``statement``, as conditions the hook can
    verify. Raises ``QueryError`` for a search whose rows cannot be
    verified.

    A search can be verified when it is a condition of the WHERE joined
    with AND, or a branch of an ``or_`` whose branches are all match
    searches or ``and_`` of them. A row that passes ``verify`` always
    passes ``@@``, so the database returns every row such an ``or_``
    keeps, and ``verify`` on each branch removes the rest."""
    if not matches:
        return []
    descriptions = statement.column_descriptions
    placed: Dict[int, _Search] = {}

    def search(match: Any) -> _Search:
        column, query = match._annotations[_MATCH]
        cls = next((c for c, (cipher, _) in _CONFIGURED.items() if cipher is _cipher_of(column)), None)
        at = next(
            (
                i
                for i, description in enumerate(descriptions)
                # A single-table subclass's objects are its base's too.
                if isinstance(description.get("type"), type)
                and cls is not None
                and issubclass(description["type"], cls)
                and description.get("expr") is description.get("type")
            ),
            None,
        )
        if at is None:
            raise _match_refused(column, "has no whole objects of its class in the result.")
        placed[id(match)] = (at, column.key, query)
        return placed[id(match)]

    conditions: List[_Condition] = []
    # The conditions as the app passed them to where(), with each and_()
    # opened. `whereclause` would join copies of them.
    for condition in _joined(list(getattr(statement, "_where_criteria", ()) or [statement.whereclause]), operators.and_):
        if _is_match(condition):
            conditions.append([[search(condition)]])
            continue
        branches = _joined([condition], operators.or_) if _is_bool(condition, operators.or_) else None
        if branches is None:
            continue
        ands = [_joined([branch], operators.and_) for branch in branches]
        if all(part and all(_is_match(match) for match in part) for part in ands):
            conditions.append([[search(match) for match in part] for part in ands])
    for match in matches:
        if id(match) not in placed:
            column, _ = match._annotations[_MATCH]
            raise _match_refused(
                column,
                "is not a condition of the WHERE joined with AND, or a branch of an or_ "
                "of match searches only.",
            )
    return conditions


def _ungrouped(element: Any) -> Any:
    while isinstance(element, Grouping):
        element = element.element
    return element


def _is_bool(element: Any, operator: Any) -> bool:
    return isinstance(element, BooleanClauseList) and element.operator is operator


def _is_match(element: Any) -> bool:
    return _MATCH in getattr(element, "_annotations", {})


def _joined(elements: List[Any], operator: Any) -> List[Any]:
    """``elements`` with each group removed, and each clause list of
    ``operator`` opened into its clauses, at any depth."""
    out = []
    pending = list(reversed(elements))
    while pending:
        element = _ungrouped(pending.pop())
        if _is_bool(element, operator):
            pending.extend(reversed(list(element.clauses)))
        else:
            out.append(element)
    return out


def _item(row: Any, at: int) -> Any:
    """Item ``at`` of a frozen row. A result of one object, as from
    ``select(Customer)``, keeps the object itself, not a one-item row."""
    return row[at] if isinstance(row, (tuple, Row)) else row


def _verify(conditions: List[_Condition], rows: List[Any]) -> List[Any]:
    """Keep the rows that pass every condition: for each, at least one
    branch whose match searches all pass ``verify``. A field that is NULL
    fails its search, and so does an object an outer join leaves out."""
    passed: Dict[int, List[bool]] = {}

    def results(search: _Search) -> List[bool]:
        if id(search) not in passed:
            at, field, query = search
            # An outer join gives None for a missing object. Its search fails,
            # as for a NULL value.
            values = [getattr(_item(row, at), field, None) for row in rows]
            present = [i for i, value in enumerate(values) if value is not None]
            ok = [False] * len(rows)
            for i, verified in zip(present, query.verify([values[i] for i in present])):
                ok[i] = verified
            passed[id(search)] = ok
        return passed[id(search)]

    keep = [
        all(
            any(all(results(search)[i] for search in branch) for branch in condition)
            for condition in conditions
        )
        for i in range(len(rows))
    ]
    return [row for row, kept in zip(rows, keep) if kept]


def _encrypted_columns(statement: Any) -> Dict[Cipher, Dict[int, str]]:
    """The result columns of ``statement`` that are encrypted fields, such
    as ``email`` in ``select(Customer.email, Customer.plan)``: their
    positions and field names, by cipher. A column of a whole object, as in
    ``select(Customer)``, is left to the load events."""
    positions: Dict[Cipher, Dict[int, str]] = {}
    for at, description in enumerate(getattr(statement, "column_descriptions", None) or ()):
        column = _column_of(description.get("expr"))
        if column is None or not isinstance(column.type, EqlType):
            continue
        cipher = _TABLES.get(getattr(column, "table", None))
        if cipher is not None:
            positions.setdefault(cipher, {})[at] = column.key
    return positions


def _decrypt_columns(positions: Dict[Cipher, Dict[int, str]], rows: List[Any]) -> List[Any]:
    """``rows`` with the encrypted columns at ``positions`` decrypted: with
    one ``decrypt_rows`` call for each class and set of fields that are not
    NULL. A row of one column, as from ``select(Customer.email)``, is the
    value itself."""
    single = bool(rows) and not isinstance(rows[0], (tuple, Row))
    lists = [[row] if single else list(row) for row in rows]
    for cipher, fields in positions.items():
        groups: Dict[FrozenSet[int], List[List[Any]]] = {}
        for row in lists:
            present = frozenset(at for at in fields if row[at] is not None)
            if present:
                groups.setdefault(present, []).append(row)
        for present, members in groups.items():
            opened = cipher.decrypt_rows(
                [{fields[at]: row[at] for at in present} for row in members]
            )
            for row, values in zip(members, opened):
                for at in present:
                    row[at] = values[fields[at]]
    return [row[0] if single else tuple(row) for row in lists]


def _column_of(expression: Any) -> Any:
    """The table column behind a result column: through an ORM attribute's
    clause element, and through a label."""
    if hasattr(expression, "__clause_element__"):
        expression = expression.__clause_element__()
    while hasattr(expression, "element") and not isinstance(getattr(expression, "table", None), Table):
        expression = expression.element
    return expression if isinstance(getattr(expression, "table", None), Table) else None


def _term(column: Any, method: str, value: object) -> Any:
    """``value`` as the query term that ``method`` makes for ``column``,
    cast to the column marker's query type."""
    term = getattr(_cipher_of(column), method)(column.key, value)
    return cast(literal(term, String()), _QueryType(column.type.marker.query_sql_domain))


def _sort_key(column: Any) -> Any:
    """What to sort an encrypted column by: its order term, such as
    ``eql_v4.ord_term(col)``. Raises ``QueryError`` for a column with no
    order index.

    A bare ``ORDER BY col`` sorts EQL v4 values in a wrong order, with no
    error: the EQL column types have no sort order of their own, so
    PostgreSQL sorts the stored JSON. The order term sorts by the
    plaintext, and the index on it serves the sort."""
    function = next(
        (_ORDER_TERMS[kind] for kind in column.type.marker.indexes if kind in _ORDER_TERMS), None
    )
    if function is None:
        raise QueryError(
            "query_unsupported",
            f"the encrypted column {_column_name(column)} has no order index, so it cannot "
            f"be sorted. Its marker, {column.type.marker.__name__}, has the indexes "
            f"{list(column.type.marker.indexes)}. Use a marker with an order index, such as "
            "IntegerOrd or TextOrd.",
            field=getattr(column, "key", None),
            reason="order",
        )
    return getattr(func.eql_v4, function)(column)


def _sorted_by_terms(statement: Any) -> Any:
    """``statement`` with each encrypted column in an ORDER BY replaced by
    its order term, in every select of it, subqueries included. A bare
    ``order_by(col)``, or ``sqlalchemy.asc(col)``, does not go through the
    column type's operators, so the hooks rewrite it here. The statement is
    copied only when an ORDER BY changes."""
    if not any(
        _select_sort_keys(element) is not element._order_by_clauses
        for element in visitors.iterate(statement)
        if isinstance(element, Select) and element._order_by_clauses
    ):
        return statement

    def visit_select(select: Any) -> None:
        # On the copy that cloned_traverse made, as SQLAlchemy's own
        # generative methods change it.
        if select._order_by_clauses:
            select._order_by_clauses = _select_sort_keys(select)

    return visitors.cloned_traverse(statement, {}, {"select": visit_select})


# The elements with an ORDER BY of their own that the hooks do not rewrite:
# a window, WITHIN GROUP, and an aggregate's ORDER BY.
_OWN_ORDER_BY = frozenset({"over", "withingroup", "aggregateorderby", "aggregate_order_by"})


def _scan(statement: Any) -> Tuple[List[Any], bool]:
    """One walk of ``statement``: its match searches, and whether any select
    in it has an ORDER BY for ``_sorted_by_terms`` to look at. Raises
    ``QueryError`` for an encrypted column sorted where the hooks cannot
    sort it by its order term."""
    matches = []
    sorted_ = False
    for element in visitors.iterate(statement):
        if _MATCH in getattr(element, "_annotations", {}):
            matches.append(element)
        if isinstance(element, Select) and element._order_by_clauses:
            sorted_ = True
        elif isinstance(element, CompoundSelect) and element._order_by_clauses:
            _refuse_compound_sort(element)
        elif getattr(element, "__visit_name__", None) in _OWN_ORDER_BY:
            column = _bare_eql_column(getattr(element, "order_by", None))
            if column is not None:
                raise _sort_refused(
                    column,
                    "in a window, WITHIN GROUP, or an aggregate's ORDER BY. Sort it by "
                    "its order term: pass Model.field.asc() or .desc() instead.",
                )
    return matches, sorted_


def _refuse_compound_sort(compound: Any) -> None:
    """A UNION's ORDER BY names its result columns, so it cannot sort by an
    order term. Refuse an encrypted column there, named or by a string."""
    named = {}
    if compound.selects:
        named = dict(compound.selects[0].selected_columns.items())
    for clause in compound._order_by_clauses:
        column = _bare_eql_column(clause)
        if column is None:
            for element in visitors.iterate(clause):
                if isinstance(element, (_label_reference, _textual_label_reference)):
                    name = element.element
                    found = named.get(name) if isinstance(name, str) else None
                    if _is_eql_column(found):
                        column = found
        if column is not None:
            raise _sort_refused(
                column,
                "in the ORDER BY of a UNION, or another compound select. That ORDER BY "
                "sorts the result columns, so it cannot sort by the order term. Sort "
                "each select, or select the order term as a column and sort by it.",
            )


def _bare_eql_column(clause: Any) -> Any:
    """An encrypted column in ``clause`` that is not inside an order term,
    or ``None``."""
    pending = [clause] if clause is not None else []
    while pending:
        element = pending.pop()
        if isinstance(element, FunctionElement) and getattr(element, "name", None) in _ORDER_TERMS.values():
            continue
        if _is_eql_column(element):
            return element
        pending.extend(element.get_children())
    return None


def _sort_refused(column: Any, where: str) -> QueryError:
    return QueryError(
        "query_unsupported",
        f"the encrypted column {_column_name(column)} is sorted {where} A bare sort of an "
        "EQL column sorts the stored JSON, in a wrong order.",
        field=getattr(column, "key", None),
        reason="order",
    )


def _select_sort_keys(select: Any) -> Any:
    """The ORDER BY of ``select`` with each encrypted column replaced by its
    order term; the same object when nothing changes. A label or a name in
    the ORDER BY, as in ``order_by(col.label("x"))``, ``order_by("x")`` or
    ``order_by(desc("level"))``, would sort by the selected column, so it is
    replaced by the order term of the column it names."""
    clauses = select._order_by_clauses
    # What a string in the ORDER BY names, as SQLAlchemy matches it when it
    # compiles the statement: a label's name first, then a selected
    # column's key, then a column of a FROM table. Every candidate is kept,
    # plaintext ones included, so that a plaintext label hides an encrypted
    # column of the same name. Only a name that resolves to an encrypted
    # column is rewritten. A name that two FROM tables share, with an
    # encrypted column among them, cannot be told apart, so it is refused.
    named: Dict[str, Any] = {}
    candidates: Dict[str, List[Any]] = {}
    for table in select.get_final_froms():
        for column in getattr(table, "c", ()):
            named[column.key] = column
            candidates.setdefault(column.key, []).append(column)
    shared = {
        name
        for name, columns in candidates.items()
        if len({id(c) for c in columns}) > 1 and any(_is_eql_column(c) for c in columns)
    }
    for key, column in select.selected_columns.items():
        named[key] = column
        shared.discard(key)
    for column in getattr(select, "_raw_columns", ()):
        if isinstance(column, Label):
            named[column.name] = column.element
            shared.discard(column.name)

    def replace(element: Any) -> Any:
        if isinstance(element, FunctionElement) and getattr(element, "name", None) in _ORDER_TERMS.values():
            return element  # already a sort key: not opened again
        if isinstance(element, (_label_reference, _textual_label_reference)):
            name = element.element
            if isinstance(name, str) and name in shared:
                raise QueryError(
                    "query_unsupported",
                    f"order_by({name!r}) names an encrypted column of more than one table "
                    "in the query, so the SDK cannot sort by its order term. Pass the "
                    "column itself, such as order_by(Model.field).",
                    reason="order",
                )
            column = named.get(name) if isinstance(name, str) else _labelled_column(name)
            return _sort_key(column) if _is_eql_column(column) else None
        column = _labelled_column(element)
        if column is not None:
            return _sort_key(column)
        # Any column of an EQL type: of a table, an alias, or a subquery.
        if _is_eql_column(element):
            return _sort_key(element)
        return None

    rewritten = tuple(visitors.replacement_traverse(clause, {}, replace) for clause in clauses)
    return clauses if all(new is old for new, old in zip(rewritten, clauses)) else rewritten


def _is_eql_column(element: Any) -> bool:
    return isinstance(element, ColumnClause) and isinstance(element.type, EqlType)


def _labelled_column(element: Any) -> Any:
    """The encrypted column inside a label, or ``None``."""
    if isinstance(element, Label) and _is_eql_column(element.element):
        return element.element
    return None


def _cipher_of(column: Any) -> Cipher:
    cipher = _TABLES.get(getattr(column, "table", None))
    if cipher is None:
        raise QueryError(
            "query_not_configured",
            f"column {_column_name(column)} is encrypted, but its class is not configured. "
            "Call configure_encryption with the class before you build a query on it.",
        )
    return cipher


def _match_refused(column: Any, why: str) -> QueryError:
    return QueryError(
        "query_unsupported",
        f"a match search on {_column_name(column)} {why} A match index can return rows "
        "that do not hold the text, and the SDK removes them after the query. It can do "
        "that only in a select run through a session, with the match as a condition of "
        "the WHERE, joined with AND, and with whole objects of the class in the result.",
        field=getattr(column, "key", None),
        reason="match",
    )


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
