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

This module imports SQLAlchemy. The rest of the package does not.
"""

from typing import Any, Dict, FrozenSet, List, Sequence, Tuple, Type

from sqlalchemy import event, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value
from sqlalchemy.sql.dml import Insert, Update

from stackencrypt._cipher import Cipher
from stackencrypt._errors import DeclarationError
from stackencrypt._markers import Passthrough

__all__ = ["configure_encryption"]

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
