"""``Cipher``: encrypts and decrypts the instances of one declared class.

It checks the class and the credentials, and builds the model's plan once.
``encrypt``, ``decrypt`` and ``query`` are here.
"""

from typing import Dict, Generic, List, Mapping, Sequence, Type, TypeVar

from stackencrypt import _engine
from stackencrypt._markers import Passthrough
from stackencrypt._declaration import Declaration, check_unchanged, declaration_of
from stackencrypt._errors import AuthenticationError, DeclarationError, QueryError


T = TypeVar("T")


class Cipher(Generic[T]):
    """The cipher for one class declared with ``stackencrypt.model``::

        users = stackencrypt.Cipher(User)

    The class must be declared itself: a subclass of a declared class is not.
    The class must also be as it was when declared. The credentials come from
    ``CS_CLIENT_ACCESS_KEY`` and ``CS_WORKSPACE_CRN``, or from the profile
    that ``stash auth login`` writes. Building a cipher makes no request.

    Every cipher in the process shares one engine client. It is built on the
    first ``encrypt`` or ``decrypt`` of any cipher, which loads the default
    keyset once.
    """

    def __init__(self, cls: Type[T]) -> None:
        # The type check comes first: declaration_of reads the class's own
        # __dict__, and a string or an instance with __slots__ has none.
        declaration = declaration_of(cls) if isinstance(cls, type) else None
        if declaration is None:
            raise _not_decorated(cls)
        check_unchanged(cls, declaration)
        refused = _engine.detect_credentials()
        if refused is not None:
            code, message, field, reason = refused
            raise AuthenticationError(code, message, field=field, reason=reason)
        self._cls = cls
        self._declaration = declaration
        self._plan = _engine.build_plan(
            declaration.table,
            [
                (
                    field.name,
                    None if field.marker is Passthrough else field.marker.name,
                    None if field.marker is Passthrough else field.marker.plaintext,
                    field.value_type,
                )
                for field in declaration.fields
            ],
        )

    def encrypt(self, models: Sequence[object]) -> List[Dict[str, object]]:
        """Encrypt ``models``, instances of the declared class.

        Returns one dict per model, from column name to column value: the
        EQL JSON as a ``str`` for a sealed field, which psycopg inserts with
        a plain ``%s``, and the value itself for a passthrough field. An
        ``Ignore`` field is left out.

        Every value is checked first, by exact type and range. A value that
        does not fit raises ``InvalidValueError`` naming the field, and no
        request is made. An empty list makes no request at all.
        """
        return _engine.encrypt(self._plan, list(models))

    def decrypt(self, rows: Sequence[Mapping[str, object]]) -> List[T]:
        """Decrypt ``rows`` into instances of the declared class.

        Each row is a mapping from column name to value, such as a row that
        psycopg's ``dict_row`` returns. A sealed column's value is the EQL
        JSON as a ``str``, as UTF-8 ``bytes``, or as a parsed ``dict``.
        Columns the class does not declare are ignored. Every declared
        field's column must be in every row, passthrough columns included.
        An ``Ignore`` field is not passed to the constructor.

        Every row is checked first. A row that is not a mapping, a missing
        column, a value that is not EQL JSON, or a value stored under
        another table or column raises ``DecryptError`` naming the field,
        and no request is made. A passthrough value of another type than the
        field's raises ``InvalidValueError``; it is never converted. The
        call is all or nothing: no instance is built when any row fails.
        """
        return _engine.decrypt(self._plan, self._cls, list(rows))

    def query(self, field: str, value: object) -> str:
        """The equality query term for ``value`` on the declared field
        ``field``, named as a ``str``::

            term = users.query("email", "a@example.com")
            cur.execute(
                "SELECT * FROM users WHERE email = %s::eql_v4.query_text_eq",
                (term,),
            )

        The term is a ``str``. The SQL casts it to the field marker's
        ``query_sql_domain``. A term is derived from the keyset already
        loaded: after the shared client is built, ``query`` makes no request.

        A name that is not a declared field raises ``QueryError``
        (``query_unknown_field``). A field whose marker answers no query,
        such as ``Text`` or ``Passthrough``, raises ``QueryError``
        (``query_unsupported``). The value is checked as ``encrypt`` checks
        it, and a value that does not fit raises ``InvalidValueError``. All
        three are raised before any request.
        """
        declared = next(
            (f for f in self._declaration.fields if f.name == field), None
        )
        if declared is None:
            raise QueryError(
                "query_unknown_field",
                f"{field!r} is not a declared field of "
                f"{self._cls.__qualname__!r}. {self._queryable()}",
                field=field if isinstance(field, str) else None,
            )
        if declared.marker is Passthrough or declared.marker.query is None:
            # Passthrough names no EQL type, so it has no `name` attribute.
            marker = declared.marker.__name__
            raise QueryError(
                "query_unsupported",
                f"field {field!r} is declared {marker}, which answers no "
                f"query. {self._queryable()}",
                field=field,
                reason=marker,
            )
        return _engine.query(self._plan, field, value)

    def _queryable(self) -> str:
        names = [
            repr(f.name)
            for f in self._declaration.fields
            if f.marker is not Passthrough and f.marker.query is not None
        ]
        if not names:
            return "The class has no field with a query."
        return "Fields with a query: " + ", ".join(names) + "."

    @property
    def declaration(self) -> Declaration:
        """What the decorator read from the class."""
        return self._declaration

    def __repr__(self) -> str:
        return f"Cipher({self._cls.__qualname__})"


def _not_decorated(cls: object) -> DeclarationError:
    if not isinstance(cls, type):
        return DeclarationError(
            "declaration_not_decorated",
            f"Cipher takes a class declared with stackencrypt.model, not {cls!r}.",
        )
    declared = next((b for b in cls.__mro__[1:] if declaration_of(b)), None)
    if declared is not None:
        detail = (
            f"It is a subclass of {declared.__name__!r}, and a subclass is not "
            "declared by its base."
        )
    else:
        detail = "It has no stackencrypt.model decorator."
    return DeclarationError(
        "declaration_not_decorated",
        f"class {cls.__name__!r} is not declared. {detail} Apply "
        f'@stackencrypt.model("...") to {cls.__name__!r} itself.',
    )
