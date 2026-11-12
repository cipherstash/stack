"""``Cipher``: encrypts and decrypts the instances of one declared class.

It checks the class and the credentials, and builds the model's plan once.
``encrypt``, ``decrypt`` and the query methods are here.
"""

from types import SimpleNamespace
from typing import (
    Dict,
    FrozenSet,
    Generic,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
)

from stackencrypt import _engine
from stackencrypt._markers import Passthrough
from stackencrypt._declaration import (
    Declaration,
    DeclaredField,
    check_unchanged,
    declaration_of,
)
from stackencrypt._errors import (
    AuthenticationError,
    DeclarationError,
    DecryptError,
    InvalidValueError,
    QueryError,
    StashError,
)


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

    A process that ``os.fork`` made, as Gunicorn's workers are, cannot use a
    client its parent built: the first ``encrypt``, ``decrypt`` or query
    call must come after the fork. A call in such a child raises
    ``StashError`` with the code ``stack_forked``. A fork before the first
    call is fine: each child builds its own client. With Gunicorn, do not
    use ``--preload``. With ``multiprocessing``, use the ``spawn`` start
    method.
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
        self._plan = _build_plan(declaration, declaration.fields)
        self._planned = frozenset(field.name for field in declaration.fields)
        # encrypt_rows's plans, one for each set of fields it has seen. Two
        # threads may build the same plan at once; either one is kept.
        self._row_plans: Dict[FrozenSet[str], object] = {}

    def encrypt(self, models: Sequence[T]) -> List[Dict[str, object]]:
        """Encrypt ``models``, instances of the declared class.

        Returns one dict per model, from column name to column value: the
        EQL JSON as a ``str`` for a sealed field, which psycopg inserts with
        a plain ``%s``, and the value itself for a passthrough field. An
        ``Ignore`` field is left out.

        Every value is checked first, by exact type and range. A value that
        does not fit raises ``InvalidValueError`` naming the field, and no
        request is made. A model that is not an instance of the declared
        class raises ``InvalidValueError`` with the code
        ``value_wrong_type``. An empty list makes no request at all.
        """
        models = list(models)
        for at, model in enumerate(models):
            # The engine reads each field by name, so a model of another
            # class with the same field names would be encrypted under this
            # table.
            if not isinstance(model, self._cls):
                raise InvalidValueError(
                    "value_wrong_type",
                    f"model {at} is a {type(model).__name__}, not a "
                    f"{self._cls.__name__}. Encrypt only instances of the "
                    "declared class.",
                )
        return _engine.encrypt(self._plan, models)

    def encrypt_rows(self, rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
        """Encrypt ``rows``, mappings from field name to value, that may
        hold only some of the declared fields::

            users.encrypt_rows([{"email": "a@example.com", "users_id": 1}])

        Returns one new dict per row. Each declared field's value is
        replaced as ``encrypt`` writes it: EQL JSON as a ``str`` for a
        sealed field, and the value itself for a passthrough field. Every
        other key, such as an ``Ignore`` field or a key that SQLAlchemy adds
        for a ``WHERE``, is kept unchanged.

        Every row must hold the same declared fields, so that one call
        sends one batch of key requests. Rows that hold none are returned
        unchanged with no request.

        Every value is checked first, as ``encrypt`` checks it. A row that
        is not a mapping, or that holds other declared fields than row 0,
        raises ``InvalidValueError`` with the code ``value_row_shape``. No
        request is made when any row fails. The input rows are not changed.
        """
        rows = _rows(rows, InvalidValueError, "value_row_shape")
        names = self._row_fields(rows, InvalidValueError, "value_row_shape", "Encrypt")
        if not names:
            return [dict(row) for row in rows]
        sealed = _engine.encrypt(
            self._row_plan(names),
            [SimpleNamespace(**{name: row[name] for name in names}) for row in rows],
        )
        return [{**row, **columns} for row, columns in zip(rows, sealed)]

    def decrypt_rows(self, rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
        """Decrypt ``rows``, mappings from field name to stored value, that
        may hold only some of the declared fields::

            users.decrypt_rows([{"email": '{"c": ...}', "id": 1}])

        The reverse of ``encrypt_rows``. Returns one new dict per row. Each
        declared field's value is replaced with its plaintext. A sealed
        value may be EQL JSON as a ``str``, as UTF-8 ``bytes``, or as a
        parsed ``dict``. Every other key is kept unchanged.

        Every row must hold the same declared fields, so that one call
        sends one batch of key requests. Rows that hold none are returned
        unchanged with no request.

        Every row is checked first, as ``decrypt`` checks it, with the same
        errors. A row that is not a mapping, or that holds other declared
        fields than row 0, raises ``DecryptError`` with the code
        ``decrypt_row_shape``. No request is made when any row fails.
        """
        rows = _rows(rows, DecryptError, "decrypt_row_shape")
        names = self._row_fields(rows, DecryptError, "decrypt_row_shape", "Decrypt")
        if not names:
            return [dict(row) for row in rows]
        opened = _engine.decrypt(
            self._row_plan(names), dict, [{name: row[name] for name in names} for row in rows]
        )
        return [{**row, **values} for row, values in zip(rows, opened)]

    def _row_fields(
        self, rows: List[Mapping[str, object]], error: Type[StashError], code: str, verb: str
    ) -> FrozenSet[str]:
        """The declared fields every row holds. Raises ``error`` with
        ``code`` for a row that is not a mapping, or that holds other
        declared fields than row 0."""
        names: Optional[FrozenSet[str]] = None
        for at, row in enumerate(rows):
            if not isinstance(row, Mapping):
                raise error(
                    code,
                    f"row {at} is a {type(row).__name__}, not a mapping of field names to values.",
                )
            these = frozenset(name for name in row if name in self._planned)
            if names is None:
                names = these
            elif these != names:
                raise error(
                    code,
                    f"row {at} holds other declared fields than row 0. "
                    f"Row 0 holds {sorted(names)}; row {at} holds {sorted(these)}. "
                    f"{verb} rows with different fields in separate calls.",
                )
        return names or frozenset()

    def _row_plan(self, names: FrozenSet[str]) -> object:
        """The plan for the declared fields ``names``, in declaration order."""
        plan = self._row_plans.get(names)
        if plan is None:
            fields = [field for field in self._declaration.fields if field.name in names]
            plan = self._row_plans[names] = _build_plan(self._declaration, fields)
        return plan

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

        It returns one instance for each row, in the order of the rows.

        Each of these errors names the row. Two errors from the engine name
        the field only, not the row: ``decrypt_malformed`` for a value that
        is not the field's EQL type, and ``decrypt_kind_mismatch`` for a
        value sealed as another type.
        """
        return _engine.decrypt(
            self._plan, self._cls, _rows(rows, DecryptError, "decrypt_row_shape")
        )

    def eq(self, field: str, value: object) -> str:
        """The equality query term for ``value`` on the declared field
        ``field``, named as a ``str``::

            term = users.eq("email", "a@example.com")
            cur.execute(
                "SELECT * FROM users WHERE email = %s::eql_v4.query_text_eq",
                (term,),
            )

        The term is a ``str``. The SQL casts it to the field marker's
        ``query_sql_domain``. A term is derived from the keyset already
        loaded: after the shared client is built, a query method makes no
        request.

        A name that is not a declared field raises ``QueryError``
        (``query_unknown_field``). A field that does not support the
        operator raises ``QueryError`` (``query_unsupported``). Examples for
        ``eq`` are ``Text``, ``Passthrough``, ``IntegerOrd`` and
        ``TextMatch``. The value is checked as ``encrypt`` checks it, and a
        value that does not fit raises ``InvalidValueError``. All three are
        raised before any request. ``lt``, ``lte``, ``gt`` and ``gte`` work
        the same way.
        """
        return self._term("eq", field, value)

    def lt(self, field: str, value: object) -> str:
        """The query term for "less than ``value``" on ``field``::

            term = users.lt("level", 3)
            cur.execute(
                "SELECT * FROM users WHERE level < %s::eql_v4.query_integer_ord",
                (term,),
            )

        The field's marker needs an order index, such as ``IntegerOrd``.
        The errors are those of ``eq``.
        """
        return self._term("lt", field, value)

    def lte(self, field: str, value: object) -> str:
        """The query term for "less than or equal to ``value``" on
        ``field``. SQL: ``<=``. See ``lt``."""
        return self._term("lte", field, value)

    def gt(self, field: str, value: object) -> str:
        """The query term for "greater than ``value``" on ``field``. SQL:
        ``>``. See ``lt``."""
        return self._term("gt", field, value)

    def gte(self, field: str, value: object) -> str:
        """The query term for "greater than or equal to ``value``" on
        ``field``. SQL: ``>=``. See ``lt``."""
        return self._term("gte", field, value)

    def matches(self, field: str, text: str) -> "MatchQuery":
        """A match search for ``text`` on the field ``field``, whose marker
        has a match index, such as ``TextMatch``::

            q = users.matches("notes", "ali")
            limit = q.target_limit(10, rows=row_count, histogram=histogram)
            cur.execute(
                "SELECT ... WHERE notes @@ %s::eql_v4.query_text_match LIMIT %s",
                (q.term, limit),
            )
            people = users.decrypt(cur.fetchall())
            keep = q.verify([p.notes for p in people])

        A match search can return rows that do not hold the text. Decrypt
        the rows, then keep those ``verify`` reports ``True``.

        The returned object keeps ``text``, because ``verify`` needs it.
        Python cannot wipe a ``str``, so the text stays in memory until
        Python frees it. ``repr`` never shows it. The errors are those of
        ``eq``.
        """
        return MatchQuery(self, field, text, self._term("matches", field, text))

    def _term(self, op: str, field: str, value: object) -> str:
        declared = next(
            (f for f in self._declaration.fields if f.name == field), None
        )
        if declared is None:
            raise QueryError(
                "query_unknown_field",
                f"{field!r} is not a declared field of "
                f"{self._cls.__qualname__!r}. {self._supporting(op)}",
                field=field if isinstance(field, str) else None,
            )
        if op not in self._operators(declared):
            # Passthrough names no EQL type, so it has no `name` attribute.
            marker = declared.marker.__name__
            raise QueryError(
                "query_unsupported",
                f"field {field!r} is declared {marker}, which does not "
                f"support {op}. {self._supporting(op)}",
                field=field,
                reason=marker,
            )
        return _engine.query(self._plan, field, op, value)

    def _operators(self, field: DeclaredField) -> List[str]:
        """The operators the engine supports on ``field``, from the plan,
        with no request. A passthrough field supports none."""
        if field.marker is Passthrough:
            return []
        return _engine.operators(self._plan, field.name)

    def _supporting(self, op: str) -> str:
        names = [
            repr(f.name) for f in self._declaration.fields if op in self._operators(f)
        ]
        if not names:
            return f"The class has no field that supports {op}."
        return f"Fields that support {op}: " + ", ".join(names) + "."

    @property
    def declaration(self) -> Declaration:
        """What the decorator read from the class."""
        return self._declaration

    def __repr__(self) -> str:
        return f"Cipher({self._cls.__qualname__})"


class MatchQuery:
    """A match search on one field, made by ``Cipher.matches``.

    ``term`` is the term as a ``str``. Cast it to the marker's
    ``query_sql_domain`` and compare it with ``@@``. The object keeps the
    search text for ``verify``. ``repr`` never shows the text.
    """

    __slots__ = ("_plan", "_field", "_text", "term")

    def __init__(self, cipher: "Cipher[object]", field: str, text: str, term: str) -> None:
        self._plan = cipher._plan
        self._field = field
        self._text = text
        self.term = term

    def target_limit(
        self,
        want: int,
        *,
        rows: int,
        histogram: Optional[Sequence[Tuple[int, int]]] = None,
        confidence: Optional[float] = None,
    ) -> Optional[int]:
        """How many rows to fetch so that ``want`` of them pass ``verify``,
        at the confidence (0.99 by default): the number for the SQL
        ``LIMIT``. ``None`` when no finite number can be promised: then
        fetch page by page.

        ``rows`` is the number of rows the search reads, such as the
        table's row count. ``histogram`` is the set-bit counts of the stored
        filters, as ``(bits, rows)`` pairs::

            SELECT cardinality(eql_v4.match_term(notes)), count(*)
            FROM users WHERE notes IS NOT NULL GROUP BY 1

        Without a histogram, the result is ``None``. Makes no request.
        """
        pairs = None if histogram is None else [(int(b), int(r)) for b, r in histogram]
        return _engine.target_limit(
            self._plan, self._field, self.term, want, rows, pairs, confidence
        )

    def verify(self, values: Sequence[str]) -> List[bool]:
        """For each decrypted value of the field, whether it holds every
        3-character token of the search text, in the same order. Keep the
        rows that are ``True``. This is not an exact substring check: the
        tokens can be in any order. Makes no request."""
        return _engine.verify(self._plan, self._field, self._text, list(values))

    def __repr__(self) -> str:
        return f"MatchQuery(field={self._field!r})"


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


def _rows(rows: object, error: Type[StashError], code: str) -> list:
    """``rows`` as a list. Raises ``error`` with ``code`` for one row on its
    own, such as ``cursor.fetchone()`` returns: ``list()`` of a mapping is its
    keys, and each key would be refused as a row that is not a mapping."""
    if isinstance(rows, Mapping):
        raise error(
            code,
            "this takes a list of rows, not one row on its own. Pass [row], "
            "or the result of fetchall().",
        )
    return list(rows)  # type: ignore[call-overload]


def _build_plan(declaration: Declaration, fields: Sequence[DeclaredField]) -> object:
    """The engine's plan for ``fields`` of ``declaration``, in their order."""
    return _engine.build_plan(
        declaration.table,
        [
            (
                field.name,
                None if field.marker is Passthrough else field.marker.name,
                None if field.marker is Passthrough else field.marker.plaintext,
                field.value_type,
                field.nullable,
            )
            for field in fields
        ],
    )
