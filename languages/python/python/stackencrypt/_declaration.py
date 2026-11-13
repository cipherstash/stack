"""The ``model`` decorator: reads a class's fields and checks what they mean.

Rule A: every field has exactly one stash marker, in the ``Annotated``
directly around its value type. A plain field has ``Passthrough``, and an
attribute that is not a column has ``Ignore``. The decorator raises
``DeclarationError`` at the class statement when a field breaks the rule, or
when one of the checks below fails.

The fields are the library's own list where one exists (dataclasses, attrs,
Pydantic, ``NamedTuple``), and otherwise the class's type hints minus
``ClassVar``, ``InitVar`` and dunder names such as ``__tablename__``, as on a
SQLAlchemy declarative class. One generic class around ``Annotated`` is read
by structure, so ``Mapped[Annotated[str, TextEq]]`` reads as ``TextEq``, with
no SQLAlchemy import. A list, ``Final`` and the other generics of the
standard library are not read through.

Then, in this order:

- Each marker is one the engine produces, and the value type is exactly the
  Python type of the marker's kind. A ``Passthrough`` value type is one of
  the eight types the engine stores as they are.
- The constructor takes every plan field as a keyword argument, and needs no
  ``Ignore`` field. A decorator applied below ``@dataclass`` finds no such
  constructor, because the class has none yet.
- The engine reads the plan, with the EQL types, as it does for every SDK.
- No hand-written ``__repr__``, ``__str__`` or ``__rich_repr__`` on the class
  itself, unless ``redact=False``. Then the decorator replaces all three, so
  that they show no plaintext.

``Cipher`` checks the class again (``check_unchanged``): the hints, the
constructor and the replaced methods must be as they were at decoration.
"""

import dataclasses
import inspect
import types
import sys
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

from stackencrypt import _engine, _eql, _redact
from stackencrypt._errors import DeclarationError
from stackencrypt._markers import Ignore, Marker, Passthrough

T = TypeVar("T", bound=type)

# The origins of a union: typing.Union, and types.UnionType for `T | None`
# from Python 3.10.
_UNIONS = tuple(
    origin for origin in (Union, getattr(types, "UnionType", None)) if origin is not None
)

# The one attribute the decorator stores, in the class's own __dict__.
DECLARATION_ATTRIBUTE = "__stash_declaration__"

# Every stash marker. A marker is found by identity, so a subclass of one, or
# another package's class of the same name, is not a marker.
_MARKERS = frozenset((Passthrough, Ignore) + _eql.TYPES)

# The modules whose generics are value types, such as a list or a dict, or
# typing forms, such as Final. A one-argument generic class from any other
# module, such as SQLAlchemy's Mapped, is read as a wrapper.
_VALUE_TYPE_MODULES = frozenset(
    {"builtins", "collections", "collections.abc", "types", "typing"}
)

# The package whose wrappers, such as Mapped, are refused inside the marker's
# Annotated. A one-argument generic from any other package, such as
# re.Pattern[str], may be a value type.
_WRAPPER_PACKAGE = "sqlalchemy"

# What evaluating a type hint raises when a name in it is missing or the
# string is not an expression.
_UNRESOLVED = (NameError, TypeError, AttributeError, SyntaxError)

# The one Python type of each marker kind. A value type must be exactly this
# type: not Optional, not a union, and not a subclass.
_KIND_TYPES: Dict[str, type] = {
    "string": str,
    "int16": int,
    "int32": int,
    "int64": int,
    "float32": float,
    "float64": float,
    "bool": bool,
    "decimal": Decimal,
    "date": date,
    "timestamp": datetime,
}

# The types the engine stores as they are, for a Passthrough field.
_PASSTHROUGH_TYPES = (str, int, float, bool, bytes, date, datetime, Decimal)


@dataclass(frozen=True)
class DeclaredField:
    """One field in the plan: its name, which is the column, its marker, and
    the Python type its annotation declares."""

    name: str
    marker: Type[Marker]
    value_type: type = dataclasses.field(default=object, repr=False, compare=False)
    # Declared Optional: None is a missing value, stored as SQL NULL.
    nullable: bool = False


@dataclass(frozen=True)
class _ReadField:
    """One field as the reader found it, ``Ignore`` fields included."""

    name: str
    marker: Type[Marker]
    value_type: Any
    nullable: bool = False


@dataclass(frozen=True)
class Declaration:
    """What the decorator read from a class: the table, and every field that
    is a column, in field order. ``Ignore`` fields are not in it.

    ``hints``, ``constructor`` and ``methods`` are the class as it was at
    decoration, for ``check_unchanged``. ``methods`` is the replaced
    ``__repr__``, ``__str__`` and ``__rich_repr__``, or empty with
    ``redact=False``.
    """

    table: str
    fields: Tuple[DeclaredField, ...]
    hints: Dict[str, Any] = dataclasses.field(repr=False, compare=False)
    constructor: Optional["_Constructor"] = dataclasses.field(repr=False, compare=False)
    methods: Tuple[Callable[..., Any], ...] = dataclasses.field(repr=False, compare=False)


# A constructor's parameters: each one's name, kind and default object. The
# defaults are compared by identity (`is`), never with `==`: a default such
# as `math.nan` is not equal to itself, and an array's `==` is not a bool.
_Constructor = Tuple[Tuple[str, Any, Any], ...]


def model(table: str, *, redact: bool = True) -> Callable[[T], T]:
    """Declare a class as a model stored in ``table``.

    Apply it outermost, above ``@dataclass`` or ``@attrs.define``::

        @stackencrypt.model("users")
        @dataclass
        class User:
            email: Annotated[str, TextEq]
            age: Annotated[int, Passthrough]

    ``repr`` and ``str`` of an instance then show ``<sealed>`` for each sealed
    field, and so does ``rich``, through ``__rich_repr__``. ``redact=False``
    keeps the class's own ``__repr__``, ``__str__`` and ``__rich_repr__``,
    which may show plaintext.
    """
    if not isinstance(table, str) or not table:
        raise TypeError('model takes the table name: @stackencrypt.model("users")')

    def decorate(cls: T) -> T:
        existing = declaration_of(cls)
        if existing is not None:
            raise DeclarationError(
                "declaration_already_declared",
                f"class {cls.__name__!r} is already declared, with table "
                f"{existing.table!r}. Apply stackencrypt.model once.",
            )
        hints = _hints(cls)
        read = _read_fields(cls, hints)
        planned = [field for field in read if field.marker is not Ignore]
        for field in planned:
            _check_value_type(field)
        _check_constructor(cls, read)
        _check_plan(table, planned)
        methods: Tuple[Callable[..., Any], ...] = ()
        if redact:
            _check_no_hand_written_methods(cls)
            methods = _redact.install(
                cls, [(f.name, f.marker is Passthrough) for f in planned]
            )
        declaration = Declaration(
            table=table,
            fields=tuple(
                DeclaredField(
                    name=f.name, marker=f.marker, value_type=f.value_type, nullable=f.nullable
                )
                for f in planned
            ),
            hints=hints,
            constructor=_constructor(cls),
            methods=methods,
        )
        setattr(cls, DECLARATION_ATTRIBUTE, declaration)
        return cls

    return decorate


def declaration_of(cls: type) -> Optional[Declaration]:
    """The declaration ``model`` stored on ``cls`` itself, or ``None``.

    Read from the class's own ``__dict__``, so a subclass of a declared class
    is not declared until it is decorated itself.
    """
    found = cls.__dict__.get(DECLARATION_ATTRIBUTE)
    return found if isinstance(found, Declaration) else None


def check_unchanged(cls: type, declaration: Declaration) -> None:
    """Refuse a class that changed after decoration, with
    ``declaration_class_changed``.

    The replaced methods, the type hints and the constructor must be as they
    were. A class is not checked again after ``Cipher`` is built.
    """
    if declaration.methods:
        replaced = [
            name
            for name, installed in zip(_redact.METHODS, declaration.methods)
            if cls.__dict__.get(name) is not installed
        ]
        if replaced:
            raise _class_changed(cls, "methods", None, f"{', '.join(replaced)} replaced")
    try:
        hints = _hints(cls)
    except DeclarationError as error:
        where = f"of {error.field!r} " if error.field else ""
        raise _class_changed(
            cls, "fields", error.field, f"a type hint {where}no longer resolves ({error.__cause__})"
        ) from error.__cause__
    changed = min(
        (
            name
            for name in set(hints) | set(declaration.hints)
            if hints.get(name) != declaration.hints.get(name)
        ),
        default=None,
    )
    if changed is not None:
        raise _class_changed(cls, "fields", changed, f"the type hint of {changed!r} changed")
    if not _same_constructor(_constructor(cls), declaration.constructor):
        raise _class_changed(cls, "constructor", None, "its constructor changed")


def _class_changed(
    cls: type, reason: str, field: Optional[str], what: str
) -> DeclarationError:
    return DeclarationError(
        "declaration_class_changed",
        f"class {cls.__name__!r} changed after stackencrypt.model declared it: "
        f"{what}. Apply every other decorator below stackencrypt.model, and "
        "change no declared class after it is defined.",
        field=field,
        reason=reason,
    )


def _hints(cls: type) -> Dict[str, Any]:
    """The class's resolved type hints, except its SQLAlchemy relationships.

    A relationship's hint often names a class defined later, such as
    ``Mapped[list["Gear"]]``, so it may not resolve yet. It is never a
    column, so it needs no hint here (see ``_relationships``)."""
    skip = _relationships(cls)
    if not skip:
        try:
            return get_type_hints(cls, include_extras=True)
        except _UNRESOLVED as error:
            raise _hints_unresolved(cls, error) from error
    hints: Dict[str, Any] = {}
    # As get_type_hints does: each base's own hints in its own namespaces,
    # the class's own last, so that they win.
    for base in reversed(cls.__mro__):
        try:
            own = _own_annotations(base)
        except _UNRESOLVED as error:
            raise _hints_unresolved(cls, error) from error
        namespaces = _namespaces(base)
        for name, hint in own.items():
            if name in skip:
                continue
            try:
                hints[name] = _resolve_one(name, hint, namespaces)
            except _UNRESOLVED as error:
                raise _hints_unresolved(cls, error) from error
    return hints


def _namespaces(base: type) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """The global and local names a hint of ``base`` resolves in, as
    ``get_type_hints`` uses them: its module's, and the class's own. Built
    once per class, not once per hint."""
    module = sys.modules.get(base.__module__)
    return (dict(vars(module)) if module is not None else {}), dict(vars(base))


def _resolve_one(
    name: str, hint: Any, namespaces: Tuple[Dict[str, Any], Dict[str, Any]]
) -> Any:
    """One hint, resolved as ``get_type_hints`` resolves it, in the
    ``namespaces`` of the class that declares it (see ``_namespaces``).

    The probe is a class, not a function: a function's annotation cannot be
    a ``ClassVar``, and before 3.14 a string ``ClassVar`` hint raises there.
    """
    global_names, local_names = namespaces
    probe = type("probe", (), {"__annotations__": {name: hint}})
    return get_type_hints(probe, global_names, local_names, include_extras=True)[name]


def _relationships(cls: type) -> frozenset:
    """The names of a SQLAlchemy class's relationships, such as ``books`` in
    ``books: Mapped[list["Book"]] = relationship()``. Empty for any other
    class.

    A relationship is never a column, so it is not a field of the plan,
    and it needs no marker. Rule A still holds for every column. SQLAlchemy
    maps a declarative class when its class statement runs, so its mapper
    lists the relationships before the decorator runs, and before the
    classes they name exist. ``Mapper._props`` is SQLAlchemy's own record
    of them; if it is missing, nothing is skipped."""
    orm = sys.modules.get("sqlalchemy.orm")
    if orm is None:
        return frozenset()
    mapper = cls.__dict__.get("__mapper__")
    props = getattr(mapper, "_props", None)
    if not isinstance(props, dict):
        return frozenset()
    return frozenset(
        name for name, prop in props.items() if isinstance(prop, orm.RelationshipProperty)
    )


def _signature(cls: type) -> Optional[inspect.Signature]:
    try:
        return inspect.signature(cls)
    except (TypeError, ValueError):
        return None


def _constructor(cls: type) -> Optional[_Constructor]:
    signature = _signature(cls)
    if signature is None:
        return None
    return tuple((p.name, p.kind, p.default) for p in signature.parameters.values())


def _same_constructor(now: Optional[_Constructor], then: Optional[_Constructor]) -> bool:
    if now is None or then is None:
        return now is then
    return len(now) == len(then) and all(
        a[0] == b[0] and a[1] == b[1] and a[2] is b[2] for a, b in zip(now, then)
    )


def _check_no_hand_written_methods(cls: type) -> None:
    for name in _redact.METHODS:
        if _redact.hand_written(cls, name):
            raise DeclarationError(
                "declaration_repr_present",
                f"class {cls.__name__!r} has a hand-written {name}, which may "
                "show plaintext. Remove it, so that stackencrypt.model can "
                "replace it, or pass redact=False to keep it.",
            )


def _read_fields(cls: type, hints: Dict[str, Any]) -> List[_ReadField]:
    names = _library_field_names(cls)
    from_hints = names is None
    if names is None:
        relationships = _relationships(cls)
        names = [
            name
            for name, hint in hints.items()
            if not _is_class_level(hint)
            and not _is_dunder(name)
            and name not in relationships
        ]
    read = []
    for name in names:
        marker, value_type = _marker_of(name, hints.get(name), from_hints=from_hints)
        value_type, nullable = _without_none(value_type)
        read.append(
            _ReadField(name=name, marker=marker, value_type=value_type, nullable=nullable)
        )
    return read


def _library_field_names(cls: type) -> Optional[List[str]]:
    """The field list of the class's own library, or ``None`` if it has none."""
    if dataclasses.is_dataclass(cls):
        return [field.name for field in dataclasses.fields(cls)]
    attrs_fields = getattr(cls, "__attrs_attrs__", None)
    if attrs_fields is not None:
        return [field.name for field in attrs_fields]
    pydantic_fields = getattr(cls, "__pydantic_fields__", None)
    if isinstance(pydantic_fields, dict):
        return list(pydantic_fields)
    named_tuple_fields = getattr(cls, "_fields", None)
    if issubclass(cls, tuple) and isinstance(named_tuple_fields, tuple):
        return list(named_tuple_fields)
    return None


def _is_dunder(name: str) -> bool:
    """A name such as ``__tablename__``: the class's configuration, which
    the user cannot mark, not a field."""
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _is_class_level(hint: Any) -> bool:
    """A ``ClassVar`` or ``InitVar`` hint, which is not a field."""
    if isinstance(hint, dataclasses.InitVar) or hint is dataclasses.InitVar:
        return True
    if get_origin(hint) is Annotated:
        hint = get_args(hint)[0]
    return hint is ClassVar or get_origin(hint) is ClassVar


def _hints_unresolved(cls: type, error: Exception) -> DeclarationError:
    unresolved = _unresolved_field(cls)
    field = unresolved[1] if unresolved else None
    if unresolved is not None and _is_bare_class_var(*unresolved):
        return DeclarationError(
            "declaration_hints_unresolved",
            f"field {field!r} is a bare ClassVar written as a string, which "
            "this version of Python cannot read. Give it a type: "
            "ClassVar[int], not ClassVar.",
            field=field,
            reason="bare_class_var",
        )
    where = f"field {field!r}" if field else f"a type hint of class {cls.__name__!r}"
    return DeclarationError(
        "declaration_hints_unresolved",
        f"{where} cannot be resolved ({error}). Define or import every name in "
        "it before the decorator runs, or declare the class after those names "
        'exist: stackencrypt.model("users")(User).',
        field=field,
    )


def _unresolved_field(cls: type) -> Optional[Tuple[type, str, Any]]:
    """The first field whose hint does not resolve, as the class that
    declares it, its name and its hint, or ``None``.

    The hints are resolved one at a time, in the order ``get_type_hints``
    resolves them, with the same namespaces. On 3.14, reading a class's
    annotations can itself raise, and then no one field can be named.
    """
    for base in reversed(cls.__mro__):
        try:
            own = _own_annotations(base)
        except _UNRESOLVED:
            return None
        namespaces = _namespaces(base)
        for name, hint in own.items():
            try:
                _resolve_one(name, hint, namespaces)
            except _UNRESOLVED:
                return base, name, hint
    return None


def _is_bare_class_var(base: type, name: str, hint: Any) -> bool:
    """Whether ``hint`` is a string that names ``ClassVar`` with no type.

    Python 3.9 cannot read one, as the future import writes it. The string is
    evaluated as ``get_type_hints`` evaluates it, so ``typing.ClassVar`` or an
    alias of it is found too.
    """
    if not isinstance(hint, str):
        return False
    global_names, local_names = _namespaces(base)
    try:
        return eval(hint, global_names, local_names) is ClassVar  # noqa: S307
    except Exception:  # noqa: BLE001  Any other failure is not this case.
        return False


def _own_annotations(base: type) -> Dict[str, Any]:
    """The annotations written on ``base`` itself, not on its bases."""
    if sys.version_info < (3, 10):
        # Before 3.10, base.__annotations__ can be a base class's.
        found = vars(base).get("__annotations__")
    else:
        found = getattr(base, "__annotations__", None)
    return found if isinstance(found, dict) else {}


def _is_marker(value: Any) -> bool:
    return isinstance(value, type) and value in _MARKERS


def _markers_in(hint: Any) -> List[Type[Marker]]:
    """The markers in the ``Annotated`` metadata of ``hint`` itself."""
    if get_origin(hint) is not Annotated:
        return []
    return [value for value in hint.__metadata__ if _is_marker(value)]


def _nested_markers(hint: Any) -> bool:
    """Whether any ``Annotated`` below ``hint``'s own level holds a marker."""
    inner = get_args(hint)[:1] if get_origin(hint) is Annotated else get_args(hint)
    return any(_markers_in(arg) or _nested_markers(arg) for arg in inner)


def _is_wrapper(hint: Any) -> bool:
    """A generic class with exactly one type argument, such as ``Mapped[str]``.

    A list, a tuple, ``Final`` and the other generics of the standard library
    are not wrappers: ``List[str]`` is a value type, not a wrapper around one.
    """
    origin = get_origin(hint)
    return (
        isinstance(origin, type)
        and origin.__module__ not in _VALUE_TYPE_MODULES
        and len(get_args(hint)) == 1
    )


def _is_orm_wrapper(hint: Any) -> bool:
    """A SQLAlchemy wrapper, such as ``Mapped[str]``, found by its module."""
    return (
        _is_wrapper(hint)
        and get_origin(hint).__module__.partition(".")[0] == _WRAPPER_PACKAGE
    )


def _without_none(value_type: Any) -> Tuple[Any, bool]:
    """``Optional[T]`` as ``(T, True)``; any other type as ``(type, False)``.
    ``Optional[T]`` is ``Union[T, None]``, and ``T | None`` from Python 3.10.
    A union of more than one type besides ``None`` is left as it is, and
    the type check refuses it."""
    if get_origin(value_type) in _UNIONS:
        others = [arg for arg in get_args(value_type) if arg is not type(None)]
        if len(others) == 1 and len(get_args(value_type)) == 2:
            return others[0], True
    return value_type, False


def _marker_of(name: str, hint: Any, *, from_hints: bool) -> Tuple[Type[Marker], Any]:
    """The one marker of a field and its value type, or a ``DeclarationError``.

    ``from_hints`` says the field list came from the type hints, as on a
    SQLAlchemy class. Only there is a SQLAlchemy wrapper inside the marker's
    ``Annotated`` refused as misplaced: ``Annotated[Mapped[str], TextEq]``.
    Any other generic value type, such as ``re.Pattern[str]``, is the value's
    own: a sealed marker refuses it later, as a type mismatch.
    """
    if hint is None:
        raise _no_marker(name)
    # One wrapper around Annotated is read by structure: Mapped[Annotated[...]].
    unwrapped = False
    if get_origin(hint) is not Annotated and _is_wrapper(hint):
        (inner,) = get_args(hint)
        if get_origin(inner) is Annotated:
            hint = inner
            unwrapped = True
    markers = _markers_in(hint)
    value_type = get_args(hint)[0] if get_origin(hint) is Annotated else hint
    # Annotated outermost, with the wrapper inside it, is the order reversed.
    # Inside a wrapper already read, a generic value type is the value's own,
    # as in a relationship: Mapped[Annotated[list[Post], Ignore]].
    if from_hints and not unwrapped and markers and _is_orm_wrapper(value_type):
        raise _marker_not_outermost(name, markers[0], value_type)
    if _nested_markers(hint):
        raise _marker_not_outermost(name, None, None)
    if not markers:
        raise _no_marker(name)
    if len(markers) > 1:
        names = ", ".join(marker.__name__ for marker in markers)
        raise DeclarationError(
            "declaration_two_markers",
            f"field {name!r} has more than one stash marker ({names}). "
            "Give each field exactly one.",
            field=name,
            reason="rule_a",
        )
    return markers[0], value_type


def _no_marker(name: str) -> DeclarationError:
    return DeclarationError(
        "declaration_no_marker",
        f"field {name!r} has no stash marker. Every field needs one: an EQL "
        "type such as TextEq to encrypt it, Passthrough to store it as it is, "
        "or Ignore if it is not a column.",
        field=name,
        reason="rule_a",
    )


def _marker_not_outermost(
    name: str, marker: Optional[Type[Marker]], value_type: Any
) -> DeclarationError:
    if marker is not None:
        wrapper = getattr(get_origin(value_type), "__name__", "the wrapper")
        (inner,) = get_args(value_type)
        fix = (
            f"Put the wrapper outside the Annotated: "
            f"{wrapper}[Annotated[{_type_name(inner)}, {marker.__name__}]]."
        )
    else:
        fix = "Put the marker in the Annotated around the field's own type."
    return DeclarationError(
        "declaration_marker_not_outermost",
        f"field {name!r} has its stash marker in the wrong place. {fix}",
        field=name,
        reason="rule_a",
    )


def _check_value_type(field: _ReadField) -> None:
    """Check that the engine produces the marker. Then check the value type
    against the marker's kind."""
    name, marker, value_type = field.name, field.marker, field.value_type
    if marker is Passthrough:
        if not any(value_type is allowed for allowed in _PASSTHROUGH_TYPES):
            raise DeclarationError(
                "declaration_type_mismatch",
                f"field {name!r} is declared {_type_name(value_type)}. "
                "Passthrough stores only str, int, float, bool, bytes, date, "
                "datetime, or Decimal.",
                field=name,
                reason="passthrough",
            )
        return
    # The engine refuses this marker too, as stack_encrypt_target_unproducible.
    # Python refuses it first, with the catalog's reason, so the engine's code
    # never reaches a Python caller. The spec asks for this (#1341, Markers).
    if not marker.producible:
        raise DeclarationError(
            "declaration_unproducible",
            f"field {name!r} is declared {marker.__name__}. The engine "
            f"cannot produce {marker.__name__} yet: {marker.reason}.",
            field=name,
        )
    kind = marker.plaintext
    expected = _KIND_TYPES.get(kind) if kind is not None else None
    if kind is None or expected is None:
        raise DeclarationError(
            "declaration_type_mismatch",
            f"field {name!r} is declared {marker.__name__}. Its plaintext kind, "
            f"{kind}, has no Python type in this version of the SDK.",
            field=name,
            reason=kind,
        )
    if value_type is not expected:
        raise DeclarationError(
            "declaration_type_mismatch",
            f"field {name!r} is declared {_type_name(value_type)}. "
            f"{marker.__name__} takes exactly {expected.__name__}: "
            f"Annotated[{expected.__name__}, {marker.__name__}].",
            field=name,
            reason=kind,
        )


def _check_constructor(cls: type, read: List[_ReadField]) -> None:
    """Check that the constructor takes every plan field as a keyword argument,
    and requires no Ignore field.

    ``decrypt`` builds an instance with one keyword argument per plan field,
    and passes no ``Ignore`` field.
    """
    signature = _signature(cls)
    parameters = (signature or inspect.Signature()).parameters
    any_keyword = any(p.kind is p.VAR_KEYWORD for p in parameters.values())
    # A plain class with no constructor: a decorator below this one, such as
    # @dataclass, has not made the class yet.
    unbuilt = _library_field_names(cls) is None and not any(
        "__init__" in vars(base) or "__new__" in vars(base)
        for base in cls.__mro__
        if base is not object
    )
    for field in read:
        parameter = parameters.get(field.name)
        if field.marker is Ignore:
            taken_as = parameters.get(_init_name(cls, field.name))
            if taken_as is not None and _required(taken_as):
                raise DeclarationError(
                    "declaration_ignore_required",
                    f"field {field.name!r} is marked Ignore, but the constructor "
                    f"of class {cls.__name__!r} requires it. Decrypt never "
                    "passes it, so give it a default or a default factory.",
                    field=field.name,
                )
        elif _takes(cls, field.name, parameter, any_keyword):
            continue
        elif unbuilt:
            raise DeclarationError(
                "declaration_not_outermost",
                f"class {cls.__name__!r} has no constructor yet. Put "
                "@stackencrypt.model above @dataclass or @attrs.define, so "
                "that it runs last.",
                field=field.name,
            )
        else:
            raise DeclarationError(
                "declaration_constructor_missing_field",
                f"the constructor of class {cls.__name__!r} does not take field "
                f"{field.name!r} as a keyword argument. Decrypt passes every "
                "field by its name, so the constructor must take that name. "
                "Look for init=False, a private attrs name, or an alias.",
                field=field.name,
            )


def _takes(
    cls: type, name: str, parameter: Optional[inspect.Parameter], any_keyword: bool
) -> bool:
    """Whether the constructor takes field ``name`` as a keyword argument."""
    info = _pydantic_field(cls, name)
    if info is not None:
        # Pydantic's signature shows a field's alias, not its name. Its config
        # says whether the name is taken too. With extra="allow" the signature
        # has **kwargs, and a name that is not taken lands in the extras. A
        # Pydantic dataclass keeps its config in __pydantic_config__.
        alias = getattr(info, "validation_alias", None) or getattr(info, "alias", None)
        if alias is None or alias == name:
            return True
        config = (
            getattr(cls, "model_config", None) or getattr(cls, "__pydantic_config__", None) or {}
        )
        return bool(config.get("populate_by_name") or config.get("validate_by_name"))
    return _keyword(parameter) or any_keyword


def _pydantic_field(cls: type, name: str) -> Any:
    """Pydantic's record of field ``name``, or ``None``."""
    fields = getattr(cls, "__pydantic_fields__", None)
    return fields.get(name) if isinstance(fields, dict) else None


def _init_name(cls: type, name: str) -> str:
    """The parameter name the constructor gives field ``name``.

    Pydantic names it by the field's alias. attrs names a private field
    without its leading underscore, so ``_cache`` is ``cache``.
    """
    info = _pydantic_field(cls, name)
    if info is not None:
        for alias in (getattr(info, "validation_alias", None), getattr(info, "alias", None)):
            if isinstance(alias, str):
                return alias
        return name
    for attribute in getattr(cls, "__attrs_attrs__", ()):
        if attribute.name == name:
            return getattr(attribute, "alias", None) or name
    return name


def _keyword(parameter: Optional[inspect.Parameter]) -> bool:
    return parameter is not None and parameter.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    )


def _required(parameter: inspect.Parameter) -> bool:
    variadic = (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    return parameter.kind not in variadic and parameter.default is parameter.empty


def _check_plan(table: str, planned: List[_ReadField]) -> None:
    """The engine's own check of the plan, with the EQL types."""
    refused = _engine.check_plan(
        table,
        [
            (
                field.name,
                None if field.marker is Passthrough else field.marker.name,
                field.nullable,
            )
            for field in planned
        ],
    )
    if refused is not None:
        code, message, field, reason = refused
        raise DeclarationError(code, message, field=field, reason=reason)


def _type_name(hint: Any) -> str:
    """A type as the user writes it: ``str``, or ``Optional[str]``."""
    if isinstance(hint, type) and not get_args(hint):
        return hint.__name__
    return repr(hint).replace("typing.", "")
