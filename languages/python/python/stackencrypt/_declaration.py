"""The ``model`` decorator: reads a class's fields and checks what they mean.

Rule A: every field has exactly one stash marker, in the ``Annotated``
directly around its value type. A plain field has ``Passthrough``, and an
attribute that is not a column has ``Ignore``. The decorator raises
``DeclarationError`` at the class statement when a field breaks the rule, or
when one of the checks below fails.

The fields are the library's own list where one exists (dataclasses, attrs,
Pydantic, ``NamedTuple``), and otherwise the class's type hints minus
``ClassVar`` and ``InitVar``, as on a SQLAlchemy declarative class. One generic
class around ``Annotated`` is read by structure, so ``Mapped[Annotated[str,
TextEq]]`` reads as ``TextEq``, with no SQLAlchemy import. A list, ``Final``
and the other generics of the standard library are not read through.

Then, in this order:

- Each marker is one the engine produces, and the value type is exactly the
  Python type of the marker's kind. A ``Passthrough`` value type is one of
  the eight types the engine stores as they are.
- The constructor takes every plan field as a keyword argument, and needs no
  ``Ignore`` field. A decorator applied below ``@dataclass`` finds no such
  constructor, because the class has none yet.
- The engine reads the plan, with the EQL types, as it does for every SDK.
"""

import dataclasses
import inspect
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
    get_args,
    get_origin,
    get_type_hints,
)

from stackencrypt import _engine, _eql
from stackencrypt._errors import DeclarationError
from stackencrypt._markers import Ignore, Marker, Passthrough

T = TypeVar("T", bound=type)

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
    """One field in the plan: its name, which is the column, and its marker."""

    name: str
    marker: Type[Marker]


@dataclass(frozen=True)
class _ReadField:
    """One field as the reader found it, ``Ignore`` fields included."""

    name: str
    marker: Type[Marker]
    value_type: Any


@dataclass(frozen=True)
class Declaration:
    """What the decorator read from a class: the table, and every field that
    is a column, in field order. ``Ignore`` fields are not in it."""

    table: str
    fields: Tuple[DeclaredField, ...]


def model(table: str) -> Callable[[T], T]:
    """Declare a class as a model stored in ``table``.

    Apply it outermost, above ``@dataclass`` or ``@attrs.define``::

        @stackencrypt.model("users")
        @dataclass
        class User:
            email: Annotated[str, TextEq]
            age: Annotated[int, Passthrough]
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
        read = _read_fields(cls)
        planned = [field for field in read if field.marker is not Ignore]
        for field in planned:
            _check_value_type(field)
        _check_constructor(cls, read)
        _check_plan(table, planned)
        fields = tuple(DeclaredField(name=f.name, marker=f.marker) for f in planned)
        setattr(cls, DECLARATION_ATTRIBUTE, Declaration(table=table, fields=fields))
        return cls

    return decorate


def declaration_of(cls: type) -> Optional[Declaration]:
    """The declaration ``model`` stored on ``cls`` itself, or ``None``.

    Read from the class's own ``__dict__``, so a subclass of a declared class
    is not declared until it is decorated itself.
    """
    found = cls.__dict__.get(DECLARATION_ATTRIBUTE)
    return found if isinstance(found, Declaration) else None


def _read_fields(cls: type) -> List[_ReadField]:
    try:
        hints = get_type_hints(cls, include_extras=True)
    except (NameError, TypeError) as error:
        raise _hints_unresolved(cls, error) from error
    names = _library_field_names(cls)
    from_hints = names is None
    if names is None:
        names = [name for name, hint in hints.items() if not _is_class_level(hint)]
    read = []
    for name in names:
        marker, value_type = _marker_of(name, hints.get(name), from_hints=from_hints)
        read.append(_ReadField(name=name, marker=marker, value_type=value_type))
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


def _is_class_level(hint: Any) -> bool:
    """A ``ClassVar`` or ``InitVar`` hint, which is not a field."""
    if isinstance(hint, dataclasses.InitVar) or hint is dataclasses.InitVar:
        return True
    if get_origin(hint) is Annotated:
        hint = get_args(hint)[0]
    return hint is ClassVar or get_origin(hint) is ClassVar


def _hints_unresolved(cls: type, error: Exception) -> DeclarationError:
    field = _unresolved_field(cls)
    where = f"field {field!r}" if field else f"a type hint of class {cls.__name__!r}"
    return DeclarationError(
        "declaration_hints_unresolved",
        f"{where} cannot be resolved ({error}). Define or import every name in "
        "it before the decorator runs, or declare the class after those names "
        'exist: stackencrypt.model("users")(User).',
        field=field,
    )


def _unresolved_field(cls: type) -> Optional[str]:
    """The first field whose hint does not resolve, or ``None``.

    The hints are resolved one at a time, in the order ``get_type_hints``
    resolves them, with the same namespaces. On 3.14, reading a class's
    annotations can itself raise, and then no one field can be named.
    """
    for base in reversed(cls.__mro__):
        try:
            own = _own_annotations(base)
        except (NameError, TypeError):
            return None
        module = sys.modules.get(base.__module__)
        global_names = dict(vars(module)) if module is not None else {}
        for name, hint in own.items():

            def probe() -> None: ...

            probe.__annotations__ = {name: hint}
            try:
                get_type_hints(probe, global_names, dict(vars(base)), include_extras=True)
            except (NameError, TypeError):
                return name
    return None


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


def _marker_of(name: str, hint: Any, *, from_hints: bool) -> Tuple[Type[Marker], Any]:
    """The one marker of a field and its value type, or a ``DeclarationError``.

    ``from_hints`` says the field list came from the type hints, as on a
    SQLAlchemy class. Only there is a wrapper inside the marker's
    ``Annotated`` refused as misplaced: ``Annotated[Mapped[str], TextEq]``.
    Elsewhere a generic value type is a type mismatch, checked later.
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
    if from_hints and not unwrapped and markers and _is_wrapper(value_type):
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
    if not marker.producible:
        raise DeclarationError(
            "declaration_unproducible",
            f"field {name!r} is declared {marker.__name__}. The engine "
            f"cannot produce {marker.__name__} yet: {marker.reason}.",
            field=name,
        )
    kind = marker.plaintext or ""
    expected = _KIND_TYPES.get(kind)
    if expected is None:
        raise DeclarationError(
            "declaration_type_mismatch",
            f"field {name!r} is declared {marker.__name__}, whose kind {kind} "
            "has no Python type in this version of the SDK.",
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
    try:
        parameters = inspect.signature(cls).parameters
    except (TypeError, ValueError):
        parameters = inspect.Signature().parameters
    any_keyword = any(p.kind is p.VAR_KEYWORD for p in parameters.values())
    for field in read:
        parameter = parameters.get(field.name)
        if field.marker is Ignore:
            if parameter is not None and _required(parameter):
                raise DeclarationError(
                    "declaration_ignore_required",
                    f"field {field.name!r} is marked Ignore, but the constructor "
                    f"of class {cls.__name__!r} requires it. Decrypt never "
                    "passes it, so give it a default or a default factory.",
                    field=field.name,
                )
        elif not (_keyword(parameter) or any_keyword):
            raise DeclarationError(
                "declaration_not_outermost",
                f"the constructor of class {cls.__name__!r} does not take field "
                f"{field.name!r} as a keyword argument. Put @stackencrypt.model "
                "above @dataclass or @attrs.define, so that it runs last.",
                field=field.name,
            )


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
            (field.name, None if field.marker is Passthrough else field.marker.name)
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
