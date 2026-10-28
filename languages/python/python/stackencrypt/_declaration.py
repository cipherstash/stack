"""The ``model`` decorator: reads a class's fields and checks rule A.

Rule A: every field has exactly one stash marker, in the ``Annotated``
directly around its value type. A plain field has ``Passthrough``, and an
attribute that is not a column has ``Ignore``. The decorator raises
``DeclarationError`` at the class statement when a field breaks the rule.

The fields are the library's own list where one exists (dataclasses, attrs,
Pydantic, ``NamedTuple``), and otherwise the class's type hints minus
``ClassVar`` and ``InitVar``, as on a SQLAlchemy declarative class. One generic
class around ``Annotated`` is read by structure, so ``Mapped[Annotated[str,
TextEq]]`` reads as ``TextEq``, with no SQLAlchemy import. A list, ``Final``
and the other generics of the standard library are not read through.

The checks of each field's meaning come later: the value type against the
marker, the constructor, and the engine's own check of the plan.
"""

import dataclasses
import sys
from dataclasses import dataclass
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

from stackencrypt import _eql
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


@dataclass(frozen=True)
class DeclaredField:
    """One field in the plan: its name, which is the column, and its marker."""

    name: str
    marker: Type[Marker]


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
                "DECLARATION_ALREADY_DECLARED",
                f"class {cls.__name__!r} is already declared, with table "
                f"{existing.table!r}. Apply stackencrypt.model once.",
            )
        declaration = Declaration(table=table, fields=tuple(_read_fields(cls)))
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


def _read_fields(cls: type) -> List[DeclaredField]:
    try:
        hints = get_type_hints(cls, include_extras=True)
    except (NameError, TypeError) as error:
        raise _hints_unresolved(cls, error) from error
    names = _library_field_names(cls)
    from_hints = names is None
    if names is None:
        names = [name for name, hint in hints.items() if not _is_class_level(hint)]
    declared = []
    for name in names:
        marker = _marker_of(name, hints.get(name), from_hints=from_hints)
        if marker is not Ignore:
            declared.append(DeclaredField(name=name, marker=marker))
    return declared


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
        "DECLARATION_HINTS_UNRESOLVED",
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


def _marker_of(name: str, hint: Any, *, from_hints: bool) -> Type[Marker]:
    """The one marker of a field, or a ``DeclarationError``.

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
            "DECLARATION_TWO_MARKERS",
            f"field {name!r} has more than one stash marker ({names}). "
            "Give each field exactly one.",
            field=name,
            reason="rule-a",
        )
    return markers[0]


def _no_marker(name: str) -> DeclarationError:
    return DeclarationError(
        "DECLARATION_NO_MARKER",
        f"field {name!r} has no stash marker. Every field needs one: an EQL "
        "type such as TextEq to encrypt it, Passthrough to store it as it is, "
        "or Ignore if it is not a column.",
        field=name,
        reason="rule-a",
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
        "DECLARATION_MARKER_NOT_OUTERMOST",
        f"field {name!r} has its stash marker in the wrong place. {fix}",
        field=name,
        reason="rule-a",
    )


def _type_name(hint: Any) -> str:
    """A type as the user writes it: ``str``, or ``Optional[str]``."""
    if isinstance(hint, type) and not get_args(hint):
        return hint.__name__
    return repr(hint).replace("typing.", "")
