"""Redaction: ``repr`` and ``str`` of a declared class show no plaintext.

The decorator replaces the class's ``__repr__``, ``__str__`` and
``__rich_repr__`` (the hook ``rich`` prints and pretty-prints through). Every
sealed field shows ``<sealed>``, a passthrough field shows its value, and an
``Ignore`` field is left out. Nothing else is covered: ``dataclasses.asdict``,
Pydantic's ``model_dump``, ``vars`` and ``__dict__`` still return plaintext,
and so does a debugger that reads attributes.

A method that dataclasses, attrs or ``NamedTuple`` generated is replaced.
Pydantic's methods are on its base classes. Anything else on the class
itself is the user's: a function, a ``staticmethod``, a ``partialmethod``,
or a function from another module. It is refused unless the decorator is
given ``redact=False``, because replacing it would silently drop the user's
code. A method inherited from a base is replaced on the declared class only.
"""

import collections
import inspect
import os
import types
from typing import Any, Callable, Iterator, Sequence, Tuple


class _Placeholder:
    """What a repr shows in place of a value: ``<sealed>`` or ``<unset>``."""

    def __init__(self, text: str) -> None:
        self._text = text

    def __repr__(self) -> str:
        return self._text


# Angle brackets, not Go's `[sealed]`: that is a valid tag in rich's markup,
# so `rich.print(repr(user))` would show the field as empty.
SEALED = _Placeholder("<sealed>")
UNSET = _Placeholder("<unset>")
UNAVAILABLE = _Placeholder("<unavailable>")

# The descriptors that only read storage: a __slots__ member, and a
# NamedTuple field. Any other descriptor may do work, such as a SELECT.
_STORAGE_DESCRIPTORS = (
    types.MemberDescriptorType,
    type(vars(collections.namedtuple("_Probe", "field"))["field"]),
)

# attrs compiles its methods under this file name.
_ATTRS_GENERATED = "<attrs generated"

# dataclasses compiles its __repr__ from a string, inside this function, from
# 3.9 to 3.14. A Pydantic dataclass's __repr__ is the same.
_DATACLASS_FILE = "<string>"
_DATACLASS_QUALNAME = "__create_fn__.<locals>."

# NamedTuple's methods are defined in collections itself.
_COLLECTIONS_FILE = (
    os.path.realpath(collections.__file__) if collections.__file__ is not None else None
)

METHODS = ("__repr__", "__str__", "__rich_repr__")


def hand_written(cls: type, name: str) -> bool:
    """Whether ``cls`` itself has a ``name`` that no known generator wrote.

    Only the class's own ``__dict__`` is read: a base's method is not the
    class's. Anything there is the user's unless it is a generator's output.
    A method compiled from a string, as in the REPL, a notebook or
    ``python -c``, is hand-written.
    """
    found = vars(cls)
    return name in found and not _generated(found[name])


def _generated(method: object) -> bool:
    """Whether dataclasses, attrs or ``NamedTuple`` generated ``method``.

    A wrapper, such as the one ``reprlib.recursive_repr`` adds, is
    unwrapped first, so the function inside it decides. A user's
    ``recursive_repr`` is then the user's own function.
    """
    if not isinstance(method, types.FunctionType):
        return False
    inner = inspect.unwrap(method)
    code = getattr(inner, "__code__", None)
    if code is None:
        return False
    filename = code.co_filename
    if filename.startswith(_ATTRS_GENERATED):
        return True
    if filename == _DATACLASS_FILE:
        return inner.__qualname__.startswith(_DATACLASS_QUALNAME)
    return _COLLECTIONS_FILE is not None and os.path.realpath(filename) == _COLLECTIONS_FILE


def install(cls: type, fields: Sequence[Tuple[str, bool]]) -> Tuple[Callable[..., Any], ...]:
    """Replace ``__repr__``, ``__str__`` and ``__rich_repr__`` on ``cls``.

    ``fields`` is ``(name, in_clear)`` per plan field, in order. Returns the
    three functions, so that ``Cipher`` can check that they are still in
    place.
    """
    shown = tuple(fields)

    def __repr__(self: object) -> str:
        parts = ", ".join(f"{name}={value!r}" for name, value in __rich_repr__(self))
        return f"{type(self).__name__}({parts})"

    def __str__(self: object) -> str:
        return __repr__(self)

    # rich reprs each value itself, so a passthrough value is yielded as it
    # is, and a sealed one as the placeholder whose repr is <sealed>.
    def __rich_repr__(self: object) -> Iterator[Tuple[str, object]]:
        for name, in_clear in shown:
            yield name, (_value(self, name) if in_clear else SEALED)

    methods = (__repr__, __str__, __rich_repr__)
    for method in methods:
        method.__qualname__ = f"{cls.__qualname__}.{method.__name__}"
        setattr(cls, method.__name__, method)
    # Pydantic builds its other print hooks from __repr_args__: __repr_str__,
    # and __pretty__, which devtools' debug() prints through. It is replaced
    # too, with the same fields. Cipher does not check it again.
    if isinstance(getattr(cls, "__pydantic_fields__", None), dict):

        def __repr_args__(self: object) -> Iterator[Tuple[str, object]]:
            return __rich_repr__(self)

        __repr_args__.__qualname__ = f"{cls.__qualname__}.__repr_args__"
        setattr(cls, "__repr_args__", __repr_args__)
    return methods


def _value(instance: object, name: str) -> object:
    """A passthrough value, read without running a descriptor that may work.

    An attribute read can do work: a SQLAlchemy column that is not loaded runs
    a SELECT, and a detached instance raises. So the value comes from the
    instance's ``__dict__`` where it has one. Otherwise it is looked up on the
    class with ``getattr_static``, with no descriptor run. A plain class
    value, such as a default, is shown. A ``__slots__`` member or a
    ``NamedTuple`` field is read, since it only reads storage. Any other
    descriptor shows ``<unset>``.
    """
    state = getattr(instance, "__dict__", None)
    if state is not None and name in state:
        return state[name]
    try:
        found = inspect.getattr_static(instance, name)
    except AttributeError:
        return UNSET
    if not hasattr(type(found), "__get__"):
        return found
    if isinstance(found, _STORAGE_DESCRIPTORS):
        try:
            return getattr(instance, name)
        except AttributeError:
            return UNSET
        except Exception:  # noqa: BLE001  A repr never raises.
            return UNAVAILABLE
    return UNSET
