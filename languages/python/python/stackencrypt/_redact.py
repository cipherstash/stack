"""Redaction: ``repr`` and ``str`` of a declared class show no plaintext.

The decorator replaces the class's ``__repr__``, ``__str__`` and
``__rich_repr__`` (the hook ``rich`` prints and pretty-prints through). Every
sealed field shows ``<sealed>``, a passthrough field shows its value, and an
``Ignore`` field is left out. Nothing else is covered: ``dataclasses.asdict``,
Pydantic's ``model_dump``, ``vars`` and ``__dict__`` still return plaintext,
and so does a debugger that reads attributes.

A generated method (dataclass, attrs, Pydantic, ``NamedTuple``) is replaced.
A method written on the class itself is refused unless the decorator is
given ``redact=False``, because replacing it would silently drop the user's
code. A method inherited from a base is replaced on the declared class only.
"""

import collections
import dataclasses
import inspect
import os
import reprlib
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

# The files a generated __repr__ reports as its own. A dataclass's __repr__ is
# wrapped for recursion, and the wrapper is in reprlib.py on 3.14 and in
# dataclasses.py on 3.9. attrs reports a "<attrs generated ...>" name.
_GENERATOR_FILES = frozenset(
    os.path.realpath(module.__file__)
    for module in (dataclasses, reprlib)
    if module.__file__ is not None
)

# attrs compiles its methods under this file name.
_ATTRS_GENERATED = "<attrs generated"

METHODS = ("__repr__", "__str__", "__rich_repr__")


def hand_written(cls: type, name: str) -> bool:
    """Whether ``cls`` itself has a ``name`` method written by hand.

    Only the class's own ``__dict__`` is read: a base's method is not the
    class's. A generated method comes from a generator's file, or from
    another module, such as ``pydantic.main``. A method compiled from a
    string, as in the REPL, a notebook or ``python -c``, is hand-written.
    """
    method = vars(cls).get(name)
    code = getattr(method, "__code__", None)
    if code is None or getattr(method, "__module__", None) != cls.__module__:
        return False
    filename = code.co_filename
    return (
        not filename.startswith(_ATTRS_GENERATED)
        and os.path.realpath(filename) not in _GENERATOR_FILES
    )


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
