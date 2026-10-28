"""The hand-written markers.

``Marker`` is the base of every stash marker. ``Passthrough`` and ``Ignore``
name no EQL type, so they are written here. The markers that name an EQL type
are generated from the EQL catalog into ``_eql.py``.

A marker is used as a class, in ``Annotated`` metadata, and is found there by
identity: ``Annotated[str, TextEq]``.
"""


class Marker:
    """The base of every stash marker."""


class Passthrough(Marker):
    """A field stored as it is, without encryption.

    The value goes through the engine with the rest of the record, and comes
    back unchanged.
    """


class Ignore(Marker):
    """An attribute that is not a column, such as a SQLAlchemy relationship.

    The SDK does not read, store, require, or show it. The marker exists so
    that every field still carries a marker, and a field with none is an error.
    """
