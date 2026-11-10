"""The exceptions the SDK raises.

Every error carries the same four fields, whoever raised it: ``code`` (a fixed
lower_snake_case token), ``message`` (prose for a person), ``reason`` (a fixed
lower_snake_case token or ``None``) and ``field`` (the field name, or
``None``). The code's prefix tells where the error came from. An engine
error's code is the engine's diagnostic code with ``::`` replaced by ``_``.
"""

from typing import Optional


class StashError(Exception):
    """The base of every SDK error, and the one to catch for all of them."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        field: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        # The code and message are the exception's args, so that pickle, which
        # rebuilds an exception as cls(*args), can rebuild this one. The other
        # attributes come back from __dict__.
        super().__init__(code, message)
        self.code = code
        self.message = message
        self.field = field
        self.reason = reason

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class DeclarationError(StashError):
    """A model class that cannot be declared, raised at its class statement."""


class AuthenticationError(StashError):
    """The credentials are missing, malformed or refused.

    The code is the engine's, such as ``stack_auth_not_authenticated``.
    """


class InvalidValueError(StashError, ValueError):
    """A model's value that does not fit its field, refused before any request.

    The code is one of ``value_none``, ``value_wrong_type``,
    ``value_out_of_range``, ``value_not_representable`` and
    ``value_naive_datetime``. ``field`` names the field. ``reason`` is the
    field's kind, such as ``int32``, or ``passthrough``. The message never
    contains the value.
    """


class DecryptError(StashError):
    """A stored row that ``decrypt`` cannot turn into a model.

    Before any key request: ``decrypt_row_shape`` (a row that is not a
    mapping), ``decrypt_missing_column`` (a declared field's column is not in
    the row), ``decrypt_malformed`` (the column value is not an EQL value),
    and ``decrypt_foreign_row`` (the value was stored under another table or
    column). After the key requests: ``decrypt_kind_mismatch`` (the value was
    stored as another type) and ``decrypt_not_representable`` (an opened value
    Python cannot hold). ``field`` names the column where it is known.
    """


class QueryError(StashError):
    """A query method call the declared class cannot answer, such as ``eq``
    or ``gte``, raised before any request.

    ``query_unknown_field``: the name is not a declared field.
    ``query_unsupported``: the field does not support the operator. For
    ``eq``, examples are ``Text``, ``Passthrough`` and ``IntegerOrd``. For
    ``gte``, an example is ``TextEq``. ``reason`` is the marker's name.
    """
