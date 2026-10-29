"""``repr`` and ``str`` of a declared class show no sealed value."""

import dataclasses
from typing import Annotated, NamedTuple

import attrs
import pydantic
import pytest
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

import stackencrypt
from stackencrypt import DeclarationError, Ignore, Passthrough, TextEq
from stackencrypt._redact import SEALED

SECRET = "alice@example.com"
EXPECTED = "User(email=[sealed], age=42)"


def declare_dataclass():
    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]
        note: Annotated[str, Ignore] = "not shown"

    return User(email=SECRET, age=42)


def declare_attrs():
    @stackencrypt.model("users")
    @attrs.define
    class User:
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]
        note: Annotated[str, Ignore] = "not shown"

    return User(email=SECRET, age=42)


def declare_pydantic():
    @stackencrypt.model("users")
    class User(pydantic.BaseModel):
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]
        note: Annotated[str, Ignore] = "not shown"

    return User(email=SECRET, age=42)


class User(NamedTuple):
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]
    note: Annotated[str, Ignore] = "not shown"


stackencrypt.model("users")(User)


def declare_named_tuple():
    return User(email=SECRET, age=42)


class Base(DeclarativeBase):
    pass


@stackencrypt.model("users")
class MappedUser(Base):
    __tablename__ = "users"
    email: Mapped[Annotated[str, TextEq]] = mapped_column(primary_key=True)
    age: Mapped[Annotated[int, Passthrough]]
    # No Ignore field: on SQLAlchemy, an Ignore field is a relationship, and a
    # relationship under Annotated loads as one object, not a list.


def declare_sqlalchemy():
    return MappedUser(email=SECRET, age=42)


KINDS = [
    declare_dataclass,
    declare_attrs,
    declare_pydantic,
    declare_named_tuple,
    declare_sqlalchemy,
]


@pytest.mark.parametrize("declare", KINDS, ids=lambda d: d.__name__)
def test_repr_and_str_seal_every_encrypted_field(declare):
    user = declare()
    expected = EXPECTED.replace("User", type(user).__name__)

    for shown in (repr(user), str(user), f"{user}", f"{user!r}"):
        assert shown == expected
        assert SECRET not in shown
        assert "note" not in shown
    # The hook rich prints through, so rich.print and a rich traceback with
    # locals show the same. rich reprs each value itself, so a passthrough
    # value is the value. Checked without rich: the hook is a plain method.
    assert list(user.__rich_repr__()) == [("email", SEALED), ("age", 42)]


def test_a_hand_written_repr_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq]

            def __repr__(self):
                return f"User({self.email})"

    error = pytest.raises(DeclarationError, build).value
    assert error.code == "declaration_repr_present"
    assert "redact=False" in str(error)


class ReprBase:
    """A base with its own __repr__, as a SQLAlchemy Base often has."""

    def __repr__(self):
        return "from the base"


def test_a_repr_inherited_from_a_base_is_replaced_not_refused():
    @stackencrypt.model("users")
    @dataclasses.dataclass(repr=False)
    class User(ReprBase):
        email: Annotated[str, TextEq]

    assert repr(User(email=SECRET)) == "User(email=[sealed])"
    assert repr(ReprBase()) == "from the base"


def test_a_repr_compiled_from_a_string_is_hand_written():
    # As in the REPL, a notebook or `python -c`: the code's file name is
    # `<stdin>`, and the method is still the user's.
    source = (
        "@stackencrypt.model('users')\n"
        "@dataclasses.dataclass\n"
        "class User:\n"
        "    email: Annotated[str, TextEq]\n"
        "    def __repr__(self):\n"
        "        return self.email\n"
    )
    namespace = dict(globals())

    with pytest.raises(DeclarationError) as raised:
        exec(compile(source, "<stdin>", "exec"), namespace)

    assert raised.value.code == "declaration_repr_present"


def test_a_passthrough_value_is_read_without_running_a_descriptor():
    # A field that is not set is shown as unset, and no attribute read runs:
    # a SQLAlchemy column that is not loaded would run a SELECT.
    @stackencrypt.model("users")
    class User:
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]

        def __init__(self, **kwargs):
            vars(self).update(kwargs)

        def __getattr__(self, name):
            raise RuntimeError(f"{name} was read")

    assert repr(User(email=SECRET)) == "User(email=[sealed], age=<unset>)"


def test_a_class_level_default_is_shown():
    @stackencrypt.model("users")
    class User:
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough] = 7

        def __init__(self, **kwargs):
            vars(self).update(kwargs)

    assert repr(User(email=SECRET)) == "User(email=[sealed], age=7)"
    assert repr(User(email=SECRET, age=8)) == "User(email=[sealed], age=8)"


def test_an_unset_slot_is_shown_as_unset():
    @stackencrypt.model("users")
    class User:
        __slots__ = ("email", "age")
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]

        def __init__(self, **kwargs):
            for name, value in kwargs.items():
                setattr(self, name, value)

    assert repr(User(email=SECRET)) == "User(email=[sealed], age=<unset>)"
    assert repr(User(email=SECRET, age=9)) == "User(email=[sealed], age=9)"


def test_a_hand_written_str_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq]

            def __str__(self):
                return self.email

    assert pytest.raises(DeclarationError, build).value.code == "declaration_repr_present"


def test_redact_false_keeps_a_hand_written_repr_and_shows_plaintext():
    @stackencrypt.model("users", redact=False)
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]

        def __repr__(self):
            return f"User({self.email})"

    # The escape hatch is visibly dangerous: the plaintext is in the repr.
    assert SECRET in repr(User(email=SECRET))


def test_redact_false_keeps_a_generated_repr_and_shows_plaintext():
    @stackencrypt.model("users", redact=False)
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]

    assert SECRET in repr(User(email=SECRET))
