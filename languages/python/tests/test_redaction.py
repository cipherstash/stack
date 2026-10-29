"""``repr`` and ``str`` of a declared class show no sealed value."""

import dataclasses
from typing import Annotated, NamedTuple

import attrs
import pydantic
import pytest
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

import stackencrypt
from stackencrypt import DeclarationError, Ignore, Passthrough, TextEq

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
