"""The declaration tests, compiled twice: as written, and with
``from __future__ import annotations``. See ``test_declaration.py`` and
``test_declaration_future_annotations.py``.

The classes the tests declare refer only to module-level names, because
under the future import a hint is resolved from the module's globals.
"""

import dataclasses
import pickle
from typing import Annotated, ClassVar, Final, List, NamedTuple, Optional

import attrs
import pydantic
import pytest
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import ForeignKey

import stackencrypt
from stackencrypt import DeclarationError, Ignore, Passthrough, Text, TextEq
from stackencrypt._declaration import declaration_of

EXPECTED_FIELDS = [("email", TextEq), ("age", Passthrough)]


def planned(cls):
    declaration = declaration_of(cls)
    assert declaration is not None, "the class was not declared"
    return [(field.name, field.marker) for field in declaration.fields]


def refusal(build):
    with pytest.raises(DeclarationError) as raised:
        build()
    return raised.value


# The five class kinds, each with one TextEq, one Passthrough and one Ignore.


def test_a_dataclass_declares():
    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]
        note: Annotated[str, Ignore] = ""

    assert planned(User) == EXPECTED_FIELDS
    assert declaration_of(User).table == "users"


def test_an_attrs_class_declares():
    @stackencrypt.model("users")
    @attrs.define
    class User:
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]
        note: Annotated[str, Ignore] = ""

    assert planned(User) == EXPECTED_FIELDS


def test_a_pydantic_model_declares():
    @stackencrypt.model("users")
    class User(pydantic.BaseModel):
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]
        note: Annotated[str, Ignore] = ""

    assert planned(User) == EXPECTED_FIELDS


class UserTuple(NamedTuple):
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]
    note: Annotated[str, Ignore] = ""


def test_a_named_tuple_declares():
    declared = stackencrypt.model("users")(UserTuple)

    assert declared is UserTuple
    assert planned(UserTuple) == EXPECTED_FIELDS


class Base(DeclarativeBase):
    pass


class Post(Base):
    __tablename__ = "posts"
    id: Mapped[Annotated[int, Passthrough]] = mapped_column(primary_key=True)
    user_id: Mapped[Annotated[int, Passthrough]] = mapped_column(ForeignKey("users.id"))


@stackencrypt.model("users")
class User(Base):
    __tablename__ = "users"
    id: Mapped[Annotated[int, Passthrough]] = mapped_column(primary_key=True)
    email: Mapped[Annotated[str, TextEq]]
    age: Mapped[Annotated[int, Passthrough]]
    posts: Mapped[Annotated[List["Post"], Ignore]] = relationship()


def test_a_sqlalchemy_class_declares_through_mapped():
    assert planned(User) == [("id", Passthrough)] + EXPECTED_FIELDS


def test_a_relationship_marked_ignore_is_not_in_the_plan():
    assert "posts" not in [name for name, _ in planned(User)]


def test_sqlalchemy_still_maps_every_column_it_was_given():
    assert set(User.__table__.columns.keys()) == {"id", "email", "age"}


# Rule A and its codes.


def test_a_field_without_a_marker_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq]
            age: int

    error = refusal(build)
    assert error.code == "DECLARATION_NO_MARKER"
    assert error.field == "age"
    assert "DECLARATION_NO_MARKER" in str(error)
    assert "'age'" in str(error)


def test_annotated_metadata_from_another_library_is_not_a_marker():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, "not a marker"]

    assert refusal(build).code == "DECLARATION_NO_MARKER"


def test_a_field_with_two_markers_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq, Text]

    error = refusal(build)
    assert error.code == "DECLARATION_TWO_MARKERS"
    assert error.field == "email"
    assert "DECLARATION_TWO_MARKERS" in str(error)
    assert "'email'" in str(error)


def test_ignore_with_another_marker_is_two_markers():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq, Ignore]

    assert refusal(build).code == "DECLARATION_TWO_MARKERS"


def test_a_wrapper_inside_the_marker_annotated_is_refused():
    # A plain class, whose fields come from its hints as a SQLAlchemy class's
    # do. On a mapped class SQLAlchemy refuses this order itself, with
    # MappedAnnotationError, before the decorator runs.
    def build():
        @stackencrypt.model("users")
        class User:
            email: Annotated[Mapped[str], TextEq]

    error = refusal(build)
    assert error.code == "DECLARATION_MARKER_NOT_OUTERMOST"
    assert error.field == "email"
    assert error.reason == "rule-a"
    assert "Mapped[Annotated[str, TextEq]]" in str(error)


def test_the_remedy_names_the_inner_type_as_written():
    def build():
        @stackencrypt.model("users")
        class User:
            email: Annotated[Mapped[Optional[str]], TextEq]

    message = str(refusal(build))
    assert "Union" not in message
    assert (
        "Mapped[Annotated[Optional[str], TextEq]]" in message
        or "Mapped[Annotated[str | None, TextEq]]" in message
    )


def test_a_collection_value_type_is_not_a_misplaced_wrapper():
    @stackencrypt.model("users")
    class User:
        tags: Annotated[List[str], Passthrough]

    assert planned(User) == [("tags", Passthrough)]


@pytest.mark.parametrize("kind", ["dataclass", "plain"])
def test_a_marker_inside_a_list_or_final_is_refused(kind):
    def build_list():
        class User:
            tags: List[Annotated[str, TextEq]]

        if kind == "dataclass":
            User = dataclasses.dataclass(User)
        stackencrypt.model("users")(User)

    def build_final():
        class User:
            email: Final[Annotated[str, TextEq]]

        if kind == "dataclass":
            User = dataclasses.dataclass(User)
        stackencrypt.model("users")(User)

    for build in (build_list, build_final):
        error = refusal(build)
        assert error.code == "DECLARATION_MARKER_NOT_OUTERMOST"
        assert error.reason == "rule-a"


def test_a_marker_inside_another_type_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Optional[Annotated[str, TextEq]]

    error = refusal(build)
    assert error.code == "DECLARATION_MARKER_NOT_OUTERMOST"
    assert error.field == "email"


class MyText(TextEq):
    """A user's subclass of a marker, which is not a marker."""


def test_a_subclass_of_a_marker_is_not_a_marker():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, MyText]

    assert refusal(build).code == "DECLARATION_NO_MARKER"


def test_an_unresolved_hint_is_refused_with_its_field():
    # "Undefined" is a forward reference that never resolves, as a
    # relationship to a class written later does.
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq]
            posts: Annotated[List["Undefined"], Ignore] = dataclasses.field(  # noqa: F821
                default_factory=list
            )

    error = refusal(build)
    assert error.code == "DECLARATION_HINTS_UNRESOLVED"
    assert error.field == "posts"
    assert "'posts'" in str(error)
    assert isinstance(error.__cause__, NameError)


def test_a_class_is_declared_once():
    def build():
        @stackencrypt.model("users")
        @stackencrypt.model("accounts")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq]

    error = refusal(build)
    assert error.code == "DECLARATION_ALREADY_DECLARED"
    assert "'accounts'" in str(error)


def test_a_declaration_error_survives_pickle():
    error = DeclarationError("DECLARATION_NO_MARKER", "no marker", field="age", reason="rule-a")

    copy = pickle.loads(pickle.dumps(error))

    assert type(copy) is DeclarationError
    assert (copy.code, copy.message, copy.field, copy.reason) == (
        "DECLARATION_NO_MARKER",
        "no marker",
        "age",
        "rule-a",
    )
    assert str(copy) == str(error) == "DECLARATION_NO_MARKER: no marker"


def test_class_level_names_are_not_fields():
    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]
        registry: ClassVar[dict] = {}

    assert planned(User) == [("email", TextEq)]


def test_a_subclass_is_not_declared_until_it_is_decorated():
    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]

    @dataclasses.dataclass
    class Admin(User):
        level: Annotated[int, Passthrough] = 0

    assert declaration_of(Admin) is None


def test_model_needs_the_table_name():
    with pytest.raises(TypeError, match="table name"):

        @stackencrypt.model
        class User:
            email: Annotated[str, TextEq]


def test_model_refuses_an_empty_table_name():
    with pytest.raises(TypeError, match="table name"):
        stackencrypt.model("")


def test_declaring_a_class_makes_no_engine_call_and_needs_no_credentials(monkeypatch):
    for name in ("CS_WORKSPACE_CRN", "CS_CLIENT_ID", "CS_CLIENT_KEY", "CS_CLIENT_ACCESS_KEY"):
        monkeypatch.delenv(name, raising=False)

    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]

    assert planned(User) == [("email", TextEq)]
