"""Annotation markers.

Three kinds of thing live here.

A **width type** (`Text`, `Int64`) resolves the field's `ValueKind`, which the
engine needs because a Python ``int`` carries no width and ``34`` and ``34.0``
derive different ORE terms. An **index marker** (`Equality`, `Match`, `Ore`)
names what a query against the field may do. `Passthrough` and `EQL` say what
the field produces.

The names follow the engine's vocabulary, not Python's: `context`,
`passthrough`, `equality`, `match`, `ore` (principle G2). The width types'
*values* are vitaminc's own kind names, which `ValueKind: FromStr` parses on
the engine side — they are not ours to choose.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Kind:
    """A field's plaintext kind, as the data plan's ``"type"`` key.

    A distinct type rather than a bare string so an unrelated
    ``Annotated[str, "a note"]`` cannot be mistaken for a declaration.
    """

    name: str


# vitaminc's kind vocabulary, from `ValueKind::name`. `Text` is the one that
# does not read like its value: the kind is `string`.
Text = Kind("string")
Int32 = Kind("int32")
Int64 = Kind("int64")
UInt32 = Kind("uint32")
UInt64 = Kind("uint64")
Float32 = Kind("float32")
Float64 = Kind("float64")
Bool = Kind("bool")
Bytes = Kind("bytes")


@dataclass(frozen=True)
class Index:
    """An index on a field, named by the engine's own output key.

    Which kinds each admits is the engine's rule (`dynamic::admits`), checked
    when the plan is built: `Equality` takes the integer kinds, `string` and
    `bytes`; `Match` takes `string` only; `Ore` and `Ope` take anything that
    is not an array or an object.
    """

    key: str


Equality = Index("eq")
Match = Index("match")
Ore = Index("ore")
Ope = Index("ope")


@dataclass(frozen=True)
class Passthrough:
    """The field is stored as it is, unsealed and unauthenticated.

    A field's only output when it has it. Declaring it is how a plain field
    stays visible to the fail-closed rule: every field of a model carries an
    annotation, and this is the one that says "not encrypted".
    """


@dataclass(frozen=True)
class EQL:
    """An EQL v3 target: the engine frames this field as an EQL type.

    ``index`` says what a query may do. The EQL type's NAME is not written
    here — the engine's resolver is asked for a producible type whose
    plaintext kind and index set match, so no EQL knowledge lives in Python.
    ``name`` overrides that, for a type the match rule cannot reach.
    """

    index: Optional[Index] = None
    name: Optional[str] = None
