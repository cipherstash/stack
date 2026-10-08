"""Read a class's `Annotated` hints into the engine's data plan grammar.

This file is the whole of the declaration shape. Nothing else knows how an
annotation is spelled, because backlog item 1 may replace the spelling after
comparing it with other Python-style shapes.

The grammar it writes, per `stack_encrypt::dynamic::record`:

    { <field>: { "context": [...], "outputs": [...], "type": "<kind>" } }
    { <field>: { "context": [...], "target": {...},  "type": "<kind>" } }

`"outputs"` and `"target"` are exclusive — a field with both, or neither, is
refused. `"type"` is **required on every field with a term output** and is
checked when the plan is built (`Error::UntypedIndex`, naming the field), so
it is always written for an indexed field. For a target field the engine
takes the type from the EQL type when it is absent and requires it to agree
when present; writing it means the engine checks the two against each other,
which is a free consistency check on the declaration.

The `"target"` value written here is a REQUEST, not an EQL type name: either
`{"name": ...}` for an explicit one, or `{"kind": ..., "index": ...}` for the
engine's resolver to answer. `plan.py` substitutes the resolved name before
the plan reaches the engine. No EQL type name is written in this file.
"""

from __future__ import annotations

from typing import Any, get_type_hints

from stackencrypt._markers import EQL, Index, Kind, Passthrough
from stackencrypt.errors import DeclarationError


def _annotations(cls: type) -> dict[str, tuple[Any, ...]]:
    """Each field's `Annotated` extras, keyed by field name.

    `include_extras=True` is what keeps the metadata; without it the hints
    come back as the bare types and every field reads as undeclared.
    """
    hints = get_type_hints(cls, include_extras=True)
    return {name: getattr(hint, "__metadata__", ()) for name, hint in hints.items()}


def fields(cls: type, context: tuple[str, ...]) -> dict[str, dict]:
    """The data plan's field map for `cls`, under `context`.

    Fails closed: every field of the class must carry a stash annotation. A
    field the plan does not name is refused by the engine on every row
    anyway (`check_source`), so saying so here moves the error from the
    first write to import.
    """
    annotated = _annotations(cls)
    if not annotated:
        raise DeclarationError(f"{cls.__name__} declares no fields")

    plan: dict[str, dict] = {}
    for name, extras in annotated.items():
        width = next((e for e in extras if isinstance(e, Kind)), None)
        target = next((e for e in extras if isinstance(e, EQL)), None)
        indexes = tuple(e for e in extras if isinstance(e, Index))
        passthrough = any(isinstance(e, Passthrough) for e in extras)

        if target is None and not indexes and not passthrough:
            raise DeclarationError(
                f"{cls.__name__}.{name} carries no stash annotation. Every "
                f"field must declare one; use Passthrough() for a field "
                f"stored as it is."
            )

        spec: dict[str, Any] = {"context": [*context, name]}

        if passthrough:
            if target is not None or indexes:
                raise DeclarationError(
                    f"{cls.__name__}.{name} is both a passthrough and "
                    f"encrypted. A passthrough is a field's only output."
                )
            spec["outputs"] = ["passthrough"]
            if width is not None:
                spec["type"] = width.name
            plan[name] = spec
            continue

        if width is None:
            raise DeclarationError(
                f"{cls.__name__}.{name} is indexed but declares no width "
                f"type. A Python int carries no width, and 34 and 34.0 "
                f"derive different terms, so the engine needs one: add "
                f"Int64, Float64, Text or another width type to the "
                f"annotation."
            )
        spec["type"] = width.name

        if target is not None:
            if indexes:
                raise DeclarationError(
                    f"{cls.__name__}.{name} names both an EQL target and a "
                    f"bare index; a target carries its own indexes."
                )
            spec["target"] = _target(target, width)
        else:
            spec["outputs"] = ["c", *(index.key for index in indexes)]

        plan[name] = spec

    return plan


def _target(target: EQL, width: Kind) -> dict:
    """The target request for a field.

    Either an explicit EQL type name, or the pair the shell resolves against
    the engine's own target descriptors. The pair is not an EQL name, which
    is the point: Python states what the field holds and what a query must
    do, and the engine says which of its types that is.
    """
    if target.name is not None:
        return {"name": target.name}
    if target.index is None:
        return {"kind": width.name}
    return {"index": target.index.key, "kind": width.name}
