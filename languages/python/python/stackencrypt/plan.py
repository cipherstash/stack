"""`Plan.of(Model).context(...).build()`.

A plan is the declaration without the values: reusable, and validated once.
The same plan serves the write, the query and the read (principle G4), so a
query cannot drift onto a different context from the write — the engine
refuses a query for an index the field never declared, and a context that
differs opens nothing.

`build()` here checks what Python can see. Task 4 adds the engine's own
checks to the same call, so a declaration defect is an import-time error
rather than a first-write one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from stackencrypt import _declare, _engine
from stackencrypt.errors import DeclarationError


@dataclass(frozen=True)
class PlanSpec:
    """A built plan: the model it came from, and the engine's field map."""

    model: type
    context: tuple[str, ...]
    fields: dict[str, dict[str, Any]]
    #: Each target field's resolved EQL type and its PostgreSQL domains.
    #: Filled by the engine's resolver in Task 4; empty until then.
    domains: dict[str, dict[str, str]] = field(default_factory=dict)


class PlanBuilder:
    """The chain between `Plan.of` and `build`."""

    def __init__(self, model: type) -> None:
        self._model = model
        self._context: tuple[str, ...] = ()

    def context(self, *pieces: str) -> PlanBuilder:
        """The context every field is sealed under, extended by field name.

        `context` is the engine's own word for what is supplied, chosen over
        `under` and over the database-centric `columns`.
        """
        self._context = pieces
        return self

    def build(self) -> PlanSpec:
        if not self._context:
            raise DeclarationError(
                f"{self._model.__name__} has no context: call "
                f".context('<table>') before .build()"
            )
        fields = _declare.fields(self._model, self._context)
        # The engine's own checks, and the EQL type each target field
        # resolves to. No credentials needed: parsing a plan mints no key
        # and makes no request, so a declaration defect is an import-time
        # error wherever the code runs.
        domains = _engine.check_plan(fields)
        for name, resolved in domains.items():
            # What crosses to the engine is the resolved NAME. The pair
            # `_declare` wrote was a request for the resolver to answer.
            fields[name]["target"] = resolved["name"]
        return PlanSpec(
            model=self._model,
            context=self._context,
            fields=fields,
            domains=domains,
        )


class Plan:
    """The entry point. `Plan.of(User)` reads `User`'s annotations."""

    @staticmethod
    def of(model: type) -> PlanBuilder:
        return PlanBuilder(model)
