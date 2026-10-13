"""`Cipher` — the sync call site.

It holds no field logic. One call hands the engine the whole plan and every
row, because the engine batches (principle G5) and the SDK never executes
(principle G1). A loop over fields here would be the bug this file exists
to avoid; the one loop it has is over MODELS, turning each into the engine's
row by reading its declared fields off.

A record, as this returns it and takes it back, is a dict of field name to
column value: a target field's EQL JSON as `bytes`, a passthrough's value
as itself. That is the shape SQL wants, and the engine's own tree never
needs a serialised form.
"""

from __future__ import annotations

from typing import Any, Iterable

from stackencrypt import _engine
from stackencrypt.plan import PlanSpec


class Cipher:
    """Encrypt, decrypt and build query terms under one plan."""

    def __init__(self, plan: PlanSpec, engine: Any | None = None) -> None:
        self._plan = plan
        # One handle per Cipher. Passing one in is for tests that already
        # paid for the credential round trip in a session fixture.
        self._engine = engine if engine is not None else _engine.Engine()

    @property
    def key_requests(self) -> int:
        """ZeroKMS requests made so far. Evidence for principle G5."""
        return self._engine.key_requests

    def encrypt(self, models: Iterable[Any]) -> list[dict[str, Any]]:
        """A batch of models as stored records, in one key request."""
        rows = [self._row(model) for model in models]
        return self._engine.encrypt(self._plan.fields, rows)

    def decrypt(self, records: Iterable[dict[str, Any]]) -> list[Any]:
        """A batch of stored records back as the plan's model type."""
        rows = self._engine.decrypt(self._plan.fields, list(records))
        return [self._plan.model(**row) for row in rows]

    def query(self, field: str, value: Any) -> bytes:
        """One query term for `field`. A query takes one value (G5)."""
        return self._engine.query(self._plan.fields, field, value)

    def _row(self, model: Any) -> dict[str, Any]:
        """A model as the engine's row: field name to value, nothing else.

        It reads the declared fields off the model. It decides nothing
        about them — no per-field encryption, no term derivation, no EQL.
        The engine's `check_source` refuses a row that does not match.
        """
        return {name: getattr(model, name) for name in self._plan.fields}
