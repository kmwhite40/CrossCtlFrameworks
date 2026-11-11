"""Migration 0093's downgrade refuses to make retired KSIs current again.

``op`` is replaced wholesale: this calls ``downgrade()`` as a function and
never touches the shared test database, so it cannot wipe the schema the way
the round trips ``test_no_mid_session_schema_wipes`` guards against do. It is
allow-listed there for that reason, not because it round-trips.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def test_the_downgrade_refuses_to_merge_retired_ksis_back_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path(__file__).parents[1] / "migrations/versions/0093_ksi_retirement.py"
    spec = importlib.util.spec_from_file_location("m0093", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    dropped: list[str] = []

    class _Result:
        def scalar(self) -> int:
            return 51

    class _Bind:
        def execute(self, *_a: object) -> _Result:
            return _Result()

    monkeypatch.setattr(mod.op, "get_bind", _Bind, raising=False)
    monkeypatch.setattr(mod.op, "drop_column", lambda *a, **k: dropped.append(a[1]), raising=False)
    monkeypatch.setattr(mod.op, "drop_index", lambda *a, **k: None, raising=False)
    with pytest.raises(RuntimeError, match="51 retired KSI"):
        mod.downgrade()
    assert dropped == []
