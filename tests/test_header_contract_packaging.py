"""The header contract must travel with the package, and must never fail open.

``etl/validate.py`` used to resolve the contract by walking out of the package
(``Path(__file__).resolve().parents[3] / "contracts" / ...``) and to return
``{"required_headers": []}`` when the file was absent. An empty contract makes
``validate_headers`` compute ``missing = set() - observed == []``, so it never
raised — a missing contract was indistinguishable from a conforming workbook.

That mattered because the file was never copied into the Docker image, and the
container is what runs ``ccf ingest``. The gate sits directly above
``delete(FrameworkMapping)`` / ``delete(Control)`` in ``etl/pipeline.py``, so in
the container the catalog was truncated and reloaded from a workbook nothing had
validated. The only signal was an ``ingest.header_drift`` INFO line — the same
line a legitimately extended workbook produces.

The contract is now package data resolved with ``Path(__file__).with_name(...)``,
and an unreadable contract raises instead of validating everything.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ccf.etl import validate as v


def test_contract_ships_inside_the_package() -> None:
    """It must sit next to validate.py, not outside the package tree."""
    assert v.CONTRACT_PATH.is_file(), f"contract missing at {v.CONTRACT_PATH}"
    assert v.CONTRACT_PATH.parent == Path(v.__file__).parent
    assert v.CONTRACT_PATH.name == "headers.v1_1.json"


def test_contract_resolves_from_any_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Models the container failure directly.

    The old path was resolved by walking out of the package, so it depended on
    where the package happened to sit relative to the repo root. In the image the
    package lives under site-packages and the walk landed somewhere with no
    contract. Resolution must depend only on the module's own location.
    """
    monkeypatch.chdir(tmp_path)
    assert v.CONTRACT_PATH.is_file()
    assert v.load_contract()["required_headers"]


def test_missing_contract_raises_instead_of_validating_everything(tmp_path: Path) -> None:
    """The old code returned an empty required set here, which passes any workbook."""
    absent = tmp_path / "nope.json"
    with pytest.raises(v.HeaderContractUnavailableError):
        v.load_contract(absent)


def test_unavailable_is_caught_by_the_pipeline_handler() -> None:
    """It must subclass HeaderContractError so ingest records a failed run."""
    assert issubclass(v.HeaderContractUnavailableError, v.HeaderContractError)


def test_the_real_contract_still_gates_a_missing_header() -> None:
    """End-to-end: the packaged contract is non-empty and rejects a bad workbook."""
    contract = v.load_contract()
    assert contract["required_headers"], "packaged contract must not be empty"
    with pytest.raises(v.HeaderContractError):
        v.validate_headers(set())


def test_a_conforming_workbook_still_passes() -> None:
    """The fix must not start failing workbooks that satisfy the contract."""
    required = set(v.load_contract()["required_headers"])
    diff = v.validate_headers(required | {"Some Extra Framework Column"})
    assert diff.missing == []
    assert diff.added == ["Some Extra Framework Column"]
