"""The CPO seeder fills what the platform knows -- three fields of ten.

This is deliberately not a generator. providerName, serviceName and
serviceDescription are the only required CPO fields with a source here;
serviceAcronym, fedRampPackageId, website, logo, certificationType, serviceType
and deploymentModel are facts about the business that live nowhere in the
platform, and inventing them would be worse than leaving them out.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ccf.cr26.cpo import SEEDED_FIELDS, _seed_values, seed_cpo
from ccf.db import session_scope
from ccf.models import Organization, System


async def _system(name: str, description: str | None = None) -> int:
    async with session_scope() as s:
        org = Organization(name=f"{name} Provider")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} Service", description=description)
        s.add(sysm)
        await s.flush()
        return sysm.id


async def test_the_seeder_fills_exactly_the_three_fields_it_can() -> None:
    system_id = await _system("Acme", description="An Acme service.")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        ident = row.document["serviceIdentification"]
        assert ident["providerName"] == "Acme Provider"
        assert ident["serviceName"] == "Acme Service"
        assert ident["serviceDescription"] == "An Acme service."
        assert sorted(ident) == sorted(SEEDED_FIELDS)


async def test_the_seeded_document_is_invalid_and_that_is_correct() -> None:
    """Seven required fields have no source. A seeder that produced a valid
    document would have invented them."""
    system_id = await _system("Beta")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        assert row.is_valid is False
        missing = " ".join(row.validation_errors)
        for field in ("serviceAcronym", "fedRampPackageId", "website", "logo"):
            assert field in missing, f"{field} should be reported missing: {row.validation_errors}"


async def test_certification_type_is_not_seeded() -> None:
    """It is a declaration the provider makes, not a fact we can compute --
    see tests/test_cr26_certification_type_not_derived.py."""
    system_id = await _system("Gamma", description="A Gamma service.")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        ident = row.document["serviceIdentification"]
        # "certificationType" not in {} would pass trivially -- pin that the
        # dict was actually populated by the seeder, not merely absent.
        assert sorted(ident) == sorted(SEEDED_FIELDS)
        assert "certificationType" not in ident


async def test_reseeding_preserves_an_authored_override_of_a_seeded_field() -> None:
    """Re-seeding must not wipe a value a human wrote over a seeded field --
    otherwise the first accidental re-seed silently reverts an authored
    correction back to the platform's guess.

    ``providerName`` is exercised deliberately: it is one of the three fields
    ``seed_cpo``'s loop actually writes (via ``setdefault``), so overwriting it
    and re-seeding is a test the loop's assignment form could fail --
    `identification[field] = value` would overwrite it back to
    ``Organization.name`` on the second seed, while `setdefault` leaves it
    alone. A field the loop never touches (``serviceAcronym``,
    ``certificationType``) would pass under both forms, proving nothing about
    which one is used -- see the copy-forward test below for what those do
    prove.
    """
    system_id = await _system("Delta")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        assert row.document["serviceIdentification"]["providerName"] == "Delta Provider"
        row.document = {
            **row.document,
            "serviceIdentification": {
                **row.document["serviceIdentification"],
                "providerName": "Authored Provider Name",
            },
        }
        await s.flush()

    async with session_scope() as s:
        again = await seed_cpo(s, system_id=system_id)
        ident = again.document["serviceIdentification"]
        assert ident["providerName"] == "Authored Provider Name"


async def test_reseeding_copies_forward_fields_the_seeder_never_touches() -> None:
    """Fields the seeder has no source for at all (serviceAcronym,
    certificationType) must survive a re-seed too -- proven separately from the
    setdefault behaviour above, since an unconditional copy-forward would carry
    these regardless of whether the loop uses setdefault or plain assignment."""
    system_id = await _system("Epsilon")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        row.document = {
            **row.document,
            "serviceIdentification": {
                **row.document["serviceIdentification"],
                "serviceAcronym": "EPS",
                "certificationType": "20x",
            },
        }
        await s.flush()

    async with session_scope() as s:
        again = await seed_cpo(s, system_id=system_id)
        ident = again.document["serviceIdentification"]
        assert ident["serviceAcronym"] == "EPS"
        assert ident["certificationType"] == "20x"


async def test_a_system_without_a_description_omits_the_field_rather_than_seeding_empty() -> None:
    """The schema puts no ``minLength`` on ``serviceDescription``, so seeding
    ``""`` would satisfy ``required`` and make the document *look* filled-in --
    the exact gap this seeder exists to leave visible. Omission is the only
    honest option, and this is the assertion that can tell the two apart:
    ``seeded["serviceDescription"] = system.description or ""`` passes every
    other test in this file and fails here.
    """
    system_id = await _system("Zeta")  # description is NULL
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        ident = row.document["serviceIdentification"]
        assert "serviceDescription" not in ident
        assert sorted(ident) == ["providerName", "serviceName"]
        assert row.is_valid is False


async def test_a_description_authored_as_empty_string_is_left_alone() -> None:
    """Only a NULL column -- nothing recorded at all -- counts as absent. A
    human who deliberately stored "" gets it back, which is why the seeder
    filters on ``is not None`` rather than on truthiness."""
    system_id = await _system("Eta", description="")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        ident = row.document["serviceIdentification"]
        assert ident["serviceDescription"] == ""
        assert sorted(ident) == sorted(SEEDED_FIELDS)


def test_an_unsourced_field_is_omitted_never_seeded_as_an_empty_string() -> None:
    """``System.organization_id`` is NOT NULL behind an FK, so a system with no
    organization row is unreachable today -- but if it ever happened, seeding
    ``providerName=""`` would produce exactly the validates-and-is-wrong
    document this module forbids. It is omitted for the same reason
    ``serviceDescription`` is."""
    system = System(organization_id=1, name="Orphan Service")
    assert _seed_values(system, None) == {"serviceName": "Orphan Service"}


async def test_a_soft_deleted_system_is_refused() -> None:
    """DATA-04 soft-deletes systems so the CASCADE never fires; a CPO seeded
    against one would be unreachable and permanent."""
    system_id = await _system("Theta", description="A Theta service.")
    async with session_scope() as s:
        system = await s.get(System, system_id)
        assert system is not None
        system.deleted_at = datetime.now(UTC)

    async with session_scope() as s:
        with pytest.raises(ValueError, match="system"):
            await seed_cpo(s, system_id=system_id)
