"""The CPO seeder fills what the platform knows -- three fields of ten.

This is deliberately not a generator. providerName, serviceName and
serviceDescription are the only required CPO fields with a source here;
serviceAcronym, fedRampPackageId, website, logo, certificationType, serviceType
and deploymentModel are facts about the business that live nowhere in the
platform, and inventing them would be worse than leaving them out.
"""

from __future__ import annotations

from ccf.cr26.cpo import SEEDED_FIELDS, seed_cpo
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
