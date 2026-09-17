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


async def test_seeding_does_not_clobber_an_authored_document() -> None:
    """Re-seeding must not wipe fields a human supplied -- otherwise the first
    accidental re-seed destroys the seven fields only a human can provide."""
    system_id = await _system("Delta")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        row.document = {
            **row.document,
            "serviceIdentification": {
                **row.document["serviceIdentification"],
                "serviceAcronym": "DELTA",
                "certificationType": "20x",
            },
        }
        await s.flush()

    async with session_scope() as s:
        again = await seed_cpo(s, system_id=system_id)
        ident = again.document["serviceIdentification"]
        assert ident["serviceAcronym"] == "DELTA"
        assert ident["certificationType"] == "20x"
