"""Concord catalog reconciliation engine (advisory).

Reconciles workbook-sourced controls against the pinned NIST OSCAL 800-53 Rev 5
catalog. Never writes to ``controls``; its only persistence target is
``catalog_integrity_reports``.

Packaging note: ``ccf.catalog.oscal.load_oscal_catalog`` resolves the OSCAL
JSON files from ``data/oscal/`` first (repo/dev + tests), falling back to the
packaged ``src/ccf/catalog/oscal_data/`` directory declared in
``pyproject.toml``'s ``[tool.setuptools.package-data]``. For local dev and
tests, ``data/oscal/`` is present and resolves first, so nothing further is
needed. For the wheel/Docker image, the ``data/oscal/*.json`` files must be
copied (or symlinked, in the Dockerfile build stage) into
``src/ccf/catalog/oscal_data/`` at build time so they end up inside the
package and ship with the wheel.
"""
