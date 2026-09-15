"""Flaw remediation: measuring it, and organizing the work of it.

SI-2 requires system flaws to be remediated within an organization-defined
period. Concord already knows what the flaws are -- ``ingest/scanners.py``
normalizes five scanner formats into POA&Ms with a severity, an asset and an
identification date -- but nothing compared that to a declared timeframe. The
parameter existed only as free text in an SSP template: a sentence in a
document, with nothing measuring it.

This package measures it, and organizes patching into ordered waves whose
completion is recorded. It deliberately does **not** apply patches: Concord has
no endpoint-management provider, and a wave either records that work was done,
with evidence, or references an enforcement plan when a deployment supplies a
provider. See ``docs/superpowers/specs/2026-09-15-flaw-remediation-design.md``.
"""

from __future__ import annotations
