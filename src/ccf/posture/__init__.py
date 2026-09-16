"""Live security posture — what the environment actually reports.

Distinct from :mod:`ccf.api.routes.posture`, which serves *compliance* posture
(internal rollups over POA&Ms and evidence). This package assesses live
provider configuration: a check is declared content, a scan produces
per-resource findings, and the results land in the existing
``ControlTest``/``ControlTestResult`` spine rather than a parallel one.
"""

from __future__ import annotations

from .rollup import EXCLUDED_FROM_ROLLUP, roll_up_findings
from .types import CheckOutcome, PostureCheck, ResourceFinding

__all__ = [
    "EXCLUDED_FROM_ROLLUP",
    "CheckOutcome",
    "PostureCheck",
    "ResourceFinding",
    "roll_up_findings",
]
