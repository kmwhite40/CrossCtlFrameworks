"""CMMC L2 assessor workflow.

- ``seed``  — create per-control results for an assessment from the scoring matrix.
- ``sar``   — render a Security Assessment Report (.docx) from the results.
"""

from __future__ import annotations

from .sar import generate_sar_docx
from .seed import (
    FINDINGS,
    result_to_dict,
    seed_assessment_results,
    summarize_results,
)

__all__ = [
    "FINDINGS",
    "generate_sar_docx",
    "result_to_dict",
    "seed_assessment_results",
    "summarize_results",
]
