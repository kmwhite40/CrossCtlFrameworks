"""System Security Plan (SSP) authoring + generation.

- ``constants`` — CMMC domain names, FedRAMP-style status / origination vocab.
- ``seed``      — build default per-control SSP entries from the scoring matrix.
- ``generator`` — render a project to a FedRAMP Appendix A style ``.docx``.
"""

from __future__ import annotations

from .generator import generate_ssp_docx

__all__ = ["generate_ssp_docx"]
