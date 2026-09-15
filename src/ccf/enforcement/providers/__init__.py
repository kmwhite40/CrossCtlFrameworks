"""Remediation providers. Imported for the side effect of registering them."""

from __future__ import annotations

from .m365 import M365AccountProvider

__all__ = ["M365AccountProvider"]
