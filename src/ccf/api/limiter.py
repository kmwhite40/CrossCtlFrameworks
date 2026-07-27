"""Shared slowapi ``Limiter`` instance.

Split into its own module (rather than defining it in ``main.py``) so that
route modules — e.g. ``api/routes/auth.py`` — can import the same limiter to
decorate individual endpoints without a circular import on ``api.main``.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])
