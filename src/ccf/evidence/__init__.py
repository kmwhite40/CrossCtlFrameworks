"""Evidence repository — versioned, content-addressed evidence with review.

:mod:`ccf.evidence.storage` provides a pluggable content store (local filesystem
by default, an S3-compatible/object-lock backend when configured), and
:mod:`ccf.evidence.service` the versioning + review + retention/access logic.
Everything degrades safely in local/dev with no external services.
"""

from __future__ import annotations

from .service import (
    add_version,
    create_object,
    expired_objects,
    mark_expired,
    read_version,
    record_access,
    review_object,
    submit_object,
)
from .storage import StorageBackend, get_backend

__all__ = [
    "StorageBackend",
    "add_version",
    "create_object",
    "expired_objects",
    "get_backend",
    "mark_expired",
    "read_version",
    "record_access",
    "review_object",
    "submit_object",
]
