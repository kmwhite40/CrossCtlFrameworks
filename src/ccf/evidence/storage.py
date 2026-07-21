"""Pluggable content storage for the evidence repository.

Content is addressed by SHA-256 digest. :class:`LocalStorage` (the default) writes
under ``CCF_EVIDENCE_LOCAL_DIR`` and needs no external services. :class:`S3Storage`
targets an S3-compatible, optionally object-locked (WORM) bucket via ``boto3`` when
installed; if ``boto3`` is unavailable it raises a clear error on use rather than
at import, and :func:`get_backend` falls back to local storage so dev never breaks.

True, storage-enforced WORM requires ``evidence_backend="s3"`` *and* S3 Object Lock
(``evidence_object_lock_enabled=True`` on a bucket with Object Lock enabled). The
local filesystem backend cannot enforce immutability at the storage layer — a WORM
request against it (``retain_until`` passed to :meth:`StorageBackend.put`) degrades
to a logged warning rather than a false immutability claim; see
:class:`LocalStorage`.
"""

from __future__ import annotations

import abc
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import get_settings
from ..logging import get_logger

log = get_logger(__name__)


class StorageBackend(abc.ABC):
    """Content-addressed blob store: ``put`` returns a storage ref, ``get`` reads it."""

    name: str = "base"

    #: Whether this backend can make ``put`` storage-level immutable (object
    #: lock). ``False`` for local filesystem storage — WORM there is
    #: application-level only (see ``ccf.evidence.service.add_version`` and the
    #: ``EvidenceObject.immutable_lock`` flag), never a storage guarantee.
    worm_capable: bool = False

    @abc.abstractmethod
    def put(
        self,
        digest: str,
        data: bytes,
        media_type: str | None = None,
        *,
        retain_until: datetime | None = None,
    ) -> str:
        """Persist ``data`` under ``digest`` (idempotent); return a storage ref.

        ``retain_until``, when given, requests WORM/object-lock protection until
        that timestamp. A backend that cannot honor it (local disk) must not
        silently claim immutability — it logs a warning instead. A backend that
        requires it to complete a lock (S3 COMPLIANCE mode) must refuse rather
        than write an incomplete lock.
        """

    @abc.abstractmethod
    def get(self, ref: str) -> bytes | None:
        """Read content by ref, or ``None`` if it is missing."""


class LocalStorage(StorageBackend):
    """Filesystem backend — ``<root>/<digest[:2]>/<digest>``.

    Not WORM-capable: plain files on disk have no storage-level immutability.
    ``EvidenceObject.immutable_lock`` still blocks new versions through the
    service/API layer, but the bytes themselves are not protected against direct
    filesystem access. A ``retain_until`` request therefore never enforces
    anything here — it only triggers a warning so the gap is visible rather than
    silently presented as real WORM.
    """

    name = "local"
    worm_capable = False

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def _path(self, digest: str) -> Path:
        return self._root / digest[:2] / digest

    def put(
        self,
        digest: str,
        data: bytes,
        media_type: str | None = None,
        *,
        retain_until: datetime | None = None,
    ) -> str:
        if retain_until is not None:
            log.warning(
                "evidence.worm_not_storage_enforced",
                digest=digest[:12],
                backend=self.name,
                retain_until=retain_until.isoformat(),
                detail=(
                    "WORM/object-lock was requested (evidence_object_lock_enabled) but "
                    "evidence_backend=local; the filesystem cannot enforce immutability. "
                    "Only the application-level immutable_lock flag applies once an "
                    "object is approved (blocks new versions via the API) — the stored "
                    "bytes are not protected against direct modification. Set "
                    "evidence_backend=s3 with object lock enabled for storage-enforced "
                    "WORM."
                ),
            )
        path = self._path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():  # content-addressed → identical digest = identical bytes
            path.write_bytes(data)
        return f"file://{path.resolve()}"

    def get(self, ref: str) -> bytes | None:
        path = Path(ref[7:]) if ref.startswith("file://") else Path(ref)
        return path.read_bytes() if path.is_file() else None


class S3Storage(StorageBackend):
    """S3-compatible backend (lazy boto3). Object Lock gives WORM immutability.

    When ``object_lock`` is enabled, ``put`` requires a ``retain_until``
    timestamp: S3 rejects ``ObjectLockMode="COMPLIANCE"`` without an
    ``ObjectLockRetainUntilDate`` (absent a bucket-level default retention,
    which Concord does not assume is configured), so a missing date is a hard
    error here rather than an incomplete, effectively-unlocked write.
    """

    name = "s3"
    worm_capable = True

    def __init__(self, bucket: str, *, object_lock: bool = False) -> None:
        self._bucket = bucket
        self._object_lock = object_lock

    def _client(self) -> Any:
        try:
            import boto3  # noqa: PLC0415
        except ImportError as e:
            raise RuntimeError(
                "S3 evidence backend requires boto3 (pip install boto3)"
            ) from e
        return boto3.client("s3")

    def _key(self, digest: str) -> str:
        return f"evidence/{digest[:2]}/{digest}"

    def put(
        self,
        digest: str,
        data: bytes,
        media_type: str | None = None,
        *,
        retain_until: datetime | None = None,
    ) -> str:
        client = self._client()
        extra: dict[str, Any] = {"ContentType": media_type} if media_type else {}
        if self._object_lock:
            if retain_until is None:
                raise ValueError(
                    "evidence object lock is enabled but no retain-until date was "
                    "supplied; refusing to write an incomplete S3 COMPLIANCE lock "
                    "(S3 rejects ObjectLockMode=COMPLIANCE without "
                    "ObjectLockRetainUntilDate)"
                )
            extra["ObjectLockMode"] = "COMPLIANCE"
            extra["ObjectLockRetainUntilDate"] = retain_until
        client.put_object(Bucket=self._bucket, Key=self._key(digest), Body=data, **extra)
        return f"s3://{self._bucket}/{self._key(digest)}"

    def get(self, ref: str) -> bytes | None:
        client = self._client()
        key = ref.split(f"{self._bucket}/", 1)[-1] if ref.startswith("s3://") else ref
        try:
            obj = client.get_object(Bucket=self._bucket, Key=key)
            data: bytes = obj["Body"].read()
            return data
        except Exception:
            return None


def get_backend() -> StorageBackend:
    """Resolve the configured backend, degrading to local storage when needed."""
    s = get_settings()
    if s.evidence_backend == "s3" and s.evidence_s3_bucket:
        try:
            import boto3  # noqa: F401,PLC0415

            return S3Storage(s.evidence_s3_bucket, object_lock=s.evidence_object_lock_enabled)
        except ImportError:
            log.warning("evidence.s3_unavailable", reason="boto3 not installed; using local")
    return LocalStorage(s.evidence_local_dir)
