"""The fetch and hash helpers shared with packs/sync.py."""

from __future__ import annotations

import hashlib
from pathlib import Path

import httpx
import pytest

from ccf.etl import sources


def test_sha256_bytes_matches_hashlib() -> None:
    body = b'{"id": "demo"}'
    assert sources.sha256_bytes(body) == hashlib.sha256(body).hexdigest()


def test_the_private_aliases_still_point_at_the_public_helpers() -> None:
    """Kept so the promotion breaks no existing caller."""
    assert sources._sha256_bytes is sources.sha256_bytes
    assert sources._fetch is sources.fetch_conditional


@pytest.mark.asyncio
async def test_a_file_url_is_read_from_disk(tmp_path: Path) -> None:
    f = tmp_path / "pack.json"
    f.write_text('{"id": "demo"}', encoding="utf-8")
    status, body, etag = await sources.fetch_conditional(f"file://{f}", None)
    assert status == 200
    assert body == b'{"id": "demo"}'
    assert etag is None


@pytest.mark.asyncio
async def test_a_304_returns_no_body_and_echoes_the_etag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The conditional path: a 304 must not be mistaken for empty content."""

    class _Client:
        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: object) -> None:
            return None

        async def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
            assert headers["If-None-Match"] == 'W/"abc"'
            return httpx.Response(304, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _Client())
    status, body, etag = await sources.fetch_conditional("https://example.gov/p.json", 'W/"abc"')
    assert (status, body, etag) == (304, None, 'W/"abc"')
