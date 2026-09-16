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


class _StreamResponse:
    """Minimal stand-in for the ``httpx.Response`` ``fetch_conditional``'s
    ``client.stream(...)`` context manager yields."""

    def __init__(
        self,
        status_code: int,
        *,
        headers: dict[str, str] | None = None,
        chunks: list[bytes] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = chunks or []

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")

    async def aread(self) -> bytes:
        return b"".join(self._chunks)

    async def aiter_bytes(self):
        for chunk in self._chunks:
            yield chunk


class _StreamCtx:
    def __init__(self, response: _StreamResponse) -> None:
        self._response = response

    async def __aenter__(self) -> _StreamResponse:
        return self._response

    async def __aexit__(self, *a: object) -> None:
        return None


class _StreamClient:
    def __init__(self, response: _StreamResponse, *, captured_headers: dict | None = None):
        self._response = response
        self._captured = captured_headers

    async def __aenter__(self) -> _StreamClient:
        return self

    async def __aexit__(self, *a: object) -> None:
        return None

    def stream(self, method: str, url: str, headers: dict[str, str]) -> _StreamCtx:
        if self._captured is not None:
            self._captured.update(headers)
        return _StreamCtx(self._response)


@pytest.mark.asyncio
async def test_a_304_returns_no_body_and_echoes_the_etag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The conditional path: a 304 must not be mistaken for empty content."""
    captured: dict[str, str] = {}
    resp = _StreamResponse(304)
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **k: _StreamClient(resp, captured_headers=captured)
    )
    status, body, etag = await sources.fetch_conditional("https://example.gov/p.json", 'W/"abc"')
    assert (status, body, etag) == (304, None, 'W/"abc"')
    assert captured["If-None-Match"] == 'W/"abc"'


@pytest.mark.asyncio
async def test_follow_redirects_false_refuses_a_redirect_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL 1 (PR #17 security review): a source that must not follow
    redirects treats any 3xx as a fetch failure rather than trusting the
    Location header -- the only safe way to stop a public URL from 302-ing a
    tenant's poll to a private address."""
    resp = _StreamResponse(302, headers={"location": "http://169.254.169.254/"})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _StreamClient(resp))
    with pytest.raises(ValueError, match="redirect"):
        await sources.fetch_conditional(
            "https://example.gov/p.json", None, follow_redirects=False
        )


@pytest.mark.asyncio
async def test_the_default_follow_redirects_true_leaves_a_200_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The catalog poller calls ``fetch_conditional`` with no
    ``follow_redirects``/``max_bytes`` kwargs at all (via the ``_fetch``
    alias) -- confirms the new keyword-only parameters default to the
    original behaviour, so that caller is unaffected. httpx itself (not this
    fake) is what would follow a real 3xx when ``follow_redirects=True``."""
    resp = _StreamResponse(200, chunks=[b'{"id": "demo"}'])
    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _StreamClient(resp))
    status, body, _etag = await sources.fetch_conditional("https://example.gov/p.json", None)
    assert (status, body) == (200, b'{"id": "demo"}')


@pytest.mark.asyncio
async def test_max_bytes_raises_before_buffering_the_whole_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL 3: the response must be capped while streaming, not read
    whole and checked after -- so a hostile/misconfigured source cannot make
    the scheduler process buffer an unbounded body."""
    chunks = [b"x" * 1024 for _ in range(10)]  # 10 KiB total
    resp = _StreamResponse(200, chunks=chunks)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _StreamClient(resp))
    with pytest.raises(sources.FetchTooLargeError):
        await sources.fetch_conditional("https://example.gov/p.json", None, max_bytes=2048)


@pytest.mark.asyncio
async def test_max_bytes_allows_a_body_within_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resp = _StreamResponse(200, chunks=[b'{"id": "demo"}'])
    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _StreamClient(resp))
    status, body, _etag = await sources.fetch_conditional(
        "https://example.gov/p.json", None, max_bytes=1024
    )
    assert (status, body) == (200, b'{"id": "demo"}')
