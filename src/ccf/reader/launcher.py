"""Concord Reader entrypoint — PyInstaller's target.

Responsibilities on launch:
  1. Pick a data dir (%LOCALAPPDATA%/Concord on Windows, ~/.concord elsewhere).
  2. Point CCF_DATABASE_URL / CCF_DATABASE_URL_SYNC at a SQLite file in there.
  3. Flag CCF_READONLY=true so the API hides write flows + blocks mutations.
  4. Initialize the SQLite schema (subset defined in reader/bootstrap.py).
  5. If the schema is empty AND a workbook xlsx sits next to the exe,
     auto-ingest it so the operator doesn't need to do anything.
  6. Open the default browser at http://127.0.0.1:8088 and run uvicorn.
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path


def _exe_dir() -> Path:
    """Directory containing the Concord Reader executable."""
    if getattr(sys, "frozen", False):  # PyInstaller
        return Path(sys.executable).resolve().parent
    return Path.cwd()


def _find_workbook(exe_dir: Path, data_dir: Path) -> Path | None:
    """Look for a bundled workbook; prefer exe-adjacent, then data_dir."""
    candidates = [
        exe_dir / "NIST Cross Mappings Rev. 1.1.xlsx",
        exe_dir / "data" / "NIST Cross Mappings Rev. 1.1.xlsx",
        data_dir / "NIST Cross Mappings Rev. 1.1.xlsx",
    ]
    for p in candidates:
        if p.is_file():
            return p
    # any xlsx in the exe dir
    for p in exe_dir.glob("*.xlsx"):
        return p
    return None


def _wait_free_port(host: str, port: int, tries: int = 40) -> int:
    for _ in range(tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((host, port)) != 0:
                return port
        port += 1
    return port


async def _init_and_maybe_ingest(dsn: str, workbook: Path | None) -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from .bootstrap import init_reader_schema
    from .ingest import ingest_into_sqlite

    engine = create_async_engine(dsn)
    try:
        # Create the attached sqlite DB's tables. bootstrap expects the file
        # to be the 'ccf' attached schema — we set that up transiently.
        target = dsn.removeprefix("sqlite+aiosqlite:///").removeprefix("sqlite:///")
        from sqlalchemy.ext.asyncio import create_async_engine as _cae

        raw = _cae(f"sqlite+aiosqlite:///{target}")
        async with raw.begin() as conn:
            # bootstrap's DDL uses unqualified names, so we run it directly
            # against the file, not the attached alias.
            from .bootstrap import READER_DDL_SQLITE
            for stmt in READER_DDL_SQLITE:
                await conn.execute(text(stmt))
        await raw.dispose()

        # Now check whether anything is in there through the main engine
        # (which attaches the file as 'ccf').
        async with engine.begin() as conn:
            r = await conn.execute(text("SELECT count(*) AS c FROM ccf.controls"))
            n = list(r)[0].c
        if n == 0 and workbook is not None:
            print(f"[Concord Reader] Ingesting {workbook.name} …", flush=True)
            stats = await ingest_into_sqlite(engine, workbook)
            print(f"[Concord Reader] Loaded {stats['controls']} controls, "
                  f"{stats['mappings']} mappings.", flush=True)
    finally:
        await engine.dispose()


def main() -> int:
    exe_dir = _exe_dir()
    # Data dir: %LOCALAPPDATA%/Concord on Windows, ~/.concord otherwise.
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    data_dir = Path(base) / ("Concord" if os.name == "nt" else ".concord")
    data_dir.mkdir(parents=True, exist_ok=True)

    db_file = data_dir / "concord.db"
    # SQLAlchemy SQLite URLs want forward slashes, even on Windows.
    db_str = db_file.as_posix()
    dsn_async = f"sqlite+aiosqlite:///{db_str}"
    dsn_sync = f"sqlite:///{db_str}"
    os.environ["CCF_DATABASE_URL"] = dsn_async
    os.environ["CCF_DATABASE_URL_SYNC"] = dsn_sync
    os.environ["CCF_READONLY"] = "true"
    os.environ["CCF_LOG_LEVEL"] = os.environ.get("CCF_LOG_LEVEL", "WARNING")

    workbook = _find_workbook(exe_dir, data_dir)
    asyncio.run(_init_and_maybe_ingest(dsn_async, workbook))

    host = "127.0.0.1"
    port = _wait_free_port(host, 8088)
    url = f"http://{host}:{port}"

    # Open the browser shortly after uvicorn starts.
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    print(f"[Concord Reader] {url}  (Ctrl-C to quit)", flush=True)

    # Clear cached settings so CCF_READONLY is picked up.
    from ..config import get_settings
    try:
        get_settings.cache_clear()  # type: ignore[attr-defined]
    except AttributeError:
        pass

    import uvicorn
    uvicorn.run("ccf.api.main:app", host=host, port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
