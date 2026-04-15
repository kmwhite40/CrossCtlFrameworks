# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Concord Reader (single-file exe).
# © 2026 Colleen Townsend. All rights reserved.
#
# Build:
#     pyinstaller concord_reader.spec --clean --noconfirm
# Output:
#     dist/ConcordReader.exe (Windows) / dist/ConcordReader (Unix)

from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_data_files

pkgs = ["uvicorn", "fastapi", "sqlalchemy", "alembic",
        "slowapi", "structlog", "openpyxl", "pydantic"]
datas, binaries, hiddenimports = [], [], []
for p in pkgs:
    d, b, h = collect_all(p)
    datas += d; binaries += b; hiddenimports += h

# Ship the web assets + templates + reader module resources.
datas += [
    ("src/ccf/api/templates", "ccf/api/templates"),
    ("src/ccf/api/static",    "ccf/api/static"),
    ("contracts",             "contracts"),
]

# Route modules imported dynamically by create_app().
hiddenimports += [
    f"ccf.api.routes.{m}" for m in [
        "controls", "coverage", "diff", "evidence", "frameworks", "health",
        "mappings", "oscal", "poams", "reports", "risks", "search",
        "systems", "ui", "users", "worksheets",
    ]
] + ["aiosqlite", "email_validator"]

block_cipher = None

a = Analysis(
    ["src/ccf/reader/launcher.py"],
    pathex=["src"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "pytest", "notebook", "IPython",
        # Reader uses SQLite only — drop the Postgres drivers to shrink the
        # binary and avoid PyInstaller hook issues on Windows wheels.
        "asyncpg", "psycopg", "psycopg2", "psycopg2-binary",
        # Unix-only event loops that creep in via uvicorn[standard].
        "uvloop",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ConcordReader",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # drop a .ico here for Windows branding
)
