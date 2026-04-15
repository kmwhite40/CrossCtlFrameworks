# Runbook — Build Concord Reader `.exe` (Windows)

Copyright © 2026 Colleen Townsend. All rights reserved.

**Audience:** release engineer producing the standalone read-only distribution
of Concord for analysts on locked-down Windows workstations.

**Outcome:** `dist\ConcordReader.exe` — a single file that, when
double-clicked, starts the Concord UI at `http://127.0.0.1:8088` backed by a
local SQLite database under `%LOCALAPPDATA%\Concord\concord.db`. No Docker,
no Postgres, no Python install required on the target machine.

---

## 0. Pre-flight

| Item | Minimum | Verify |
|---|---|---|
| Windows 10/11 x64 | 22H2+ | `winver` |
| Python 3.12 | | `py -3.12 --version` |
| PowerShell 7+ | (or Windows PowerShell 5.1) | `$PSVersionTable.PSVersion` |
| Git | | `git --version` |

Build on the platform you're shipping for. Cross-platform PyInstaller builds
do **not** work — build the Windows `.exe` on Windows.

---

## 1. Clone & install

```powershell
git clone https://github.com/kmwhite40/CrossCtlFrameworks.git
cd CrossCtlFrameworks
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[reader]"
```

The `reader` extra pulls in `pyinstaller`.

---

## 2. (Optional) Stage the workbook

If you want analysts to have data on first launch, place the workbook
next to where the `.exe` will land. The launcher checks, in order:

1. `<exe>\NIST Cross Mappings Rev. 1.1.xlsx`
2. `<exe>\data\NIST Cross Mappings Rev. 1.1.xlsx`
3. `%LOCALAPPDATA%\Concord\NIST Cross Mappings Rev. 1.1.xlsx`
4. any `*.xlsx` next to the exe

If none is found and the DB is empty, the Reader starts with an empty
catalog and shows an empty-state page. Analysts can drop a workbook later.

---

## 3. Build

```powershell
pyinstaller concord_reader.spec --clean --noconfirm
```

Expected timing: 60–120 s on first build; ~30 s incremental. Output:

```
dist\ConcordReader.exe   # ~70-90 MB single file
build\                   # working dir (safe to delete)
```

### Per-build verification

```powershell
.\dist\ConcordReader.exe
```

- Console prints `[Concord Reader] http://127.0.0.1:8088  (Ctrl-C to quit)`
- Default browser opens at that URL.
- Sidebar shows **Catalog** + **Reader mode** groups only (Operations /
  Admin hidden because `CCF_READONLY=true`).
- Any `POST/PUT/PATCH/DELETE` request returns HTTP 403.

Quit with Ctrl-C; re-run to confirm idempotent startup (no re-ingest when
the DB is already populated).

---

## 4. Sign the binary (recommended)

SmartScreen will block unsigned `.exe`s downloaded from the internet.
Authenticode-sign before distribution:

```powershell
signtool sign `
  /tr http://timestamp.digicert.com `
  /td sha256 `
  /fd sha256 `
  /f concord-signing.pfx `
  /p "$env:PFX_PASSPHRASE" `
  dist\ConcordReader.exe
```

Verify:

```powershell
signtool verify /pa /v dist\ConcordReader.exe
```

---

## 5. (Optional) Wrap in Inno Setup

For a proper installer with Start Menu shortcut and uninstall:

1. Install Inno Setup from https://jrsoftware.org/isdl.php
2. Create `installer\concord-reader.iss`:

```ini
[Setup]
AppName=Concord Reader
AppVersion=0.2.0
AppPublisher=Colleen Townsend
DefaultDirName={autopf}\Concord Reader
DefaultGroupName=Concord Reader
UninstallDisplayIcon={app}\ConcordReader.exe
OutputBaseFilename=ConcordReaderSetup
OutputDir=..\dist
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "..\dist\ConcordReader.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Concord Reader"; Filename: "{app}\ConcordReader.exe"
Name: "{autodesktop}\Concord Reader"; Filename: "{app}\ConcordReader.exe"; Tasks: desktopicon

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\ConcordReader.exe"; Description: "Launch Concord Reader"; Flags: postinstall nowait skipifsilent
```

3. Build: `iscc installer\concord-reader.iss` → `dist\ConcordReaderSetup.exe`.

---

## 6. Distribute

- Internal share / intranet: hand over `ConcordReader.exe` or the installer.
- `SHA-256` it before shipping so recipients can verify:
  ```powershell
  Get-FileHash dist\ConcordReader.exe -Algorithm SHA256
  ```
- For each release bump `__version__` in `src/ccf/__init__.py` and in
  `CHANGELOG.md`.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ImportError: email_validator` at runtime | Add it to `hiddenimports` in `concord_reader.spec` (already listed). |
| `TemplateNotFound` | Confirm `datas` in the spec still ships `src/ccf/api/templates`. |
| `aiosqlite` not found | Confirm `collect_all("sqlalchemy")` picked up aiosqlite or add it to `hiddenimports`. |
| Browser doesn't open | Launcher falls back to printing the URL. Paste it manually. |
| `sqlite3.OperationalError: no such table: ccf.controls` | Schema wasn't created. Delete `%LOCALAPPDATA%\Concord\concord.db` and re-run. |
| SmartScreen "Windows protected your PC" | Binary isn't code-signed yet. Step 4. |
| Port 8088 busy | Launcher auto-increments until it finds a free port. |

---

## 8. What the Reader does NOT do

Deliberate omissions vs. the full Docker platform (see `docs/ARCHITECTURE.md`):

- No writes (systems, POA&Ms, evidence, risks, users) — blocked at the
  middleware.
- No Postgres-only features: `tsvector` FTS, `pg_trgm` substring search,
  `GIN(JSONB)`, SCD-2 provenance history.
- No `/diff`, `/ingestions`, `/quarantine` pages (those rely on the
  Postgres-only audit schema).
- No OSCAL export, no reports targeting operational data — those query
  `control_implementations`.

Analysts can still: browse the control catalog, read per-control details
and mappings, search controls, search mappings, view coverage heatmap,
browse worksheets.

---

*End of runbook — Concord Reader build.*
