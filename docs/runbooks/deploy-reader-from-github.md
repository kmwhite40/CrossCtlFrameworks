# Runbook — Deploy Concord Reader from GitHub

Copyright © 2026 Colleen Townsend. All rights reserved.

Two audiences, one document:

- **Maintainer** (cut a release and publish the `.exe`)
- **Operator / end user** (download and run the published `.exe`)

Repository: **https://github.com/kmwhite40/CrossCtlFrameworks**

---

## Part 1 — Maintainer: cut a release

### 1.1 Pre-flight

- Tree clean, tests green on `main` (`.github/workflows/ci.yml` passing).
- `CHANGELOG.md` updated with an entry for the version you're about to cut.
- `__version__` in `src/ccf/__init__.py` bumped.
- Runbook + docs reflect any behavior changes.

### 1.2 Pick a version

Concord follows **semver** (`MAJOR.MINOR.PATCH`). Two tag shapes are
accepted by the release workflow:

| Shape | Use when |
|---|---|
| `v0.2.0` | Unified release — app + Reader share a version. |
| `reader-v0.2.0` | Reader hotfix decoupled from the app version. |

Pre-releases: append `-rc.1`, `-beta.1`, etc. The workflow auto-flags these
as `prerelease` on the GitHub Release.

### 1.3 Tag and push

```sh
git tag v0.2.0
git push origin v0.2.0
```

The `release-reader.yml` workflow fires on `refs/tags/v*` and
`refs/tags/reader-v*`. Watch it:

```sh
gh run watch --repo kmwhite40/CrossCtlFrameworks
```

…or in the browser at **Actions → release-reader**.

### 1.4 What the workflow does

1. **Checkout** the tagged commit on `windows-latest`.
2. **Install** Python 3.12 + `pip install -e ".[reader]"` (pulls PyInstaller).
3. **Build** with `pyinstaller concord_reader.spec --clean --noconfirm`.
4. **Smoke test** — launches the exe, polls `GET /healthz` until 200
   (20 s budget), fails the release on timeout.
5. **Hash** — writes `dist/ConcordReader.exe.sha256`.
6. **Artifact** — uploads both files as a workflow artifact so you can
   download them even on a dry run.
7. **Release** — on a tag push, creates a GitHub Release and attaches
   `ConcordReader.exe` + the `.sha256` file. Body includes the hash
   verbatim.

### 1.5 Dry run without tagging

Release workflow supports `workflow_dispatch`:

```sh
gh workflow run release-reader.yml -f tag=v0.2.0-dryrun
```

Produces the artifact, skips the Release if `tag` is not a real tag ref.

### 1.6 (Recommended) Sign the binary

Unsigned `.exe`s trigger SmartScreen warnings and are usually blocked by
corporate AppLocker. Add these secrets to the repo:

- `PFX_B64` — base64 of the code-signing `.pfx`
- `PFX_PASSPHRASE`

Then add a step before **Publish GitHub Release** in
`.github/workflows/release-reader.yml`:

```yaml
- name: Sign exe
  shell: pwsh
  env:
    PFX_B64: ${{ secrets.PFX_B64 }}
    PFX_PASSPHRASE: ${{ secrets.PFX_PASSPHRASE }}
  run: |
    [IO.File]::WriteAllBytes("cert.pfx", [Convert]::FromBase64String($env:PFX_B64))
    & "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe" `
       sign /fd sha256 /td sha256 `
            /tr http://timestamp.digicert.com `
            /f cert.pfx /p $env:PFX_PASSPHRASE `
            dist\ConcordReader.exe
    Remove-Item cert.pfx
```

Re-hash after signing so the published `.sha256` matches the signed blob.

### 1.7 After publishing

- Verify the Release page shows both artifacts:
  `https://github.com/kmwhite40/CrossCtlFrameworks/releases/tag/v0.2.0`
- Copy the SHA-256 into your internal distribution announcement.
- If signed, users can verify:
  `signtool verify /pa /v ConcordReader.exe`

### 1.8 Rolling a release back

Delete the Release page *and* the git tag:

```sh
gh release delete v0.2.0 --yes
git push --delete origin v0.2.0
git tag -d v0.2.0
```

Then re-tag fresh. Avoid moving a tag that consumers may already have
pulled.

---

## Part 2 — Operator: install & run

Target: a Windows 10/11 machine that **does not** have Python, Docker,
or Postgres. Zero dependencies required beyond Windows itself.

### 2.1 Download

Open the latest Release:

**https://github.com/kmwhite40/CrossCtlFrameworks/releases/latest**

Download:

- `ConcordReader.exe` — the application (~70–90 MB)
- `ConcordReader.exe.sha256` — integrity hash

…or via PowerShell:

```powershell
$ver = "v0.2.0"
$base = "https://github.com/kmwhite40/CrossCtlFrameworks/releases/download/$ver"
Invoke-WebRequest "$base/ConcordReader.exe"        -OutFile ConcordReader.exe
Invoke-WebRequest "$base/ConcordReader.exe.sha256" -OutFile ConcordReader.exe.sha256
```

…or via the GitHub CLI:

```powershell
gh release download v0.2.0 --repo kmwhite40/CrossCtlFrameworks
```

### 2.2 Verify integrity

```powershell
$expected = (Get-Content .\ConcordReader.exe.sha256).Split(" ")[0].Trim()
$actual   = (Get-FileHash -Algorithm SHA256 .\ConcordReader.exe).Hash.ToLower()
if ($actual -eq $expected) { "OK: $actual" } else { throw "HASH MISMATCH: $actual != $expected" }
```

If the binary is code-signed, also:

```powershell
signtool verify /pa /v .\ConcordReader.exe
```

Do not proceed on mismatch — re-download or escalate.

### 2.3 (Optional) Place the workbook

If the distributor included a workbook, drop it next to the `.exe`
before first launch. The Reader auto-ingests any `*.xlsx` adjacent to
the executable (preferring the filename
`NIST Cross Mappings Rev. 1.1.xlsx`).

Skip this step for an empty start; you can ingest later by dropping an
xlsx into `%LOCALAPPDATA%\Concord\` and restarting the Reader.

### 2.4 Run

Double-click `ConcordReader.exe`.

On first run:

1. Windows may show **SmartScreen** ("Windows protected your PC").
   Click **More info → Run anyway**. Unsigned binaries always trigger
   this; signed ones do not.
2. A console window opens and prints
   `[Concord Reader] http://127.0.0.1:8088 (Ctrl-C to quit)`.
3. Your default browser opens at that URL showing the Concord dashboard.
4. Sidebar shows **Catalog** + **Reader mode · SQLite**. No
   Operations/Admin groups — this is by design.

### 2.5 What's where on disk

| Path | Purpose |
|---|---|
| `ConcordReader.exe` | The self-contained application. |
| `%LOCALAPPDATA%\Concord\concord.db` | The local SQLite catalog. |
| `%LOCALAPPDATA%\Concord\*.xlsx` | Optional workbook auto-loaded at startup. |

To move an existing catalog to another machine: copy the `concord.db`
file; it's standalone SQLite.

### 2.6 Update

Download a newer `ConcordReader.exe` from the Releases page and
overwrite the old file. The catalog DB under `%LOCALAPPDATA%\Concord\`
is preserved across upgrades. If the new version ingests a newer
workbook, it will do so on first launch.

### 2.7 Uninstall

- Delete `ConcordReader.exe`.
- (Optional) Delete `%LOCALAPPDATA%\Concord\` to remove the local
  database and any ingested workbooks.

### 2.8 Troubleshooting

| Symptom | Fix |
|---|---|
| SmartScreen blocks the exe | Click **More info → Run anyway**; talk to the distributor about code signing. |
| Browser doesn't open | Paste `http://127.0.0.1:8088` manually. The Reader prints the URL in the console. |
| "Port 8088 is in use" behavior | Reader auto-increments to the next free port; read the URL from the console. |
| Empty catalog after first run | No workbook was adjacent. Drop an `.xlsx` into `%LOCALAPPDATA%\Concord\` and relaunch. |
| HTTP 403 on any write attempt | Expected — Reader is read-only. Use the full Docker platform for writes. |
| Antivirus quarantines the exe | Submit the hash to your vendor's whitelist with the GitHub Release URL for provenance. |
| Crash with "no such table: ccf.controls" | Delete `%LOCALAPPDATA%\Concord\concord.db` and relaunch; the Reader recreates the schema. |

### 2.9 Uninstalling the full Concord app (separate product)

This runbook covers only the Reader. The Docker-based Concord platform
is installed and uninstalled via `docker compose` (see
`docs/runbooks/docker-on-windows.md`).

---

## Part 3 — Internal distribution (optional)

If your org does **not** want staff downloading from github.com directly:

1. Mirror the release artifact to an internal share / artifactory /
   S3 bucket / SharePoint.
2. Re-hash after copying; publish the hash with the link.
3. Update your internal wiki with the mirrored URL in place of
   `https://github.com/kmwhite40/…`.
4. If using SCCM / Intune, wrap `ConcordReader.exe` in a managed
   install script that:
   - Verifies the SHA-256.
   - Copies to `%ProgramFiles%\Concord Reader\`.
   - Creates a Start Menu shortcut.
   - Adds an uninstall entry.

The Inno Setup installer template in
`docs/runbooks/build-windows-exe.md` handles all four of those steps.

---

*End of runbook — Deploying Concord Reader from GitHub.*
