# Runbook — Install & Run Docker on Windows (for Concord)

Copyright © 2026 Colleen Townsend. All rights reserved.

**Audience:** an operator standing up Concord on a Windows 10/11 workstation
or VM for the first time.
**Outcome:** Docker Desktop running, Concord brought up via `docker compose`,
the Postgres schema migrated, the workbook ingested, and the UI reachable at
`http://localhost:8088`.

---

## 0. Pre-flight checks

| Item | Minimum | How to verify |
|------|---------|---------------|
| Windows edition | Windows 10 64-bit (Pro/Enterprise/Education **22H2**) **or** Windows 11 64-bit | Run `winver` |
| RAM | 8 GB (16 GB recommended) | Task Manager → Performance |
| Free disk | 20 GB on `%USERPROFILE%` drive | `Get-PSDrive C` |
| CPU | x86_64 with **SLAT** + virtualization enabled in BIOS/UEFI | Task Manager → Performance → CPU → "Virtualization: Enabled" |
| Admin rights | Yes — required for Hyper-V / WSL install | `whoami /groups` shows `S-1-5-32-544` |

If "Virtualization" reports **Disabled**, reboot into BIOS/UEFI and enable
**Intel VT-x** or **AMD-V** (and **VT-d** / **AMD-Vi** if listed).

---

## 1. Enable Windows features (one-time)

Run an **Administrator PowerShell** and execute:

```powershell
# Enable WSL2 + Virtual Machine Platform
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Reboot before continuing
Restart-Computer
```

After reboot, install / update WSL and set version 2 as the default:

```powershell
wsl --install --no-distribution
wsl --set-default-version 2
wsl --update
wsl --status
```

Expected `wsl --status` output includes `Default Version: 2`.

(Optional but recommended) install an Ubuntu distro for a Linux shell:

```powershell
wsl --install -d Ubuntu-22.04
```

---

## 2. Install Docker Desktop

### Option A — Winget (preferred)

```powershell
winget install --id Docker.DockerDesktop --source winget --accept-source-agreements --accept-package-agreements
```

### Option B — Manual

1. Download **Docker Desktop for Windows** from
   <https://www.docker.com/products/docker-desktop/>.
2. Run `Docker Desktop Installer.exe` as Administrator.
3. On the configuration screen leave **Use WSL 2 instead of Hyper-V** ✅ checked.
4. Finish the installer, then **sign out** of Windows and back in (the
   installer adds your user to the `docker-users` local group).

---

## 3. First launch

1. Start **Docker Desktop** from the Start menu.
2. Accept the EULA. A free **personal** account is fine for individual use;
   Pro/Team/Business subscriptions are required for organizations >250
   employees or >$10 M revenue.
3. Wait for the whale icon in the system tray to turn solid (≈ 30–60 s on
   first boot — it's downloading the WSL2 distro `docker-desktop`).
4. Open **Settings → Resources → WSL Integration** and enable integration
   with any Ubuntu distro you installed.
5. **Settings → General**: enable
   - ✅ Use the WSL 2 based engine
   - ✅ Start Docker Desktop when you sign in to your computer
   - ✅ Enable integrated container runtime for Kubernetes (only if you need k8s)
6. Apply & Restart.

### Verify

Open a new PowerShell or Windows Terminal:

```powershell
docker --version              # e.g. Docker version 27.x.x
docker compose version        # e.g. Docker Compose version v2.30.x
docker run --rm hello-world   # downloads + runs the demo image
```

If `hello-world` prints the success message, Docker is operational.

---

## 4. Network & firewall

Docker Desktop publishes services on `localhost`. The Concord stack uses:

| Service | Host port |
|---------|-----------|
| API (FastAPI) | **8088** |
| Postgres | **5433** |

If those ports are in use on your machine, edit
`docker-compose.yml` and change the left-hand side of the `ports:` mapping,
e.g. `"9088:8000"`.

Windows Defender Firewall normally allows local-only traffic without prompt.
If you connect from another machine on the LAN, allow the port:

```powershell
New-NetFirewallRule -DisplayName "Concord API" -Direction Inbound -Protocol TCP -LocalPort 8088 -Action Allow
```

---

## 5. Get the code

Install Git (`winget install Git.Git`) and clone:

```powershell
cd $HOME
git clone https://github.com/kmwhite40/CrossCtlFrameworks.git
cd CrossCtlFrameworks
```

Place the workbook so the ETL container can see it:

```powershell
mkdir data -Force
Copy-Item "<path>\NIST Cross Mappings Rev. 1.1.xlsx" .\data\
```

---

## 6. Bring up Concord

```powershell
docker compose up -d db migrator api
```

What this does, in order:

1. Pulls `postgres:16-alpine` and starts the `ccf-db` container.
2. Builds the Concord image (~2 min first time).
3. Runs the `migrator` service which executes `alembic upgrade head` and exits.
4. Starts the `api` service on port 8088.

Wait for healthy status:

```powershell
docker compose ps
# look for ccf-db (healthy), ccf-api (healthy), ccf-migrator (Exited 0)
```

Run the ETL once to load the workbook:

```powershell
docker compose --profile etl run --rm etl
```

When it finishes you should see a JSON summary with row counts per sheet.

Open the UI:

```powershell
Start-Process http://localhost:8088
```

---

## 7. Day-to-day operations

```powershell
# Tail logs
docker compose logs -f api

# Restart just the API after a code change
docker compose build api
docker compose up -d api

# Open a Concord CLI prompt (Typer)
docker compose --profile cli run --rm cli stats
docker compose --profile cli run --rm cli show AC-01
docker compose --profile cli run --rm cli search "encryption"

# Drop into Postgres
docker exec -it ccf-db psql -U ccf -d ccf

# Stop everything (data persists in the named volume)
docker compose down

# Wipe data volume too (DESTRUCTIVE)
docker compose down -v
```

---

## 8. Updating Docker Desktop

Docker Desktop will prompt when an update is available. Apply during a
maintenance window:

1. Save work; close any containers you depend on (`docker compose down`).
2. Click **Update** in the Docker Desktop notification.
3. Approve the UAC prompt; the installer restarts the engine.
4. After it relaunches, run `docker version` to confirm.

---

## 9. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `docker: command not found` | Open a **new** terminal after install. If still missing, ensure `C:\Program Files\Docker\Docker\resources\bin` is on `PATH`. |
| Docker Desktop stuck on "Starting…" | Right-click whale icon → **Quit Docker Desktop**, then run `wsl --shutdown` in PowerShell, then relaunch. |
| `Bind for 0.0.0.0:8088 failed: port is already allocated` | Another process owns the port. `Get-Process -Id (Get-NetTCPConnection -LocalPort 8088).OwningProcess` to identify; either stop it or remap the port in `docker-compose.yml`. |
| `Bind for 0.0.0.0:5433 failed` | Same as above for Postgres. |
| Migrator exits with `schema "ccf" does not exist` | Old migration artifact. Run `docker exec ccf-db psql -U ccf -d ccf -c "DROP SCHEMA IF EXISTS ccf CASCADE; CREATE SCHEMA ccf;"`, then re-run `docker compose up migrator`. |
| `wsl --update` fails with 0x80370102 | Virtualization is disabled in BIOS. Re-check § 0. |
| API logs show `jinja2 must be installed` | Stale image cache. `docker compose build --no-cache api && docker compose up -d api`. |
| `IntegrityError: duplicate key value` during ingest | Stop, then `docker exec ccf-db psql -U ccf -d ccf -c "TRUNCATE ccf.framework_mappings, ccf.controls RESTART IDENTITY CASCADE;"` and re-run the ETL. |
| Slow file I/O between Windows and containers | Move the repo into the WSL filesystem (`\\wsl$\Ubuntu-22.04\home\<you>\…`) and run `docker compose` from inside WSL. |

Reset to a clean slate (last-resort):

```powershell
docker compose down -v
docker system prune -af --volumes
wsl --shutdown
```

Then start Docker Desktop again and go back to § 6.

---

## 10. Acceptance checklist

- [ ] `docker run --rm hello-world` succeeds.
- [ ] `docker compose ps` shows `ccf-db` and `ccf-api` as **healthy**.
- [ ] <http://localhost:8088/healthz> returns `{"status":"ok"}`.
- [ ] <http://localhost:8088/> renders the Concord dashboard with non-zero KPIs.
- [ ] <http://localhost:8088/docs> shows the OpenAPI Swagger UI.
- [ ] `docker compose --profile cli run --rm cli stats` lists row counts.

When every box is checked, the install is complete.

---

*End of runbook — Concord on Windows.*
