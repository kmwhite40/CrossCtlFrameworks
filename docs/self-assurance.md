# Concord self-assurance (Concord-on-Concord)

Concord continuously assesses **itself**. A seeded *Concord Platform* system carries
Concord's own controls, evidenced by the platform's reliability checks, scored by
the evidence-confidence engine, and exportable as an authorization package that can
be diffed and replayed like any other.

## Control areas

| Self-control | What it asserts | Evidenced by (reliability check) |
|---|---|---|
| `CSA-RLS` | Row-level security on tenant tables | `required_tables`, `database_connectivity` |
| `CSA-AUDIT` | Tamper-evident audit hash-chain | `audit_log_write_path` |
| `CSA-MIGRATIONS` | Schema managed by reversible migrations | `alembic_migration_status` |
| `CSA-SUPPLY` | SBOM + dependency + container scanning | CI (SBOM/Trivy/pip-audit) — planned/CI-verified |
| `CSA-AI` | AI actions citation-first + human-approved | `ai_disabled_safe_default`, `ai_guardrail_violations` |

The self-controls come from the bundled **`concord-self-assurance`** compliance
pack (see the pack runtime). `run` maps each control to its reliability checks:
all-pass → `implemented`, any-warn → `partial`, any-fail → `not_implemented`, and
controls with no runtime check (supply chain, verified in CI) → `planned`.

## Usage

```sh
ccf self-assess init            # seed system + install the self pack + stub controls/evidence
ccf self-assess run             # run reliability checks → self-controls + scored evidence
ccf self-assess status          # readiness % + per-control status
ccf self-assess export-package  # export Concord's own authorization package
```

Or over the API (admin role):

- `POST /api/admin/self-assurance/init`
- `POST /api/admin/self-assurance/run`
- `GET  /api/admin/self-assurance/status`
- `GET  /api/admin/self-assurance/package`

UI: **/admin/self-assurance** (Governance → Self-assurance).

## How it composes

- **Pack runtime** supplies the control/evidence definitions (`concord-self-assurance`).
- **Reliability checks** supply the evidence (their pass/warn/fail results).
- **Evidence repository + confidence** version and score each control's evidence.
- **Authorization package** export captures the self-assurance facts, so Concord's
  own posture can be diffed and replayed over time exactly like a customer system.

Everything runs in local/dev with no external services.
