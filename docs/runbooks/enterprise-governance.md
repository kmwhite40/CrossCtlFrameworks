# Guide — Enterprise governance layer

Turns the compliance data model into a living program: continuous monitoring,
a cross-module work queue, alerts, policies, vendors, an artifact/evidence
intake API, diagramming, quantitative risk scoring, and an event bus that lets
everything (and external systems) communicate.

## The interoperability backbone

Every module calls `ccf.governance.bus.emit(...)` when something happens. `emit`
writes an append-only `Event` (the activity feed) **and** fans it out to
subscribed `Webhook`s (HMAC-signed). `bus.notify(...)` raises de-duplicated
`Notification`s. Records cross-reference each other by generic
`entity_type` + `entity_id`, so modules interoperate without hard coupling.

- `GET /api/events` — activity feed
- `GET/POST/DELETE /api/webhooks` — outbound subscriptions (`X-CCF-Signature: sha256=…`)

## Continuous monitoring (ConMon)

Control health is derived from three live signals: evidence freshness
(`expires_on`), assessment recency (`next_assessment_due`), and open POA&Ms.
Status escalates `healthy → due_soon → at_risk → overdue`.

```bash
GET  /api/conmon/health   # live rollup + controls needing attention (read-only)
POST /api/conmon/scan     # generate tasks + alerts for unhealthy controls
GET  /api/conmon/runs     # scan history
ccf conmon-scan           # same scan from the CLI (cron it)
```

A scan opens one auto `Task` per unhealthy control (idempotent by `dedupe_key`;
a human closing a task is respected on re-scan) and one `Notification`.

## Work queue (tasks)

`GET/POST /api/tasks`, `PATCH /api/tasks/{id}` — assignments, priority, due
dates, status (`open|in_progress|blocked|done|cancelled`), linked to any entity.

## Alerts + digest

`GET /api/notifications` (unread inbox), `POST /api/notifications/{id}/read`,
`POST /api/notifications/read-all`. The org-level digest raises cross-module
alerts (ATO expiry, catalog drift, overdue POA&M load, policy/vendor reviews):

```bash
POST /api/notifications/scan   #  or:  ccf notify-digest
```

## Evidence collection API + artifact store

Automated collectors push proof of a control here (content-addressed, deduped):

```bash
curl -X POST /api/evidence/collect \
  -F implementation_id=42 -F title="MFA export" -F kind=config_export \
  -F expires_on=2026-12-31 -F file=@mfa.json
GET /api/artifacts            # list
GET /api/artifacts/{id}/download
```

Emits a `captured` event; links `Evidence.artifact_id → Artifact` (SHA-256).

## Diagramming (Mermaid)

```bash
GET /api/diagrams/systems/{id}/authorization-boundary
GET /api/diagrams/systems/{id}/control-coverage
GET /api/diagrams/system-landscape
```

Returns Mermaid source; the `/governance` page renders it client-side, and the
same text pipes to mermaid-cli / Kroki for SVG/PNG in a document pipeline.

## Policies & vendors (TPRM)

- `GET/POST /api/policies`, `POST /api/policies/{id}/versions`,
  `POST /api/policies/versions/{vid}/attest` — policy lifecycle + attestation.
- `GET/POST /api/vendors`, `PATCH /api/vendors/{id}` — third-party register with
  criticality, risk rating, authorization (inheritance), review cadence.

## Quantitative risk scoring

The risk register now computes an inherent exposure (likelihood × impact, 1-25)
and a residual score discounted by treatment, plus a band. Automatic on
create/update of `/api/risks`.

## UI

`/governance` is the command center: control-health %, work queue, alerts,
activity feed, and a diagram viewer. "Run ConMon scan" triggers a scan + digest.

## Operate on a schedule

Wrap the two scans in host cron / CI (they are idempotent):

```bash
ccf conmon-scan     # daily — refresh control health, open work
ccf notify-digest   # daily — portfolio alerts
```
