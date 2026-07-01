# Guide — ODP fill-in-the-blank, canned statements, and config-capture

The SSP builder composes implementation statements in three layers, each
feeding the next:

```
Canned statement template   →   ODP fill-in-the-blank   →   Auto-populate from live config
(reusable per control)          ({{param}} placeholders)     (MS Graph / AWS GovCloud)
```

## 1. Organization-defined parameters (ODPs)

Each CMMC L2 practice carries `odp_definitions` — the "fill-in-the-blank" slots
(a period, a frequency, a condition). They come from a curated 800-171 overlay
(`ccf.ssp.odp.CURATED_ODP_171`) plus any `[Assignment:]`/`[Selection:]` markers
parsed from the requirement/objective text. Seed/refresh them with:

```bash
ccf scoring-seed         # re-derives odp_definitions for all 110 practices
```

In the SSP editor, each control with ODPs shows fill-in fields; values are saved
per control on `SSPControlEntry.odp_values`.

## 2. Canned implementation statements

A reusable library (`ccf.statement_templates`) of statement bodies with
`{{odp_key}}` and `{{environment}}` / `{{services}}` tokens. Load it with:

```bash
ccf templates-seed            # add missing; --overwrite to refresh bodies
```

- `GET /api/ssp/templates?domain=AU` — templates offered to a control
- `POST /api/ssp/projects/{id}/entries/{control_id}/apply-template` —
  render `{template_key}` with the entry's ODP values + platform context; the
  response includes `missing_odps` (parameters still blank). In the UI, pick a
  template in the editor and Save — it renders and appends.

Scope precedence when matching a control: `control` > `domain` > `global`.

## 3. Config-capture connectors

Populate ODP values from live cloud configuration instead of by hand.

```bash
GET  /api/ssp/connectors                              # list + configured? + parameter_map
POST /api/ssp/projects/{id}/autofill?connector=msgraph            # dry run (default)
POST /api/ssp/projects/{id}/autofill?connector=msgraph&apply=true # merge into odp_values
```

- **msgraph** (M365 Government / GCC High) — client-credentials OAuth against
  `graph.microsoft.us`. Configure `CCF_GRAPH_TENANT_ID`, `CCF_GRAPH_CLIENT_ID`,
  `CCF_GRAPH_CLIENT_SECRET` (app registration with `Policy.Read.All`). Maps e.g.
  Conditional Access sign-in frequency → session-lock period (3.1.10).
- **aws_govcloud** — uses `boto3` (`us-gov-west-1` by default); set
  `CCF_AWS_CAPTURE_ENABLED=true` and provide standard AWS credentials. Maps e.g.
  CloudWatch Logs retention → audit retention period (3.3.1).

Until credentials are set, a connector reports `configured: false` and returns
its `parameter_map` so you can see what it *would* pull. `capture()` is
best-effort — it returns `[]` on any error and never breaks the request. A
dry-run (`apply=false`) previews per-control matches without writing.

**Adding a connector:** subclass `ccf.connectors.base.ConfigConnector`
(`key`, `label`, `PARAMETER_MAP`, `is_configured`, `capture`) and register it in
`ccf.connectors._REGISTRY`. The autofill endpoint matches `CapturedParameter.nist_id`
to each SSP entry, so no route changes are needed.
