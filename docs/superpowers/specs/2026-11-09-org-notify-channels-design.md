# Alert channels per organization — design

Status: design approved by the owner 2026-11-09 (decisions in chat, recorded in section 2); built on
branch `feat/org-notify-channels`, stacked on `fix/event-bus-followups`.

## 1. Why

Concord has one Slack/Teams destination for the whole platform (`CCF_NOTIFY_WEBHOOK_URL`). Every
organization's alerts land in it, untagged, so an operator cannot tell whose alert is whose, and
a customer cannot get its own alerts at all. The owner wants:

- an **operator's ops channel** where each organization's alerts are grouped — on Slack, one
  thread per organization;
- each **organization's own channel**, which that organization's admins point wherever they like.

## 2. Owner decisions (2026-11-09)

1. Ops channel on Slack: **real threads, one per organization**, through the Slack Web API (a bot
   token). On Teams (incoming webhook, which cannot thread): **posts tagged `[Org name]`**, no
   threads. Graph-based Teams threads are out of scope.
2. Organizations may also have **their own channel**, in addition to the ops threads.
3. An organization's channel is set by **that organization's admins** (platform admins may too).
4. Customers never see the ops channel; it is the operator's, and the operator already sees every
   tenant's data. No tenant alert goes to another tenant's channel, ever.

## 3. Destinations

| Destination | Configured by | Where | Receives |
|---|---|---|---|
| Ops, Slack threads | operator | env: `CCF_NOTIFY_SLACK_BOT_TOKEN`, `CCF_NOTIFY_SLACK_CHANNEL` | every alert at or above `CCF_NOTIFY_MIN_SEVERITY`; an org's in that org's thread, an org-less one at top level |
| Ops, webhook (Slack or Teams) | operator | env: `CCF_NOTIFY_WEBHOOK_URL` (existing) | as above, each post prefixed `[Org name]` (org-less: `[Platform]`); used only when the Slack bot settings are not both set |
| Org channel | the org's admins | DB, encrypted | that org's alerts at or above the channel's own minimum severity |

Upgrade: a deployment with only `CCF_NOTIFY_WEBHOOK_URL` keeps receiving every alert there, now
tagged — nothing goes quiet.

## 4. Data

- `org_notify_channels` — one per organization: `organization_id` (unique, FK, RLS by org),
  `encrypted_url` (envelope-encrypted with a **purpose-specific AAD**, never the connector
  credential's), `url_hint` (scheme + host only (no path or query: the path carries the token), for display), `min_severity`
  (`info|warning|critical`, default `critical`), `enabled`, `created_by/at`, `updated_by/at`.
  The URL is a secret (anyone holding it can post to the channel): never returned by any API,
  never logged.
- `ops_notify_threads` — the ops Slack thread per organization: `organization_id` (unique),
  `channel`, `thread_ts`, `created_at`. Platform-owned: no tenant may read or write it (RLS deny
  for tenant sessions, written only by the consumer on an unscoped session).

## 5. Delivery

- `bus.notify` queues **one job per destination** (in the caller's transaction, as today): the ops
  job when ops is configured and severity passes, and the org job when the notification's org has
  an enabled channel and its severity passes. The destination rides in the job's `result`
  (`{"destination": "ops"|"org", "text": ...}`); scope stays `notification:N`. A failure at one
  destination never blocks the other.
- **Org job**: reads the channel at send time on the job's tenant; decrypts; sends through
  `webhook_url.pinned_target` (SSRF guard, DNS pinned). Channel removed or disabled since queueing
  → `skipped` (the admin turned it off; not an outage). Undecryptable → final failure.
- **Ops job (Slack threads)**: `chat.postMessage` to the configured channel. For an org alert,
  look up the org's `ops_notify_threads` row; if none, create the thread parent ("Alerts for
  {org name}") and store its `ts`, under a per-org transaction advisory lock so two first alerts
  open one thread. Then post the alert with `thread_ts`. If Slack reports the parent gone
  (`thread_not_found` / `message_not_found`), drop the row and open a new thread once.
- **Slack errors**: Slack answers HTTP 200 with `{"ok": false, "error": ...}`. `ratelimited`
  (or HTTP 429) retries; `invalid_auth`, `not_authed`, `account_inactive`, `token_revoked`,
  `channel_not_found`, `not_in_channel`, `is_archived`, `missing_scope` are final (a retry cannot
  fix them; the reliability check FAILs and names the error). Others retry.
- Retries, backoff and dead letters as the existing `notify_delivery` consumer (webhook schedule;
  4xx other than 408/429 final). Delivery is at least once.
- Severity and destination are decided at queue time; the URL/token is read at send time.

## 6. Managing an org channel

- API: `GET/PUT/DELETE /api/org/notify-channel`, `POST /api/org/notify-channel/test`.
  Admin of the org (or platform admin acting on an org) only; viewers and other roles 403.
  `GET` returns `url_hint`, `min_severity`, `enabled`, who/when — never the URL.
- `PUT` refuses a URL the SSRF guard refuses, or that is not `https`; sends a test post before
  saving and refuses to save if it fails (with the receiver's status). Each change writes an audit
  log entry and an event (dispatch false: it is settings, not news) — the URL never in either.
- UI: an "Alert channel" section on the organization settings page with the same operations; every
  form post carries its own admin check.
- A platform admin's view of an org's channel shows the same masked view.

## 7. Not in scope

Teams threads (Graph), several channels per organization or routing by system/category, per-user
channels, Slack OAuth app installation flow (the operator pastes a bot token).
