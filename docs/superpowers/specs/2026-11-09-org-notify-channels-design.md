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
- `ops_notify_threads` — the ops Slack thread per organization: `organization_id`, `channel`,
  `thread_ts`, `created_at`, **unique on (`organization_id`, `channel`)** rather than on
  `organization_id` alone (as built, migration 0120): pointing `CCF_NOTIFY_SLACK_CHANNEL` at
  another channel starts new threads there instead of replying to parents in a channel no longer
  used. Platform-owned: no tenant may read or write it (`ccf_app` holds no privilege on it, and
  RLS is forced with a policy admitting only an unscoped session); written only by the consumer,
  on its own unscoped session.

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
  open one thread. The parent is written in its own committed transaction, so a reply that fails
  and retries never opens a second parent. Then post the alert with `thread_ts`. An org-less alert
  posts at the top level, tagged `[Platform]`.
- **A gone or locked thread.** If Slack reports the parent unusable -- `thread_not_found`,
  `invalid_thread_ts`, `message_not_found`, `cannot_reply_to_message`, or
  `restricted_action_thread_locked` (a lock is per thread, so dead-lettering would lose every later
  alert of that org) -- drop the row, open a new thread **once**, and reply there; a second refusal
  is retried like any other. **Unverified:** Slack's chat.postMessage reference (checked
  2026-11-09) names no error for a deleted or unknown `thread_ts`, and Slack may instead accept
  the reply and post it at the top level. Both are handled: an error code above reopens the
  thread; an accepted reply whose `message.thread_ts` is not the thread's means it went to the top
  level, so the row is dropped and the next alert opens a new parent (that one alert is at the
  top, untagged).
- **Slack errors**: Slack answers HTTP 200 with `{"ok": false, "error": ...}`, classified against
  the documented chat.postMessage error list:
  - **retry** -- rate limits (`ratelimited`, `rate_limited`, `message_limit_exceeded`, HTTP 429),
    Slack-side faults (`internal_error`, `fatal_error`, `service_unavailable`,
    `request_timeout`), workspace migrations, 5xx, and any code not listed. `Retry-After` is
    honoured, **capped at 15 minutes**, and never shortens the normal backoff;
  - **final** (dead-lettered at once; `last_error` names Slack's code, never the token) -- the
    token (`invalid_auth`, `not_authed`, `token_revoked`, `token_expired`, `account_inactive`,
    ...), its scopes and permissions (`missing_scope`, `no_permission`, ...), the channel
    (`channel_not_found`, `not_in_channel`, `is_archived`, read-only and other restricted actions
    except a locked thread), workspace policy, malformed requests (`invalid_arguments`, `no_text`,
    `msg_too_long`, ...), and HTTP 4xx other than 408/429. The full set is
    `ccf.governance.slack.FINAL_ERRORS`.
- **Text.** Every outbound text is escaped for its destination, decided at send time from the
  URL's host: Slack (the bot API, `hooks.slack.com`, `hooks.slack-gov.com`) gets `&`, `<`, `>` as
  entities; any other webhook gets Markdown metacharacters backslash-escaped and `@channel`,
  `@here`, `@all`, `@everyone` given a full-width `@`. It is then cut to **3,000 characters**,
  ending "… (truncated)", so `msg_too_long` (kept final as a backstop) cannot dead-letter an
  alert.
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
