# OnlineMainServer

OnlineMainServer (OMS) is a FastAPI service for registering connector devices, ingesting scan results, brokering WebSocket commands and blobs, and exposing admin and bot HTTP APIs backed by SQLite.

## Features

The sections below document env vars, run instructions, and API examples. This list calls out capabilities that are easy to miss or only appear implicitly elsewhere.

### Platform and security

- **Database lifecycle**: SQLite schema is created/updated on startup (`init_db`); Docker and local runs both rely on this.
- **Role-based access control**: Permissions for bot users come from `ROLES_CONFIG_PATH` (default `./config/roles.json`), loaded at startup. Notification settings and bot endpoints enforce these roles.
- **Static assets**: Files under the project `static/` directory are served at `/static`.
- **Production mode**: If `APP_ENV` or `ENVIRONMENT` is `prod` or `production`, the browser admin session cookie is marked `Secure`, and `TGBOT_SERVICE_TOKEN` plus `OMS_ADMIN_SESSION_SECRET` must be set or the app will not start.
- **Custom validation errors** for `POST /update`: invalid envelopes return `400` with `{"detail":"Invalid update envelope.","errors":[...]}` instead of the generic FastAPI `422` shape.

### Background behavior

- **Blob retention**: A background loop deletes blob files and DB rows past `BLOB_RETENTION_SECONDS`, on the interval `BLOB_CLEANUP_INTERVAL_SECONDS`.
- **Notifications** (when `NOTIFICATIONS_ENABLED`): a status monitor tracks device online/offline for notification rules; a delivery worker batches pushes to tgbot when `NOTIFICATION_PUSH_BASE_URL` is set; stale deliveries are reconciled on startup (see [Notification architecture](#notification-architecture-milestone-6)).

### Admin HTTP API (`/admin/v1/*`, `X-ADMIN-KEY`)

Documented in part below; additionally:

- **Stores**: `GET /admin/v1/stores` (optional `include_inactive`), `GET /admin/v1/stores/{store_id}`, `PATCH /admin/v1/stores/{store_id}` for updates and active flag (deactivating a store with registered devices is allowed but logged).
- **Memberships**: `PUT /admin/v1/users/{user_id}/stores/{store_id}/membership` to create or update a user’s store membership and role, optionally setting their active store.
- **User lookup**: `GET /admin/v1/users/lookup` returns `409` with `ambiguous_username` and candidate list when a username matches more than one user.

### Browser admin UI (`/admin/*`)

Session-based UI (not `X-ADMIN-KEY`). Optional first-time admin via `OMS_ADMIN_BOOTSTRAP_USERNAME` / `OMS_ADMIN_BOOTSTRAP_PASSWORD` when no admin account exists.

- **Pages**: login/logout, dashboard summary, users (list, search, detail, ban/unban, membership management), stores (list, create, detail, update, memberships), devices (list, detail), enroll tokens (list, create).
- **Internationalization**: Russian (default) and English; language is switched via `GET /admin/set-language` (cookie-backed). UI strings are translated in-app.

### Bot service API (`/bot/v1/*`, `Authorization: Bearer <TGBOT_SERVICE_TOKEN>`)

Besides health, session, and notification endpoints documented below:

- **Invites**: `POST /bot/v1/invites/create`, `POST /bot/v1/invites/redeem`.
- **Stores and devices**: `GET /bot/v1/stores`, `GET /bot/v1/stores/{store_id}/devices`.
- **User context**: `POST /bot/v1/context/active_store`, `POST /bot/v1/context/active_device` for the bot user’s active store/device selection.
- **Scan results**: `GET /bot/v1/results/last` (latest result in the active store), `GET /bot/v1/devices/{device_id}/results/last` (latest for a device in the active store); both require the appropriate result-read permission.
- **Device status (bot)**: `GET /bot/v1/devices/{device_id}/status` — same online/connected semantics as admin, plus permission-derived hints such as whether the user may request a photo or tare (for UI gating).
- **Device commands (async)**: `POST /bot/v1/devices/{device_id}/commands` records a command, delivers it over the connector WebSocket, and returns when the device responds (with timeout). Use `GET /bot/v1/commands/{command_id}` to poll status by `command_id` for commands tied to that user. For `camera.capture` successes, `GET /bot/v1/commands/{command_id}/photo` returns the image bytes when ready.
- **Membership exit**: `POST /bot/v1/memberships/revoke_self` lets a bot user leave a store membership according to server rules.

### Connector realtime

- **WebSocket heartbeats**: `WS_HEARTBEAT_TIMEOUT_SECONDS` controls how long the server waits for connector heartbeat traffic before treating the connection as timed out (see server logs / `realtime` module behavior).

## Environment variables

Set these before starting the app:

- `ADMIN_KEY` (required; OMS fails to start if missing)
- `SECRET_SALT` (required, used for `SHA-256(token + SECRET_SALT)`)
- `OMS_ADMIN_SESSION_SECRET` (required in production for browser admin sessions)
- `TGBOT_SERVICE_TOKEN` (required in production for `/bot/v1/*` service auth)
- `DATABASE_PATH` (optional, default: `./data/onlinemainserver.db`)
- `ROLES_CONFIG_PATH` (optional, default: `./config/roles.json`)
- `BLOB_STORAGE_DIR` (optional, default: `./data/blobs`)
- `MAX_BLOB_SIZE_BYTES` (optional, default: `52428800` / 50 MB)
- `ONLINE_THRESHOLD_SECONDS` (optional, default: `60`)
- `WS_HEARTBEAT_TIMEOUT_SECONDS` (optional, default: `60`)
- `COMMAND_DEFAULT_TIMEOUT_SECONDS` (optional, default: `15`)
- `BLOB_RETENTION_SECONDS` (optional, default: `86400` / 24h)
- `BLOB_CLEANUP_INTERVAL_SECONDS` (optional, default: `300` / 5m)
- `NOTIFICATIONS_ENABLED` (optional, default: `true`)
- `NOTIFICATION_STARTUP_GRACE_SECONDS` (optional, default: `120`)
- `DEFECT_NOTIFICATION_DEDUP_SECONDS` (optional, default: `10`)
- `NOTIFICATION_PUSH_BATCH_SIZE` (optional, default: `10`)
- `ANNOTATED_IMAGE_CACHE_TTL_SECONDS` (optional, default: `43200` / 12h)
- `NOTIFICATION_PUSH_BASE_URL` (optional, default: empty; when set OMS will push notification batches to tgbot)
- `NOTIFICATION_PUSH_ENDPOINT_PATH` (optional, default: `/internal/notifications/push`)
- `NOTIFICATION_PUSH_TIMEOUT_SECONDS` (optional, default: `10`)
- `NOTIFICATION_PUSH_POLL_INTERVAL_SECONDS` (optional, default: `2`)
- `NOTIFICATION_STATUS_POLL_INTERVAL_SECONDS` (optional, default: `2`)
- `OMS_ADMIN_BOOTSTRAP_USERNAME` (optional; when set with password and no admin exists, creates initial admin account)
- `OMS_ADMIN_BOOTSTRAP_PASSWORD` (optional; used with `OMS_ADMIN_BOOTSTRAP_USERNAME`)

Example:

```bash
export ADMIN_KEY="change-me-admin-key"
export SECRET_SALT="change-me-long-random-salt"
export OMS_ADMIN_SESSION_SECRET="change-me-admin-session-secret"
export TGBOT_SERVICE_TOKEN="change-me-bot-service-token"
export DATABASE_PATH="./data/onlinemainserver.db"
export ROLES_CONFIG_PATH="./config/roles.json"
export BLOB_STORAGE_DIR="./data/blobs"
export MAX_BLOB_SIZE_BYTES="52428800"
export ONLINE_THRESHOLD_SECONDS="60"
export WS_HEARTBEAT_TIMEOUT_SECONDS="60"
export COMMAND_DEFAULT_TIMEOUT_SECONDS="15"
export BLOB_RETENTION_SECONDS="86400"
export BLOB_CLEANUP_INTERVAL_SECONDS="300"
export NOTIFICATIONS_ENABLED="true"
export NOTIFICATION_STARTUP_GRACE_SECONDS="120"
export DEFECT_NOTIFICATION_DEDUP_SECONDS="10"
export NOTIFICATION_PUSH_BATCH_SIZE="10"
export ANNOTATED_IMAGE_CACHE_TTL_SECONDS="43200"
export NOTIFICATION_PUSH_BASE_URL="http://tgbot:8081"
export NOTIFICATION_PUSH_ENDPOINT_PATH="/internal/notifications/push"
export NOTIFICATION_PUSH_TIMEOUT_SECONDS="10"
export NOTIFICATION_PUSH_POLL_INTERVAL_SECONDS="2"
export NOTIFICATION_STATUS_POLL_INTERVAL_SECONDS="2"
export OMS_ADMIN_BOOTSTRAP_USERNAME="superadmin"
export OMS_ADMIN_BOOTSTRAP_PASSWORD="change-me-admin-password"
```

## Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Admin interfaces

- Machine/admin automation API remains at `/admin/v1/*` and uses `X-ADMIN-KEY`.
- Human browser UI is served by OMS at `/admin/*` and uses session login.
- Browser clients must not use `X-ADMIN-KEY`, `SECRET_SALT`, or other machine secrets.

## Docker

Copy `.env.example` to `.env`, set `ADMIN_KEY` and `SECRET_SALT` (and `TGBOT_SERVICE_TOKEN` for production), then:

**Build:**
```bash
docker build -t onlinemainserver .
```

**Run (standalone):**
```bash
docker run -d --name oms -p 8080:8080 --env-file .env -v oms_data:/app/data onlinemainserver
```

**Run with Docker Compose:**
```bash
docker compose up -d
```

The app listens on port 8080. Data (SQLite DB and blobs) is persisted in the `oms_data` volume. Migrations run automatically on startup via `init_db`.

**Post-startup setup:** Seed the stores table before creating enroll tokens (see "Seed stores table" below). With Docker, use the admin API:

```bash
curl -sS -X POST "http://127.0.0.1:8080/admin/v1/stores" \
  -H "Content-Type: application/json" \
  -H "X-ADMIN-KEY: ${ADMIN_KEY}" \
  -d '{"display_name": "Store 1", "is_active": true}'
```

## Bot service endpoints

All `/bot/v1/*` endpoints require:

- `Authorization: Bearer <TGBOT_SERVICE_TOKEN>`

Health check:

```bash
curl -sS "http://127.0.0.1:8000/bot/v1/health" \
  -H "Authorization: Bearer ${TGBOT_SERVICE_TOKEN}"
```

Ensure bot session:

```bash
curl -sS -X POST "http://127.0.0.1:8000/bot/v1/session/ensure" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TGBOT_SERVICE_TOKEN}" \
  -d '{
    "provider": "telegram",
    "provider_user_id": "123456789",
    "provider_chat_id": "123456789",
    "username": "example_user",
    "display_name": "Example User"
  }'
```

## Admin user ban/unban

Admins can lookup bot users and update ban state:

- `GET /admin/v1/users/lookup?provider=telegram&provider_user_id=<ID>`
- `GET /admin/v1/users/lookup?provider=telegram&username=<USERNAME>`
- `PATCH /admin/v1/users/{user_id}`
- Header: `X-ADMIN-KEY: <ADMIN_KEY>`

Lookup example:

```bash
curl -sS "http://127.0.0.1:8000/admin/v1/users/lookup?provider=telegram&username=@example_user" \
  -H "X-ADMIN-KEY: ${ADMIN_KEY}"
```

Ban/unban update example:

```bash
curl -sS -X PATCH "http://127.0.0.1:8000/admin/v1/users/<USER_ID>" \
  -H "Content-Type: application/json" \
  -H "X-ADMIN-KEY: ${ADMIN_KEY}" \
  -d '{"is_banned": true, "reason": "policy_violation"}'
```

## Seed stores table (required for enroll tokens)

`POST /admin/v1/enroll_tokens` only accepts active stores that already exist in `stores`.

Manual seed example:

```bash
sqlite3 "${DATABASE_PATH}" "
INSERT INTO stores (store_id, name, address, is_active, created_at)
VALUES ('store-1', 'Store 1', NULL, 1, datetime('now'))
ON CONFLICT(store_id) DO UPDATE SET is_active = 1;
"
```

## Create enroll token (admin)

```bash
curl -sS -X POST "http://127.0.0.1:8000/admin/v1/enroll_tokens" \
  -H "Content-Type: application/json" \
  -H "X-ADMIN-KEY: ${ADMIN_KEY}" \
  -d '{
    "store_id": "store-1",
    "expires_in_sec": 600,
    "max_uses": 1,
    "note": "initial pair"
  }'
```

## Connector registration call

Use the `enroll_token` from the admin response:

```bash
curl -sS -X POST "http://127.0.0.1:8000/connector/v1/register" \
  -H "Content-Type: application/json" \
  -d '{
    "enroll_token": "<ENROLL_TOKEN>",
    "device_info": {
      "label": "Kitchen Display",
      "hostname": "kiosk-01",
      "os": "linux",
      "connector_version": "1.0.0"
    }
  }'
```

## Scan ingestion update call

Send scan envelopes with the connector `device_token` returned by registration:

```bash
curl -sS -X POST "http://127.0.0.1:8000/update" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <DEVICE_TOKEN>" \
  -H "Idempotency-Key: <IMAGE_ID>" \
  -d '{
    "envelope_version": "v1",
    "sent_at": "2026-03-01T23:40:00Z",
    "image_id": "<IMAGE_ID>",
    "scan_result": {
      "session_id": "session-1",
      "image_id": "<IMAGE_ID>",
      "timestamp": "2026-03-01T23:39:59Z",
      "weight_grams": 120.5,
      "fruits": []
    }
  }'
```

Response:

- First ingestion: `200` with `{"status":"ok","duplicate":false}`
- Duplicate for same `(device_id, image_id)`: `409` with `{"status":"ok","duplicate":true}`
- OMS treats `200`, `201`, `202`, and `409` as successful processing outcomes.
- Legacy `scan_id` payloads are invalid and rejected with `400`.

## Connector WebSocket endpoint

Connectors open a websocket to receive on-demand commands:

- `GET /connector/v1/ws`
- Auth header is required: `Authorization: Bearer <DEVICE_TOKEN>`

Example with `websocat`:

```bash
websocat -H="Authorization: Bearer <DEVICE_TOKEN>" \
  ws://127.0.0.1:8000/connector/v1/ws
```

## Device online status (admin)

OMS stores device `last_seen_at` (UTC) on connector WS connect and on every inbound WS message.

Online/offline is computed by:

```text
now_utc - last_seen_at <= ONLINE_THRESHOLD_SECONDS
```

Endpoints:

- `GET /admin/v1/stores/{store_id}/devices` (header: `X-ADMIN-KEY`)
- `GET /admin/v1/devices/{device_id}/status` (header: `X-ADMIN-KEY`)

The response includes both:

- `connected`: current in-memory websocket presence
- `online`: computed from persisted `last_seen_at` and `ONLINE_THRESHOLD_SECONDS`

## Admin command dispatch endpoint

For manual testing (before Telegram bot integration), dispatch commands as admin:

- `POST /admin/v1/devices/{device_id}/commands`
- Header: `X-ADMIN-KEY: <ADMIN_KEY>`

Example:

```bash
curl -sS -X POST "http://127.0.0.1:8000/admin/v1/devices/<DEVICE_ID>/commands" \
  -H "Content-Type: application/json" \
  -H "X-ADMIN-KEY: ${ADMIN_KEY}" \
  -d '{
    "request_type": "ping",
    "params": {}
  }'
```

If the connector does not answer in time, OMS returns `504`.

## Blob upload endpoint (connector)

For `camera.capture`, upload binary bytes over HTTP:

- `POST /connector/v1/blobs`
- Header: `Authorization: Bearer <DEVICE_TOKEN>`
- Body: `multipart/form-data` with required `file` field and optional `image_id`, `content_type`, `sha256`.
- Files larger than `MAX_BLOB_SIZE_BYTES` are rejected with HTTP `413`.

Example:

```bash
curl -sS -X POST "http://127.0.0.1:8000/connector/v1/blobs" \
  -H "Authorization: Bearer <DEVICE_TOKEN>" \
  -F "file=@./capture.jpg" \
  -F "image_id=image-123"
```

## Blob download endpoint (admin)

For debugging, admins can fetch stored bytes:

- `GET /admin/v1/blobs/{blob_id}`
- Header: `X-ADMIN-KEY: <ADMIN_KEY>`

Example:

```bash
curl -sS "http://127.0.0.1:8000/admin/v1/blobs/<BLOB_ID>" \
  -H "X-ADMIN-KEY: ${ADMIN_KEY}" \
  --output blob.bin
```

## Notification architecture (Milestone 6)

OMS is the source of truth for notifications:

- detects notification events (`device_offline`, `device_online`, `defect_detected`)
- resolves eligible recipients (membership + ban checks + permissions + preferences)
- persists notification events and per-recipient deliveries
- pushes pending deliveries to tgbot internal endpoint
- reconciles per-delivery send results and retries temporary failures
- marks stale `pending`/`sending` deliveries as failed on startup

tgbot is only the delivery/UI layer. LocalConnector is only the image-fetch executor.

### Notification DB entities

OMS now initializes these tables at startup in `app/db.py`:

- `notification_events`
- `notification_deliveries`
- `notification_preferences`
- `annotated_image_cache`
- `device_notification_state` (restart-safe online/offline transition tracking for notification logic)

## Notification preferences (bot API)

Preferences are per-user per-store and are evaluated together with permissions.

Per-store settings flow endpoints:

- `GET /bot/v1/notifications/settings/stores`
  - returns stores eligible for notification settings picker
  - filters out inactive/inaccessible stores and stores where role lacks `notifications.access`
  - returns `{"items":[]}` when no stores are eligible (not an error)
- `GET /bot/v1/notifications/settings/stores/{store_id}`
  - returns selected store notification settings view (`preferences` + `capabilities`)
  - re-checks membership/store availability/permissions on every request
- `PUT /bot/v1/notifications/settings/stores/{store_id}`
  - applies partial updates to allowed toggles
  - rejects disallowed subtype updates with `403 {"detail":"notification_option_not_available"}`
  - re-checks access fresh; stale/inaccessible stores return `404 {"detail":"store_not_available"}`

Selected store settings response shape:

```json
{
  "store_id": "store-1",
  "store_name": "Main Store",
  "preferences": {
    "notifications_enabled": true,
    "device_status_enabled": true,
    "defect_detected_enabled": true
  },
  "capabilities": {
    "can_access_notifications": true,
    "can_subscribe_device_status": true,
    "can_subscribe_defect_detected": true
  }
}
```

Capability semantics:

- `can_access_notifications` requires current store access plus `notifications.access`.
- Subtype capabilities require `can_access_notifications` and the matching subtype permission.
- Stored preference values and capabilities are returned separately so tgbot does not need to recompute authorization logic.
- OMS returns stored subtype values even when master toggle is off (bot may hide subtype UI rows/buttons).

Default row behavior (current repo behavior):

- If `notification_preferences` row is missing for `(user_id, store_id)`, OMS currently treats defaults as:
  - `notifications_enabled=true`
  - `device_status_enabled=true`
  - `defect_detected_enabled=true`
- First successful update upserts the row.

Legacy active-store compatibility endpoints remain available:

- `GET /bot/v1/notifications/preferences`
- `PUT /bot/v1/notifications/preferences`

Required auth:

- Header: `Authorization: Bearer <TGBOT_SERVICE_TOKEN>`
- Query/body actor fields: `provider=telegram`, `provider_user_id=<ID>`

Example picker load:

```bash
curl -sS "http://127.0.0.1:8000/bot/v1/notifications/settings/stores?provider=telegram&provider_user_id=<ID>" \
  -H "Authorization: Bearer ${TGBOT_SERVICE_TOKEN}"
```

Example selected-store update:

```bash
curl -sS -X PUT "http://127.0.0.1:8000/bot/v1/notifications/settings/stores/<STORE_ID>" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TGBOT_SERVICE_TOKEN}" \
  -d '{
    "provider": "telegram",
    "provider_user_id": "<ID>",
    "notifications_enabled": false
  }'
```

## OMS -> tgbot internal push contract

When `NOTIFICATION_PUSH_BASE_URL` is configured, OMS pushes batches to:

- `POST {NOTIFICATION_PUSH_BASE_URL}{NOTIFICATION_PUSH_ENDPOINT_PATH}`
- default path: `/internal/notifications/push`

Request body:

```json
{
  "batch_id": "uuid",
  "deliveries": [
    {
      "notification_delivery_id": "uuid",
      "provider_user_id": "123456789",
      "payload": {
        "event_type": "defect_detected",
        "store_name": "Main Store",
        "device_display_name": "Counter Scale",
        "occurred_at": "2026-03-14T12:00:00Z",
        "fruit_name": "banana",
        "defect_type": "bruise",
        "result_id": "42",
        "can_show_image": true
      }
    }
  ]
}
```

Response body (from tgbot to OMS):

```json
{
  "batch_id": "uuid",
  "results": [
    {"notification_delivery_id": "uuid", "status": "sent"},
    {
      "notification_delivery_id": "uuid-2",
      "status": "failed",
      "failure_reason": "telegram_forbidden"
    }
  ]
}
```

## Defect notification image retrieval flow

Bot callback endpoint:

- `GET /bot/v1/notifications/results/{result_id}/image`
- query: `provider`, `provider_user_id`
- auth: `Authorization: Bearer <TGBOT_SERVICE_TOKEN>`

Behavior:

- OMS verifies membership/permissions and that the requesting provider user had a delivery for that defect result.
- OMS returns cached annotated image if available and not expired.
- On cache miss, OMS sends LocalConnector command `request_image` through existing WS command broker.
- LocalConnector uploads image bytes through existing blob flow (`POST /connector/v1/blobs`).
- OMS annotates the image, stores it in blobs, caches linkage in `annotated_image_cache`, and returns annotated bytes.
