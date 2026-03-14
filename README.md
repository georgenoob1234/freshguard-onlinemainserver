# OnlineMainServer

## Environment variables

Set these before starting the app:

- `ADMIN_KEY` (required; OMS fails to start if missing)
- `SECRET_SALT` (required, used for `SHA-256(token + SECRET_SALT)`)
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

Example:

```bash
export ADMIN_KEY="change-me-admin-key"
export SECRET_SALT="change-me-long-random-salt"
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
```

## Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

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

Preferences are per-user per-store and are evaluated together with permissions:

- `GET /bot/v1/notifications/preferences`
- `PUT /bot/v1/notifications/preferences`

Required auth:

- Header: `Authorization: Bearer <TGBOT_SERVICE_TOKEN>`
- Query/body actor fields: `provider=telegram`, `provider_user_id=<ID>`

Example read:

```bash
curl -sS "http://127.0.0.1:8000/bot/v1/notifications/preferences?provider=telegram&provider_user_id=<ID>" \
  -H "Authorization: Bearer ${TGBOT_SERVICE_TOKEN}"
```

Example update:

```bash
curl -sS -X PUT "http://127.0.0.1:8000/bot/v1/notifications/preferences" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TGBOT_SERVICE_TOKEN}" \
  -d '{
    "provider": "telegram",
    "provider_user_id": "<ID>",
    "notifications_enabled": true,
    "device_status_enabled": true,
    "defect_detected_enabled": true
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
