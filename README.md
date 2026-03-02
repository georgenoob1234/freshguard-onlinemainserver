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
```

## Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
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
