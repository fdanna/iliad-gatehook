# Gatehook Features & Options

## Overview
- Baresip handles SIP calls and exposes ctrl_tcp on the host.
- Gatehook listens to ctrl_tcp events and triggers the Shelly device.
- Healthchecks validate ctrl_tcp reachability for both services.

## Configuration (single source of truth)
All user-configurable settings live in `docker-compose.yml` under `x-ctrl-env`
and `x-gatehook-env`. Edit those values and run `docker compose up -d`.

### ctrl_tcp settings
- `CTRL_HOST` (default `127.0.0.1`): host where ctrl_tcp listens.
- `CTRL_PORT` (default `4444`): ctrl_tcp port.

### Shelly control
- `SHELLY_URL` (default `http://192.168.2.35/rpc/Switch.Set`): Shelly RPC URL.
- `SHELLY_TIMEOUT` (default `2`): HTTP timeout in seconds.

### Gatehook behavior
- `DEBOUNCE_SECONDS` (default `2.0`): minimum time between triggers.
- `RECONNECT_DELAY` (default `2.0`): delay before reconnecting to ctrl_tcp.
- `RECV_CHUNK` (default `4096`): socket read size.

### Whitelist (live reload, no restarts)
- `WHITELIST_ENABLED` (default `0`): fallback if toggle file is missing/invalid.
- `WHITELIST_PATH` (default `/opt/gatehook/whitelist.txt`): allow-list file path.
- `WHITELIST_TOGGLE_PATH` (default `/opt/gatehook/whitelist.enabled`): on/off file.

### Telegram authorization
- `TELEGRAM_BOT_TOKEN`: bot token (set in `.env`, never commit).
- `TELEGRAM_CHAT_ID`: numeric chat id (preferred) or `@username`.
- `TELEGRAM_TIMEOUT` (default `15`): seconds to wait for a decision.
- `TELEGRAM_POLL_INTERVAL` (default `1`): poll interval in seconds.

Notes:
- The bot must be messaged at least once before it can send you notifications.
- To discover your numeric chat id, send a message to the bot, then call:
  `https://api.telegram.org/bot<token>/getUpdates`

## Whitelist files (editable at runtime)
These files are mounted from `./scripts` and are read on every incoming call.
No container restarts are needed for changes to take effect.

### `scripts/whitelist.enabled`
- Set to `1`/`true`/`on` to enable whitelist.
- Set to `0`/`false`/`off` to disable whitelist.
- Blank lines and `#` comments are ignored.

### `scripts/whitelist.txt`
- One caller ID per line (exact string match).
- Blank lines and `#` comments are ignored.
- Example entries:
  - `sip:+393331234567@provider`
  - `sip:alice@example.com`

## Healthchecks
- `baresip` is healthy when ctrl_tcp is accepting connections.
- `gatehook` is healthy when it can connect to ctrl_tcp.

## Operations
- Start stack: `docker compose up -d`
- Restart baresip: `docker compose restart baresip`
- Follow gatehook logs: `docker compose logs -f gatehook`
- Follow baresip logs: `docker compose logs -f baresip`

## GHCR Image
The Gatehook image is published to GHCR as `ghcr.io/fdanna/gatehook`.

### Authenticate to GHCR
Use a GitHub PAT with `read:packages` (and `write:packages` if pushing).
```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u fdanna --password-stdin
```

### Pull the Image
```bash
docker pull ghcr.io/fdanna/gatehook:latest
```
## Testing

### Test Shelly Endpoint Manually
```bash
docker compose exec gatehook \
  python - <<'PY'
import json
import urllib.request
req = urllib.request.Request(
    "http://192.168.2.35/rpc/Switch.Set",
    data=json.dumps({"id": 0, "on": True}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=2) as resp:
    print(resp.read().decode("utf-8", errors="replace"))
PY
```

### Test by Calling the Iliad Number
- Place a call to the Iliad number configured in `baresip/accounts`.
- Confirm the gate triggers and the call is immediately rejected/hung up.
