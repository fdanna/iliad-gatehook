#!/usr/bin/env python3
import json
import os
import sys
import time
import urllib.request


HEALTH_PATH = os.environ.get("HEALTH_PATH", "/tmp/gatehook-health.json")
HEALTH_MAX_AGE = float(os.environ.get("HEALTH_MAX_AGE", "20"))
SHELLY_HOST = os.environ.get("SHELLY_HOST", "192.168.8.159")
SHELLY_INFO_URL = os.environ.get(
    "SHELLY_INFO_URL", f"http://{SHELLY_HOST}/rpc/Shelly.GetDeviceInfo"
)
SHELLY_EXPECTED_ID = os.environ.get(
    "SHELLY_EXPECTED_ID", "shellypro1-80f3dac96878"
)
SHELLY_TIMEOUT = float(os.environ.get("SHELLY_TIMEOUT", "2"))


def check_ctrl_state(now=None):
    now = time.time() if now is None else now
    with open(HEALTH_PATH, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not payload.get("ctrl_connected"):
        raise RuntimeError("ctrl_tcp is disconnected")
    age = now - float(payload.get("updated_at", 0))
    if age > HEALTH_MAX_AGE:
        raise RuntimeError(f"ctrl_tcp heartbeat is stale: {age:.1f}s")


def check_shelly():
    with urllib.request.urlopen(SHELLY_INFO_URL, timeout=SHELLY_TIMEOUT) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    device_id = payload.get("id") if isinstance(payload, dict) else None
    if device_id != SHELLY_EXPECTED_ID:
        raise RuntimeError(
            f"wrong Shelly device: expected={SHELLY_EXPECTED_ID} actual={device_id}"
        )


def main():
    try:
        check_ctrl_state()
        check_shelly()
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
