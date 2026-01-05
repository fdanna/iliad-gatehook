#!/usr/bin/env python3
import json
import os
import socket
import time
import urllib.error
import urllib.request

def env_bool(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    if raw.lower() in {"1", "true", "yes", "on"}:
        return True
    if raw.lower() in {"0", "false", "no", "off"}:
        return False
    return default


def env_int(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def env_float(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


CTRL_HOST = os.environ.get("CTRL_HOST", "127.0.0.1")
CTRL_PORT = env_int("CTRL_PORT", 4444)
CTRL_SUBSCRIBE_COMMAND = os.environ.get("CTRL_SUBSCRIBE_COMMAND", "event")
CTRL_SUBSCRIBE_PARAMS = os.environ.get("CTRL_SUBSCRIBE_PARAMS", "register call")

SHELLY_URL = os.environ.get("SHELLY_URL", "http://192.168.2.35/rpc/Switch.Set")
SHELLY_TIMEOUT = env_float("SHELLY_TIMEOUT", 2.0)

DEBOUNCE_SECONDS = env_float("DEBOUNCE_SECONDS", 2.0)
RECONNECT_DELAY = env_float("RECONNECT_DELAY", 2.0)
RECV_CHUNK = env_int("RECV_CHUNK", 4096)

WHITELIST_ENABLED = env_bool("WHITELIST_ENABLED", False)
WHITELIST_PATH = os.environ.get("WHITELIST_PATH", "/opt/gatehook/whitelist.txt")
WHITELIST_TOGGLE_PATH = os.environ.get(
    "WHITELIST_TOGGLE_PATH", "/opt/gatehook/whitelist.enabled"
)
SYSTEM_LOG_PATH = os.environ.get("SYSTEM_LOG_PATH", "/opt/gatehook/system.log")
ACCESS_LOG_PATH = os.environ.get("ACCESS_LOG_PATH", "/opt/gatehook/access.log")


last_trigger = 0.0


def log(message):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    line = f"{ts} {message}"
    print(line, flush=True)
    append_log(SYSTEM_LOG_PATH, line)


def append_log(path, line):
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


def touch_log(path):
    try:
        with open(path, "a", encoding="utf-8"):
            pass
    except OSError:
        pass


def log_access(status, caller, reason):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    line = f"{ts} {status} caller={caller} reason={reason}"
    append_log(ACCESS_LOG_PATH, line)


def whitelist_enabled():
    try:
        with open(WHITELIST_TOGGLE_PATH, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return WHITELIST_ENABLED
    except OSError as exc:
        log(f"whitelist toggle read failed: {exc}")
        return WHITELIST_ENABLED

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower() in {"1", "true", "yes", "on", "enable", "enabled"}:
            return True
        if line.lower() in {"0", "false", "no", "off", "disable", "disabled"}:
            return False
        log(f"whitelist toggle invalid value: {line}")
        return WHITELIST_ENABLED

    return WHITELIST_ENABLED


def load_whitelist():
    if not whitelist_enabled():
        return None
    try:
        with open(WHITELIST_PATH, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        log(f"whitelist enabled but file missing: {WHITELIST_PATH}")
        return set()
    except OSError as exc:
        log(f"whitelist read failed: {exc}")
        return set()

    allowed = set()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        allowed.add(line)
    return allowed


def trigger_shelly():
    payload = json.dumps({"id": 0, "on": True}).encode("utf-8")
    req = urllib.request.Request(
        SHELLY_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=SHELLY_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        log(f"shelly trigger response: status={resp.status} body={body}")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        log(f"shelly trigger failed: {exc}")


def send_hangup(sock):
    payload = json.dumps({"command": "hangup"}).encode("utf-8")
    netstring = str(len(payload)).encode("ascii") + b":" + payload + b","
    try:
        sock.sendall(netstring)
        log("sent ctrl_tcp hangup")
    except OSError as exc:
        log(f"ctrl_tcp hangup failed: {exc}")


def send_command(sock, command, params=None):
    payload = {"command": command}
    if params:
        payload["params"] = params
    encoded = json.dumps(payload).encode("utf-8")
    netstring = str(len(encoded)).encode("ascii") + b":" + encoded + b","
    try:
        sock.sendall(netstring)
        log(f"sent ctrl_tcp command: {command} {params or ''}".strip())
    except OSError as exc:
        log(f"ctrl_tcp command failed: {exc}")


def subscribe_events(sock):
    if not CTRL_SUBSCRIBE_COMMAND:
        return
    params = CTRL_SUBSCRIBE_PARAMS if CTRL_SUBSCRIBE_PARAMS else None
    send_command(sock, CTRL_SUBSCRIBE_COMMAND, params)


def parse_netstrings(buffer):
    messages = []
    idx = 0
    while True:
        colon = buffer.find(b":", idx)
        if colon == -1:
            break
        length_bytes = buffer[idx:colon]
        if not length_bytes.isdigit():
            log(f"invalid netstring length prefix: {length_bytes!r}")
            idx = colon + 1
            continue
        length = int(length_bytes)
        end = colon + 1 + length
        if len(buffer) < end + 1:
            break
        if buffer[end : end + 1] != b",":
            log("invalid netstring terminator")
            idx = colon + 1
            continue
        messages.append(buffer[colon + 1 : end])
        idx = end + 1
    return messages, buffer[idx:]


def handle_message(sock, msg):
    global last_trigger

    event_class = str(msg.get("class") or "").lower()
    if event_class != "call":
        log(f"unhandled message: {msg}")
        return

    event_type = msg.get("type") or msg.get("event") or msg.get("name")
    event_name = str(event_type or "").upper()
    direction = msg.get("direction")
    incoming_types = {
        "CALL_INCOMING",
        "CALL_RINGING",
        "CALL_PROGRESS",
        "CALL_REMOTE_SDP",
    }

    if event_name not in incoming_types:
        log(f"call event ignored: {msg}")
        return

    if direction and direction != "incoming":
        log(f"call event ignored: {msg}")
        return

    params = msg.get("param", {})
    if not isinstance(params, dict):
        params = {}

    caller = (
        params.get("peer")
        or params.get("peeruri")
        or params.get("uri")
        or params.get("from")
        or msg.get("peeruri")
        or msg.get("from")
        or msg.get("uri")
        or "unknown"
    )

    now = time.monotonic()
    if now - last_trigger < DEBOUNCE_SECONDS:
        log("debounce active, skipping trigger")
        return

    last_trigger = now

    allowed = load_whitelist()
    if allowed is not None and caller not in allowed:
        log(f"caller not allowed: {caller}")
        log_access("rejected", caller, "not_whitelisted")
        return

    log(f"incoming call from {caller}; triggering shelly")
    log_access("accepted", caller, "triggered")
    trigger_shelly()
    send_hangup(sock)


def connect_and_run():
    while True:
        try:
            sock = socket.create_connection((CTRL_HOST, CTRL_PORT), timeout=5)
            sock.settimeout(5)
            log(f"connected to ctrl_tcp at {CTRL_HOST}:{CTRL_PORT}")
            subscribe_events(sock)
            buffer = b""
            while True:
                try:
                    chunk = sock.recv(RECV_CHUNK)
                except socket.timeout:
                    continue
                if not chunk:
                    raise ConnectionError("ctrl_tcp connection closed")
                buffer += chunk
                messages, buffer = parse_netstrings(buffer)
                for payload in messages:
                    try:
                        msg = json.loads(payload.decode("utf-8", errors="replace"))
                    except json.JSONDecodeError:
                        log(f"invalid JSON payload: {payload!r}")
                        continue
                    handle_message(sock, msg)
        except (OSError, ConnectionError) as exc:
            log(f"ctrl_tcp connection error: {exc}")
            time.sleep(RECONNECT_DELAY)
        finally:
            try:
                sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    log("gatehook starting")
    log(f"access log path: {ACCESS_LOG_PATH}")
    log(f"system log path: {SYSTEM_LOG_PATH}")
    if CTRL_SUBSCRIBE_COMMAND:
        log(
            "ctrl_tcp subscribe: "
            f"{CTRL_SUBSCRIBE_COMMAND} {CTRL_SUBSCRIBE_PARAMS}".strip()
        )
    touch_log(ACCESS_LOG_PATH)
    connect_and_run()
