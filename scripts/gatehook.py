#!/usr/bin/env python3
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime
from zoneinfo import ZoneInfo

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

SHELLY_URL = os.environ.get("SHELLY_URL", "http://192.168.8.159/rpc/Switch.Set")
SHELLY_TIMEOUT = env_float("SHELLY_TIMEOUT", 2.0)

DEBOUNCE_SECONDS = env_float("DEBOUNCE_SECONDS", 2.0)
RECONNECT_DELAY = env_float("RECONNECT_DELAY", 2.0)
RECV_CHUNK = env_int("RECV_CHUNK", 4096)

WHITELIST_ENABLED = env_bool("WHITELIST_ENABLED", False)
WHITELIST_PATH = os.environ.get("WHITELIST_PATH", "/opt/gatehook/whitelist.txt")
WHITELIST_TOGGLE_PATH = os.environ.get(
    "WHITELIST_TOGGLE_PATH", "/opt/gatehook/whitelist.enabled"
)
METADATA_PATH = os.environ.get(
    "METADATA_PATH", "/opt/gatehook/whitelist_meta.json"
)
SYSTEM_LOG_PATH = os.environ.get("SYSTEM_LOG_PATH", "/opt/gatehook/system.log")
ACCESS_LOG_PATH = os.environ.get("ACCESS_LOG_PATH", "/opt/gatehook/access.log")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_TIMEOUT = env_float("TELEGRAM_TIMEOUT", 15.0)
TELEGRAM_POLL_INTERVAL = env_float("TELEGRAM_POLL_INTERVAL", 1.0)
TELEGRAM_API_BASE = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org")
WATCHDOG_ENABLED = env_bool("WATCHDOG_ENABLED", True)
WATCHDOG_INTERVAL = env_float("WATCHDOG_INTERVAL", 30.0)
WATCHDOG_FAIL_THRESHOLD = env_int("WATCHDOG_FAIL_THRESHOLD", 3)
WATCHDOG_SCAN_LINES = env_int("WATCHDOG_SCAN_LINES", 400)
WATCHDOG_STARTUP_GRACE = env_float("WATCHDOG_STARTUP_GRACE", 180.0)
WATCHDOG_RESTART_COOLDOWN = env_float("WATCHDOG_RESTART_COOLDOWN", 600.0)
WATCHDOG_TARGET_CONTAINER = os.environ.get("WATCHDOG_TARGET_CONTAINER", "baresip")
DOCKER_SOCKET_PATH = os.environ.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock")


last_trigger = 0.0
telegram_update_offset = None
ROME_TZ = ZoneInfo("Europe/Rome")
watchdog_started_at = time.monotonic()
watchdog_last_restart = 0.0
watchdog_log_offset = None
watchdog_events = []


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


def read_new_lines(path, start_offset):
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            end_offset = handle.tell()
            if start_offset is None or start_offset > end_offset:
                return [], end_offset
            handle.seek(start_offset)
            text = handle.read(end_offset - start_offset).decode(
                "utf-8", errors="replace"
            )
    except OSError as exc:
        log(f"watchdog log read failed: {exc}")
        return [], start_offset
    return text.splitlines(), end_offset


def docker_restart_container(container_name):
    payload = (
        f"POST /containers/{container_name}/restart?t=10 HTTP/1.1\r\n"
        "Host: docker\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(10)
        sock.connect(DOCKER_SOCKET_PATH)
        sock.sendall(payload)
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    finally:
        sock.close()

    header = response.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
    if " 204 " in header or " 304 " in header:
        return True, header
    return False, header


def parse_registration_events(lines):
    events = []
    for line in lines:
        lowered = line.lower()
        if "baresip v" in lowered:
            events.append("startup")
            continue
        if "[1 binding]" in lowered or "register_ok" in lowered:
            events.append("ok")
            continue
        if "connection timed out [110]" in lowered:
            events.append("timeout")
            continue
        if "register_fail" in lowered and "glare" not in lowered:
            events.append("fail")
            continue
    return events


def analyze_registration(events):
    if not events:
        return False, 0
    if events[-1] == "ok":
        return True, 0

    failures = 0
    for event in reversed(events):
        if event in {"ok", "startup"}:
            break
        if event in {"timeout", "fail"}:
            failures += 1
    return False, failures


def watchdog_loop():
    global watchdog_events, watchdog_last_restart, watchdog_log_offset

    while True:
        time.sleep(WATCHDOG_INTERVAL)

        if time.monotonic() - watchdog_started_at < WATCHDOG_STARTUP_GRACE:
            continue

        lines, watchdog_log_offset = read_new_lines(SYSTEM_LOG_PATH, watchdog_log_offset)
        if lines:
            watchdog_events.extend(parse_registration_events(lines))
            watchdog_events = watchdog_events[-WATCHDOG_SCAN_LINES:]

        healthy, failure_count = analyze_registration(watchdog_events)
        if healthy or failure_count < WATCHDOG_FAIL_THRESHOLD:
            continue

        if time.monotonic() - watchdog_last_restart < WATCHDOG_RESTART_COOLDOWN:
            continue

        log(
            "watchdog detected repeated registration failures; "
            f"restarting container={WATCHDOG_TARGET_CONTAINER} count={failure_count}"
        )
        try:
            ok, detail = docker_restart_container(WATCHDOG_TARGET_CONTAINER)
        except OSError as exc:
            log(f"watchdog restart failed: {exc}")
            continue

        if ok:
            watchdog_last_restart = time.monotonic()
            watchdog_events = ["startup"]
            log(f"watchdog restart requested successfully: {detail}")
        else:
            log(f"watchdog restart request failed: {detail}")


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

    allowed = {"raw": set(), "keys": set()}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        allowed["raw"].add(line)
        allowed["keys"].add(caller_key(line))
    return allowed


def load_expiration_metadata():
    try:
        with open(METADATA_PATH, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        log(f"whitelist metadata read failed: {exc}")
        return {}

    entries = payload.get("entries", {}) if isinstance(payload, dict) else {}
    return entries if isinstance(entries, dict) else {}


def expiration_for_caller(caller):
    metadata = load_expiration_metadata()
    entry = metadata.get(caller)
    if not isinstance(entry, dict):
        target_key = caller_key(caller)
        for stored_caller, stored_entry in metadata.items():
            if caller_key(stored_caller) == target_key and isinstance(stored_entry, dict):
                entry = stored_entry
                break
    if not isinstance(entry, dict) or not entry.get("expiration_enabled"):
        return None

    expires_on = entry.get("expires_on")
    try:
        expiry_date = datetime.strptime(str(expires_on), "%Y-%m-%d").date()
    except (TypeError, ValueError):
        log(f"invalid expiration date for caller {caller}: {expires_on}")
        return None
    return {
        "expires_on": expires_on,
        "expired": datetime.now(ROME_TZ).date() > expiry_date,
    }


def caller_user(caller):
    value = str(caller or "").strip()
    if value.startswith("sip:"):
        value = value[4:]
    value = value.split(";", 1)[0]
    if "@" in value:
        value = value.split("@", 1)[0]
    return value


def split_phone_number(value):
    phone = caller_user(value)
    explicit_country = True
    if phone.startswith("+"):
        digits = phone[1:]
    elif phone.startswith("00"):
        digits = phone[2:]
    else:
        explicit_country = False
        digits = phone

    if not digits.isdigit():
        return "", phone, explicit_country

    if explicit_country:
        for length in (3, 2, 1):
            country = digits[:length]
            # Only the country codes gatehook needs to distinguish today.
            if country in {"1", "30", "33", "39", "43", "46", "49", "421"}:
                return country, digits[length:], explicit_country
        return "", digits, explicit_country

    return "39", digits, explicit_country


def normalize_italian_national_number(national):
    # Some Iliad caller IDs arrive with an extra leading trunk 0 before
    # Italian mobile numbers. Italian landlines legitimately start with 0,
    # so only collapse 03... to 3....
    if national.startswith("03"):
        return national[1:]
    return national


def caller_key(caller):
    country, national, explicit_country = split_phone_number(caller)
    if not country:
        return caller_user(caller)
    if country == "39":
        national = normalize_italian_national_number(national)
    return f"{country}:{national}"


def normalized_whitelist_caller(caller):
    country, national, explicit_country = split_phone_number(caller)
    if country == "39":
        national = normalize_italian_national_number(national)
        return replace_caller_user(caller, national)
    return caller


def replace_caller_user(caller, user):
    value = str(caller or "").strip()
    prefix = "sip:" if value.startswith("sip:") else ""
    rest = value[4:] if prefix else value
    suffix = ""
    if ";" in rest:
        rest, suffix = rest.split(";", 1)
        suffix = ";" + suffix
    if "@" in rest:
        _, host = rest.split("@", 1)
        return f"{prefix}{user}@{host}{suffix}"
    return f"{prefix}{user}{suffix}"


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


def telegram_enabled():
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def telegram_api(method, data):
    url = f"{TELEGRAM_API_BASE}/bot{TELEGRAM_BOT_TOKEN}/{method}"
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=encoded, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(body)
        if not payload.get("ok"):
            log(f"telegram api error: {payload}")
        return payload
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError) as exc:
        log(f"telegram api failed: {exc}")
        return None


def telegram_init_offset():
    global telegram_update_offset
    if not telegram_enabled():
        return
    payload = telegram_api("getUpdates", {"timeout": "0"})
    if not payload or "result" not in payload:
        return
    updates = payload.get("result") or []
    if updates:
        telegram_update_offset = updates[-1].get("update_id", 0) + 1


def telegram_chat_matches(message):
    if not message:
        return False
    target = str(TELEGRAM_CHAT_ID).strip()
    if not target:
        return False
    chat = message.get("chat", {}) if isinstance(message, dict) else {}
    chat_id = chat.get("id")
    if target.lstrip("-").isdigit():
        return str(chat_id) == target
    username = chat.get("username") or ""
    if target.startswith("@"):
        return username.lower() == target[1:].lower()
    return username.lower() == target.lower()


def telegram_wait_for_decision(request_id, timeout_seconds):
    global telegram_update_offset
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        params = {"timeout": "0"}
        if telegram_update_offset is not None:
            params["offset"] = str(telegram_update_offset)
        payload = telegram_api("getUpdates", params)
        if payload and "result" in payload:
            updates = payload.get("result") or []
            for update in updates:
                update_id = update.get("update_id")
                if isinstance(update_id, int):
                    telegram_update_offset = update_id + 1
                callback = update.get("callback_query") or {}
                data = callback.get("data") or ""
                message = callback.get("message") or {}
                if not data.startswith(f"gatehook:{request_id}:"):
                    continue
                if not telegram_chat_matches(message):
                    continue
                choice = data.split(":", 2)[-1]
                callback_id = callback.get("id")
                if callback_id:
                    telegram_api(
                        "answerCallbackQuery",
                        {"callback_query_id": callback_id, "text": "Received"},
                    )
                return choice
        time.sleep(TELEGRAM_POLL_INTERVAL)
    return None


def format_caller(caller):
    if not caller:
        return "unknown"
    value = caller
    if value.startswith("sip:"):
        value = value[4:]
    value = value.split(";", 1)[0]
    if "@" in value:
        value = value.split("@", 1)[0]
    if value.startswith("00"):
        return f"+{value[2:]}"
    return value


def telegram_notify(caller, origin):
    request_id = os.urandom(6).hex()
    display_caller = format_caller(caller)
    text = (
        "Incoming call from non-whitelisted number.\n"
        f"Caller: {display_caller}\n"
        "Authorize?"
    )
    keyboard = {
        "inline_keyboard": [
            [
                {"text": "AUTHORIZE", "callback_data": f"gatehook:{request_id}:AUTH"},
                {"text": "DECLINE", "callback_data": f"gatehook:{request_id}:DECLINE"},
            ],
            [
                {
                    "text": "AUTHORIZE AND ADD",
                    "callback_data": f"gatehook:{request_id}:AUTH_ADD",
                }
            ],
        ]
    }
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "reply_markup": json.dumps(keyboard),
    }
    result = telegram_api("sendMessage", payload)
    if not result or not result.get("ok"):
        return None
    return request_id


def extract_origin(caller):
    if not caller:
        return "unknown"
    value = caller
    if value.startswith("sip:"):
        value = value[4:]
    if "@" in value:
        value = value.split("@", 1)[1]
    if ";" in value:
        value = value.split(";", 1)[0]
    return value or "unknown"


def append_whitelist(caller):
    caller = normalized_whitelist_caller(caller)
    allowed = load_whitelist()
    if allowed is not None and caller_key(caller) in allowed["keys"]:
        return False
    try:
        with open(WHITELIST_PATH, "a", encoding="utf-8") as handle:
            handle.write(caller + "\n")
        return True
    except OSError as exc:
        log(f"whitelist append failed: {exc}")
        return False


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

    expiration = expiration_for_caller(caller)
    if expiration and expiration["expired"]:
        log(f"caller access expired on {expiration['expires_on']}: {caller}")
        log_access("rejected", caller, "expired")
        send_hangup(sock)
        return

    allowed = load_whitelist()
    caller_allowed = (
        allowed is None
        or caller in allowed["raw"]
        or caller_key(caller) in allowed["keys"]
    )
    if not caller_allowed:
        log(f"caller not allowed: {caller}")
        if telegram_enabled():
            origin = extract_origin(caller)
            request_id = telegram_notify(caller, origin)
            if request_id:
                choice = telegram_wait_for_decision(request_id, TELEGRAM_TIMEOUT)
                if choice == "AUTH":
                    log(f"telegram authorized: {caller}")
                    log_access("accepted", caller, "telegram_authorized")
                    trigger_shelly()
                    send_hangup(sock)
                    return
                if choice == "AUTH_ADD":
                    added = append_whitelist(caller)
                    log(f"telegram authorized and add: {caller} added={added}")
                    log_access("accepted", caller, "telegram_authorized_added")
                    trigger_shelly()
                    send_hangup(sock)
                    return
                if choice == "DECLINE":
                    log(f"telegram declined: {caller}")
                    log_access("rejected", caller, "telegram_declined")
                    send_hangup(sock)
                    return
                log(f"telegram timeout/no decision: {caller}")
                log_access("rejected", caller, "telegram_timeout")
                send_hangup(sock)
                return
            log("telegram notify failed; rejecting")
            log_access("rejected", caller, "telegram_notify_failed")
            send_hangup(sock)
            return
        log_access("rejected", caller, "not_whitelisted")
        send_hangup(sock)
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
    if WATCHDOG_ENABLED:
        log(
            "watchdog enabled: "
            f"interval={WATCHDOG_INTERVAL}s "
            f"fail_threshold={WATCHDOG_FAIL_THRESHOLD} "
            f"cooldown={WATCHDOG_RESTART_COOLDOWN}s"
        )
    if telegram_enabled():
        log("telegram notifications enabled")
    telegram_init_offset()
    if CTRL_SUBSCRIBE_COMMAND:
        log(
            "ctrl_tcp subscribe: "
            f"{CTRL_SUBSCRIBE_COMMAND} {CTRL_SUBSCRIBE_PARAMS}".strip()
        )
    touch_log(ACCESS_LOG_PATH)
    if WATCHDOG_ENABLED:
        threading.Thread(target=watchdog_loop, daemon=True).start()
    connect_and_run()
