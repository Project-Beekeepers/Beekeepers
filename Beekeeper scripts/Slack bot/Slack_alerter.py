import json
import logging
import re
import os
import time
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import requests
from queue import Full, Queue
from threading import Lock, Thread

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


#load KEY=VALUE pairs from the .env file next to this script
def load_env():
    with open(os.path.join(SCRIPT_DIR, ".env")) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                value = value.strip().strip('"').strip("'") #allow KEY="value" as well as KEY=value
                os.environ.setdefault(key.strip(), value)


load_env()
WEBHOOK_TYPE = os.environ["WEBHOOK_TYPE"].lower()  #"discord" or "slack"
WEBHOOK_URL = os.environ["WEBHOOK_URL"]
LOG_FILE = os.path.join(SCRIPT_DIR, os.environ.get("LOG_FILE", "../../logs/beelzebub.log"))

#!!! IMPORTANT - WINDOWS / DOCKER DESKTOP IP PROBLEM !!!
#on windows, docker desktop hides the attacker's real IP: every event shows the docker
#gateway (e.g. 172.17.0.1 or 192.168.65.x) as the SourceIp instead.
#the cooldown below groups by (IP, protocol), so attackers using the same protocol
#can still share one cooldown when Docker Desktop reports the same gateway IP.
#  - workaround for local testing on windows: set COOLDOWN_SECONDS = 0
#  - real fix: run the docker stack on a linux host/VM, where real IPs come through
#    (no code changes needed, set COOLDOWN_SECONDS back to 300 there)

#filter settings
IGNORE_PATHS = {"/example.ico"}
PROBE_THRESHOLD = 1                     #number of probes to alert on, set to 1 for testing
PROBE_WINDOW_SECONDS = 60               #the given threshhold for probes
COOLDOWN_SECONDS = 300

# SSH commands use separate rules so a login alert cannot hide later commands.
SSH_COMMANDS_PER_ALERT = 1
SSH_COMMAND_COOLDOWN_SECONDS = 0
ALERT_ON_SSH_SESSION_END = False
SSH_SESSION_STATE_TTL_SECONDS = 3600

#in-memory state
last_alerted = {}
request_times = defaultdict(list)
ssh_command_state = {}
cooldown_suppressed = defaultdict(int)

#alert filter
def alert_key(ip, protocol=None):
    name = protocol.strip().upper() if isinstance(protocol, str) else ""
    return (ip, name or "UNKNOWN")


def should_alert(ip, path, protocol=None):
    now = time.time()

    if path in IGNORE_PATHS:
        return False

    key = alert_key(ip, protocol)

    #record this request, then drop anything outside the window
    request_times[key].append(now)
    request_times[key] = [t for t in request_times[key] if now - t <= PROBE_WINDOW_SECONDS]

    if len(request_times[key]) < PROBE_THRESHOLD:
        return False #too few requests yet to call this active probing

    if key in last_alerted and now - last_alerted[key] < COOLDOWN_SECONDS:
        cooldown_suppressed[key] += 1
        return False #already alerted for this IP and protocol recently

    last_alerted[key] = now
    return True


#Convert UTC timestamps for display without changing the original log.
def format_nz_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return "Unknown"

    try:
        event_time = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return value

    if event_time.tzinfo is None:
        return value  #The source timezone is unknown; do not guess.

    return event_time.astimezone(ZoneInfo("Pacific/Auckland")).strftime(
        "%d %b %Y %H:%M:%S %Z"
    )

def ssh_event_kind(details):
    protocol = details.get("Protocol")
    protocol = protocol.strip().upper() if isinstance(protocol, str) else ""
    if protocol != "SSH":
        return None

    message = details.get("Msg")
    message = message.strip().casefold() if isinstance(message, str) else ""
    if message == "end ssh session":
        return "end"
    if message in ("ssh raw command", "ssh terminal session interaction"):
        return "command"
    return None


def ssh_session_key(details):
    ip = details.get("SourceIp")
    session_id = details.get("ID")
    if not isinstance(ip, str) or not ip.strip():
        ip = "unknown"
    if not isinstance(session_id, str) or not session_id.strip():
        session_id = "unknown-session"
    return (ip, session_id)


def should_alert_ssh_command(details):
    # Default settings alert for every SSH command, without storing session state.
    if SSH_COMMANDS_PER_ALERT <= 1 and SSH_COMMAND_COOLDOWN_SECONDS <= 0:
        return True, 1

    now = time.time()
    stale = [key for key, state in ssh_command_state.items()
             if now - state["last_seen"] > SSH_SESSION_STATE_TTL_SECONDS]
    for key in stale:
        ssh_command_state.pop(key, None)

    key = ssh_session_key(details)
    state = ssh_command_state.setdefault(
        key, {"pending": 0, "last_alerted": None, "last_seen": now}
    )
    state["last_seen"] = now
    state["pending"] += 1
    if state["pending"] < max(1, SSH_COMMANDS_PER_ALERT):
        return False, state["pending"]
    if (state["last_alerted"] is not None
            and now - state["last_alerted"] < max(0, SSH_COMMAND_COOLDOWN_SECONDS)):
        return False, state["pending"]

    count = state["pending"]
    state["pending"] = 0
    state["last_alerted"] = now
    return True, count



#alert message
def alert_title(details):
    protocol = details.get("Protocol")
    protocol = protocol.strip().upper() if isinstance(protocol, str) else ""
    event_message = details.get("Msg")
    event_message = event_message.strip().casefold() if isinstance(event_message, str) else ""

    if protocol == "SSH":
        if event_message == "new ssh login attempt":
            return "New SSH login attempt"
        if event_message in ("ssh raw command", "ssh terminal session interaction"):
            return "SSH command received"
        if event_message == "new ssh terminal session":
            return "New SSH terminal session"
        if event_message == "end ssh session":
            return "SSH session ended"
        if not event_message and isinstance(details.get("Command"), str) and details["Command"].strip():
            return "SSH command received"
        return "New SSH activity detected"

    if protocol == "HTTP":
        return "New HTTP request"
    if protocol in ("TCP", "TELNET", "MCP"):
        return f"New {protocol} activity detected"
    return "New honeypot activity detected"


# These redactions protect common credential patterns in displayed values.
# They do not alter the underlying event logs or replace upstream log redaction.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|token|secret|authorization)"
    r"(\s*[=:]\s*)(?:Bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s&;,]+)"
)


def safe_alert_value(value, limit=500):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    else:
        value = str(value)

    value = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", value
    )
    value = value[:limit]
    value = value.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    value = "".join(
        char if ord(char) >= 32 and ord(char) != 127 and char not in ("\u2028", "\u2029")
        else "?" for char in value
    )
    # Slack uses <...> for mentions; Discord interprets @ mentions.
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    value = value.replace("@", "@\u200b")
    return value


# ATT&CK mappings are heuristic *possibilities*, not confirmed attack findings.
# Names, IDs, and tactics follow https://attack.mitre.org/techniques/.
_MITRE_HTTP_PROBE_PATHS = frozenset({
    "/.env", "/.git/config", "/actuator/env", "/server-status",
    "/phpmyadmin", "/wp-login.php",
})


def mitre_attack_candidate(details, count=1):
    """Return (ID, name, tactic, signal), or None when evidence is insufficient.

    The count comes from the existing per-IP/protocol alert window, not a
    dedicated failed-authentication detector. Labels must remain tentative.
    """
    if not isinstance(details, dict):
        return None
    protocol = details.get("Protocol")
    protocol = protocol.strip().upper() if isinstance(protocol, str) else ""
    repeated = isinstance(count, int) and not isinstance(count, bool) and count >= 5

    if protocol == "HTTP":
        uri = details.get("RequestURI")
        if not isinstance(uri, str):
            return None
        path = urlsplit(uri).path.casefold().rstrip("/") or "/"
        if path in _MITRE_HTTP_PROBE_PATHS:
            return ("T1595.002", "Vulnerability Scanning", "Reconnaissance",
                    "request for a commonly probed endpoint")
        if repeated:
            return ("T1595", "Active Scanning", "Reconnaissance",
                    "five or more HTTP requests in the alert window")

    if protocol == "SSH":
        if ssh_event_kind(details) == "command":
            command = details.get("Command")
            if isinstance(command, str) and re.match(
                r"^\s*(?:(?:/usr)?/bin/)?(?:bash|sh|zsh|dash|ash)\b",
                command, re.IGNORECASE,
            ):
                return ("T1059.004", "Unix Shell", "Execution",
                        "SSH command explicitly invokes a Unix shell")
        message = details.get("Msg")
        if (isinstance(message, str)
                and message.strip().casefold() == "new ssh login attempt"
                and repeated):
            return ("T1110", "Brute Force", "Credential Access",
                    "repeated SSH activity including a login attempt")

    return None


def format_message(details, count, suppressed=0):
    b = "**" if WEBHOOK_TYPE == "discord" else "*"
    request = f"{details.get('HTTPMethod') or ''} {details.get('RequestURI') or details.get('Command') or ''}"
    lines = [
        alert_title(details),
        f"{b}Time (NZ):{b} {safe_alert_value(format_nz_timestamp(details.get('DateTime')), 80)}",
        f"{b}Protocol:{b} {safe_alert_value(details.get('Protocol'), 80)}",
        f"{b}Source IP:{b} {safe_alert_value(details.get('SourceIp'), 100)}",
        f"{b}Request:{b} {safe_alert_value(request, 500)}",
        f"{b}Service:{b} {safe_alert_value(details.get('Description'), 200)}",
        f"{b}Response given:{b} {safe_alert_value(details.get('CommandOutput'), 500)}",
    ]

    extra_fields = [
        ("Source Port", "SourcePort"),
        ("User Agent", "UserAgent"),
        ("Status", "Status"),
        ("Session ID", "ID"),
        ("Client", "Client"),
        ("HTTP Host", "HostHTTPRequest"),
        ("TLS Server Name", "TLSServerName"),
        ("Handler", "Handler"),
    ]
    for label, key in extra_fields:
        value = safe_alert_value(details.get(key), 150)
        if value.strip():
            lines.append(f"{b}{label}:{b} {value}")

    mapping = mitre_attack_candidate(details, count)
    if mapping is not None:
        technique_id, technique_name, tactic, signal = mapping
        lines.append(
            f"{b}Possible MITRE ATT&CK:{b} {technique_id} - "
            f"{technique_name} ({tactic})"
        )
        lines.append(f"{b}Indicator:{b} {signal}")

    lines.append(f"{b}Probes in last {PROBE_WINDOW_SECONDS}s:{b} {count}")
    lines.append(f"{b}Events suppressed by cooldown since last alert:{b} {suppressed}")
    return "\n".join(lines)
# A bounded in-memory queue keeps the log reader responsive when webhooks are slow.
WEBHOOK_QUEUE_MAXSIZE = 256
WEBHOOK_MAX_ATTEMPTS = 3
WEBHOOK_RETRY_MAX_SECONDS = 30
webhook_queue = Queue(maxsize=WEBHOOK_QUEUE_MAXSIZE)
webhook_worker_thread = None
webhook_worker_lock = Lock()
_WEBHOOK_STOP = object()


def _retry_delay(attempt, response=None):
    delay = min(WEBHOOK_RETRY_MAX_SECONDS, 2 ** (attempt - 1))
    if response is not None and response.status_code == 429:
        retry_after = response.headers.get("Retry-After")
        try:
            requested = float(retry_after)
        except (TypeError, ValueError):
            requested = 0
        if 0 <= requested < float("inf"):
            delay = min(WEBHOOK_RETRY_MAX_SECONDS, max(delay, requested))
    return delay


def _deliver_webhook(text):
    if WEBHOOK_TYPE == "discord":
        payload = {"content": text[:2000], "allowed_mentions": {"parse": []}}
    elif WEBHOOK_TYPE == "slack":
        payload = {"text": text}
    else:
        raise ValueError(f"Unknown WEBHOOK_TYPE: {WEBHOOK_TYPE}")

    for attempt in range(1, WEBHOOK_MAX_ATTEMPTS + 1):
        response = None
        try:
            response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        except requests.RequestException as exc:
            if attempt == WEBHOOK_MAX_ATTEMPTS:
                logging.error("Webhook delivery failed after %d attempts (%s)",
                              attempt, type(exc).__name__)
                return False
        else:
            if 200 <= response.status_code < 300:
                return True
            retryable = response.status_code in (408, 429) or response.status_code >= 500
            if not retryable:
                logging.error("Webhook rejected alert with HTTP %d", response.status_code)
                return False
            if attempt == WEBHOOK_MAX_ATTEMPTS:
                logging.error("Webhook failed after %d attempts: HTTP %d",
                              attempt, response.status_code)
                return False

        time.sleep(_retry_delay(attempt, response))
    return False


def _webhook_worker_loop():
    while True:
        item = webhook_queue.get()
        try:
            if item is _WEBHOOK_STOP:
                return
            try:
                _deliver_webhook(item)
            except Exception:
                logging.exception("Unexpected webhook delivery failure")
        finally:
            webhook_queue.task_done()


def _ensure_webhook_worker():
    global webhook_worker_thread
    with webhook_worker_lock:
        if webhook_worker_thread is None or not webhook_worker_thread.is_alive():
            webhook_worker_thread = Thread(
                target=_webhook_worker_loop, name="honeypot-webhook", daemon=True
            )
            webhook_worker_thread.start()


def send_alert(text):
    # This function enqueues; it does not confirm remote delivery.
    if WEBHOOK_TYPE not in ("discord", "slack"):
        raise ValueError(f"Unknown WEBHOOK_TYPE: {WEBHOOK_TYPE}")
    try:
        webhook_queue.put_nowait(text)
    except Full:
        logging.error("Webhook queue full; dropping an alert (capacity=%d)",
                      webhook_queue.maxsize)
        return False
    _ensure_webhook_worker()
    return True


def stop_webhook_worker():
    # Gracefully drain queued alerts on normal exit / Ctrl+C.
    worker = webhook_worker_thread
    if worker is None or not worker.is_alive():
        return
    webhook_queue.join()
    webhook_queue.put(_WEBHOOK_STOP)
    worker.join()


#grabs code from the log output
def handle_line(line):
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return

    # Skip JSON values that are not objects.
    if not isinstance(entry, dict):
        logging.warning("Skipping JSON log entry that is not an object")
        return

    if entry.get("msg") != "New Event":
        return

    details = entry.get("event", {})

    # Reject malformed event payloads.
    if not isinstance(details, dict):
        logging.warning("Skipping New Event with non-object event payload")
        return

    kind = ssh_event_kind(details)

    # Handle SSH session-end events.
    if kind == "end":
        session_id = details.get("ID")

        if isinstance(session_id, str) and session_id.strip():
            for key in list(ssh_command_state):
                if key[1] == session_id:
                    ssh_command_state.pop(key, None)

        if ALERT_ON_SSH_SESSION_END:
            send_alert(format_message(details, 1))

        return

    # Handle SSH commands independently of login cooldowns.
    if kind == "command":
        allowed, count = should_alert_ssh_command(details)

        if allowed:
            send_alert(format_message(details, count))

        return

    # Existing protocol-specific cooldown handling.
    ip = details.get("SourceIp", "unknown")
    path = details.get("RequestURI", "")
    protocol = details.get("Protocol")

    if should_alert(ip, path, protocol):
        key = alert_key(ip, protocol)
        count = len(request_times[key])
        suppressed = cooldown_suppressed.pop(key, 0)

        queued = send_alert(format_message(details, count, suppressed))
        if queued is False:
            print(f"Alert dropped for {ip} ({count} probes)")
        else:
            print(f"Alert queued for {ip} ({count} probes)")
    else:
        print(f"Suppressed event from {ip} ({path})")


#long running loop: follow the log file like `tail -f`
#
#!!! IMPORTANT - TODO: FIX LATER !!!
#beelzebub.log is never rotated, so it grows forever and will eventually fill the disk.
#do NOT delete the log while the containers are running: this loop keeps reading the
#old (deleted) file and silently stops alerting. to clear it for now:
#  docker compose stop -> delete logs/beelzebub.log -> docker compose start
#proper fix later: add log rotation and make this loop reopen the file when it shrinks/changes.
def follow_log():
    #wait for beelzebub to create the log file
    while not os.path.exists(LOG_FILE):
        print(f"Waiting for {LOG_FILE} ...")
        time.sleep(5)

    with open(LOG_FILE, encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END) #start at the end so old events aren't re-alerted
        print(f"Watching {LOG_FILE} ({WEBHOOK_TYPE} webhook)")
        while True:
            line = f.readline()
            if not line:
                time.sleep(1) #nothing new yet
                continue
            try:
                handle_line(line)
            except Exception:
                # One malformed event must not permanently stop log monitoring.
                logging.exception("Failed to process honeypot log entry; continuing")


if __name__ == "__main__":
    try:
        follow_log()
    finally:
        stop_webhook_worker()
