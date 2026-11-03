import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo

import requests

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


def format_message(details, count, suppressed=0):
    #discord bolds with **text**, slack bolds with *text*
    b = "**" if WEBHOOK_TYPE == "discord" else "*"
    return (
        f"{alert_title(details)}\n"
        f"{b}Time (NZ):{b} {format_nz_timestamp(details.get('DateTime'))}\n"
        f"{b}Protocol:{b} {details.get('Protocol')}\n"
        f"{b}Source IP:{b} {details.get('SourceIp')}\n"
        f"{b}Request:{b} {details.get('HTTPMethod', '')} {details.get('RequestURI') or details.get('Command', '')}\n"
        f"{b}Service:{b} {details.get('Description', '')}\n"
        f"{b}Response given:{b} {details.get('CommandOutput', '')[:500]}\n" #cut long LLM replies short
        f"{b}Probes in last {PROBE_WINDOW_SECONDS}s:{b} {count}\n"
        f"{b}Events suppressed by cooldown since last alert:{b} {suppressed}"
    )


#discord or slack output decider
def send_alert(text):
    #each service expects a different JSON key for the message
    if WEBHOOK_TYPE == "discord":
        payload = {"content": text[:2000]}  #discord rejects messages over 2000 chars
    elif WEBHOOK_TYPE == "slack":
        payload = {"text": text}
    else:
        raise ValueError(f"Unknown WEBHOOK_TYPE: {WEBHOOK_TYPE}")

    #catch network errors so one failed post doesn't kill the loop
    try:
        r = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        if r.status_code >= 300:
            print(f"Webhook returned {r.status_code}: {r.text}")
    except requests.RequestException as e:
        print(f"Failed to send alert: {e}")


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

        send_alert(format_message(details, count, suppressed))
        print(f"Alert sent for {ip} ({count} probes)")
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
    follow_log()
