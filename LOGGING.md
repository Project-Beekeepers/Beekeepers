# Beekeeper Log Format

Reference for the events Beelzebub writes to `logs/beelzebub.log`, which the Slack alerter reads.

## Where the log comes from

| Step | File |
|---|---|
| Log file is opened, output set to JSON | `internal/builder/builder.go` → `buildLogger()` |
| Log path is configured | `configurations/beelzebub.yaml` (`core.logging.logsPath`), overridden in Docker by `BEELZEBUB_LOGGING_LOGS_PATH` |
| Each protocol creates an event | `internal/protocols/strategies/<PROTOCOL>/*.go` → `tr.TraceEvent(...)` |
| Timestamp is added | `internal/tracer/tracer.go` → `TraceEvent()` |
| Event is written as a `"New Event"` log line | `internal/builder/director.go` → `standardOutStrategy()` |
| Log is read and turned into alerts | `Beekeeper scripts/Slack bot/Slack_alerter.py` |

Each line in the file is a single JSON object. Lines that don't have `"msg":"New Event"` are startup or error messages, not attacker activity.

## Line structure

Every attacker event uses the same outer shape:

```json
{
  "event":  { ...event fields, see below... },
  "level":  "info",
  "msg":    "New Event",
  "status": "End"
}
```

| Field | Meaning |
|---|---|
| `event` | The event details (all fields below) |
| `level` | Log level. Always `info` for events |
| `msg` | Always `New Event` for attacker activity. This is what the alerter filters on |
| `status` | Copy of `event.Status`, at the top level so it's easy to filter |
| `time` | Log timestamp. **Not present** because `logDisableTimestamp: true`; use `event.DateTime` instead |
| `func`, `file` | Source location of the log call. Only present when `debugReportCaller: true` |

## Example: end of an SSH session

The same event, formatted for reading:

```json
{
  "event": {
    "DateTime": "2026-11-11T09:59:42Z",
    "ID": "68119f58-24a2-41fe-94a0-1ba120220510",
    "Protocol": "SSH",
    "Status": "End",
    "Msg": "End SSH Session",

    "SourceIp": "",
    "SourcePort": "",
    "RemoteAddr": "",

    "User": "",
    "Password": "",
    "Client": "",
    "Environ": "",

    "Command": "",
    "CommandOutput": "",
    "Handler": "",
    "Description": "",

    "HTTPMethod": "",
    "RequestURI": "",
    "HostHTTPRequest": "",
    "UserAgent": "",
    "Headers": "",
    "HeadersMap": null,
    "Cookies": "",
    "Body": "",
    "TLSServerName": ""
  },
  "level": "info",
  "msg": "New Event",
  "status": "End"
}
```

Most fields are empty because an **End** event only records *that* the session closed. To see who it was and what they did, find the other events with the same `ID`: the `Start` event has the IP and username, and the `Interaction` events have the commands.

In the raw file the fields appear in a fixed order (the order of the Go struct), all on one line. The grouping above is only for readability.

## Event fields

All fields are strings unless noted. Empty means "not used by this kind of event".

### Identity and timing

| Field | Meaning | Example |
|---|---|---|
| `DateTime` | When the event happened, UTC, RFC 3339 | `2026-11-11T09:59:42Z` |
| `ID` | Unique ID (UUID). Shared by every event in one SSH/TELNET/TCP session; new for each stateless event | `68119f58-...` |
| `Protocol` | `HTTP`, `SSH`, `TCP`, `TELNET` or `MCP` | `SSH` |
| `Status` | Where the event sits in a session (see [Status values](#status-values)) | `End` |
| `Msg` | Human-readable event type (see [Event types](#event-types)) | `End SSH Session` |
| `Description` | The `description` from that service's YAML in `configurations/services/` | `SSH interactive` |

### Attacker's connection

| Field | Meaning | Example |
|---|---|---|
| `SourceIp` | Attacker's IP address | `172.18.0.1` |
| `SourcePort` | Attacker's source port | `51544` |
| `RemoteAddr` | IP and port together | `172.18.0.1:51544` |

When running in Docker, connections from your own machine show the Docker bridge IP (e.g. `172.18.0.1`), not `127.0.0.1`.

### Login and client (SSH, TELNET)

| Field | Meaning | Example |
|---|---|---|
| `User` | Username the attacker tried | `root` |
| `Password` | Password the attacker tried | `admin123` |
| `Client` | SSH client version string | `SSH-2.0-OpenSSH_9.6p1` |
| `Environ` | Environment variables the SSH client sent, comma-separated | `LANG=en_US.UTF-8` |

### Commands (SSH, TELNET, TCP, MCP)

| Field | Meaning | Example |
|---|---|---|
| `Command` | What the attacker typed or sent | `cat /etc/passwd` |
| `CommandRaw` | Exact bytes as `\xNN` escapes. **Only present** when `Command` isn't valid text (binary protocols) | `\x16\x03\x01...` |
| `CommandOutput` | What the honeypot replied with (fixed text or LLM-generated) | `root:x:0:0:root:/root:/bin/bash` |
| `Handler` | Name of the matching command rule from the service YAML. `not_found` if nothing matched | `ls` |

### HTTP requests

| Field | Meaning | Example |
|---|---|---|
| `HTTPMethod` | Request method | `GET` |
| `RequestURI` | Path and query string | `/admin?id=1` |
| `HostHTTPRequest` | `Host` header value | `localhost:8080` |
| `UserAgent` | `User-Agent` header | `curl/8.5.0` |
| `Headers` | All headers as a single string | `[Key: Accept, values: */*],` |
| `HeadersMap` | All headers as an object (header name → list of values); `null` for non-HTTP events | `{"Accept":["*/*"]}` |
| `Cookies` | Cookies sent | `session=abc` |
| `Body` | Request body | `user=admin&pass=1` |
| `TLSServerName` | SNI name for HTTPS requests (empty for plain HTTP) | `example.com` |

### Extra

| Field | Meaning |
|---|---|
| `Metadata` | Protocol-specific key/value data added by plugins (e.g. VNC challenge-response). **Only present** when a plugin sets it |

## Status values

| Status | Meaning |
|---|---|
| `Start` | A session opened (SSH/TELNET/TCP terminal session, or a one-off SSH command) |
| `Interaction` | One command inside an open session |
| `End` | The session closed. Only `ID`, `Protocol`, `Status`, `Msg` and `DateTime` are filled |
| `Stateless` | A one-off event with no session: an HTTP request, a login attempt, an MCP call, a single TCP payload |

## Event types

Every `Msg` value the honeypot can produce, and which fields it fills (besides `DateTime`, `ID`, `Protocol`, `Status`, `Msg`).

| Protocol | `Msg` | Status | Fields filled |
|---|---|---|---|
| HTTP | `HTTP New request` | Stateless | Source*, `HTTPMethod`, `RequestURI`, `HostHTTPRequest`, `UserAgent`, `Headers`, `HeadersMap`, `Cookies`, `Body`, `TLSServerName`, `Description`, `Handler` |
| SSH | `New SSH Login Attempt` | Stateless | Source*, `User`, `Password`, `Client`, `Description` |
| SSH | `New SSH Terminal Session` | Start | Source*, `User`, `Environ`, `Description` |
| SSH | `SSH Terminal Session Interaction` | Interaction | Source*, `Command`, `CommandOutput`, `Handler`, `Description` |
| SSH | `SSH Raw Command` (e.g. `ssh host 'ls'`) | Start | Source*, `User`, `Environ`, `Command`, `CommandOutput`, `Handler`, `Description` |
| SSH | `End SSH Session` | End | *(none)* |
| TELNET | `New TELNET Login Attempt` | Stateless | Source*, `User`, `Password`, `Description` |
| TELNET | `New TELNET Terminal Session` | Start | Source*, `User`, `Description` |
| TELNET | `TELNET Terminal Session Interaction` | Interaction | Source*, `User`, `Command`, `CommandOutput`, `Handler`, `Description` |
| TCP | `New TCP attempt` | Stateless | Source*, `Command`, `CommandRaw`, `Description` |
| TCP | `New TCP Session` | Start | Source*, `Description` |
| TCP | `TCP Session Interaction` | Interaction | Source*, `Command`, `CommandRaw`, `CommandOutput`, `Handler`, `Description`, `Metadata` |
| TCP | `End TCP Session` | End | *(none)* |
| MCP | `New MCP tool invocation` | Stateless | Source*, `Command` (`tool name\|arguments`), `CommandOutput`, `Description` |

\*Source = `SourceIp`, `SourcePort`, `RemoteAddr`.

## Following one attacker's session

Every event in a session shares the same `ID`. A typical SSH session in the log:

```
New SSH Login Attempt              Stateless    (own ID)   user root / password 123456
New SSH Terminal Session           Start        ID=6811…   from 172.18.0.1
SSH Terminal Session Interaction   Interaction  ID=6811…   whoami → root
SSH Terminal Session Interaction   Interaction  ID=6811…   ls → ...
End SSH Session                    End          ID=6811…
```

The login attempt gets its own `ID`. Link it to the session by `SourceIp`, `SourcePort` and time.

To pull out one session with `jq`:

```bash
jq -c 'select(.event.ID == "68119f58-24a2-41fe-94a0-1ba120220510") | .event | {DateTime, Msg, Command, CommandOutput}' logs/beelzebub.log
```

## Notes for the Slack alerter

- `Slack_alerter.py` treats every `New Event` line as activity, including `End` events.
- `End` events have `SourceIp: ""`, so the alerter counts all session endings from every attacker under the same empty IP. It may make sense to skip `Status == "End"` in `handle_line()`.
- The log is never rotated and grows forever. Stop the containers before deleting it (see the comments in `follow_log()`).
- The log contains passwords attackers tried and anything they typed. Treat it as sensitive.
