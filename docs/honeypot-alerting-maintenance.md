# Beekeepers honeypot alerting — architecture and maintenance

This guide documents the Beekeepers-specific event tracing and Discord/Slack alerting integration. It is for teammates reviewing, deploying, and maintaining the combined changes. The underlying Beelzebub project is documented separately.

## How an alert is produced

1. A client interacts with an SSH, HTTP, or other configured honeypot service. Port and service definitions are in `configurations/services/`.
2. The Go Beelzebub runtime writes structured events to `logs/beelzebub.log`. The HTTP implementation at `internal/protocols/strategies/HTTP/http.go` traces requests and, when present, response bodies as `CommandOutput`.
3. The Python alerter at `Beekeeper scripts/Slack bot/Slack_alerter.py` follows the shared log file. It starts at end-of-file so historical events are not resent on startup.
4. `handle_line()` accepts JSON object entries with `msg == "New Event"` and object-valued `event` data. It routes SSH command/session events separately from general source-IP/protocol cooldowns.
5. `format_message()` renders a title, NZ-local time, request, response, optional fields, suppression counts, and possible MITRE ATT&CK classifications. Display values are escaped, redacted for common credential patterns, and put inside backtick-safe code blocks.
6. `send_alert()` enqueues a notification. A background worker invokes `_deliver_webhook()` to send the payload to Discord or Slack, retrying eligible failures.

**Important:** “Alert queued” means it entered the local queue; it does not prove remote delivery. The queue is in-memory and is **not durable**.

## Where to change behavior

| Change requested | File or function | Relevant tests |
| --- | --- | --- |
| SSH/HTTP service models, command handlers, routes or listening ports | `configurations/services/ssh-22.yaml`, `ssh-2222.yaml`, `http-80.yaml`, `http-8080.yaml`, `http-methods-8081.yaml`, and other service YAML as appropriate | Confirm Dell/Max's actual configuration; service-specific integration tests |
| Ports Docker publishes, service volumes, environment wiring | `docker-compose.yml` | `docker compose config`, build and live connection tests |
| HTTP route matching, fallback, unmatched requests, response tracing | `internal/protocols/strategies/HTTP/http.go`: `newHTTPHandler()`, `matchHTTPCommand()`, `buildHTTPResponse()`, `traceRequest()` | `http_route_alert_test.go`, `http_response_trace_test.go` |
| Parse and filter event log entries | `Slack_alerter.py`: `follow_log()`, `handle_line()` | `test_alerter_malformed_events.py` |
| Per-IP/protocol cooldown, probe count, ignored paths | `should_alert()` and constants near the beginning of `Slack_alerter.py` | `test_alerter_protocol_cooldown.py`, `test_alerter_suppressed_events.py` |
| SSH command frequency or session-end alerts | `ssh_event_kind()`, `should_alert_ssh_command()`, `ALERT_ON_SSH_SESSION_END` | `test_alerter_ssh_sessions.py` |
| New Zealand timestamps and alert titles | `format_nz_timestamp()`, `alert_title()` | `test_alerter_nz_timestamps.py`, `test_alerter_event_titles.py` |
| Alert fields, display redaction and Markdown safety | `safe_alert_value()`, `_append_untrusted_field()`, `format_message()`, `_discord_content()` | `test_alerter_additional_fields.py`, `test_alerter_security.py`, `test_alerter_code_blocks.py` |
| MITRE ATT&CK heuristic classifications | `mitre_attack_candidate()` | `test_alerter_mitre_attack.py` |
| Webhook queue, retries or formatting | `send_alert()`, `_webhook_worker_loop()`, `_deliver_webhook()`, `_retry_delay()` | `test_alerter_webhook_queue.py` |
| Python dependencies or runtime image | `Beekeeper scripts/Slack bot/Dockerfile` | Build and Python tests |

In this table, `Slack_alerter.py` means `Beekeeper scripts/Slack bot/Slack_alerter.py`.

## Configuration defaults

These values are **Python source constants**, not `.env` settings. Changing them requires changing the script and redeploying it.

| Constant | Current value | Purpose |
| --- | --- | --- |
| `IGNORE_PATHS` | `{ "/example.ico" }` | Skip specified paths |
| `PROBE_THRESHOLD` | `1` | Minimum activity before alerting |
| `PROBE_WINDOW_SECONDS` | `60` | Probe tracking window |
| `COOLDOWN_SECONDS` | `300` | General cooldown by `(source IP, protocol)` |
| `SSH_COMMANDS_PER_ALERT` | `1` | SSH commands grouped per alert |
| `SSH_COMMAND_COOLDOWN_SECONDS` | `0` | Separate SSH command delay |
| `ALERT_ON_SSH_SESSION_END` | `False` | Default session-end filtering |
| `SSH_SESSION_STATE_TTL_SECONDS` | `3600` | Expire stale SSH command session state |
| `WEBHOOK_QUEUE_MAXSIZE` | `256` | In-memory pending alerts capacity |
| `WEBHOOK_MAX_ATTEMPTS` | `3` | Webhook delivery attempts |
| `WEBHOOK_RETRY_MAX_SECONDS` | `30` | Maximum retry delay |

A local file at `Beekeeper scripts/Slack bot/.env` supplies `WEBHOOK_TYPE=discord` or `WEBHOOK_TYPE=slack`, and `WEBHOOK_URL=...`. The alerter also accepts `LOG_FILE` from the environment. Docker Compose sets `LOG_FILE=/logs/beelzebub.log` and mounts the local `.env` into the alerter container. **Do not commit or share real webhooks.** `.gitignore` and `.dockerignore` reduce accidental inclusion but do not clean prior Git history. Revoke/rotate any historical exposed webhook URLs.

The current `docker-compose.yml` publishes host ports **22, 23, 2222, 8080, 8081, 80, 3306 and 2112**. Before deployment, confirm the actual intended port/model configuration, collisions with host SSH, firewall rules and exposure of metrics port `2112`; these defaults are *not* a recommendation to expose every port publicly.

## Behavior and safety decisions

- **Malformed events:** The reader skips JSON scalars/lists and invalid event bodies. Per-line processing exceptions are logged rather than stopping the tail loop.
- **HTTP:** Requests can match a configured method/path handler, receive a 405 for method mismatch, use a fallback handler, or be traced as unmatched. Tracing an unmatched route does not mean every future static route is already supported; check the actual team's routes and event fields.
- **SSH:** SSH commands have separate notification rules from login events. `End SSH Session` is filtered by default and clears relevant session tracking.
- **Cooldown accounting:** The next eligible general alert reports events suppressed since the previous notification for that source IP and protocol.
- **Alert metadata:** Source port, user agent, status, session ID, client, HTTP host, TLS server name and handler are conditionally shown. Raw `Body` and `Headers` are not displayed by default. Team approval of the chosen fields is not yet confirmed.
- **Untrusted text:** Alert display values get length limits, common-secret redaction, control-character escaping, neutralized Markdown backticks and code fencing. Discord disables allowed mentions. Original log data may still carry sensitive inputs.
- **MITRE ATT&CK:** Classifications are *possible indicators*, not confirmed findings. Heuristics cover selected HTTP scanning signals and explicit SSH shell invocations/repeated login indicators.
- **Queue semantics:** Webhook delivery retries eligible errors, but a full queue, exhausted retries, terminal HTTP error or process crash can still drop notifications.

## How to validate changes (PowerShell, repository root)

```powershell
python -m py_compile "Beekeeper scripts/Slack bot/Slack_alerter.py"
python -m unittest discover -s tests -p "test_alerter_*.py" -q
git diff --check
docker compose config
docker compose build
```

The latest confirmed Python suite on integration commit `6a8498f` ran **91 tests successfully**. Broader Go package tests and live HTTP/SSH-to-Discord checks passed on earlier integration work. Run those again after future runtime changes; prior results do not validate unknown subsequent changes.

For a targeted Go check, with a working Go toolchain:

```powershell
go test ./internal/protocols/strategies/HTTP/...
```

Previous broader Go testing used a Go 1.26 container and explicit package paths, because temporary untracked `pr*-package` directories can interfere with `go test ./...`. Test services on loopback-bound ports unless intentionally deploying them.

## Known limitations and outstanding work

1. **Team configurations (tasks #0 and #12):** Obtain Dell's intended SSH/HTTP models/port definitions and Max/Dell's static routes. Verify those exact configurations create the intended trace events; add focused integration tests for gaps. Existing unmatched-HTTP-route work only partially addresses the broader requirement.
2. **Original honeypot defects:** The leader referenced two earlier honeypot problems without providing their exact statements here. Their completion is unknown.
3. **Group sign-off (task #11):** Added metadata is implemented, but approval from the group is unconfirmed.
4. **Webhook secrets:** Locally ignored `.env` files help, but previously committed real URLs may need rotation; evaluate an external secrets manager if required by deployment.
5. **Non-durable alert queue:** Capacity is finite, with no persistence or guaranteed delivery after crashes/retry exhaustion.
6. **Log lifecycle:** `follow_log()` opens the file once and does not handle rotation/replacement/truncation. The source log can grow without bound; plan log rotation and safe reopen logic for long-running deployments.
7. **Source IPs under Docker Desktop:** NAT may report the gateway IP for multiple connections. Per-IP rate limiting is therefore not a trustworthy per-attacker limit in all environments.
8. **Production exposure:** Review published ports, host SSH conflicts, metrics endpoint exposure, firewall rules and secrets before rollout. A local Docker pass does not constitute production approval.

## Safe change and review workflow

1. Confirm the actual requested service configuration or alert schema with the relevant teammate.
2. Branch from the **current final integration branch** for each independent feature/fix.
3. Add targeted regression tests; keep a single final PR to `main` for the combined work.
4. Run Python/Go checks as applicable, inspect `git diff --check` and ensure no `.env`, backup or `pr*-package` files were staged.
5. Incorporate reviewed work into the integration branch, update the final PR and revise this guide when behavior changes.
6. Obtain team approval and merge the final combined PR into `main` only once.
