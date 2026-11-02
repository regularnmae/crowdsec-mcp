# crowdsec-mcp — agent notes

Flat Python MCP server (not a package). `server.py` is the app — config, tools,
auth middleware; `crowdsec.py` is its **stdlib-only** LAPI/Prometheus client
(urllib, json — no HTTP library); `healthcheck.py` is the container healthcheck
probe. Shipped as a rootless podman/quadlet container; the runtime — its unit,
the host network it shares and the env wiring — is owned by the `stack` repo
(https://github.com/regularnmae/stack), not here. Toolchain is uv only — no pip
in CI, in the build, or in the image. `mcp` is the 2.x line: the app object is
`MCPServer` (the v2 rename of `FastMCP`).

This is a sibling of `victoria-logs-mcp`, `fulcrum-mcp`, `bitcoin-node-mcp`,
`monero-node-mcp`, `monero-wallet-mcp`, `lightning-mcp` and `searxng-mcp`.
Follow their structure and conventions. Env vars, tool list and the security
model are documented in `README.md`; don't re-derive them from the code.

## Commands

```sh
uv run ruff check .            # lint (CI gate). No `ruff format`; line-length 100, rules E,F,I,UP,B,SIM
uv run pyright                 # typecheck (CI gate); include list in [tool.pyright]
uv run pytest -q               # no network, no engine
uv run python scripts/smoke.py # boots the real app on loopback: /health, /ready, 401s, handshake
uv add <pkg>                   # edits pyproject.toml AND re-locks — commit the uv.lock change
uv lock --check                # CI drift gate
podman build -t localhost/crowdsec-mcp:latest .   # single-stage Containerfile
```

Deployment is owned by the `stack` repo: `cd ~/build/stack && ./deploy.sh
--only crowdsec-mcp` rebuilds the image, restarts `crowdsec-mcp.service` and
waits for "(healthy)"; `./deploy.sh` deploys the whole stack.

## Facts that are easy to get wrong

- **The key is a bouncer key, and that is a design constraint, not a detail.**
  `X-Api-Key` from `cscli bouncers add` reads `/v1/decisions` and cannot write.
  A *machine* password also answers `/v1/alerts`, but it may create and delete
  decisions and push alerts — ban and unban — so it must never be accepted
  here. If a tool needs alerts, the answer is "not in this server": the stack
  keeps that authority out of an agent's reach on purpose.
- **`GET /v1/decisions` answers `null` when nothing matches.** Not `[]`, not an
  error. `LapiClient.decisions` maps it; a "quiet host" that reads as a
  protocol error is the bug `stack-bouncer` already documents once.
- **Only active decisions exist in this view.** Expired bans are gone the
  moment the TTL ends, so nothing here can answer "why was that address blocked
  this morning". Say so in a tool description before adding a filter that looks
  like it could.
- **`check_ip` is the enforceability question, not just the ban question.**
  `enforceable` is `ipaddress.is_global`: the host's bouncer refuses private
  space and every address the host holds, so a decision on `10.89.0.5` exists
  and is never applied. Do not "simplify" that field away — it is the one thing
  this server knows that the raw decision list does not.
- **The metrics endpoint is a different port and a different server.** The LAPI
  is `:8080`; the engine's Prometheus exposition is `:6060`, unauthenticated,
  pinned to loopback by the stack. `fetch_metrics` is separate on purpose, and
  its timeout is longer: it is a fixed-size document, not a lookup.
- **Prometheus text parsing is not `split(",")`.** Label values may contain
  commas and escaped quotes (`reason="a,b"`, `note="a\"b"`), so `_labels` scans
  quoted strings. A naive split silently mislabels every series — the health
  report would still look plausible, which is worse than failing.
- **Counters are cumulative since the engine started.** `get_engine_health` is a
  snapshot, not a rate; do not present a counter as "per minute", and do not add
  a tool that pretends to know the last bouncer pull — the exposition has no
  such timestamp (a bouncer key pulls without a heartbeat).
- **`/ready` probes the LAPI and must never gate podman.** The stack's unit uses
  `healthcheck.py` (authenticated `initialize`) for that. A LAPI restart must
  not restart-loop this container.
- **The tool set is the security boundary, and `tests/test_schemas.py` pins
  it.** A new name — `ban`, `unban`, `add_decision`, `list_alerts` — fails the
  build. That is deliberate; see the README's "What is deliberately absent".
- **In the stack this container is on the host network** (`Network=host`, binds
  `127.0.0.1:8113`), because the LAPI is a loopback bind a bridge container
  cannot reach. `healthcheck.py` therefore derives its URL from `MCP_PORT`
  instead of assuming 8000 — the unit sets a non-default port.
