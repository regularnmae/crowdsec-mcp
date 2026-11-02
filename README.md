# crowdsec-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that gives a
client read-only access to this host's [CrowdSec](https://docs.crowdsec.net)
engine: which decisions are being enforced, whether one address is blocked right
now, and the engine's own health counters. Nothing here writes, deletes or
changes anything — and the credential it holds could not do so if asked.

It exists because the LAPI is deliberately closed. `crowdsec` runs on the host
network with its API pinned to `127.0.0.1:8080` (a root bouncer on the host
polls it every minute), so no LAN client reaches it and a bridge container
cannot see it at all. This server is the authenticated front door: one bearer
token, three tools, and an upstream key that is a **bouncer** key.

Three tools, all read-only:

| Tool | What it does |
| --- | --- |
| `list_decisions` | Active decisions, filtered by address, scenario, type, scope or origin |
| `check_ip` | Whether one address is blocked right now, why, and whether it is enforceable at all |
| `get_engine_health` | Version, active decisions and alerts per scenario, detection counters, agent heartbeat age, bouncer pulls |

Each tool returns text — pretty-printed JSON. They are all marked read-only and
*not* open-world, so a well-behaved client skips the confirmation prompt. A
failure comes back as a tool error (`is_error=True`) with the same readable
message, so a client can tell "the engine did not answer" from "nothing is
blocked".

## What a decision is

A decision is one block the engine is enforcing:

```json
{
  "id": 61,
  "value": "203.0.113.9",
  "scope": "Ip",
  "type": "ban",
  "scenario": "stack/http-probing",
  "origin": "crowdsec",
  "duration": "1h57m13s"
}
```

`duration` is what is left of the TTL, so the same decision shrinks between
calls. Only **active** decisions are visible: the bouncer API is "what is
enforced now", which is exactly what "is this client blocked" needs, and means
an expired ban is gone. That is a real limit, and the reason there is no alert
tool (below).

## What is deliberately absent

- **Alerts.** `/v1/alerts` needs a *machine* credential, and a machine may also
  create and delete decisions and push alerts — ban and unban. Wiring one in
  would put the authority the stack keeps out of an agent's reach inside a
  network-facing container, whatever tools this code exposes. The engine's
  per-scenario alert *counts* are in `get_engine_health`, and the full objects
  are `podman exec crowdsec cscli alerts list` on the host.
- **Bouncers.** The LAPI has no `/v1/bouncers` route at all. `cscli bouncers
  list` reads the engine's database, and it is misleading for a hand-rolled
  poller anyway (ours never heartbeats). Enforcement freshness is the host's
  `audit/bouncer.status`, which `scripts/monitor.sh` already fails on.
- **Ban/unban.** Enforcement belongs to the host's `stack-bouncer`, which
  refuses private space and every address the host holds. `check_ip` says so:
  `enforceable: false` for non-global addresses.

## The engine it reads

| Endpoint | What it is |
| --- | --- |
| `http://127.0.0.1:8080/v1/decisions` | The LAPI, bouncer-key gated (`X-Api-Key`) |
| `http://127.0.0.1:6060/metrics` | The engine's own Prometheus exposition, no auth, loopback-pinned |

`GET /v1/decisions` answers a JSON array, or the literal `null` when nothing
matches — the same trap `stack-bouncer` documents. The client maps it to an
empty list; a quiet host is not a protocol error.

Counters are cumulative since the engine started, so `get_engine_health` is a
snapshot, not a rate: ask twice to see movement. History (if the host publishes
it) is the metrics store's job, not this server's.

## Running it

```sh
uv sync
CROWDSEC_MCP_TOKEN=<a long random token> \
CROWDSEC_LAPI_KEY=<a bouncer key> \
uv run python server.py
```

Or, inside the container, with no uv anywhere:

```sh
podman build -t localhost/crowdsec-mcp:latest .
podman run --network=host \
  -e CROWDSEC_MCP_TOKEN=<token> \
  -e CROWDSEC_LAPI_KEY=<bouncer key> \
  -e MCP_HOST=127.0.0.1 -e MCP_PORT=8113 \
  localhost/crowdsec-mcp:latest
```

It serves streamable HTTP at `/mcp`. `GET /health` is unauthenticated and
answers `{"status":"ok"}` — nothing more, so a poller can say "up" without
holding the token. `GET /ready` is open too and adds whether the LAPI answers:
`200` with `{"status":"ready","lapi":"ok"}`, or `503` with the reason, probed on
a 3-second timeout and cached for five seconds. Both paths answer `GET` and
`HEAD`; any other method is a `405`.

Keep the container healthcheck off `/ready`: `healthcheck.py` probes `/mcp`
with an authenticated initialize, which tests the process and the endpoint
without touching the LAPI. `/ready` stays `503` while CrowdSec restarts, so
gating podman on it would restart this server in a loop instead of reporting the
engine's state.

### Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CROWDSEC_LAPI_URL` | `http://127.0.0.1:8080` | LAPI base URL |
| `CROWDSEC_METRICS_URL` | `http://127.0.0.1:6060` | Engine metrics base URL |
| `CROWDSEC_LAPI_KEY` | – | **Bouncer** key (`cscli bouncers add`). Never a machine password |
| `CROWDSEC_LAPI_TIMEOUT` | `5` | Decision-request timeout, seconds |
| `CROWDSEC_METRICS_TIMEOUT` | `10` | Metrics-scrape timeout, seconds |
| `CROWDSEC_MCP_TOKEN` | – | Bearer token. **Required** unless `MCP_ALLOW_ANONYMOUS=1` |
| `MCP_HOST` / `MCP_PORT` | `0.0.0.0` / `8000` | Listen address (the stack's unit sets `127.0.0.1` / `8113`) |
| `MCP_ALLOW_ANONYMOUS` | – | Set to `1` to serve with no token (loud warning) |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `CROWDSEC_MCP_URL` | `http://127.0.0.1:$MCP_PORT/mcp` | Where `healthcheck.py` probes |

Without `CROWDSEC_MCP_TOKEN` the server refuses to start rather than serving
unauthenticated — a client reaches it through nginx-proxy-manager.

## Security model

The bearer token gates every request except `/health` and `/ready`, which report
status only; the comparison is constant-time. Startup fails without a token
unless `MCP_ALLOW_ANONYMOUS=1`.

The upstream key is the interesting half. A bouncer key can pull decisions and
nothing else: it cannot add or remove one, cannot read alerts, and cannot read
machines. That is why this server holds one, and why its tool set has no write
path even if the token leaks — a stolen token exposes the current bans, not the
ability to make or lift one.

In the stack this container runs with `Network=host`, because the LAPI is a
loopback bind a bridge container cannot reach. The price is that it shares the
host's network namespace and can therefore reach every loopback-only service
(alertmanager, the metrics and log stores, NPM's admin API). The app is three
fixed-URL GETs with no generic fetch tool, which bounds that blast radius but
does not remove it.

## Development

Dependencies are managed with [uv](https://docs.astral.sh/uv/) from
`pyproject.toml`; `uv.lock` is the exact closure (versions *and* hashes).

```sh
uv run pytest -q                # tests, no network
uv run ruff check .             # lint
uv run pyright                  # typecheck
uv run python scripts/smoke.py  # boots the real app on loopback
```

The LAPI is replaced in tests by a scripted fake (`tests/conftest.py`) and the
transport by a monkeypatched `urlopen`, so the suite pins the filters each tool
builds without a live engine. `tests/test_schemas.py` asserts the tool set is
exactly the three reads above — a fourth name fails the build.

Deployment is owned by the `stack` repo: `cd ~/build/stack && ./deploy.sh --only
crowdsec-mcp` rebuilds the image, restarts `crowdsec-mcp.service` and waits for
`(healthy)`.
