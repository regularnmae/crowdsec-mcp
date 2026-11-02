"""Container healthcheck: POST an MCP initialize handshake to the local
streamable-HTTP endpoint. Exits non-zero on any failure so podman marks
the container unhealthy. Attaches the bearer token when one is configured
(the endpoint requires it).

The URL follows MCP_PORT rather than assuming the SDK's default 8000: this
server is the one that binds its own port on the host's loopback instead of
being published, so the unit sets MCP_PORT=8113 and the probe has to land
there too.
"""

import json
import os
import urllib.request

PORT = os.environ.get("MCP_PORT", "8000")
URL = os.environ.get("CROWDSEC_MCP_URL", f"http://127.0.0.1:{PORT}/mcp")
TOKEN = os.environ.get("CROWDSEC_MCP_TOKEN", "")

payload = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "healthcheck", "version": "1"},
        },
    }
).encode()

headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
if TOKEN:
    headers["Authorization"] = f"Bearer {TOKEN}"

req = urllib.request.Request(URL, data=payload, headers=headers, method="POST")
with urllib.request.urlopen(req, timeout=5) as resp:
    raw = resp.read().decode()

# Streamable-HTTP answers are SSE-framed by default (json_response=False):
# extract the `data:` line.
body = None
for line in raw.splitlines():
    if line.startswith("data:"):
        body = json.loads(line[len("data:") :].strip())
        break

if not body or "result" not in body:
    raise SystemExit(f"healthcheck failed: {body!r}")
