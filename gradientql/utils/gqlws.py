"""Minimal GraphQL-over-WebSocket subscription probing (the one transport the HTTP loop can't drive).

Covers the confirmable, non-destructive subscription attacks: legacy-subprotocol downgrade,
pre-handshake auth bypass (subscribe before connection_init), unauthenticated connection
establishment, and immediate data exfil over a subscription. Needs the optional `websocket-client`
dependency (`pip install "gradientql[ws]"`); degrades to a clear message when absent.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse, urlunparse

try:  # optional dependency, like the semantic-index extra
    import websocket  # type: ignore
    _WS_AVAILABLE = True
except Exception:  # noqa: BLE001
    _WS_AVAILABLE = False

# graphql-transport-ws (the modern, gated protocol) vs graphql-ws (legacy subscriptions-transport-ws)
_PROTO_MODERN = "graphql-transport-ws"
_PROTO_LEGACY = "graphql-ws"


def is_available() -> bool:
    return _WS_AVAILABLE


def _ws_url(http_url: str) -> str:
    p = urlparse(http_url)
    scheme = {"http": "ws", "https": "wss"}.get(p.scheme, "ws")
    return urlunparse((scheme, p.netloc, p.path, p.params, p.query, p.fragment))


def _connect(ws_url: str, subprotocol: str, headers: dict | None, timeout: int) -> Any:
    hdr = [f"{k}: {v}" for k, v in (headers or {}).items()]
    return websocket.create_connection(ws_url, subprotocols=[subprotocol], header=hdr, timeout=timeout)


def _recv_json(ws: Any) -> dict | None:
    try:
        raw = ws.recv()
    except Exception:  # noqa: BLE001
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def _start_msg(proto: str, sub_field: str) -> str:
    op = "start" if proto == _PROTO_LEGACY else "subscribe"
    return json.dumps({"id": "1", "type": op, "payload": {"query": f"subscription {{ {sub_field} }}"}})


def probe_subscriptions(url: str, headers: dict | None = None, sub_field: str | None = None,
                        timeout: int = 6) -> dict[str, Any]:
    """Probe the WS endpoint. Returns {available, observations:[str], findings:[(vuln_type, evidence)]}."""
    if not _WS_AVAILABLE:
        return {"available": False, "findings": [],
                "observations": ["websocket-client not installed - run `pip install \"gradientql[ws]\"` "
                                 "to enable subscription probing (auth-over-subscription, pre-init bypass, "
                                 "legacy-protocol downgrade)."]}
    ws_url = _ws_url(url)
    field = sub_field or "__typename"
    obs: list[str] = []
    findings: list[tuple[str, str]] = []

    # 1. Which subprotocols does the server accept? Legacy acceptance = downgrade to the weaker handler.
    accepts: dict[str, bool] = {}
    for proto in (_PROTO_MODERN, _PROTO_LEGACY):
        try:
            ws = _connect(ws_url, proto, headers, timeout)
            negotiated = ws.getsubprotocol() or proto
            accepts[proto] = True
            obs.append(f"WS accepts subprotocol '{negotiated}'")
            ws.close()
        except Exception as e:  # noqa: BLE001
            accepts[proto] = False
            obs.append(f"WS subprotocol '{proto}' rejected/unreachable ({str(e)[:50]})")
    if accepts.get(_PROTO_LEGACY) and accepts.get(_PROTO_MODERN):
        findings.append(("GraphQL WS Subprotocol Downgrade",
                         "server enables BOTH graphql-transport-ws and the legacy graphql-ws/"
                         "subscriptions-transport-ws handler - a client can pick the weaker legacy "
                         "protocol (often skipping the modern handler's auth/timeout hardening)."))
    if not (accepts.get(_PROTO_MODERN) or accepts.get(_PROTO_LEGACY)):
        return {"available": True, "observations": obs, "findings": findings}

    proto = _PROTO_MODERN if accepts.get(_PROTO_MODERN) else _PROTO_LEGACY

    # 2. Pre-handshake bypass: send subscribe/start BEFORE connection_init.
    try:
        ws = _connect(ws_url, proto, headers, timeout)
        ws.send(_start_msg(proto, field))
        msg = _recv_json(ws)
        if msg and msg.get("type") in ("next", "data"):
            findings.append(("GraphQL Subscription Auth Bypass (pre-handshake)",
                             f"a '{proto}' subscribe was accepted and returned '{msg.get('type')}' data "
                             "WITHOUT a connection_init handshake - the init auth gate is bypassable."))
            obs.append("pre-init subscribe -> data (BYPASS)")
        else:
            obs.append(f"pre-init subscribe -> {(msg or {}).get('type', 'closed/no-data')} (gated)")
        ws.close()
    except Exception as e:  # noqa: BLE001
        obs.append(f"pre-init probe failed ({str(e)[:50]})")

    # 3. Unauthenticated connection_init + subscribe: does data flow with no auth?
    try:
        ws = _connect(ws_url, proto, headers, timeout)
        ws.send(json.dumps({"type": "connection_init", "payload": {}}))
        ack = _recv_json(ws)
        if ack and ack.get("type") in ("connection_ack", "ka", "connection_keep_alive"):
            obs.append("connection_init ACK'd with no auth payload")
            ws.send(_start_msg(proto, field))
            msg = _recv_json(ws)
            if msg and msg.get("type") in ("next", "data") and (msg.get("payload") or {}).get("data"):
                findings.append(("Broken Authorization over GraphQL Subscription",
                                 f"an unauthenticated subscription to '{field}' returned data "
                                 f"({json.dumps(msg.get('payload'))[:160]}) - subscription resolvers are "
                                 "not enforcing the auth applied to queries/mutations."))
                obs.append("unauth subscription -> DATA (BROKEN AUTHZ)")
            else:
                obs.append(f"unauth subscribe -> {(msg or {}).get('type', 'no immediate data')} "
                           "(event-driven; may still be reachable)")
        else:
            obs.append(f"connection_init -> {(ack or {}).get('type', 'no ack')}")
        ws.close()
    except Exception as e:  # noqa: BLE001
        obs.append(f"init probe failed ({str(e)[:50]})")

    return {"available": True, "observations": obs, "findings": findings}
