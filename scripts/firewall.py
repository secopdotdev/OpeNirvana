"""firewall.py — Cloudflare firewall event ingestion via GraphQL API.

Canonical source: github.com/your-org/cloudflare-toolkit (private).
This is a LOCAL COPY — do not edit here; update the canonical and re-copy.
Vendored so the firewall-event poller runs standalone on the deploy host (and in
the sanitized public OpeNirvana mirror) with no private-package dependency — the
standalone-script pattern blessed by toolkit ADR-0001. The only deviation from
canonical is the import line below: `from _http` (sibling vendored module) instead
of `from cloudflare_toolkit._http` (installed package).

Fetches firewall events from firewallEventsAdaptive (1000-event cap per call,
23h lookback hard limit) and appends them as NDJSON to a log file. Cursor state
is persisted across runs so each call fetches only new events.

Typical usage (cron / maintain.py equivalent)::

    from pathlib import Path
    from cred_store import auto_select_store
    from firewall import fetch_events

    store = auto_select_store()
    written = fetch_events(
        token=store.retrieve("CLOUDFLARE_API_TOKEN"),
        fqdn=store.retrieve("PUBLIC_FQDN"),
        log_path=Path("/var/log/cloudflare/firewall-events.log"),
        state_path=Path("/var/lib/cloudflare/state.json"),
    )
    print(f"Fetched {written} events")
"""
from __future__ import annotations

import datetime
import json
import sys
import urllib.error
from pathlib import Path
from typing import Any

from _http import api_get, api_graphql, resolve_zone_id

_GRAPHQL_QUERY = """\
query ($zoneTag: String!, $datetimeGt: String!, $datetimeLt: String!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(
        filter: {datetime_gt: $datetimeGt, datetime_lt: $datetimeLt}
        limit: 1000
        orderBy: [datetime_ASC]
      ) {
        action
        clientCountryName
        clientIP
        clientRequestHTTPHost
        clientRequestHTTPMethodName
        clientRequestPath
        datetime
        rayName
        ruleId
        source
        userAgent
      }
    }
  }
}
"""

_MAX_LOOKBACK_HOURS = 23  # firewallEventsAdaptive's hard cap
_FALLBACK_MINUTES = 15    # first-run window when no cursor exists


def fetch_events(
    token: str,
    fqdn: str,
    log_path: Path,
    state_path: Path,
) -> int:
    """Fetch new firewall events and append them to *log_path*.

    Returns the number of events written. Raises on unrecoverable API errors.
    The caller is responsible for env var loading and error reporting.
    """
    state: dict[str, Any] = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except (json.JSONDecodeError, OSError):
            print(
                f"WARNING: {state_path} unparseable — starting from last {_FALLBACK_MINUTES} min",
                file=sys.stderr,
            )

    # Zone ID — cached in state; re-resolved if stale.
    zone_id: str = state.get("zone_id", "")
    if zone_id:
        try:
            api_get(token, f"/zones/{zone_id}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                print(f"Cached zone ID {zone_id!r} is invalid — re-resolving", file=sys.stderr)
                zone_id = ""
    if not zone_id:
        zone_id = resolve_zone_id(token, fqdn)
        state["zone_id"] = zone_id

    # Cursor with 23h lookback cap.
    utcnow = datetime.datetime.now(datetime.UTC)
    now_str = utcnow.strftime("%Y-%m-%dT%H:%M:%SZ")
    max_back = (utcnow - datetime.timedelta(hours=_MAX_LOOKBACK_HOURS)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    fallback = (utcnow - datetime.timedelta(minutes=_FALLBACK_MINUTES)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    raw_last: str = state.get("last_seen") or fallback
    last_seen = raw_last if raw_last >= max_back else max_back
    if raw_last != last_seen:
        print(
            f"WARNING: last_seen {raw_last!r} > {_MAX_LOOKBACK_HOURS}h ago"
            f" — clamped to {last_seen}",
            file=sys.stderr,
        )

    result = api_graphql(
        token,
        _GRAPHQL_QUERY,
        {"zoneTag": zone_id, "datetimeGt": last_seen, "datetimeLt": now_str},
    )

    if result.get("errors"):
        raise RuntimeError(f"CF GraphQL errors: {result['errors']}")

    data = result.get("data")
    if data is None:
        raise RuntimeError("CF GraphQL returned null data")

    events: list[dict[str, Any]] = (
        data.get("viewer", {}).get("zones", [{}])[0].get("firewallEventsAdaptive", [])
    )

    # Append NDJSON + heartbeat.
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
        f.write(json.dumps({
            "action": "heartbeat",
            "datetime": now_str,
            "type": "heartbeat",
            "events_fetched": len(events),
        }) + "\n")

    # Advance cursor.
    state["last_seen"] = events[-1]["datetime"] if events else now_str
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2))

    return len(events)
