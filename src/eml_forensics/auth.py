"""Email authenticity: Received hop tracing and security headers.

``Received`` headers are processed oldest hop (origin) -> newest (final MX).
Each hop reports relay/host/IP, protocol, target and the hop date; the delay
between consecutive hops is computed when dates parse. DKIM / SPF /
Authentication-Results headers are summarized heuristically.
"""

from __future__ import annotations

import datetime as _dt
import email.utils
import re
from dataclasses import dataclass, field

_IP_RE = re.compile(r"\[([0-9a-fA-F.:]+)\]")
_HELO_RE = re.compile(r"from\s+([^\s;(]+)")
_BY_RE = re.compile(r"\bby\s+([^\s;(]+)")
_WITH_RE = re.compile(r"\bwith\s+(\S+)")
_FOR_RE = re.compile(r"\bfor\s+<([^>]+)>")
_DATE_RE = re.compile(r";\s*(.+)$")


def _iso_to_dt(value: str) -> _dt.datetime | None:
    """Parse an ISO-8601 string (with optional trailing Z) to aware UTC."""
    try:
        normalized = value
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = _dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def _parse_hop_date(value: str) -> _dt.datetime | None:
    if not value:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(value.strip())
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


@dataclass
class Hop:
    index: int                      # 0 = closest to origin
    relay: str = ""
    ip: str = ""
    by: str = ""
    protocol: str = ""
    for_addr: str = ""
    date: str = ""
    delay_seconds: int | None = None


def parse_received_line(line: str, index: int) -> Hop:
    hop = Hop(index=index)
    # Folded headers arrive with newlines/spaces: normalize so the date
    # regex never gets truncated.
    line = re.sub(r"\s+", " ", line).strip()
    match = _IP_RE.search(line)
    if match:
        hop.ip = match.group(1)
    relay = _HELO_RE.search(line)
    if relay:
        hop.relay = relay.group(1)
    by = _BY_RE.search(line)
    if by:
        hop.by = by.group(1)
    protocol = _WITH_RE.search(line)
    if protocol:
        hop.protocol = protocol.group(1)
    for_addr = _FOR_RE.search(line)
    if for_addr:
        hop.for_addr = for_addr.group(1)
    date_match = _DATE_RE.search(line)
    if date_match:
        parsed = _parse_hop_date(date_match.group(1))
        if parsed:
            hop.date = parsed.isoformat()
    return hop


def received_hops(received_headers: list[str]) -> list[Hop]:
    """Header list top-down (newest first) -> hops oldest -> newest."""
    hops = [parse_received_line(line, index) for index, line
            in enumerate(reversed(received_headers))]
    previous: _dt.datetime | None = None
    for hop in hops:
        parsed = _iso_to_dt(hop.date) if hop.date else None
        if parsed and previous:
            hop.delay_seconds = max(0, int((parsed - previous).total_seconds()))
        if parsed:
            previous = parsed
    return hops


def auth_results_summary(value: str) -> dict:
    """Heuristic digest of an Authentication-Results header."""
    summary: dict = {"authserv_id": "", "results": []}
    if not value:
        return summary
    parts = [part.strip() for part in value.split(";")]
    if parts:
        summary["authserv_id"] = parts.pop(0)
    for part in parts:
        match = re.match(r"([a-z-]+)=(pass|fail|softfail|neutral|temperror|none)",
                         part, re.I)
        if match:
            summary["results"].append({
                "method": match.group(1).lower(),
                "result": match.group(2).lower(),
            })
    return summary


def spf_summary(value: str) -> dict:
    """Received-SPF / SPF header: result and (envelope-)mailfrom."""
    summary: dict = {"result": "", "mailfrom": ""}
    if not value:
        return summary
    first = re.split(r"\s+", value.strip(), maxsplit=1)
    summary["result"] = first[0].lower() if first else ""
    match = re.search(r"(?:mailfrom|envelope-from)\s*=\s*([^\s;]+)",
                      value, re.I)
    if match:
        summary["mailfrom"] = match.group(1)
    return summary


def dkim_summary(value: str) -> dict:
    """DKIM-Signature: version, selector, domain, algorithms."""
    summary: dict = {"present": bool(value), "selector": "", "domain": "",
                     "sign_algo": "", "hash_algo": ""}
    if not value:
        return summary
    fields = {}
    for key, val in re.findall(r"([a-z]+)\s*=\s*([^;]+)", value, re.I):
        fields[key.lower()] = val.strip()
    summary["selector"] = fields.get("s", "")
    summary["domain"] = fields.get("d", "")
    algo = fields.get("a", "")
    if algo:
        parts = re.split(r"[-/]", algo, maxsplit=1)
        summary["sign_algo"] = parts[0]
        if len(parts) > 1:
            summary["hash_algo"] = parts[1]
    return summary


def analyze_headers(message) -> dict:
    """Full authenticity digest for a parsed email message."""
    received = message.get_all("Received", [])
    return {
        "hops": [vars(h) for h in received_hops(received)],
        "hop_count": len(received),
        "spf": spf_summary(message.get("Received-SPF", "") or
                           message.get("SPF", "")),
        "dkim": dkim_summary(message.get("DKIM-Signature", "")),
        "authentication_results": [
            auth_results_summary(value)
            for value in message.get_all("Authentication-Results", [])
        ],
    }
