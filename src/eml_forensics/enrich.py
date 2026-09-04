"""Registry enrichment bridge: extract corpus participants and correlate
them against professional registers through the ``albo``/``albo-search``
CLI when it is installed in the environment.

Never fails the pipeline when the external tool is missing: correlation
rows simply report the reason. ``--dry-run`` disables external calls.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class Participant:
    email: str
    name: str = ""
    pecs: list[str] = field(default_factory=list)
    count: int = 0


def _surname(name: str) -> str:
    tokens = name.split()
    return tokens[-1] if tokens and len(tokens[-1]) >= 3 else ""


def _is_pec(address: str) -> bool:
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    return ".pec." in domain or domain.startswith("pec.") or \
        domain.endswith(".pec.it") or domain.startswith("legalmail")


def collect_participants(entries: list[dict]) -> list[Participant]:
    by_address: dict[str, Participant] = {}

    def add(entry: dict, role: str) -> None:
        email_addr = (entry.get("email") or "").strip().lower()
        if not email_addr:
            return
        participant = by_address.setdefault(
            email_addr, Participant(email=email_addr))
        name = (entry.get("name") or "").strip()
        if name and not participant.name:
            participant.name = name
        participant.count += 1
        if _is_pec(email_addr) and email_addr not in participant.pecs:
            participant.pecs.append(email_addr)

    for message in entries:
        for address in message.get("from", []):
            add(address, "from")
        for address in message.get("to", []):
            add(address, "to")
        for address in message.get("cc", []):
            add(address, "cc")
    return sorted(by_address.values(), key=lambda p: p.email)


def _find_binary() -> str | None:
    for name in ("albo-search", "albo"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _query_albo(binary: str, foro: str, surname: str) -> dict:
    try:
        completed = subprocess.run(
            [binary, "avvocati", "--foro", foro, surname, "--json"],
            capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "detail": str(exc)[:120]}
    if completed.returncode == 0:
        try:
            payload = json.loads(completed.stdout)
            return {"status": "verified",
                    "matches": len(payload.get("results", []))}
        except json.JSONDecodeError:
            return {"status": "error", "detail": "unparsable output"}
    if completed.returncode == 1:
        return {"status": "not_found"}
    return {"status": "error", "detail": f"exit {completed.returncode}"}


def correlate(participants: list[Participant], foro: str | None,
              dry_run: bool = False) -> list[dict]:
    """One row per participant with the register check outcome."""
    binary = None if dry_run else _find_binary()
    rows = []
    for participant in participants:
        surname = _surname(participant.name)
        row = {
            "email": participant.email,
            "name": participant.name,
            "pec": bool(participant.pecs),
            "surname_query": surname,
            "foro": foro or "",
        }
        if not foro or not surname:
            row["status"] = "skipped"
            row["detail"] = "missing foro or surname"
        elif binary is None:
            row["status"] = "not_checked"
            row["detail"] = ("dry-run" if dry_run else
                             "albo-search not installed")
        else:
            result = _query_albo(binary, foro, surname)
            row.update(result)
        rows.append(row)
    return rows


def render_table(rows: list[dict]) -> str:
    headers = ["email", "name", "pec", "status", "detail"]
    columns = [headers] + [[str(row.get(h, "")) for h in headers]
                           for row in rows]
    widths = [max(len(cell) for cell in column)
              for column in zip(*columns)]
    lines = ["  ".join(cell.ljust(w) for cell, w in
                       zip(columns[0], widths))]
    lines.append("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for row in columns[1:]:
        lines.append("  ".join(cell.ljust(w) for cell, w in zip(row, widths)))
    return "\n".join(lines)
