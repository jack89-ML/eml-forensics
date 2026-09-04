"""Relational graph of a corpus: participants as nodes, directed weighted
communication edges (From->To and From->Cc), exportable to Graphviz DOT or
JSON for network analysis."""

from __future__ import annotations

import json


def _clean_address(entry: dict) -> str:
    return (entry.get("email") or "").strip().lower()


def interactions(entries: list[dict]) -> tuple[dict, list[dict]]:
    """Return (address -> {email, name}, edges).

    Edge: {from, to, weight, cc} where ``weight`` counts every message and
    ``cc`` is True when at least one message reached the target via Cc.
    """
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str], dict] = {}

    def node(entry: dict) -> str:
        address = _clean_address(entry)
        if not address:
            return ""
        existing = nodes.setdefault(address, {"email": address, "name": ""})
        name = (entry.get("name") or "").strip()
        if name and not existing["name"]:
            existing["name"] = name
        return address

    for message in entries:
        sender = node(message.get("from")[0]) if message.get("from") else ""
        if not sender:
            continue
        for recipient in message.get("to", []):
            target = node(recipient)
            if not target:
                continue
            key = (sender, target)
            edge = edges.setdefault(key, {"from": sender, "to": target,
                                          "weight": 0, "cc": False})
            edge["weight"] += 1
        for recipient in message.get("cc", []):
            target = node(recipient)
            if not target:
                continue
            key = (sender, target)
            edge = edges.setdefault(key, {"from": sender, "to": target,
                                          "weight": 0, "cc": True})
            edge["weight"] += 1
            edge["cc"] = True
    return nodes, sorted(edges.values(),
                         key=lambda e: (e["from"], e["to"]))


def _dot_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def to_dot(nodes: dict, edges: list[dict]) -> str:
    lines = ["digraph corpus {"]
    for address in sorted(nodes):
        label = nodes[address].get("name") or address
        lines.append(f'  {_dot_quote(address)} [label={_dot_quote(label)}];')
    for edge in edges:
        attrs = [f"label={_dot_quote(str(edge['weight']))}"]
        if edge["cc"]:
            attrs.append("style=dashed")
        lines.append(f"  {_dot_quote(edge['from'])} -> "
                     f"{_dot_quote(edge['to'])} [{', '.join(attrs)}];")
    lines.append("}")
    return "\n".join(lines)


def to_json(nodes: dict, edges: list[dict]) -> str:
    payload = {
        "nodes": [{"email": nodes[key]["email"], "name": nodes[key]["name"]}
                  for key in sorted(nodes)],
        "edges": edges,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
