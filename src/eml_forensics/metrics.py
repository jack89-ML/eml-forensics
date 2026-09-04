"""Conversation metrics: thread reconstruction, reply latency, blackouts.

Threads are linked through References / In-Reply-To; when both are missing,
messages sharing a normalized subject are grouped by time adjacency. Reply
latency is the delta between a message and its resolved parent; blackouts
are intra-thread gaps beyond a configurable threshold.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field

_PREFIX_RE = re.compile(
    r"^\s*(?:(?:re|fwd?|ris|r|i|aw|tr|oggetto|sv|vs?)\s*[:.\-]?\s*"
    r"(?:\[\d+\]\s*)?)+",
    re.I,
)


def normalize_subject(subject: str) -> str:
    """Strip reply/forward prefixes (Re:, Fwd:, R:, I:, AW: ...)."""
    cleaned = _PREFIX_RE.sub("", subject or "")
    return re.sub(r"\s+", " ", cleaned).strip().lower()


def _parse_utc(value: str):
    if not value:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


@dataclass
class ThreadMessage:
    message_id: str
    subject: str
    subject_norm: str
    date: str
    from_email: str = ""
    to_emails: list[str] = field(default_factory=list)
    in_reply_to: str = ""
    references: list[str] = field(default_factory=list)
    thread_id: str = ""

    @property
    def when(self):
        return _parse_utc(self.date)


@dataclass
class ReplyEdge:
    parent: str
    child: str
    delay_seconds: int | None = None


@dataclass
class Blackout:
    thread_id: str
    start: str
    end: str
    gap_days: int


@dataclass
class ThreadMetrics:
    thread_id: str
    subject: str
    members: list[str] = field(default_factory=list)
    edges: list[ReplyEdge] = field(default_factory=list)
    blackouts: list[Blackout] = field(default_factory=list)


def build_threads(messages: list[ThreadMessage],
                  blackout_days: int = 30) -> list[ThreadMetrics]:
    """Group messages into threads and compute latency edges + blackouts."""
    by_id = {m.message_id: m for m in messages if m.message_id}
    pool = sorted(messages, key=lambda m: m.when or _dt.datetime.min.replace(
        tzinfo=_dt.timezone.utc))

    # --- thread grouping -------------------------------------------------
    root_ids: list[str] = []
    assigned: dict[str, str] = {}
    subject_groups: dict[str, list[str]] = {}

    def resolve_parent(m: ThreadMessage) -> str | None:
        for ref in reversed(m.references):
            if ref in by_id and ref != m.message_id:
                return ref
        if m.in_reply_to in by_id and m.in_reply_to != m.message_id:
            return by_id[m.in_reply_to].message_id
        # fallback: earlier sibling with the same normalized subject
        for earlier in pool:
            if earlier.message_id == m.message_id:
                break
            if earlier.subject_norm == m.subject_norm and m.subject_norm:
                return earlier.message_id
        return None

    for message in pool:
        parent = resolve_parent(message)
        if parent and parent in assigned:
            thread = assigned[parent]
        elif message.subject_norm and message.subject_norm in subject_groups:
            thread = subject_groups[message.subject_norm]
        else:
            thread = f"thread-{len(root_ids) + 1}"
            root_ids.append(thread)
        assigned[message.message_id] = thread
        subject_groups.setdefault(message.subject_norm, thread)
        message.thread_id = thread

    # --- metrics per thread ----------------------------------------------
    grouped: dict[str, list[ThreadMessage]] = {}
    for message in messages:
        grouped.setdefault(message.thread_id, []).append(message)

    results: list[ThreadMetrics] = []
    for thread_id, members in grouped.items():
        ordered = sorted(members, key=lambda m: m.when or _dt.datetime.min.replace(
            tzinfo=_dt.timezone.utc))
        subject = next((m.subject for m in ordered if m.subject), thread_id)
        metrics = ThreadMetrics(thread_id=thread_id, subject=subject,
                                members=[m.message_id for m in ordered])

        for message in ordered:
            parent = None
            for ref in reversed(message.references):
                if ref in by_id and ref != message.message_id and \
                        assigned.get(ref) == thread_id:
                    parent = by_id[ref]
                    break
            if parent is None and message.in_reply_to in by_id and \
                    assigned.get(message.in_reply_to) == thread_id:
                parent = by_id[message.in_reply_to]
            if parent is None and message is not ordered[0]:
                # adjacent same-subject predecessor inside the thread
                for earlier in reversed(ordered):
                    if earlier.message_id == message.message_id:
                        continue
                    if earlier.subject_norm == message.subject_norm:
                        parent = earlier
                        break
            if parent is not None:
                delay = None
                if message.when and parent.when:
                    delay = max(0, int((message.when - parent.when).total_seconds()))
                metrics.edges.append(ReplyEdge(parent=parent.message_id,
                                               child=message.message_id,
                                               delay_seconds=delay))

        for earlier, later in zip(ordered, ordered[1:]):
            if earlier.when and later.when:
                gap_days = (later.when - earlier.when).days
                if gap_days > blackout_days:
                    metrics.blackouts.append(Blackout(
                        thread_id=thread_id,
                        start=earlier.date,
                        end=later.date,
                        gap_days=gap_days,
                    ))
        results.append(metrics)
    return results
