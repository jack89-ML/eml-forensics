"""Deterministic synthetic .eml corpus builder (RFC 2606 entities only).

Every entity below is fictional: alice@example.com, bob@example.org,
charlie@example.net and "Acme Corp". Dates are fixed so latency and
blackout tests are exact. Used by the offline test-suite; nothing real
lives here.
"""

from __future__ import annotations

import base64
import email.message
import email.policy
from pathlib import Path

PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)

ALICE = "Alice <alice@example.com>"
BOB = "Bob <bob@example.org>"
CHARLIE = "Charlie <charlie@example.net>"
ACME = "Acme Corp <info@acme.example>"


def _new(subject: str, msg_id: str, date: str) -> email.message.EmailMessage:
    message = email.message.EmailMessage(policy=email.policy.default)
    message["Subject"] = subject
    message["Message-ID"] = f"<{msg_id}>"
    message["Date"] = date
    return message


def _write(target: Path, message: email.message.EmailMessage,
           filename: str) -> None:
    target.mkdir(parents=True, exist_ok=True)
    (target / filename).write_bytes(message.as_bytes())


def build_corpus(target: Path) -> list[str]:
    """Write the synthetic corpus; returns the list of created filenames."""
    created: list[str] = []

    # 1) Thread root: Alice -> Bob, plain text + two attachments.
    m = _new("Project kickoff", "kickoff@example.com",
             "Sat, 10 Jan 2026 09:00:00 +0000")
    m["From"] = ALICE
    m["To"] = BOB
    m.set_content("Hi Bob,\n\nlet's kick off the project next week.\n\nAlice\n")
    m.add_attachment(b"alpha bravo charlie delta\n", maintype="text",
                     subtype="plain", filename="notes.txt")
    m.add_attachment(PNG_1PX, maintype="image", subtype="png",
                     filename="plan.png")
    _write(target, m, "01_kickoff.eml")
    created.append("01_kickoff.eml")

    # 2) Reply 1: Bob -> Alice, +2 days 1h30m.
    m = _new("Re: Project kickoff", "reply1@example.org",
             "Mon, 12 Jan 2026 10:30:00 +0000")
    m["From"] = BOB
    m["To"] = ALICE
    m["In-Reply-To"] = "<kickoff@example.com>"
    m["References"] = "<kickoff@example.com>"
    m.set_content("Got it, thanks. Monday works.\n\nBob\n")
    _write(target, m, "02_reply1.eml")
    created.append("02_reply1.eml")

    # 3) Reply 2: Alice -> Charlie (cc Bob), +3 days from reply 1.
    m = _new("Re: Project kickoff", "reply2@example.net",
             "Thu, 15 Jan 2026 08:00:00 +0000")
    m["From"] = ALICE
    m["To"] = CHARLIE
    m["Cc"] = BOB
    m["In-Reply-To"] = "<reply1@example.org>"
    m["References"] = "<kickoff@example.com> <reply1@example.org>"
    m.set_content("Charlie, please add the schedule to the shared drive.\n\nAlice\n")
    _write(target, m, "03_reply2.eml")
    created.append("03_reply2.eml")

    # 4) Late reply: Charlie -> all, ~76 days later (blackout window).
    m = _new("Re: Project kickoff", "late@example.com",
             "Wed, 01 Apr 2026 12:00:00 +0000")
    m["From"] = CHARLIE
    m["To"] = ALICE
    m["Cc"] = BOB
    m["In-Reply-To"] = "<reply2@example.net>"
    m["References"] = ("<kickoff@example.com> <reply1@example.org> "
                       "<reply2@example.net>")
    m.set_content("Apologies for the silence — schedule is live now.\n\nCharlie\n")
    _write(target, m, "04_late.eml")
    created.append("04_late.eml")

    # 5) HTML-only with script and a 1x1 tracking pixel.
    m = _new("Draft for review", "html@example.org",
             "Sat, 17 Jan 2026 10:00:00 +0000")
    m["From"] = BOB
    m["To"] = ALICE
    html_body = ("<html><head><style>p{color:red}</style></head><body>"
                 "<script>alert(1)</script>"
                 '<img width="1" height="1" '
                 'src="https://track.example.net/pixel.gif">'
                 "<p>Please review the <b>draft</b> before Monday.</p>"
                 "</body></html>")
    m.set_content(html_body, subtype="html")
    _write(target, m, "05_html.eml")
    created.append("05_html.eml")

    # 6) PEC-style certified message.
    m = _new("ACCETTAZIONE: delivery report", "pec@example.com",
             "Mon, 19 Jan 2026 08:30:00 +0000")
    m["From"] = "postmaster@pec.example"
    m["To"] = ALICE
    m["X-Riferimento-Message-ID"] = "<original@pec.example>"
    m["X-TipoRicevuta"] = "accettazione"
    m.set_content("Ricevuta di accettazione del messaggio.\n")
    _write(target, m, "06_pec.eml")
    created.append("06_pec.eml")

    # 7) ISO-8859-1 body with accented characters.
    m = _new("Rendiconto", "latin@example.com",
             "Tue, 20 Jan 2026 09:00:00 +0000")
    m["From"] = ALICE
    m["To"] = BOB
    m.set_content("Ecco il rendiconto: è tutto versato, totale 100 euro.\n",
                  charset="iso-8859-1")
    _write(target, m, "07_latin1.eml")
    created.append("07_latin1.eml")

    # 8) Attachment with path-traversal filename.
    m = _new("Attachment test", "trav@example.com",
             "Wed, 21 Jan 2026 10:00:00 +0000")
    m["From"] = ALICE
    m["To"] = BOB
    m.set_content("See the attached file.\n")
    m.add_attachment(b"just a test payload\n", maintype="text",
                     subtype="plain", filename="../../evil.txt")
    _write(target, m, "08_traversal.eml")
    created.append("08_traversal.eml")

    return created


if __name__ == "__main__":  # pragma: no cover
    import sys
    print("\n".join(build_corpus(Path(sys.argv[1]))))
