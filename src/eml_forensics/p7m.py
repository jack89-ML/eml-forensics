"""CAdES / P7M envelope unpacking and signature metadata inspection.

Attached signatures (``.p7m`` / ``application/pkcs7-mime``) are unwrapped
preferring the OpenSSL CLI (``smime -verify -noverify``), which needs no
Python dependencies. SHA-256 is recorded for both the envelope and the
extracted payload, and signer/issuer certificates are listed for the chain
of custody report.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .attachments import sha256_file
from .errors import ForensicsError

P7M_EXTS = (".p7m", ".p7s")
P7M_TYPES = ("application/pkcs7-mime", "application/x-pkcs7-mime",
             "application/pkcs7-signature", "application/x-pkcs7-signature")


def is_p7m(filename: str = "", content_type: str = "") -> bool:
    name = (filename or "").lower()
    ctype = (content_type or "").lower()
    return name.endswith(P7M_EXTS) or ctype in P7M_TYPES


def payload_stem(p7m_name: str) -> str:
    """Original name hint: 'report.pdf.p7m' -> 'report.pdf'."""
    name = Path(p7m_name).name
    for ext in P7M_EXTS:
        if name.lower().endswith(ext):
            return name[: -len(ext)]
    return name + ".payload"


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=60)
    except FileNotFoundError as exc:
        raise ForensicsError(
            "OpenSSL is required to unwrap .p7m envelopes "
            "(install the openssl binary)") from exc
    except subprocess.TimeoutExpired as exc:
        raise ForensicsError(f"openssl timed out: {exc}") from exc
    return completed.returncode, (completed.stderr or completed.stdout or "")


def signer_certificates(p7m_path: Path) -> list[dict]:
    """List signer certificates: CN, issuer CN, validity end (if shown)."""
    code, output = _run(["openssl", "pkcs7", "-inform", "DER",
                         "-print_certs", "-in", str(p7m_path)])
    if code != 0:
        return []
    certificates: list[dict] = []
    subject_cn = issuer_cn = ""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            subject_cn = _cn_of(line[8:])
        elif line.startswith("issuer="):
            issuer_cn = _cn_of(line[7:])
        elif line.startswith("-----BEGIN"):
            if subject_cn:
                certificates.append({"cn": subject_cn, "issuer_cn": issuer_cn})
            subject_cn = issuer_cn = ""
    if subject_cn:  # trailing certificate without closing banner parsed
        certificates.append({"cn": subject_cn, "issuer_cn": issuer_cn})
    return certificates


def _cn_of(subject: str) -> str:
    match = re.search(r"(?:^|[,/])CN\s*=\s*([^,/\n]+)", subject)
    return match.group(1).strip() if match else subject.strip()


def unpack_p7m(p7m_path: Path, out_path: Path) -> dict:
    """Unwrap an attached CAdES envelope.

    Returns {ok, payload_path, sha256_envelope, sha256_payload, signers,
    error}. ``ok`` is False for detached signatures or malformed envelopes,
    but signer metadata is still collected where possible.
    """
    if not p7m_path.is_file():
        raise ForensicsError(f"envelope not found: {p7m_path}")
    if not shutil.which("openssl"):
        raise ForensicsError(
            "OpenSSL is required to unwrap .p7m envelopes "
            "(install the openssl binary)")
    result: dict = {
        "ok": False,
        "payload_path": "",
        "sha256_envelope": sha256_file(p7m_path),
        "sha256_payload": None,
        "signers": [],
        "error": "",
    }
    code, message = _run(["openssl", "smime", "-verify", "-noverify",
                          "-inform", "DER", "-in", str(p7m_path),
                          "-out", str(out_path)])
    if code == 0 and out_path.is_file() and out_path.stat().st_size > 0:
        result["ok"] = True
        result["payload_path"] = str(out_path)
        result["sha256_payload"] = sha256_file(out_path)
    else:
        result["error"] = (message or "verify failed").strip().splitlines()
        result["error"] = result["error"][-1] if result["error"] else "unknown"
    try:
        result["signers"] = signer_certificates(p7m_path)
    except ForensicsError:
        result["signers"] = []
    return result
