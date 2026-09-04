"""OCR with a 4-way rotation grid (0/90/180/270).

The grid runs tesseract on each orientation and picks the angle with the
best lexical score, so rotated scans are transcribed correctly without
manual pre-rotation. OCR dependencies are optional (``pip install -e
".[ocr]"``); the lexical scorer itself is pure and unit-testable.
"""

from __future__ import annotations

import re
from pathlib import Path

from .errors import ForensicsError, OptionalDependencyError

ANGLES = (0, 90, 180, 270)
_WORD_RE = re.compile(r"[A-Za-zÀ-ÖØ-öø-ÿ]{3,}")
_NOISE_RE = re.compile(r"[^A-Za-zÀ-ÖØ-öø-ÿ0-9\s.,;:!?'\"()\-]")
_IMG_EXTS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif"}
_PDF_EXT = ".pdf"


def score_text(text: str) -> float:
    """Lexical quality score: real words up-weight, OCR noise down-weights.

    Higher is better. A clean sentence outscores tesseract gibberish.
    """
    words = _WORD_RE.findall(text)
    if not words:
        return 0.0
    word_chars = sum(len(w) for w in words)
    noise = len(_NOISE_RE.findall(text))
    long_words = sum(1 for w in words if len(w) >= 6)
    return word_chars - 3.0 * noise + 1.5 * long_words - 2.0 * len(words)


def _ocr_modules():
    try:
        import PIL.Image  # noqa: F401
        import pytesseract  # noqa: F401
    except ImportError as exc:
        raise OptionalDependencyError(
            "OCR requires the optional extra: pip install -e \".[ocr]\" "
            "(pytesseract + pdf2image + Pillow) and a tesseract binary"
        ) from exc
    try:
        from pdf2image import convert_from_path  # noqa: F401
    except ImportError:
        convert_from_path = None
    import pytesseract
    import PIL.Image
    return pytesseract, PIL.Image, convert_from_path


def choose_best_angle(ocr_call, image, lang: str) -> tuple[int, str]:
    """Run ``ocr_call(image_rotated, lang)`` on every angle of ``image``
    and return (best_angle, best_text). Injectable for offline tests."""
    best_angle, best_text, best_score = 0, "", -1.0
    for angle in ANGLES:
        rotated = image.rotate(angle, expand=True)
        try:
            text = ocr_call(rotated, lang) or ""
        except Exception as exc:
            raise ForensicsError(f"tesseract failed at {angle}°: {exc}") from exc
        score = score_text(text)
        if score > best_score:
            best_angle, best_text, best_score = angle, text, score
    return best_angle, best_text


def ocr_file(path: Path, lang: str = "ita+eng", out_dir: Path | None = None,
             suffix: str = ".ocr.txt") -> tuple[Path, int, str]:
    """OCR one image/PDF with rotation-grid orientation. Returns
    (output_path, best_angle, best_text)."""
    pytesseract, PILImage, convert_from_path = _ocr_modules()
    if path.suffix.lower() in _IMG_EXTS:
        with PILImage.open(path) as image:
            best_angle, best_text = choose_best_angle(
                pytesseract.image_to_string, image.convert("RGB"), lang)
    elif path.suffix.lower() == _PDF_EXT:
        if convert_from_path is None:
            raise OptionalDependencyError(
                "PDF OCR needs poppler: install poppler-utils and the "
                "\"[ocr]\" extra (pdf2image)")
        pages = convert_from_path(str(path))
        if not pages:
            raise ForensicsError(f"no pages rendered from {path.name}")
        best_angle, best_text = 0, ""
        for page in pages:
            angle, text = choose_best_angle(
                pytesseract.image_to_string, page.convert("RGB"), lang)
            best_text += text + "\n"
    else:
        raise ForensicsError(f"unsupported input for OCR: {path.name}")

    target_dir = out_dir if out_dir is not None else path.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    out_path = target_dir / (path.stem + suffix)
    out_path.write_text(best_text, encoding="utf-8")
    return out_path, best_angle, best_text


def iter_ocr_targets(path: Path) -> list[Path]:
    """Image/PDF files under a path (file itself or directory scan)."""
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*")
                  if p.suffix.lower() in _IMG_EXTS or p.suffix.lower() == _PDF_EXT)
