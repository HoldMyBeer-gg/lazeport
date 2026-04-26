"""Local OCR for extracting text from images using Tesseract (no AI/API cost)."""
import base64
import io
import logging

log = logging.getLogger(__name__)

# Optional: only import when used so server starts even if Tesseract not installed
_pytesseract = None
_Image = None


def _ensure_ocr():
    """Lazy-load pytesseract and PIL so missing Tesseract doesn't break startup."""
    global _pytesseract, _Image
    if _pytesseract is None:
        try:
            import pytesseract
            from PIL import Image
            _pytesseract = pytesseract
            _Image = Image
        except ImportError as e:
            log.warning("OCR dependencies missing: %s. Install: pip install pytesseract Pillow; system: tesseract", e)
            raise RuntimeError(
                "Local OCR is not available. Install: pip install pytesseract Pillow, "
                "and install Tesseract (e.g. brew install tesseract on macOS)."
            ) from e
    return _pytesseract, _Image


def extract_text_from_image_base64(image_base64: str, image_mime_type: str = "image/png") -> str:
    """
    Extract text from an image using Tesseract (local, no API cost).
    image_base64: raw base64 string (no data:... prefix).
    image_mime_type: e.g. image/png, image/jpeg.
    """
    pytesseract, Image = _ensure_ocr()
    try:
        raw = base64.b64decode(image_base64)
    except Exception as e:
        log.warning("OCR: invalid base64: %s", e)
        raise ValueError("Invalid image base64") from e
    try:
        img = Image.open(io.BytesIO(raw))
    except Exception as e:
        log.warning("OCR: could not open image: %s", e)
        raise ValueError("Invalid or unsupported image format") from e
    # Convert to RGB if necessary (e.g. RGBA, P)
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    try:
        text = pytesseract.image_to_string(img).strip()
    except Exception as e:
        log.warning("OCR (Tesseract) failed: %s", e)
        raise RuntimeError(
            "Tesseract failed. Ensure Tesseract is installed (e.g. brew install tesseract on macOS)."
        ) from e
    log.info("OCR extraction successful: %d chars", len(text))
    return text
