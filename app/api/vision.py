"""Vision API endpoints for extracting text from images."""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.services.llm import vision_completion
from app.services.ocr import extract_text_from_image_base64 as ocr_extract_text
from app.services.auth import get_current_user
from app.services.field_extraction import user_api_key_for_provider
from app.db import get_adapter

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vision", tags=["vision"])


class VisionExtractRequest(BaseModel):
    """Request to extract text from an image."""
    image_base64: str
    image_mime_type: str = "image/png"
    prompt: Optional[str] = None
    vision_model: Optional[str] = None
    provider: Optional[str] = None
    base_url: Optional[str] = None
    use_ocr: bool = False  # If True, use local Tesseract OCR instead of vision API (cost-free)
    sampling_params: Optional[dict] = None

    @field_validator('image_base64')
    @classmethod
    def validate_image(cls, v):
        if not v or len(v) < 50:
            raise ValueError("Invalid image data")
        # Basic base64 validation
        if not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in v):
            raise ValueError("Invalid base64 encoding")
        return v


@router.post("/extract-text")
def extract_text_from_image(
    payload: VisionExtractRequest,
    user=Depends(get_current_user),
    adapter=Depends(get_adapter),
):
    """
    Extract text from an image. When use_ocr=True, uses local Tesseract (no API cost).
    Otherwise uses the configured vision model (OpenAI/Ollama).
    Returns the extracted text that can be appended to notes.
    """
    try:
        if payload.use_ocr:
            log.info("OCR extraction request (local Tesseract)")
            extracted_text = ocr_extract_text(
                payload.image_base64,
                image_mime_type=payload.image_mime_type,
            )
            log.info("OCR extraction successful: %d chars extracted", len(extracted_text))
            return {"text": extracted_text, "model": "local (Tesseract)"}

        log.info(
            "Vision extraction request: model=%s, provider=%s, base_url=%s, mime=%s",
            payload.vision_model or "default",
            payload.provider or "default",
            payload.base_url or "default",
            payload.image_mime_type,
        )

        # Default prompt for extracting pentest notes
        prompt = payload.prompt or (
            "Extract content from this screenshot for pentest report notes.\n\n"
            "If the image contains text, transcribe it exactly:\n"
            "- URLs and endpoints (preserve exactly as shown)\n"
            "- HTTP headers, cookies, and parameters\n"
            "- Request/response bodies\n"
            "- Error messages or status codes\n"
            "- Code snippets or payloads\n"
            "- Any other visible text\n\n"
            "If the image contains little or no text, describe only what is literally visible in 1–2 sentences. "
            "Do not invent URLs, system names, or security context that are not clearly present in the image.\n\n"
            "Use [unclear] only for specific characters or words you cannot read. "
            "Do not add commentary beyond what is needed. Return only the extracted text or description."
        )

        # Use provided model or default to gpt-4o-mini
        model = payload.vision_model or "gpt-4o-mini"

        user_openai_key = user_api_key_for_provider(user, adapter, payload.provider)
        extracted_text = vision_completion(
            prompt=prompt,
            image_base64=payload.image_base64,
            image_mime_type=payload.image_mime_type,
            model_override=model,
            provider_override=payload.provider,
            base_url_override=payload.base_url,
            api_key_override=user_openai_key,
            sampling_params=payload.sampling_params,
        )

        log.info("Vision extraction successful: %d chars extracted", len(extracted_text))

        return {
            "text": extracted_text,
            "model": model,
        }

    except ValueError as e:
        log.error(f"Vision extraction error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        log.error("OCR not available: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Local text extraction is not available. Try 'Process with AI' or insert the image without extraction.",
        )
    except Exception as e:
        log.exception("Vision extraction failed")
        raise HTTPException(status_code=500, detail="Failed to extract text from image")
