"""
api/ai_routes.py — AI-assisted content generation endpoints.

Security controls:
  - API key read from settings.GEMINI_API_KEY (env var) — NEVER hardcoded
  - Rate limiting: 20 requests/minute per IP
  - Input validation: field allow-list, title/content length caps
  - Generic error responses — no raw exception detail exposed to client
  - Authenticated: JWT required (enforced in main.py via dependencies)
"""
import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

try:
    from google import genai
    from google.genai import types as genai_types
    _GENAI_AVAILABLE = True
except ImportError:
    _GENAI_AVAILABLE = False

from config.settings import settings
from security.middleware import check_rate_limit, get_client_ip, rate_limit_response
from security.validators import InputValidator

log = logging.getLogger(__name__)

router = APIRouter(tags=["AI"])

# ── Max input lengths ─────────────────────────────────────────────────────────
_MAX_TITLE_LEN = 512
_MAX_CONTENT_LEN = 4096


class AIGenerateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=_MAX_TITLE_LEN)
    field: str = Field(..., min_length=1, max_length=32)
    current_content: str = Field(default="", max_length=_MAX_CONTENT_LEN)

    model_config = {"extra": "ignore"}


@router.post("/generate")
async def generate_ai_content(request: Request, req: AIGenerateRequest):
    """
    Generate AI-assisted content for a VAPT finding section.
    Requires JWT authentication (enforced globally in main.py).
    Rate limited to prevent abuse.
    """
    # Rate limit: 20 AI requests per minute per IP
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip, "ai_generate", limit=20, window_seconds=60):
        log.warning("Rate limit exceeded on /ai/generate from IP: %s", client_ip)
        return rate_limit_response()
    # ── Validate API key is configured ───────────────────────────────────────
    if not settings.GEMINI_API_KEY or not _GENAI_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="AI generation is not available. Contact your administrator.",
        )

    # ── Validate field against allow-list ─────────────────────────────────────
    InputValidator.ai_field(req.field)

    # ── Sanitise inputs ───────────────────────────────────────────────────────
    title = req.title.strip()[:_MAX_TITLE_LEN]
    current_content = req.current_content.strip()[:_MAX_CONTENT_LEN]

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)

        system_prompt = (
            "You are an elite offensive security expert writing a VAPT (Vulnerability Assessment and Penetration Testing) report. "
            "Write the specific requested section concisely, using professional technical language. "
            "Use Markdown formatting (like code blocks, bolding, lists) where appropriate. "
            "Do NOT include introductory phrases like 'Here is the description'. Just output the raw markdown content for the section. "
            "Keep the length appropriate for a typical vulnerability report section (1-3 paragraphs)."
        )

        prompts = {
            "description": f"Write the 'Description' section for a vulnerability titled '{title}'. Explain what the vulnerability is and how it occurs.",
            "impact": f"Write the 'Business Impact' section for a vulnerability titled '{title}'. Explain what an attacker could achieve.",
            "poc": f"Write a hypothetical 'Proof of Concept' section for '{title}'. Provide generic steps or a code snippet to reproduce it.",
            "recommendation": f"Write the 'Recommendation' section for a vulnerability titled '{title}'. Explain how a developer should fix this issue.",
        }

        user_prompt = prompts[req.field]
        if current_content:
            user_prompt += f"\n\nThe user started writing this, use it as context if helpful:\n{current_content}"

        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=user_prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=system_prompt,
            ),
        )
        generated_text = response.text.strip()
        return {"content": generated_text}

    except HTTPException:
        raise
    except Exception as e:
        # Log the full exception internally but return a generic message to client
        log.error("AI generation error for field '%s': %s", req.field, str(e))
        raise HTTPException(
            status_code=500,
            detail="AI generation failed. Please try again later.",
        )
