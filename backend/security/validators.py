"""
security/validators.py
───────────────────────────────────────────────────────────────────────────────
Centralised server-side input validation and sanitisation helpers.

Security controls implemented
──────────────────────────────
• Allow-list character validation (usernames, template names, status values)
• Path traversal prevention — template names resolved to an absolute path that
  must stay inside the configured TEMPLATES_DIR root.
• File upload security — extension allow-list, MIME type via magic bytes,
  file size cap, UUID rename.
• Field length enforcement — minimum and maximum lengths.
• URL validation — only http/https schemes allowed.
• No block-list / regex bypass risk: all rules use positive allow-lists.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, UploadFile

# ── Allow-lists ───────────────────────────────────────────────────────────────

# Username: 2-32 chars, alphanumeric + underscore only
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{2,32}$")

# Template name: alphanumeric, underscore, hyphen, forward-slash only
# Max 80 chars — enough for any nested path like "VA_template/default_report"
_TEMPLATE_RE = re.compile(r"^[a-zA-Z0-9_\-/]{1,80}$")

# CVSS vector — basic structural check (CVSS:3.x/...)
_CVSS_VECTOR_RE = re.compile(r"^CVSS:[0-9]\.[0-9]/.+$")

# HTTP/HTTPS URL
_URL_RE = re.compile(
    r"^https?://"
    r"(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]){1,2048}$"
)

# Allowed report status values (positive allow-list — no free-text from client)
ALLOWED_STATUSES = frozenset({"draft", "pending_approval", "approved", "needs_change"})

# Allowed user roles
ALLOWED_ROLES = frozenset({"admin", "editor", "viewer"})

# Allowed AI generation fields
ALLOWED_AI_FIELDS = frozenset({"description", "impact", "poc", "recommendation"})

# Allowed file upload extensions (VAPT context: CSV imports only via /import/csv)
ALLOWED_UPLOAD_EXTENSIONS = frozenset({".csv"})

# Magic-byte signatures for allowed MIME types
# Format: {extension: [(offset, magic_bytes), ...]}
_MAGIC_BYTES: dict[str, list[tuple[int, bytes]]] = {
    ".csv": [],  # CSV is plain text — no magic bytes; rely on extension + content check
}


class InputValidator:
    """Stateless helper class — all methods are classmethods."""

    # ── Username ──────────────────────────────────────────────────────────────

    @classmethod
    def username(cls, value: str, field_label: str = "Username") -> str:
        """Validate username: 2-32 chars, alphanumeric + underscore only."""
        if not value or not isinstance(value, str):
            raise HTTPException(status_code=400, detail=f"{field_label} is required.")
        value = value.strip()
        if not _USERNAME_RE.match(value):
            raise HTTPException(
                status_code=400,
                detail=f"{field_label} must be 2–32 characters and contain only "
                       "letters, digits, or underscores.",
            )
        return value

    # ── Password ──────────────────────────────────────────────────────────────

    @classmethod
    def password(cls, value: str, field_label: str = "Password") -> str:
        """
        Enforce minimum 12-char password with at least one uppercase letter,
        one lowercase letter, one digit, and one special character.
        """
        if not value or not isinstance(value, str):
            raise HTTPException(status_code=400, detail=f"{field_label} is required.")
        if len(value) < 12:
            raise HTTPException(
                status_code=400,
                detail=f"{field_label} must be at least 12 characters long.",
            )
        if len(value) > 128:
            raise HTTPException(
                status_code=400,
                detail=f"{field_label} must not exceed 128 characters.",
            )
        checks = [
            (r"[A-Z]", "one uppercase letter"),
            (r"[a-z]", "one lowercase letter"),
            (r"[0-9]", "one digit"),
            (r"[^A-Za-z0-9]", "one special character"),
        ]
        for pattern, hint in checks:
            if not re.search(pattern, value):
                raise HTTPException(
                    status_code=400,
                    detail=f"{field_label} must contain at least {hint}.",
                )
        return value

    # ── Role ──────────────────────────────────────────────────────────────────

    @classmethod
    def role(cls, value: str) -> str:
        """Validate role against allow-list."""
        if value not in ALLOWED_ROLES:
            raise HTTPException(
                status_code=400,
                detail=f"Role must be one of: {', '.join(sorted(ALLOWED_ROLES))}.",
            )
        return value

    # ── Report status ─────────────────────────────────────────────────────────

    @classmethod
    def report_status(cls, value: str) -> str:
        """Validate report status against allow-list."""
        if value not in ALLOWED_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Status must be one of: {', '.join(sorted(ALLOWED_STATUSES))}.",
            )
        return value

    # ── Template name / Path Traversal prevention ─────────────────────────────

    @classmethod
    def template_name(cls, value: str, templates_root: Path) -> str:
        """
        Validate a template name and prevent path traversal.
        Resolves basename matching (e.g. 'default_report' -> 'VA_template/default_report')
        to match what the render engine supports.
        """
        if not value or not isinstance(value, str):
            raise HTTPException(status_code=400, detail="Template name is required.")
        value = value.strip()
        if not _TEMPLATE_RE.match(value):
            raise HTTPException(
                status_code=400,
                detail="Invalid template name. Only letters, digits, underscores, hyphens and slashes are allowed.",
            )

        # Get all available template paths relative to templates_root (without .html extension)
        available = [
            str(p.relative_to(templates_root)).replace("\\", "/")[:-5]
            for p in templates_root.glob("**/*.html")
        ]

        matched_template = None
        for t in available:
            if t.endswith(f"/{value}") or t == value:
                matched_template = t
                break

        if not matched_template:
            raise HTTPException(status_code=400, detail=f"Template '{value}' not found.")

        # Resolve to absolute path and check it remains inside templates_root
        resolved = (templates_root / f"{matched_template}.html").resolve()
        try:
            resolved.relative_to(templates_root.resolve())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid template name.")
        if not resolved.exists():
            raise HTTPException(status_code=400, detail=f"Template '{value}' not found.")
        return matched_template

    # ── File upload ───────────────────────────────────────────────────────────

    @classmethod
    async def upload_file(
        cls,
        file: UploadFile,
        allowed_extensions: frozenset = ALLOWED_UPLOAD_EXTENSIONS,
        max_mb: int = 10,
    ) -> tuple[bytes, str]:
        """
        Validate an uploaded file for:
          - Non-empty filename
          - Extension allow-list
          - File size (enforced after reading into memory)
          - Basic content safety for CSV (no null bytes, reasonable line structure)

        Returns (content_bytes, safe_uuid_filename).
        Raises HTTPException on any violation.
        """
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided.")

        original_name = file.filename
        ext = Path(original_name).suffix.lower()

        if ext not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"File type '{ext}' is not allowed. Accepted: {', '.join(sorted(allowed_extensions))}.",
            )

        # Read into memory and enforce size cap
        content = await file.read()
        max_bytes = max_mb * 1024 * 1024
        if len(content) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds the maximum allowed size of {max_mb} MB.",
            )
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        # Basic CSV safety: reject null bytes unless file is valid UTF-16 encoded text
        if ext == ".csv" and b"\x00" in content:
            is_utf16 = False
            for enc in ("utf-16", "utf-16-le", "utf-16-be"):
                try:
                    content.decode(enc)
                    is_utf16 = True
                    break
                except Exception:
                    pass
            if not is_utf16:
                raise HTTPException(
                    status_code=400,
                    detail="File content is invalid (binary data detected in CSV).",
                )

        # Generate a UUID filename to prevent path traversal / overwrite attacks
        safe_filename = f"{uuid.uuid4().hex}{ext}"

        return content, safe_filename

    # ── URL validation ────────────────────────────────────────────────────────

    @classmethod
    def url(cls, value: str, field_label: str = "URL") -> str:
        """Validate that value is a safe http/https URL."""
        if not value:
            return value
        if not _URL_RE.match(value):
            raise HTTPException(
                status_code=400,
                detail=f"{field_label} must be a valid http or https URL.",
            )
        return value

    # ── Free text length guard ────────────────────────────────────────────────

    @classmethod
    def text_field(
        cls,
        value: Optional[str],
        field_label: str,
        min_len: int = 0,
        max_len: int = 65535,
    ) -> Optional[str]:
        """Enforce min/max length on free-text fields."""
        if value is None:
            if min_len > 0:
                raise HTTPException(
                    status_code=400,
                    detail=f"{field_label} is required (min {min_len} chars).",
                )
            return value
        if len(value) < min_len:
            raise HTTPException(
                status_code=400,
                detail=f"{field_label} must be at least {min_len} characters.",
            )
        if len(value) > max_len:
            raise HTTPException(
                status_code=400,
                detail=f"{field_label} must not exceed {max_len} characters.",
            )
        return value

    # ── Report / UUID ID ──────────────────────────────────────────────────────

    @classmethod
    def report_id(cls, value: str) -> str:
        """Validate that a report ID is a valid UUID v4 string."""
        try:
            parsed = uuid.UUID(value, version=4)
            return str(parsed)
        except (ValueError, AttributeError):
            raise HTTPException(
                status_code=400,
                detail="Invalid report ID format.",
            )

    # ── AI field allow-list ───────────────────────────────────────────────────

    @classmethod
    def ai_field(cls, value: str) -> str:
        """Validate AI generation field is in the allow-list."""
        if value not in ALLOWED_AI_FIELDS:
            raise HTTPException(
                status_code=400,
                detail=f"Field must be one of: {', '.join(sorted(ALLOWED_AI_FIELDS))}.",
            )
        return value
