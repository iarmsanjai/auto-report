"""
PDF Parser — extracts text from PDF reports for manual review or basic parsing.
Uses PyMuPDF (fitz) for text extraction.
"""
from __future__ import annotations

import io
import re
import uuid
import logging
from typing import List

from models.schemas import Finding, CVSSModel, ImportResult

log = logging.getLogger(__name__)

SEV_KEYWORDS = {
    "critical": ["critical", "crit"],
    "high": ["high"],
    "medium": ["medium", "moderate", "med"],
    "low": ["low", "minor"],
    "info": ["info", "informational", "note", "best practice"],
}


def _detect_severity(text: str) -> str:
    t = text.lower()
    for level, kws in SEV_KEYWORDS.items():
        if any(kw in t for kw in kws):
            return level
    return "info"


def _extract_text_fitz(content: bytes) -> str:
    """Extract full text using PyMuPDF."""
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(stream=io.BytesIO(content), filetype="pdf")
        pages = []
        for page in doc:
            pages.append(page.get_text("text"))
        return "\n".join(pages)
    except ImportError:
        log.warning("PyMuPDF not installed — falling back to pdfminer")
        return _extract_text_pdfminer(content)
    except Exception as e:
        log.error("fitz extraction failed: %s", e)
        return ""


def _extract_text_pdfminer(content: bytes) -> str:
    """Fallback text extraction using pdfminer.six."""
    try:
        from pdfminer.high_level import extract_text as pm_extract
        return pm_extract(io.BytesIO(content))
    except ImportError:
        log.warning("pdfminer not installed — cannot extract PDF text")
        return ""
    except Exception as e:
        log.error("pdfminer extraction failed: %s", e)
        return ""


def _extract_raw_text(content: bytes) -> str:
    """Try multiple extractors."""
    text = _extract_text_fitz(content)
    if not text.strip():
        text = _extract_text_pdfminer(content)
    return text


def _parse_finding_blocks(text: str) -> List[Finding]:
    """
    Heuristic parser: tries to split PDF text into finding blocks.
    Works best with well-structured reports (section-per-finding layout).
    """
    findings: List[Finding] = []

    # Pattern: look for numbered finding sections like "6.1 SQL Injection"
    block_re = re.compile(
        r"(?:6\.\d+|Finding\s+\d+|Vulnerability\s+\d+|Issue\s+\d+)[:\s]+(.+?)(?=(?:6\.\d+|Finding\s+\d+|Vulnerability\s+\d+|Issue\s+\d+)|$)",
        re.IGNORECASE | re.DOTALL,
    )

    matches = list(block_re.finditer(text))

    for match in matches:
        block = match.group(0).strip()
        title_match = re.search(r"(?:6\.\d+|Finding \d+|Vulnerability \d+)\s+(.+)", block, re.IGNORECASE)
        title = title_match.group(1).split("\n")[0].strip() if title_match else "Extracted Finding"

        # Severity
        sev_match = re.search(
            r"(?:risk level|severity|criticality)[:\s]+(critical|high|medium|low|info\w*)",
            block, re.IGNORECASE
        )
        level = sev_match.group(1).lower() if sev_match else _detect_severity(block)
        if "info" in level:
            level = "info"

        # CVSS
        cvss_match = re.search(r"CVSS[^:]*Score[:\s]+(\d+\.?\d*)", block, re.IGNORECASE)
        score = float(cvss_match.group(1)) if cvss_match else 0.0

        cvss_vec_match = re.search(r"(CVSS:3\.[01]/[A-Z:/]+)", block)
        vector = cvss_vec_match.group(1) if cvss_vec_match else ""

        # Description: text after title before known section headers
        desc_match = re.search(
            r"(?:Description|Details)[:\s]+(.+?)(?:Impact|Recommendation|Solution|Proof|References|$)",
            block, re.IGNORECASE | re.DOTALL
        )
        description = desc_match.group(1).strip()[:2000] if desc_match else block[:500].strip()

        # Impact
        impact_match = re.search(
            r"(?:Business Impact|Impact)[:\s]+(.+?)(?:Recommendation|Solution|Proof|References|$)",
            block, re.IGNORECASE | re.DOTALL
        )
        impact = impact_match.group(1).strip()[:1000] if impact_match else ""

        # Recommendation
        rec_match = re.search(
            r"(?:Recommendation|Solution|Remediation)[:\s]+(.+?)(?:References|Proof|$)",
            block, re.IGNORECASE | re.DOTALL
        )
        recommendation = rec_match.group(1).strip()[:1000] if rec_match else ""

        # CWE
        cwe_match = re.search(r"CWE-(\d+)", block, re.IGNORECASE)
        cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else ""

        # References
        refs = re.findall(r"https?://[^\s\)\]>\"]+", block)

        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            title=title[:200],
            summary="",
            description=description,
            impact=impact,
            recommendation=recommendation,
            cvss=CVSSModel(score=score, vector=vector, level=level),
            ease="Moderate",
            cwe=cwe,
            affected_components=[],
            payload=[],
            poc="",
            references=list(set(refs)),
            validated=False,
            false_positive=False,
            source="pdf",
        ))

    return findings


def parse_pdf(content: bytes, filename: str = "") -> ImportResult:
    """
    Extract and parse a PDF report.
    Returns raw text extraction + any structured findings detected.
    """
    warnings: List[str] = []

    raw_text = _extract_raw_text(content)
    if not raw_text.strip():
        return ImportResult(
            count=0,
            findings=[],
            skipped=0,
            source="pdf",
            warnings=["Could not extract text from PDF. Ensure the PDF is not image-only/scanned."],
        )

    findings = _parse_finding_blocks(raw_text)

    if not findings:
        warnings.append(
            "PDF text extracted but no structured findings detected. "
            "Use the raw text below to manually create findings."
        )

    return ImportResult(
        count=len(findings),
        findings=findings,
        skipped=0,
        source="pdf",
        warnings=warnings,
    )


def extract_raw_text(content: bytes) -> str:
    """Public helper — return raw PDF text without parsing."""
    return _extract_raw_text(content)
