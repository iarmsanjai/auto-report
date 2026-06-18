"""
Snyk HTML Parser — extracts findings from Snyk HTML reports.
"""
from __future__ import annotations

import uuid
import logging
from typing import List

from bs4 import BeautifulSoup

from models.schemas import Finding, CVSSModel, ImportResult

log = logging.getLogger(__name__)

SEV_KEYWORDS = {
    "critical": ["critical", "crit"],
    "high": ["high"],
    "medium": ["medium", "moderate"],
    "low": ["low", "minor"],
    "info": ["info"],
}


def _detect_severity(text: str) -> str:
    t = text.lower()
    for level, kws in SEV_KEYWORDS.items():
        if any(kw in t for kw in kws):
            return level
    return "info"


def parse_snyk_html(content: bytes, filename: str = "") -> ImportResult:
    """
    Parse a Snyk HTML report into Finding objects.
    """
    soup = BeautifulSoup(content, "html.parser")
    findings: List[Finding] = []
    
    # Snyk reports often have vulnerabilities in <div class="card"> or similar.
    # We will look for cards or blocks that contain severity labels.
    cards = soup.find_all("div", class_=lambda c: c and "card" in c.lower())
    
    if not cards:
        # Fallback to looking for headings if no cards are found
        cards = soup.find_all(["h2", "h3"])
    
    for card in cards:
        text_content = card.get_text(" ", strip=True)
        # Skip empty or very short blocks
        if len(text_content) < 20:
            continue
            
        # Try to find a title — usually the first strong tag or heading
        title_el = card.find(["h2", "h3", "h4", "strong", "b"])
        title = title_el.get_text(strip=True) if title_el else text_content[:100]
        
        # Avoid duplicate titles if we accidentally parse a wrapper
        if any(f.title == title for f in findings):
            continue
            
        # Look for severity
        sev_classes = card.find_all(class_=lambda c: c and "severity" in c.lower())
        level = "info"
        if sev_classes:
            level = _detect_severity(sev_classes[0].get_text(strip=True))
        else:
            level = _detect_severity(text_content[:200])
            
        # If it doesn't look like a vulnerability block, skip it
        # Typical keywords: vulnerability, introduced through, fixed in
        if not any(kw in text_content.lower() for kw in ["vulnerability", "introduced", "cve", "cwe", "fixed in"]):
            continue
            
        # CVSS Score
        score = 0.0
        # Simple heuristic for CVSS score
        import re
        cvss_match = re.search(r"CVSS[^:]*Score[:\s]+(\d+\.?\d*)", text_content, re.IGNORECASE)
        if cvss_match:
            score = float(cvss_match.group(1))
            
        description = text_content[:2000]
        
        findings.append(Finding(
            id=str(uuid.uuid4())[:8],
            title=title[:200],
            summary="",
            description=description,
            impact="",
            recommendation="Review the Snyk report for detailed remediation steps.",
            cvss=CVSSModel(score=score, vector="", level=level),
            ease="Moderate",
            cwe="",
            affected_components=[],
            payload=[],
            poc="",
            references=[],
            validated=False,
            false_positive=False,
            source="snyk_html",
        ))

    warnings = []
    if not findings:
        warnings.append("No findings extracted from HTML. Check if it's a valid Snyk report.")

    return ImportResult(
        count=len(findings),
        findings=findings,
        skipped=0,
        source="html",
        warnings=warnings,
    )
