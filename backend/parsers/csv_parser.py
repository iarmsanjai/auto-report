"""
CSV Parser — supports Nessus, OpenVAS, Burp Suite, and generic CSV formats.
Auto-detects the scanner type by inspecting column headers.
"""
from __future__ import annotations

import io
import uuid
import logging
from typing import List, Tuple

import pandas as pd

from config.mappings import (
    NESSUS_MAP, OPENVAS_MAP, BURP_MAP, GENERIC_MAP,
    SEVERITY_NORMALISE, EASE_NORMALISE,
)
from models.schemas import Finding, CVSSModel, ImportResult

log = logging.getLogger(__name__)

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _detect_scanner(columns: List[str]) -> Tuple[str, dict]:
    """Return (scanner_name, field_map) by column fingerprinting."""
    cols_lower = {c.lower().strip() for c in columns}

    nessus_sig = {"plugin id", "synopsis", "plugin output"}
    openvas_sig = {"nvt oid", "specific result", "nvt name"}
    burp_sig = {"issue name", "issue background", "remediation background"}

    if nessus_sig & cols_lower:
        return "nessus", NESSUS_MAP
    if openvas_sig & cols_lower:
        return "openvas", OPENVAS_MAP
    if burp_sig & cols_lower:
        return "burp", BURP_MAP
    return "generic", GENERIC_MAP


def _norm_sev(raw: str) -> str:
    s = (raw or "").lower().strip()
    return SEVERITY_NORMALISE.get(s, "info")


def _norm_ease(raw: str) -> str:
    s = (raw or "").lower().strip()
    return EASE_NORMALISE.get(s, "Moderate")


def _resolve(row: pd.Series, col_map: List[str], df_cols_lower: dict) -> str:
    """Try each alias in col_map and return first non-empty value."""
    for alias in col_map:
        key = df_cols_lower.get(alias.lower().strip())
        if key:
            val = str(row.get(key, "") or "").strip()
            if val and val.lower() not in ("nan", "none", "null", ""):
                return val
    return ""


def _build_finding(row: pd.Series, field_map: dict, df_cols_lower: dict) -> Finding | None:
    """Map a CSV row to a Finding. Returns None if row should be skipped."""

    def get(key: str) -> str:
        return _resolve(row, field_map.get(key, []), df_cols_lower)

    risk_raw = get("cvss.level")
    level = _norm_sev(risk_raw)

    # Skip rows with no meaningful severity
    if not risk_raw or risk_raw.lower() in ("none", "passed", "open", "n/a"):
        return None

    title = get("title") or "Untitled Finding"

    score_raw = get("cvss.score")
    try:
        score = float(score_raw)
    except (ValueError, TypeError):
        score = 0.0

    # References — may be newline-separated
    refs_raw = get("references")
    refs = [r.strip() for r in refs_raw.replace(";", "\n").split("\n") if r.strip() and r.strip().lower() != "nan"]

    # Components
    component = get("affected_components")
    components = [component] if component else []

    # Payloads from poc field if present
    poc = get("poc")

    return Finding(
        id=str(uuid.uuid4())[:8],
        title=title,
        summary=get("summary"),
        description=get("description"),
        impact=get("impact"),
        recommendation=get("recommendation"),
        cvss=CVSSModel(
            score=score,
            vector=get("cvss.vector"),
            level=level,
        ),
        ease=_norm_ease(""),
        cwe=get("cwe"),
        affected_components=components,
        payload=[],
        poc=poc,
        references=refs,
        validated=False,
        false_positive=False,
        source="csv",
    )


def parse_csv(content: bytes, filename: str = "") -> ImportResult:
    """
    Parse a CSV file and return an ImportResult with normalized findings.
    Auto-detects encoding and scanner type.
    """
    warnings = []

    # Try UTF-8 first, fall back to latin-1
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            df = pd.read_csv(
                io.BytesIO(content),
                encoding=enc,
                on_bad_lines="skip",
                low_memory=False,
            )
            break
        except Exception:
            df = None

    if df is None or df.empty:
        return ImportResult(count=0, findings=[], source="csv", warnings=["Empty or unreadable CSV"])

    scanner, field_map = _detect_scanner(list(df.columns))
    log.info("Detected scanner: %s, rows: %d", scanner, len(df))

    # Build a lowercase column lookup: lower_name → original_name
    df_cols_lower = {c.lower().strip(): c for c in df.columns}

    findings: List[Finding] = []
    skipped = 0

    for _, row in df.iterrows():
        try:
            f = _build_finding(row, field_map, df_cols_lower)
            if f:
                findings.append(f)
            else:
                skipped += 1
        except Exception as e:
            log.warning("Row parse error: %s", e)
            skipped += 1

    # Sort by severity
    findings.sort(key=lambda f: SEV_ORDER.get(f.cvss.level, 99))

    if not findings:
        warnings.append(f"No findings extracted. Detected format: {scanner}. Check column names match expected format.")

    return ImportResult(
        count=len(findings),
        findings=findings,
        skipped=skipped,
        source=f"csv:{scanner}",
        warnings=warnings,
    )
