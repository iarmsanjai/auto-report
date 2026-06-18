"""
Field Mapper — normalises any JSON findings structure into internal Finding schema.
Handles: direct schema, nested objects, various naming conventions.
"""
from __future__ import annotations

import uuid
import logging
from typing import Any, Dict, List

from config.mappings import GENERIC_MAP, SEVERITY_NORMALISE, EASE_NORMALISE
from models.schemas import AffectedHost, Finding, CVSSModel, ImportResult
from parsers.csv_parser import extract_port_from_string

log = logging.getLogger(__name__)

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _norm_sev(raw: Any) -> str:
    s = str(raw or "").lower().strip()
    return SEVERITY_NORMALISE.get(s, "info")


def _norm_ease(raw: Any) -> str:
    s = str(raw or "").lower().strip()
    return EASE_NORMALISE.get(s, "Moderate")


def _pluck(obj: Dict, keys: List[str], default: Any = "") -> Any:
    """Return first non-empty value matching any of the keys (case-insensitive)."""
    obj_lower = {k.lower().replace("-", "_").replace(" ", "_"): v for k, v in obj.items()}
    for key in keys:
        norm = key.lower().replace("-", "_").replace(" ", "_")
        v = obj_lower.get(norm)
        if v is not None and str(v).strip() not in ("", "none", "null", "nan"):
            return v
    return default


def _extract_cvss(raw: Any, obj: Dict) -> CVSSModel:
    """Extract CVSS data from various formats."""
    if isinstance(raw, dict):
        score_raw = raw.get("score") or raw.get("base_score") or 0
        vector = raw.get("vector") or raw.get("vector_string") or ""
        level_raw = raw.get("level") or raw.get("severity") or ""
        try:
            score = float(score_raw)
        except (TypeError, ValueError):
            score = 0.0
        return CVSSModel(score=score, vector=str(vector), level=_norm_sev(level_raw or score_to_level(score)))

    # flat fields
    for key in ["cvss_score", "cvss score", "score", "base_score"]:
        if key.lower().replace(" ", "_") in {k.lower().replace(" ", "_") for k in obj}:
            val = _pluck(obj, [key])
            try:
                score = float(val)
            except (TypeError, ValueError):
                score = 0.0
            break
    else:
        score = 0.0

    vector = str(_pluck(obj, ["cvss_vector", "cvss vector", "vector", "vector_string"]))
    sev_raw = _pluck(obj, ["severity", "risk", "level", "cvss_level"])
    return CVSSModel(score=score, vector=vector, level=_norm_sev(sev_raw or score_to_level(score)))


def score_to_level(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"


def _coerce_list(val: Any) -> List[str]:
    if isinstance(val, list):
        return [str(v).strip() for v in val if v and str(v).strip()]
    if isinstance(val, str) and val.strip():
        return [s.strip() for s in val.replace(";", "\n").split("\n") if s.strip()]
    return []


def map_finding(raw: Dict) -> Finding | None:
    """Map a single raw dict → Finding. Returns None if unusable."""
    if not raw or not isinstance(raw, dict):
        return None

    title = str(_pluck(raw, ["title", "name", "vulnerability", "finding", "issue", "plugin_name"]) or "").strip()
    if not title:
        return None

    cvss_raw = raw.get("cvss") or raw.get("cvss_info") or {}
    cvss = _extract_cvss(cvss_raw, raw)

    components = _coerce_list(
        _pluck(raw, ["affected_components", "hosts", "host", "url", "endpoint", "target", "component"])
    )
    payloads = _coerce_list(_pluck(raw, ["payload", "payloads", "pocs"]))
    refs = _coerce_list(_pluck(raw, ["references", "refs", "see_also", "links"]))
    evidence = _coerce_list(_pluck(raw, ["evidence_images", "screenshots", "images"]))

    ease_raw = _pluck(raw, ["ease", "ease_of_exploit", "exploitability"])
    cwe = str(_pluck(raw, ["cwe", "cwe_id", "weakness_id"]))
    if cwe and not cwe.upper().startswith("CWE"):
        cwe = f"CWE-{cwe}"

    # VA-specific extras
    port_proto = str(_pluck(raw, ["port_protocol", "port", "protocol"]))
    if not port_proto.strip() or port_proto.lower() in ("nan", "none", "null"):
        # Fallback 1: Try to extract from affected_components
        for comp in components:
            ext_port, ext_proto = extract_port_from_string(comp)
            if ext_port:
                port_proto = f"{ext_port}/{ext_proto}" if ext_proto else ext_port
                break

        # Fallback 2: Check other common fields in the raw dictionary
        if not port_proto.strip() or port_proto.lower() in ("nan", "none", "null"):
            for field in ["host", "ip", "url", "target", "endpoint", "destination", "dest"]:
                val = _pluck(raw, [field])
                if val:
                    ext_port, ext_proto = extract_port_from_string(str(val))
                    if ext_port:
                        port_proto = f"{ext_port}/{ext_proto}" if ext_proto else ext_port
                        break

    output_text = str(_pluck(raw, ["output", "plugin_output", "raw_output"]))
    raw_hosts = _pluck(raw, ["affected_hosts", "hosts"], default=[])
    if isinstance(raw_hosts, list):
        ah_list = [AffectedHost(**h) if isinstance(h, dict) else AffectedHost(ip=str(h)) for h in raw_hosts]
    else:
        ah_list = []

    return Finding(
        id=str(_pluck(raw, ["id"])) or str(uuid.uuid4())[:8],
        title=title[:300],
        summary=str(_pluck(raw, ["summary", "synopsis", "brief"]))[:500],
        description=str(_pluck(raw, ["description", "details", "body", "detail"]))[:5000],
        impact=str(_pluck(raw, ["impact", "business_impact", "effect"]))[:2000],
        recommendation=str(_pluck(raw, ["recommendation", "solution", "remediation", "fix", "mitigation"]))[:3000],
        cvss=cvss,
        ease=_norm_ease(ease_raw),
        cwe=cwe,
        affected_components=components,
        payload=payloads,
        poc=str(_pluck(raw, ["poc", "proof_of_concept", "steps_to_reproduce", "reproduction"]))[:3000],
        references=refs,
        validated=bool(_pluck(raw, ["validated", "verified"])),
        false_positive=bool(_pluck(raw, ["false_positive", "fp", "false_pos"])),
        source=str(_pluck(raw, ["source"])) or "json",
        evidence_images=evidence,
        port_protocol=port_proto,
        output=output_text,
        affected_hosts=ah_list,
    )


def map_json_findings(data: Any) -> ImportResult:
    """
    Map a JSON payload of any structure to ImportResult.
    Handles: list of findings, {findings: []}, {vulnerabilities: []}, {results: []}.
    """
    warnings: List[str] = []

    if isinstance(data, list):
        raw_list = data
    elif isinstance(data, dict):
        # Look for the findings array under common keys
        for key in ("findings", "vulnerabilities", "results", "issues", "items", "data"):
            if key in data and isinstance(data[key], list):
                raw_list = data[key]
                break
        else:
            # Try the whole dict as a single finding
            raw_list = [data]
    else:
        return ImportResult(count=0, findings=[], source="json", warnings=["Unrecognised JSON structure"])

    findings: List[Finding] = []
    skipped = 0

    for item in raw_list:
        try:
            f = map_finding(item)
            if f:
                findings.append(f)
            else:
                skipped += 1
        except Exception as e:
            log.warning("Mapping error: %s", e)
            skipped += 1

    findings.sort(key=lambda f: SEV_ORDER.get(f.cvss.level, 99))

    if not findings:
        warnings.append("No valid findings mapped. Check JSON structure matches expected schema.")

    return ImportResult(
        count=len(findings),
        findings=findings,
        skipped=skipped,
        source="json",
        warnings=warnings,
    )
