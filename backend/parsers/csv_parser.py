"""
CSV Parser — supports Nessus, OpenVAS, Burp Suite, and generic CSV formats.
Auto-detects the scanner type by inspecting column headers.
"""
from __future__ import annotations

import io
import re
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


def extract_port_from_string(s: str) -> Tuple[str, str]:
    """
    Extract (port, protocol) from a string component like URL, IP:port, etc.
    Returns (port, protocol) or ("", "").
    """
    s = s.strip()
    if not s:
        return "", ""

    # Check for formats like (tcp/80) or tcp/80 or 80/tcp
    m = re.search(r'\b(tcp|udp)/(\d+)\b', s, re.IGNORECASE)
    if m:
        return m.group(2), m.group(1).lower()
    m = re.search(r'\b(\d+)/(tcp|udp)\b', s, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2).lower()
    m = re.search(r'\b(tcp|udp)\s*[:\(\s]\s*(\d+)\b', s, re.IGNORECASE)
    if m:
        return m.group(2), m.group(1).lower()
    m = re.search(r'\b(\d+)\s*\(\s*(tcp|udp)\s*\)', s, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2).lower()

    # Check for URL with port: http://example.com:8080/path
    m = re.search(r'^(https?)://[^/:]+:(\d+)', s, re.IGNORECASE)
    if m:
        return m.group(2), "tcp"

    # Check for URL without explicit port: https://example.com/path
    if s.lower().startswith("https://"):
        return "443", "tcp"
    if s.lower().startswith("http://"):
        return "80", "tcp"

    # Check for IP:port or Host:port (ignoring IPv6 unless in brackets)
    m = re.search(r':(\d+)\b', s)
    if m:
        if s.count(':') <= 2 or ('[' in s and ']' in s):
            return m.group(1), "tcp"

    return "", ""


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


def _get_vulnerability_key(row: pd.Series, field_map: dict, df_cols_lower: dict) -> tuple:
    """
    Construct a stable vulnerability grouping key using vulnerability-identifying fields:
    1. Plugin ID / Plugin / PluginId
    2. Vulnerability Name / Plugin Name
    3. CVE / CVEs
    4. CWE
    Does NOT include Host IP, Port, Protocol, or Hostname.
    """
    plugin_id = _resolve(row, ["Plugin ID", "Plugin", "PluginId", "ID", "NVT OID", "Issue ID"], df_cols_lower)
    title = _resolve(row, field_map.get("title", []), df_cols_lower)
    cve = _resolve(row, ["CVE", "CVEs", "CVE ID", "cve_id"], df_cols_lower)
    cwe = _resolve(row, field_map.get("cwe", []), df_cols_lower)

    if plugin_id:
        return ("plugin_id", plugin_id.lower().strip())
    elif cve:
        return ("cve_title", cve.lower().strip(), title.lower().strip())
    elif cwe and title:
        return ("cwe_title", cwe.lower().strip(), title.lower().strip())
    else:
        return ("title", title.lower().strip())


def _extract_row_endpoint(row: pd.Series, field_map: dict, df_cols_lower: dict) -> Tuple[str, str, str]:
    """
    Extract (host_ip, port, protocol) for a single CSV row.
    """
    host_ip = _resolve(row, field_map.get("affected_components", []) + ["Host", "IP", "IP Address", "Hostname", "Target", "URL"], df_cols_lower)
    port = _resolve(row, field_map.get("port", []), df_cols_lower)
    protocol = _resolve(row, field_map.get("protocol", []), df_cols_lower)

    if host_ip:
        if not port:
            ext_port, ext_proto = extract_port_from_string(host_ip)
            if ext_port:
                port = ext_port
                if ext_proto and not protocol:
                    protocol = ext_proto
        # Strip port or scheme from host_ip if embedded (e.g. "192.168.0.1:8080" -> "192.168.0.1")
        m = re.match(r'^(?:https?://)?([^:/]+)', host_ip, re.IGNORECASE)
        if m:
            host_ip = m.group(1)

    return host_ip.strip(), port.strip(), protocol.strip()


def parse_csv(content: bytes, filename: str = "") -> ImportResult:
    """
    Parse a CSV file and return an ImportResult with normalized, grouped findings.
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

    grouped_data: dict[tuple, dict] = {}
    skipped = 0

    for _, row in df.iterrows():
        try:
            def get(key: str) -> str:
                return _resolve(row, field_map.get(key, []), df_cols_lower)

            risk_raw = get("cvss.level")
            level = _norm_sev(risk_raw)

            # Skip rows with no meaningful severity
            if not risk_raw or risk_raw.lower() in ("none", "passed", "open", "n/a"):
                skipped += 1
                continue

            title = get("title") or "Untitled Finding"

            score_raw = get("cvss.score")
            try:
                score = float(score_raw)
            except (ValueError, TypeError):
                score = 0.0

            refs_raw = get("references")
            refs = [r.strip() for r in refs_raw.replace(";", "\n").split("\n") if r.strip() and r.strip().lower() != "nan"]

            poc = get("poc")

            group_key = _get_vulnerability_key(row, field_map, df_cols_lower)
            host_ip, port, protocol = _extract_row_endpoint(row, field_map, df_cols_lower)

            if group_key not in grouped_data:
                grouped_data[group_key] = {
                    "title": title,
                    "summary": get("summary"),
                    "description": get("description"),
                    "impact": get("impact"),
                    "recommendation": get("recommendation"),
                    "cvss_vector": get("cvss.vector"),
                    "cwe": get("cwe"),
                    "ease": _norm_ease(""),
                    "severities": [level],
                    "scores": [score],
                    "poc": poc,
                    "references": set(refs),
                    "endpoints_seen": set(),
                    "affected_hosts": [],
                }

            group = grouped_data[group_key]
            group["severities"].append(level)
            group["scores"].append(score)
            if refs:
                group["references"].update(refs)
            if not group["description"] and get("description"):
                group["description"] = get("description")
            if not group["impact"] and get("impact"):
                group["impact"] = get("impact")
            if not group["recommendation"] and get("recommendation"):
                group["recommendation"] = get("recommendation")
            if not group["cwe"] and get("cwe"):
                group["cwe"] = get("cwe")
            if not group["poc"] and poc:
                group["poc"] = poc

            # Deduplicate Affected Endpoints: IP + Port + Protocol
            ep_key = (host_ip, port, protocol.lower())
            if (host_ip or port) and ep_key not in group["endpoints_seen"]:
                group["endpoints_seen"].add(ep_key)
                from models.schemas import AffectedHost
                group["affected_hosts"].append(
                    AffectedHost(ip=host_ip, port=port, protocol=protocol)
                )

        except Exception as e:
            log.warning("Row parse error: %s", e)
            skipped += 1

    findings: List[Finding] = []
    for key, group in grouped_data.items():
        unique_sevs = set(group["severities"])
        # Pick highest severity (Critical=0, High=1, Medium=2, Low=3, Info=4)
        highest_level = min(group["severities"], key=lambda s: SEV_ORDER.get(s, 99))
        highest_score = max(group["scores"]) if group["scores"] else 0.0

        if len(unique_sevs) > 1:
            msg = f"Vulnerability '{group['title']}' has inconsistent severities across endpoints: {sorted(list(unique_sevs))}. Retained highest severity '{highest_level}'."
            log.warning(msg)
            warnings.append(msg)

        # Build affected_components list
        affected_comps = []
        for ah in group["affected_hosts"]:
            if ah.ip and ah.port:
                comp_str = f"{ah.ip}:{ah.port}"
            elif ah.ip:
                comp_str = ah.ip
            elif ah.port:
                comp_str = f"Port {ah.port}"
            else:
                comp_str = ""
            if comp_str and comp_str not in affected_comps:
                affected_comps.append(comp_str)

        # Build port_protocol summary
        unique_ports = []
        for ah in group["affected_hosts"]:
            p_str = ah.port
            if ah.protocol and p_str and ah.protocol.lower() not in p_str.lower():
                p_str = f"{ah.port}/{ah.protocol}"
            if p_str and p_str not in unique_ports:
                unique_ports.append(p_str)
        port_protocol_str = ", ".join(unique_ports)

        f = Finding(
            id=str(uuid.uuid4())[:8],
            title=group["title"],
            summary=group["summary"],
            description=group["description"],
            impact=group["impact"],
            recommendation=group["recommendation"],
            cvss=CVSSModel(
                score=highest_score,
                vector=group["cvss_vector"],
                level=highest_level,
            ),
            ease=group["ease"],
            cwe=group["cwe"],
            affected_components=affected_comps,
            affected_hosts=group["affected_hosts"],
            payload=[],
            poc=group["poc"],
            references=sorted(list(group["references"])),
            validated=False,
            false_positive=False,
            source="csv",
            port_protocol=port_protocol_str,
        )
        findings.append(f)

    # Sort grouped findings by severity (Critical → High → Medium → Low → Info)
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
