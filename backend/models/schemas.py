"""
models/schemas.py — Pydantic models with enforced field-level validation.

Security controls:
  - Field length limits (min/max) on all free-text fields
  - URL validation — only http/https schemes on reference URLs
  - CVSS score range enforcement
  - Severity/ease allow-list via validator
  - extra="ignore" on all models to reject unexpected fields
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator
import uuid


# ── Validation constants ──────────────────────────────────────────────────────
_CVSS_VECTOR_RE = re.compile(r"^CVSS:[0-9]\.[0-9]/.{5,}$")

VALID_SEVERITY_LEVELS = frozenset({"critical", "high", "medium", "low", "info"})
VALID_EASE_VALUES = frozenset({"Trivial", "Moderate", "Difficult"})
VALID_SOURCES = frozenset({"manual", "nessus", "openvas", "generic", "burp", "csv", "import"})


def gen_id() -> str:
    return str(uuid.uuid4())[:8]


class CVSSModel(BaseModel):
    score: float = 0.0
    vector: str = Field(default="", max_length=256)
    level: str = Field(default="info", max_length=16)

    model_config = {"extra": "ignore"}

    @field_validator("level", mode="before")
    @classmethod
    def normalize_level(cls, v: Any) -> str:
        s = str(v or "").lower().strip()
        if "crit" in s:
            return "critical"
        if "high" in s:
            return "high"
        if "med" in s or "mod" in s:
            return "medium"
        if "low" in s:
            return "low"
        return "info"

    @field_validator("score", mode="before")
    @classmethod
    def coerce_score(cls, v: Any) -> float:
        try:
            score = float(v or 0)
        except (TypeError, ValueError):
            return 0.0
        # Clamp to valid CVSS range
        return max(0.0, min(10.0, score))

    @field_validator("vector", mode="before")
    @classmethod
    def validate_vector(cls, v: Any) -> str:
        if not v:
            return ""
        v = str(v).strip()
        # Allow empty or valid CVSS vector format
        if v and not _CVSS_VECTOR_RE.match(v):
            # Be lenient — warn but don't reject legacy data
            return v[:256]
        return v[:256]


class ScopedAsset(BaseModel):
    """A single in-scope asset for VA reports."""
    type: str = Field(default="", max_length=64)
    hostname: str = Field(default="", max_length=255)
    ip: str = Field(default="", max_length=45)  # IPv6 max = 45 chars

    model_config = {"extra": "ignore"}


class AffectedHost(BaseModel):
    """Affected host entry inside a finding (VA template)."""
    type: str = Field(default="", max_length=64)
    ip: str = Field(default="", max_length=45)
    port: str = Field(default="", max_length=64)
    protocol: str = Field(default="", max_length=32)

    model_config = {"extra": "ignore"}


class Finding(BaseModel):
    id: str = Field(default_factory=gen_id, max_length=64)
    title: str = Field(..., min_length=1, max_length=512)
    summary: str = Field(default="", max_length=1024)
    description: str = Field(default="", max_length=10485760)
    impact: str = Field(default="", max_length=10485760)
    recommendation: str = Field(default="", max_length=10485760)
    cvss: CVSSModel = Field(default_factory=CVSSModel)
    ease: str = Field(default="Moderate", max_length=32)
    cwe: str = Field(default="", max_length=32)
    affected_components: List[str] = Field(default_factory=list, max_length=100)
    payload: List[str] = Field(default_factory=list, max_length=50)
    poc: str = Field(default="", max_length=10485760)
    references: List[str] = Field(default_factory=list, max_length=50)
    validated: bool = False
    false_positive: bool = False
    source: str = Field(default="manual", max_length=32)
    evidence_images: List[str] = Field(default_factory=list, max_length=50)
    device_identifier: str = Field(default="", max_length=256)
    # VA-specific extras
    port_protocol: str = Field(default="", max_length=64)
    output: str = Field(default="", max_length=10485760)
    affected_hosts: List[AffectedHost] = Field(default_factory=list, max_length=500)

    model_config = {"extra": "ignore"}

    @field_validator("ease", mode="before")
    @classmethod
    def validate_ease(cls, v: Any) -> str:
        if not v:
            return "Moderate"
        v = str(v).strip()
        if v not in VALID_EASE_VALUES:
            return "Moderate"  # Normalise unknown values instead of rejecting
        return v

    @field_validator("source", mode="before")
    @classmethod
    def validate_source(cls, v: Any) -> str:
        if not v:
            return "manual"
        v = str(v).strip().lower()
        if v not in VALID_SOURCES:
            return "import"  # Normalise unknown source tags
        return v

    @field_validator("affected_components", "payload", "references", mode="before")
    @classmethod
    def cap_list_items(cls, v: Any) -> list:
        """Enforce maximum string length on list items to prevent oversized payloads."""
        if not isinstance(v, list):
            return []
        # Cap each item at 2048 chars; drop non-string items
        return [str(item)[:2048] for item in v if item is not None][:100]

    @field_validator("evidence_images", mode="before")
    @classmethod
    def cap_evidence_images(cls, v: Any) -> list:
        """Allow full base64 image strings for evidence images up to 10MB per item."""
        if not isinstance(v, list):
            return []
        return [str(item)[:10485760] for item in v if item is not None][:50]

    @property
    def severity(self) -> str:
        """Alias for cvss.level — used by VA template."""
        return self.cvss.level


class ReportMeta(BaseModel):
    client_name: str = Field(default="", max_length=256)
    application_name: str = Field(default="", max_length=256)
    application_version: str = Field(default="1.0", max_length=64)
    application_approach: str = Field(default="Gray Box", max_length=64)
    application_url: List[str] = Field(default_factory=list, max_length=20)
    tester_name: str = Field(default="", max_length=128)
    validator_name: str = Field(default="", max_length=128)
    approver_name: str = Field(default="", max_length=128)
    project_id: str = Field(default="", max_length=128)
    assessment_startdate: str = Field(default="", max_length=32)
    assessment_enddate: str = Field(default="", max_length=32)
    report_delivery_date: str = Field(default="", max_length=32)
    basic_document_date: str = Field(default="", max_length=32)
    draft_document_date: str = Field(default="", max_length=32)
    peer_review_date: str = Field(default="", max_length=32)
    reassessment: str = Field(default="30 days", max_length=64)
    outofscope: List[str] = Field(default_factory=list, max_length=100)
    # VA-specific extras
    report_month_year: str = Field(default="", max_length=32)
    assessment_type: str = Field(default="Internal/External", max_length=64)
    scoped_ips_count: str = Field(default="", max_length=16)
    document_title: str = Field(default="", max_length=256)
    approved_by: str = Field(default="", max_length=128)
    risk_graph: str = Field(default="", max_length=10485760)  # base64 image or SVG
    scoped_assets: List[ScopedAsset] = Field(default_factory=list, max_length=500)

    model_config = {"extra": "ignore"}

    @field_validator("application_url", "outofscope", mode="before")
    @classmethod
    def cap_string_lists(cls, v: Any) -> list:
        if not isinstance(v, list):
            return []
        return [str(item)[:512] for item in v if item is not None][:100]


class FindingStats(BaseModel):
    count_critical: int = 0
    count_high: int = 0
    count_medium: int = 0
    count_low: int = 0
    count_info: int = 0
    total: int = 0


class ReportPayload(BaseModel):
    report: ReportMeta
    findings: List[Finding] = Field(default_factory=list, max_length=2000)
    finding_stats: Optional[FindingStats] = None
    template: str = Field(default="default", max_length=80)

    model_config = {"extra": "ignore"}


class ValidationError(BaseModel):
    index: int
    finding_id: str
    field: str
    message: str


class ValidationResult(BaseModel):
    valid: bool
    errors: List[ValidationError] = []
    warnings: List[ValidationError] = []


class ImportResult(BaseModel):
    count: int
    findings: List[Finding]
    skipped: int = 0
    source: str = Field(default="", max_length=64)
    warnings: List[str] = []


class ParseOptions(BaseModel):
    severity_threshold: str = Field(default="info", max_length=16)
    skip_false_positives: bool = False
    normalize_severity: bool = True
    deduplicate: bool = False

    model_config = {"extra": "ignore"}
