from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
import uuid


def gen_id() -> str:
    return str(uuid.uuid4())[:8]


class CVSSModel(BaseModel):
    score: float = 0.0
    vector: str = ""
    level: str = "info"

    @field_validator("level", mode="before")
    @classmethod
    def normalize_level(cls, v: Any) -> str:
        s = str(v or "").lower().strip()
        if "crit" in s: return "critical"
        if "high" in s: return "high"
        if "med" in s or "mod" in s: return "medium"
        if "low" in s: return "low"
        return "info"

    @field_validator("score", mode="before")
    @classmethod
    def coerce_score(cls, v: Any) -> float:
        try:
            return float(v or 0)
        except (TypeError, ValueError):
            return 0.0


class ScopedAsset(BaseModel):
    """A single in-scope asset for VA reports."""
    type: str = ""
    hostname: str = ""
    ip: str = ""

    model_config = {"extra": "ignore"}


class AffectedHost(BaseModel):
    """Affected host entry inside a finding (VA template)."""
    type: str = ""
    ip: str = ""

    model_config = {"extra": "ignore"}


class Finding(BaseModel):
    id: str = Field(default_factory=gen_id)
    title: str
    summary: str = ""
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    cvss: CVSSModel = Field(default_factory=CVSSModel)
    ease: str = "Moderate"
    cwe: str = ""
    affected_components: List[str] = []
    payload: List[str] = []
    poc: str = ""
    references: List[str] = []
    validated: bool = False
    false_positive: bool = False
    source: str = "manual"
    evidence_images: List[str] = []
    # VA-specific extras
    port_protocol: str = ""
    output: str = ""
    affected_hosts: List[AffectedHost] = []

    model_config = {"extra": "ignore"}

    @property
    def severity(self) -> str:
        """Alias for cvss.level — used by VA template."""
        return self.cvss.level


class ReportMeta(BaseModel):
    client_name: str = ""
    application_name: str = ""
    application_version: str = "1.0"
    application_approach: str = "Gray Box"
    application_url: List[str] = []
    tester_name: str = ""
    validator_name: str = ""
    approver_name: str = ""          # VA: approval authority name
    project_id: str = ""
    assessment_startdate: str = ""
    assessment_enddate: str = ""
    report_delivery_date: str = ""
    basic_document_date: str = ""
    draft_document_date: str = ""
    peer_review_date: str = ""
    reassessment: str = "30 days"
    outofscope: List[str] = []
    # VA-specific extras
    report_month_year: str = ""      # e.g. "May 2026"
    assessment_type: str = "Internal/External"
    scoped_ips_count: str = ""       # e.g. "12"
    scoped_assets: List[ScopedAsset] = []

    model_config = {"extra": "ignore"}


class FindingStats(BaseModel):
    count_critical: int = 0
    count_high: int = 0
    count_medium: int = 0
    count_low: int = 0
    count_info: int = 0
    total: int = 0


class ReportPayload(BaseModel):
    report: ReportMeta
    findings: List[Finding]
    finding_stats: Optional[FindingStats] = None
    template: str = "default"


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
    source: str = ""
    warnings: List[str] = []


class ParseOptions(BaseModel):
    severity_threshold: str = "info"
    skip_false_positives: bool = False
    normalize_severity: bool = True
    deduplicate: bool = False
