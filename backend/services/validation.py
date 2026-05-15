"""
Validation service — validates findings against required schema rules.
"""
from __future__ import annotations

from typing import List
from models.schemas import Finding, ValidationError, ValidationResult

VALID_LEVELS = {"critical", "high", "medium", "low", "info"}
VALID_EASE = {"Trivial", "Moderate", "Difficult"}


def validate_findings(findings: List[Finding]) -> ValidationResult:
    errors: List[ValidationError] = []
    warnings: List[ValidationError] = []

    for i, f in enumerate(findings):
        idx = i
        fid = f.id

        # Required fields
        if not f.title or not f.title.strip():
            errors.append(ValidationError(index=idx, finding_id=fid, field="title", message="Title is required"))
        elif len(f.title.strip()) < 3:
            warnings.append(ValidationError(index=idx, finding_id=fid, field="title", message="Title is very short"))

        if not f.description or not f.description.strip():
            errors.append(ValidationError(index=idx, finding_id=fid, field="description", message="Description is required"))

        if not f.recommendation or not f.recommendation.strip():
            errors.append(ValidationError(index=idx, finding_id=fid, field="recommendation", message="Recommendation is required"))

        # CVSS level
        if f.cvss.level not in VALID_LEVELS:
            errors.append(ValidationError(
                index=idx, finding_id=fid, field="cvss.level",
                message=f"Invalid severity '{f.cvss.level}'. Must be one of: {', '.join(VALID_LEVELS)}"
            ))

        # CVSS score range
        if not (0.0 <= f.cvss.score <= 10.0):
            errors.append(ValidationError(
                index=idx, finding_id=fid, field="cvss.score",
                message=f"CVSS score {f.cvss.score} out of range [0.0, 10.0]"
            ))

        # Ease of exploit
        if f.ease and f.ease not in VALID_EASE:
            warnings.append(ValidationError(
                index=idx, finding_id=fid, field="ease",
                message=f"Unknown ease value '{f.ease}'. Expected: {', '.join(VALID_EASE)}"
            ))

        # Warnings — not blockers
        if not f.impact or not f.impact.strip():
            warnings.append(ValidationError(index=idx, finding_id=fid, field="impact", message="Business impact not set"))

        if not f.affected_components:
            warnings.append(ValidationError(index=idx, finding_id=fid, field="affected_components", message="No affected components specified"))

        if f.cvss.level in ("critical", "high") and not f.poc:
            warnings.append(ValidationError(
                index=idx, finding_id=fid, field="poc",
                message=f"{f.cvss.level.capitalize()} finding has no Proof of Concept"
            ))

        if not f.references:
            warnings.append(ValidationError(index=idx, finding_id=fid, field="references", message="No references provided"))

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )
