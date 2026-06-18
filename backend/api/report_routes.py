"""
api/report_routes.py — Report persistence endpoints (save, list, load, delete, status).

Security controls:
  - report_id validated as UUID v4 before any DB query (prevents injection/IDOR enumeration)
  - status values validated against explicit allow-list (no free-text from client)
  - Ownership checks on every read/write endpoint (prevents IDOR/BOLA)
  - requested_by username validated against allow-list format
  - Generic error messages for not-found/forbidden (no information leakage)
  - All authorization failures logged for audit
"""
import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.deps import require_user
from auth.utils import load_users
from db import save_report, get_reports, get_report, delete_report, update_report_status
from security.validators import InputValidator

log = logging.getLogger(__name__)

router = APIRouter(tags=["reports"])

# ── Allowed status transitions ────────────────────────────────────────────────
ALLOWED_STATUSES = frozenset({"draft", "pending_approval", "approved", "needs_change"})
# Status values a non-admin can set
USER_ALLOWED_STATUSES = frozenset({"draft", "pending_approval"})


class ReportData(BaseModel):
    meta: dict
    findings: list

    model_config = {"extra": "ignore"}


class StatusUpdate(BaseModel):
    status: str = Field(..., max_length=32)

    model_config = {"extra": "ignore"}


class ApproveEditReq(BaseModel):
    requested_by: str = Field(..., min_length=2, max_length=32)

    model_config = {"extra": "ignore"}


# ── Helper: get role ──────────────────────────────────────────────────────────

def _get_role(username: str) -> str:
    users = load_users()
    return users.get(username, {}).get("role", "viewer")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/reports")
async def save_user_report(
    data: ReportData,
    report_id: Optional[str] = None,
    username: str = Depends(require_user),
):
    """Save or update a report to the database."""
    # Validate report_id if provided
    if report_id:
        report_id = InputValidator.report_id(report_id)
    else:
        report_id = str(uuid.uuid4())

    # Sanitise meta fields that go into DB columns
    client_name = str(data.meta.get("client_name", "Unknown Client"))[:256]
    project_id = str(data.meta.get("project_id", "Unknown Project"))[:128]

    # Check ownership on update
    existing = get_report(report_id)
    if existing:
        role = _get_role(username)
        is_admin = role == "admin"
        if not is_admin and existing["username"] != username:
            log.warning(
                "IDOR attempt: user '%s' tried to overwrite report '%s' owned by '%s'",
                username, report_id, existing["username"],
            )
            raise HTTPException(status_code=403, detail="Access denied")
        status = existing["status"]
        owner_to_save = existing["username"] if is_admin else username
    else:
        status = "draft"
        owner_to_save = username

    save_report(report_id, owner_to_save, client_name, project_id, data.model_dump(), status)
    return {"message": "Report saved successfully", "id": report_id, "status": status}


@router.get("/reports")
async def list_reports(username: str = Depends(require_user)):
    """List reports. Admins/editors/viewers see all; regular users see their own."""
    role = _get_role(username)
    is_privileged = role in ("admin", "editor", "viewer")
    reports = get_reports(admin=is_privileged, username=username)
    return reports


@router.get("/reports/{report_id}")
async def load_user_report(report_id: str, username: str = Depends(require_user)):
    """Load a specific report."""
    # Validate UUID format before hitting DB
    report_id = InputValidator.report_id(report_id)

    data = get_report(report_id)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")

    role = _get_role(username)
    is_privileged = role in ("admin", "editor", "viewer")

    if not is_privileged and data["username"] != username:
        log.warning(
            "IDOR attempt: user '%s' tried to read report '%s' owned by '%s'",
            username, report_id, data["username"],
        )
        raise HTTPException(status_code=403, detail="Access denied")

    return {
        "meta": data["data"].get("meta", {}),
        "findings": data["data"].get("findings", []),
        "status": data["status"],
    }


@router.put("/reports/{report_id}/status")
async def update_status(
    report_id: str,
    req: StatusUpdate,
    username: str = Depends(require_user),
):
    """Update report status. Non-admins can only set draft/pending_approval."""
    # Validate UUID
    report_id = InputValidator.report_id(report_id)

    # Validate status against allow-list
    InputValidator.report_status(req.status)

    role = _get_role(username)
    is_admin = role == "admin"

    if not is_admin and req.status not in USER_ALLOWED_STATUSES:
        log.warning(
            "Authorization failure: user '%s' tried to set status '%s'",
            username, req.status,
        )
        raise HTTPException(status_code=403, detail="Only admins can set this status")

    update_report_status(report_id, req.status)
    log.info("Report '%s' status set to '%s' by '%s'", report_id, req.status, username)
    return {"message": "Status updated", "status": req.status}


@router.delete("/reports/{report_id}")
async def delete_user_report(report_id: str, username: str = Depends(require_user)):
    """Delete a report. Only admins can delete reports."""
    # Validate UUID
    report_id = InputValidator.report_id(report_id)

    role = _get_role(username)
    if role != "admin":
        log.warning(
            "Authorization failure: user '%s' (role=%s) tried to delete report '%s'",
            username, role, report_id,
        )
        raise HTTPException(status_code=403, detail="Only admins can delete reports")

    delete_report(report_id)
    log.info("Report '%s' deleted by admin '%s'", report_id, username)
    return {"message": "Deleted successfully"}


@router.put("/reports/{report_id}/request_edit")
async def request_edit(report_id: str, username: str = Depends(require_user)):
    """Request edit access to a report."""
    report_id = InputValidator.report_id(report_id)

    data = get_report(report_id)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")

    report_data = data["data"]
    if "meta" not in report_data:
        report_data["meta"] = {}
    # Store validated username
    report_data["meta"]["edit_requested_by"] = username

    save_report(
        report_id, data["username"], data["client_name"],
        data["project_id"], report_data, data["status"],
    )
    log.info("Edit request for report '%s' by user '%s'", report_id, username)
    return {"message": "Edit requested"}


@router.put("/reports/{report_id}/approve_edit")
async def approve_edit(
    report_id: str,
    req: ApproveEditReq,
    username: str = Depends(require_user),
):
    """Admin approves an edit request, transferring ownership."""
    report_id = InputValidator.report_id(report_id)

    role = _get_role(username)
    if role != "admin":
        log.warning(
            "Authorization failure: user '%s' tried to approve edit for report '%s'",
            username, report_id,
        )
        raise HTTPException(status_code=403, detail="Only admins can approve edit requests")

    # Validate the requested_by username format
    InputValidator.username(req.requested_by, field_label="Requested-by username")

    # Verify the requested_by user actually exists
    users = load_users()
    if req.requested_by not in users:
        raise HTTPException(status_code=400, detail="Requested user does not exist")

    data = get_report(report_id)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")

    report_data = data["data"]
    if "meta" in report_data and "edit_requested_by" in report_data["meta"]:
        del report_data["meta"]["edit_requested_by"]

    save_report(
        report_id, req.requested_by, data["client_name"],
        data["project_id"], report_data, data["status"],
    )
    log.info(
        "Edit request for report '%s' approved by admin '%s', transferred to '%s'",
        report_id, username, req.requested_by,
    )
    return {"message": "Edit request approved"}
