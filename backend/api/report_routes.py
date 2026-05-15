import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.deps import require_user
from auth.utils import load_users
from db import save_report, get_reports, get_report, delete_report, update_report_status

log = logging.getLogger(__name__)

router = APIRouter(tags=["reports"])

class ReportData(BaseModel):
    meta: dict
    findings: list

@router.post("/reports")
async def save_user_report(
    data: ReportData,
    report_id: Optional[str] = None,
    username: str = Depends(require_user)
):
    """Save or update a report to the database."""
    r_id = report_id or str(uuid.uuid4())
    client_name = data.meta.get("client_name", "Unknown Client")
    project_id = data.meta.get("project_id", "Unknown Project")
    
    # If the report already exists, keep its status, else 'draft'
    existing = get_report(r_id)
    if existing:
        users = load_users()
        is_admin = users.get(username, {}).get("role") == "admin"
        if not is_admin and existing["username"] != username:
            raise HTTPException(status_code=403, detail="Cannot save a report you do not own")
        status = existing["status"]
        owner_to_save = existing["username"] if is_admin else username
    else:
        status = "draft"
        owner_to_save = username

    save_report(r_id, owner_to_save, client_name, project_id, data.model_dump(), status)
    return {"message": "Report saved successfully", "id": r_id, "status": status}

@router.get("/reports")
async def list_reports(username: str = Depends(require_user)):
    """List reports. Admins, viewers, and editors see all, users see their own."""
    users = load_users()
    role = users.get(username, {}).get("role")
    is_admin = role == "admin"
    is_viewer = role == "viewer"
    is_editor = role == "editor"
    reports = get_reports(admin=(is_admin or is_viewer or is_editor), username=username)
    return reports

@router.get("/reports/{report_id}")
async def load_user_report(report_id: str, username: str = Depends(require_user)):
    """Load a specific report."""
    data = get_report(report_id)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
        
    # Check access: Admin, viewer, editor, or owner
    users = load_users()
    role = users.get(username, {}).get("role")
    is_admin = role == "admin"
    is_viewer = role == "viewer"
    is_editor = role == "editor"
    
    # We need to know who owns it, get_reports can help or we fetch raw
    if not is_admin and not is_viewer and not is_editor:
        reports = get_reports(admin=False, username=username)
        if not any(r["id"] == report_id for r in reports):
            raise HTTPException(status_code=403, detail="Forbidden")
            
    return {"meta": data["data"]["meta"], "findings": data["data"]["findings"], "status": data["status"]}

class StatusUpdate(BaseModel):
    status: str

@router.put("/reports/{report_id}/status")
async def update_status(report_id: str, req: StatusUpdate, username: str = Depends(require_user)):
    """Update report status (user: pending_approval, admin: approved/needs_change)."""
    users = load_users()
    role = users.get(username, {}).get("role")
    
    if role != "admin" and req.status not in ["pending_approval", "draft"]:
        raise HTTPException(status_code=403, detail="Only admins can approve/reject")
        
    update_report_status(report_id, req.status)
    return {"message": "Status updated", "status": req.status}

@router.delete("/reports/{report_id}")
async def delete_user_report(report_id: str, username: str = Depends(require_user)):
    """Delete a report. Only admins can delete reports."""
    users = load_users()
    if users.get(username, {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete reports")
            
    delete_report(report_id)
    return {"message": "Deleted successfully"}

@router.put("/reports/{report_id}/request_edit")
async def request_edit(report_id: str, username: str = Depends(require_user)):
    """Request edit access to a report."""
    data = get_report(report_id)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
        
    report_data = data["data"]
    if "meta" not in report_data:
        report_data["meta"] = {}
    report_data["meta"]["edit_requested_by"] = username
    
    save_report(report_id, data["username"], data["client_name"], data["project_id"], report_data, data["status"])
    return {"message": "Edit requested"}

class ApproveEditReq(BaseModel):
    requested_by: str

@router.put("/reports/{report_id}/approve_edit")
async def approve_edit(report_id: str, req: ApproveEditReq, username: str = Depends(require_user)):
    """Admin approves an edit request, transferring ownership."""
    users = load_users()
    if users.get(username, {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can approve edit requests")
        
    data = get_report(report_id)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
        
    report_data = data["data"]
    if "meta" in report_data and "edit_requested_by" in report_data["meta"]:
        del report_data["meta"]["edit_requested_by"]
        
    # Transfer ownership to the requested user
    save_report(report_id, req.requested_by, data["client_name"], data["project_id"], report_data, data["status"])
    return {"message": "Edit request approved"}
