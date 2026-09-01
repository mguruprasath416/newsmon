from fastapi import APIRouter, Depends, Query, HTTPException, Path, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from math import ceil
from bson import ObjectId
from app.core.dependencies import get_current_user, require_permission
from app.db.mongodb import get_reports_collection
from datetime import datetime, timezone
import uuid
import secrets
import structlog

log = structlog.get_logger()
router = APIRouter()


def serialize_report(doc: dict, include_full: bool = False) -> dict:
    doc["id"] = str(doc.pop("_id"))
    doc["created_by"] = str(doc.get("created_by", ""))
    if not include_full:
        doc.pop("report", None)
    return doc


@router.get("")
async def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    col = get_reports_collection()
    query = {"status": "complete"}
    if current_user["role"] != "admin":
        query["created_by"] = ObjectId(current_user["id"])

    total = await col.count_documents(query)
    skip = (page - 1) * page_size
    cursor = col.find(query, {"report": 0}).sort("created_at", -1).skip(skip).limit(page_size)
    reports = [serialize_report(doc) async for doc in cursor]

    return {
        "data": reports,
        "meta": {"total": total, "page": page, "page_size": page_size, "pages": ceil(total/page_size) if total > 0 else 0}
    }


@router.get("/{report_id}")
async def get_report(
    report_id: str = Path(...),
    current_user: dict = Depends(get_current_user),
):
    col = get_reports_collection()
    try:
        doc = await col.find_one({"_id": ObjectId(report_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Report not found")

    if not doc:
        raise HTTPException(status_code=404, detail="Report not found")

    if current_user["role"] != "admin":
        if str(doc.get("created_by")) != current_user["id"]:
            raise HTTPException(status_code=403, detail="Access denied")

    return serialize_report(doc, include_full=True)


@router.delete("/{report_id}")
async def delete_report(
    report_id: str = Path(...),
    current_user: dict = Depends(get_current_user),
):
    col = get_reports_collection()
    try:
        doc = await col.find_one({"_id": ObjectId(report_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Report not found")

    if not doc:
        raise HTTPException(status_code=404, detail="Report not found")

    if current_user["role"] != "admin" and str(doc.get("created_by")) != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    await col.delete_one({"_id": ObjectId(report_id)})
    return {"deleted": True}


@router.post("/{report_id}/share")
async def create_share_link(
    report_id: str = Path(...),
    current_user: dict = Depends(get_current_user),
):
    col = get_reports_collection()
    try:
        doc = await col.find_one({"_id": ObjectId(report_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Report not found")

    if not doc:
        raise HTTPException(status_code=404, detail="Report not found")

    # TLP RED cannot be shared
    if doc.get("tlp_level") == "red":
        raise HTTPException(status_code=403, detail="TLP:RED reports cannot be shared externally")

    token = secrets.token_urlsafe(32)
    from datetime import timedelta
    expires = datetime.now(timezone.utc) + timedelta(days=7)

    await col.update_one(
        {"_id": ObjectId(report_id)},
        {"$set": {"share_token": token, "share_expires_at": expires, "is_public": True}}
    )

    return {
        "share_token": token,
        "share_url": f"/api/v1/reports/share/{token}",
        "expires_at": expires.isoformat(),
    }


@router.get("/share/{token}")
async def get_shared_report(token: str):
    """Public endpoint — no auth required."""
    col = get_reports_collection()
    doc = await col.find_one({
        "share_token": token,
        "is_public": True,
        "share_expires_at": {"$gt": datetime.now(timezone.utc)}
    })
    if not doc:
        raise HTTPException(status_code=404, detail="Shared report not found or expired")

    result = serialize_report(doc, include_full=True)
    # Remove sensitive fields for public view
    result.pop("created_by", None)
    return result


@router.post("/{report_id}/export")
async def export_report(
    report_id: str = Path(...),
    format: str = Query("markdown", pattern="^(markdown|pdf|stix|csv)$"),

    background_tasks: BackgroundTasks = BackgroundTasks(),
    current_user: dict = Depends(get_current_user),
):
    """Export report in various formats."""
    col = get_reports_collection()
    try:
        doc = await col.find_one({"_id": ObjectId(report_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Report not found")

    if not doc or doc.get("status") != "complete":
        raise HTTPException(status_code=400, detail="Report not yet complete")

    from app.services.export_service import ReportExportService
    service = ReportExportService()

    if format == "markdown":
        content = await service.to_markdown(doc)
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content=content, media_type="text/markdown",
                                 headers={"Content-Disposition": f"attachment; filename=report-{report_id[:8]}.md"})
    elif format == "csv":
        content = await service.iocs_to_csv(doc)
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content=content, media_type="text/csv",
                                 headers={"Content-Disposition": f"attachment; filename=iocs-{report_id[:8]}.csv"})
    elif format == "stix":
        content = await service.to_stix(doc)
        from fastapi.responses import JSONResponse
        return JSONResponse(content=content,
                           headers={"Content-Disposition": f"attachment; filename=report-{report_id[:8]}.stix.json"})
    else:
        raise HTTPException(status_code=501, detail="PDF export coming soon")
