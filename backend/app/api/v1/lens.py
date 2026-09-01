from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Optional
import uuid
from datetime import datetime, timezone
from bson import ObjectId
from app.core.dependencies import get_current_user, require_permission
from app.db.mongodb import get_reports_collection
import structlog

log = structlog.get_logger()
router = APIRouter()


class LensAnalyzeRequest(BaseModel):
    input_type: str  # url | text | markdown | html
    value: str       # URL or raw text
    tlp_level: str = "white"
    tags: list[str] = []


def serialize_report(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    if "created_by" in doc:
        doc["created_by"] = str(doc["created_by"])
    return doc


@router.post("/analyze", status_code=202)
async def submit_analysis(
    req: LensAnalyzeRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_permission("lens:write")),
):
    """Submit URL or text for AI-powered CTI report generation."""
    job_id = str(uuid.uuid4())
    reports_col = get_reports_collection()

    report_doc = {
        "job_id": job_id,
        "created_by": ObjectId(current_user["id"]),
        "input_type": req.input_type,
        "input_value": req.value[:500],  # Store first 500 chars
        "source_url": req.value if req.input_type == "url" else None,
        "status": "queued",
        "progress": 0,
        "error": None,
        "created_at": datetime.now(timezone.utc),
        "completed_at": None,
        "tlp_level": req.tlp_level,
        "tags": req.tags,
        "report": None,
        "share_token": None,
        "is_public": False,
        "linked_threat_actors": [],
        "linked_campaigns": [],
        "linked_malware": [],
    }

    await reports_col.insert_one(report_doc)

    # Dispatch task to background worker / task loop
    background_tasks.add_task(
        _run_analysis_inline, job_id, req.input_type, req.value
    )
    try:
        from workers.tasks.lens_tasks import run_lens_analysis
        run_lens_analysis.apply_async(
            kwargs={"job_id": job_id, "input_type": req.input_type, "input_value": req.value},
            queue="lens",
            priority=5,
        )
    except Exception as e:
        log.warning("Celery dispatch warning", error=str(e))

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Analysis queued. Poll /lens/jobs/{job_id} for status.",
        "poll_url": f"/api/v1/lens/jobs/{job_id}",
    }


@router.post("/analyze/file", status_code=202)
async def submit_file_analysis(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    tlp_level: str = "white",
    current_user: dict = Depends(require_permission("lens:write")),
):
    """Upload a file (PDF, MD, TXT, HTML) for analysis."""
    allowed_types = ["application/pdf", "text/plain", "text/markdown", "text/html", "application/json"]
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail=f"File type not supported: {file.content_type}")

    max_size = 50 * 1024 * 1024  # 50MB
    content = await file.read()
    if len(content) > max_size:
        raise HTTPException(status_code=413, detail="File too large (max 50MB)")

    job_id = str(uuid.uuid4())
    reports_col = get_reports_collection()

    # Determine input type
    ext_map = {"application/pdf": "pdf", "text/plain": "text", "text/markdown": "markdown", "text/html": "html"}
    input_type = ext_map.get(file.content_type, "text")

    # Store file content as text for processing
    if input_type == "pdf":
        text_content = await _extract_pdf_text(content)
    else:
        text_content = content.decode("utf-8", errors="ignore")

    report_doc = {
        "job_id": job_id,
        "created_by": ObjectId(current_user["id"]),
        "input_type": input_type,
        "input_value": f"[FILE: {file.filename}]",
        "source_url": None,
        "status": "queued",
        "progress": 0,
        "error": None,
        "created_at": datetime.now(timezone.utc),
        "completed_at": None,
        "tlp_level": tlp_level,
        "tags": [],
        "report": None,
        "share_token": None,
        "is_public": False,
        "linked_threat_actors": [],
    }
    await reports_col.insert_one(report_doc)

    background_tasks.add_task(_run_analysis_inline, job_id, input_type, text_content)

    return {"job_id": job_id, "status": "queued", "filename": file.filename}


@router.get("/jobs/{job_id}")
async def get_job_status(
    job_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Poll analysis job status."""
    reports_col = get_reports_collection()
    doc = await reports_col.find_one(
        {"job_id": job_id},
        {"report": 0}  # Exclude full report from status endpoint
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Job not found")

    # Check ownership (admin can see all)
    if current_user["role"] != "admin":
        if str(doc.get("created_by")) != current_user["id"]:
            raise HTTPException(status_code=403, detail="Access denied")

    return {
        "job_id": job_id,
        "status": doc["status"],
        "progress": doc.get("progress", 0),
        "error": doc.get("error"),
        "created_at": doc.get("created_at"),
        "completed_at": doc.get("completed_at"),
        "input_type": doc.get("input_type"),
        "report_url": f"/api/v1/reports/{str(doc['_id'])}" if doc["status"] == "complete" else None,
    }


async def _extract_pdf_text(content: bytes) -> str:
    """Extract text from PDF bytes."""
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(stream=content, filetype="pdf")
        text = ""
        for page in doc:
            text += page.get_text()
        return text
    except Exception as e:
        log.error("PDF extraction failed", error=str(e))
        return ""


async def _run_analysis_inline(job_id: str, input_type: str, input_value: str):
    """Fallback inline analysis for development without Celery."""
    from app.services.lens_service import LensAnalysisService
    service = LensAnalysisService()
    await service.run_analysis(job_id, input_type, input_value)
