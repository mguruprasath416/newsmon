from fastapi import APIRouter, Depends, BackgroundTasks
from app.core.dependencies import get_current_user, require_role
from app.db.mongodb import get_digests_collection
import structlog

log = structlog.get_logger()
router = APIRouter()


@router.get("/latest")
async def get_latest_digest(current_user: dict = Depends(get_current_user)):
    col = get_digests_collection()
    doc = await col.find_one({}, sort=[("generated_at", -1)])
    if not doc:
        return {"message": "No digest generated yet"}
    doc["id"] = str(doc.pop("_id"))
    return doc


@router.get("")
async def list_digests(current_user: dict = Depends(get_current_user)):
    col = get_digests_collection()
    cursor = col.find({}, {"digest": 0}).sort("generated_at", -1).limit(30)
    digests = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        digests.append(doc)
    return {"data": digests}


@router.get("/{digest_id}")
async def get_digest(digest_id: str, current_user: dict = Depends(get_current_user)):
    from bson import ObjectId
    col = get_digests_collection()
    doc = await col.find_one({"_id": ObjectId(digest_id)})
    if not doc:
        return {"message": "Digest not found"}
    doc["id"] = str(doc.pop("_id"))
    return doc


@router.post("/generate")
async def generate_digest(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_role("admin")),
):
    background_tasks.add_task(_run_digest)
    return {"message": "Digest generation triggered"}


async def _run_digest():
    from app.services.digest_service import DigestGenerationService
    service = DigestGenerationService()
    await service.generate()
