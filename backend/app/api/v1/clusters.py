"""
News Clusters & Custom Discovery Rules REST API Router.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.core.dependencies import get_current_user
from app.services.clustering_service import ClusteringService
import structlog

log = structlog.get_logger()
router = APIRouter()


class RulePayload(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = ""
    keywords: List[str] = Field(default_factory=list)
    country: Optional[str] = "All"
    sectors: List[str] = Field(default_factory=lambda: ["All"])
    incident_type: Optional[str] = "All"
    enabled: Optional[bool] = True


@router.get("", summary="Get all intelligence news clusters with summary stats")
async def list_clusters(current_user: dict = Depends(get_current_user)):
    """
    Returns high-impact intelligence clusters (built-in spotlight + custom user discovery rules).
    """
    try:
        clusters = await ClusteringService.get_all_clusters()
        return {
            "status": "success",
            "data": clusters,
            "meta": {"total_clusters": len(clusters)}
        }
    except Exception as e:
        log.error("Failed to fetch clusters", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to generate clusters: {str(e)}")


@router.get("/rules", summary="List custom discovery rules")
async def list_rules(current_user: dict = Depends(get_current_user)):
    try:
        rules = await ClusteringService.list_rules()
        return {"status": "success", "data": rules}
    except Exception as e:
        log.error("Failed to list cluster rules", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules", summary="Create custom discovery rule")
async def create_rule(
    payload: RulePayload,
    current_user: dict = Depends(get_current_user),
):
    try:
        rule = await ClusteringService.create_rule(payload.model_dump())
        return {"status": "created", "data": rule}
    except Exception as e:
        log.error("Failed to create cluster rule", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/rules/{rule_id}", summary="Update custom discovery rule")
async def update_rule(
    rule_id: str,
    payload: RulePayload,
    current_user: dict = Depends(get_current_user),
):
    try:
        rule = await ClusteringService.update_rule(rule_id, payload.model_dump())
        return {"status": "updated", "data": rule}
    except Exception as e:
        log.error("Failed to update cluster rule", rule_id=rule_id, error=str(e))
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/rules/{rule_id}", summary="Delete custom discovery rule")
async def delete_rule(
    rule_id: str,
    current_user: dict = Depends(get_current_user),
):
    try:
        success = await ClusteringService.delete_rule(rule_id)
        if not success:
            raise HTTPException(status_code=444, detail="Rule not found or already deleted")
        return {"status": "deleted", "rule_id": rule_id}
    except HTTPException:
        raise
    except Exception as e:
        log.error("Failed to delete cluster rule", rule_id=rule_id, error=str(e))
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/rules/{rule_id}/run", summary="Run/test a custom discovery rule")
async def run_rule(
    rule_id: str,
    current_user: dict = Depends(get_current_user),
):
    try:
        result = await ClusteringService.run_rule(rule_id)
        return {"status": "success", "data": result}
    except Exception as e:
        log.error("Failed to run cluster rule", rule_id=rule_id, error=str(e))
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{slug}", summary="Get detail & matched articles for a specific cluster")
async def get_cluster_detail(
    slug: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    q: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
):
    try:
        result = await ClusteringService.get_cluster_detail(slug=slug, page=page, page_size=page_size, q=q)
        return {"status": "success", "data": result}
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        log.error("Failed to fetch cluster detail", slug=slug, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
