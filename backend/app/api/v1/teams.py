"""
Microsoft Teams Integration REST API Router — Webhook Configuration & Regional Cluster Dispatch.

Endpoints:
  GET  /teams/config                  — Get current user's Microsoft Teams configuration
  POST /teams/webhook                 — Save and test Microsoft Teams Webhook URL (indian_based | gcc_middle_east)
  POST /teams/send-todays-news        — Send today's news feed to Teams regional channels (#indian-based, #gcc-middle-east)
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta

from app.core.dependencies import get_current_user
from app.db.mongodb import get_users_collection, get_articles_collection
from app.services.teams_service import TeamsService
from app.config import settings
import structlog

log = structlog.get_logger()
router = APIRouter()


class TeamsWebhookRequest(BaseModel):
    webhook_url: str
    channel: Optional[str] = "indian_based"  # 'indian_based' | 'gcc_middle_east'
    auto_dispatch: Optional[bool] = False


# ── GET Configuration ─────────────────────────────────────────────────────────

@router.get("/config")
async def get_teams_config(current_user: dict = Depends(get_current_user)):
    prefs = current_user.get("preferences", {})
    common_url = (
        prefs.get("teams_webhook_url_cyber_pulse") or
        prefs.get("teams_webhook_url") or
        getattr(settings, "TEAMS_WEBHOOK_URL_CYBER_PULSE", "") or
        getattr(settings, "TEAMS_WEBHOOK_URL", "") or
        getattr(settings, "CYBER_PULSE_WEBHOOK_URL", "")
    )

    return {
        "webhook_url": common_url,
        "is_configured": bool(common_url),
        "auto_dispatch": prefs.get("teams_auto_dispatch", False),
        "channel_webhooks": {
            "cyber-pulse": common_url,
            "cyber_pulse": common_url,
            "high-priority-news": common_url,
            "daily-cti-digest": common_url,
        }
    }


# ── Save & Test Webhook ───────────────────────────────────────────────────────

@router.post("/webhook")
async def save_teams_webhook(
    req: TeamsWebhookRequest,
    current_user: dict = Depends(get_current_user),
):
    url_str = req.webhook_url.strip()
    if not url_str:
        raise HTTPException(status_code=400, detail="Microsoft Teams Webhook URL cannot be empty.")

    # Test the webhook connection
    try:
        await TeamsService.send_test_webhook(url_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to connect to Microsoft Teams Webhook: {str(e)}")

    # Update MongoDB user preferences
    users_col = get_users_collection()
    user_id = current_user["_id"]

    field_map = {
        "high_priority_news": "preferences.teams_webhook_url_high_priority_news",
        "high-priority-news": "preferences.teams_webhook_url_high_priority_news",
        "daily_digest": "preferences.teams_webhook_url_daily_digest",
        "daily-cti-digest": "preferences.teams_webhook_url_daily_digest",
        "indian_breaches": "preferences.teams_webhook_url_indian_breaches",
        "indian-breaches": "preferences.teams_webhook_url_indian_breaches",
        "indian_based": "preferences.teams_webhook_url_indian_breaches",
        "indian-based": "preferences.teams_webhook_url_indian_breaches",
        "middle_east_companies": "preferences.teams_webhook_url_middle_east_companies",
        "middle-east-companies": "preferences.teams_webhook_url_middle_east_companies",
        "gcc_middle_east": "preferences.teams_webhook_url_middle_east_companies",
        "gcc-middle-east": "preferences.teams_webhook_url_middle_east_companies",
    }
    target_field = field_map.get(req.channel, "preferences.teams_webhook_url_high_priority_news")

    update_dict = {
        target_field: url_str,
        "preferences.teams_auto_dispatch": req.auto_dispatch,
        "updated_at": datetime.now(timezone.utc),
    }

    await users_col.update_one({"_id": user_id}, {"$set": update_dict})

    return {
        "status": "connected",
        "message": f"Microsoft Teams Webhook connected successfully for channel '{req.channel}'!",
        "webhook_url": url_str,
        "channel": req.channel,
    }


# ── Send Today's News to Microsoft Teams ──────────────────────────────────────

@router.post("/send-todays-news")
async def send_todays_news_to_teams(
    current_user: dict = Depends(get_current_user),
):
    prefs = current_user.get("preferences", {})
    common_url = (
        prefs.get("teams_webhook_url_cyber_pulse") or
        prefs.get("teams_webhook_url") or
        getattr(settings, "TEAMS_WEBHOOK_URL_CYBER_PULSE", "") or
        getattr(settings, "TEAMS_WEBHOOK_URL", "") or
        getattr(settings, "CYBER_PULSE_WEBHOOK_URL", "")
    )
    channel_webhooks = {
        "cyber-pulse": common_url,
        "high-priority-news": common_url,
    }

    if not common_url:
        raise HTTPException(
            status_code=400,
            detail="Microsoft Teams CyberPulse Webhook is not configured in .env."
        )

    # Query today's HIGH & CRITICAL severity articles (or last 24h)
    articles_col = get_articles_collection()
    since_time = datetime.now(timezone.utc) - timedelta(hours=24)

    cursor = articles_col.find({
        "published_at": {"$gte": since_time},
        "is_duplicate": {"$ne": True},
        "is_cybersecurity_news": True,
        "$or": [
            {"severity": {"$in": ["CRITICAL", "HIGH", "critical", "high"]}},
            {"cves": {"$exists": True, "$not": {"$size": 0}}},
            {"threat_actors": {"$exists": True, "$not": {"$size": 0}}}
        ]
    }).sort("published_at", -1).limit(100)

    articles = [a async for a in cursor]
    if not articles:
        cursor_fallback = articles_col.find({
            "is_duplicate": {"$ne": True},
            "is_cybersecurity_news": True,
            "$or": [
                {"severity": {"$in": ["CRITICAL", "HIGH", "critical", "high"]}},
                {"threat_actors": {"$exists": True, "$not": {"$size": 0}}}
            ]
        }).sort("published_at", -1).limit(50)
        articles = [a async for a in cursor_fallback]

    # Process and dispatch to Microsoft Teams using the official CyberPulse Alert template
    default_webhook = common_url
    result = await TeamsService.send_todays_news(default_webhook, articles, channel_webhooks=channel_webhooks)
    return result


