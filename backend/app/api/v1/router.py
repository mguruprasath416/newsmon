from fastapi import APIRouter
from app.api.v1 import auth, feed, lens, kev, search, malware, campaigns, reports, sources, analytics, admin, ws, teams, clusters, cyberpulse

api_router = APIRouter()

api_router.include_router(auth.router,          prefix="/auth",          tags=["Authentication"])
api_router.include_router(feed.router,          prefix="/feed",          tags=["Intelligence Feed"])
api_router.include_router(cyberpulse.router,    prefix="/viral-events",  tags=["CyberPulse Viral Events"])
api_router.include_router(cyberpulse.router,    prefix="/cyberpulse",    tags=["CyberPulse Heat Map"])
api_router.include_router(lens.router,          prefix="/lens",          tags=["Advisory Lens"])
api_router.include_router(reports.router,       prefix="/reports",       tags=["Reports"])
api_router.include_router(kev.router,           prefix="/kev",           tags=["CISA KEV"])
api_router.include_router(search.router,        prefix="/search",        tags=["Search"])
api_router.include_router(clusters.router,      prefix="/clusters",      tags=["Country & Sector Clusters"])
api_router.include_router(teams.router,         prefix="/teams",         tags=["Microsoft Teams Integration"])
api_router.include_router(malware.router,       prefix="/malware",       tags=["Malware"])
api_router.include_router(campaigns.router,     prefix="/campaigns",     tags=["Campaigns"])
api_router.include_router(sources.router,       prefix="/sources",       tags=["Sources"])
api_router.include_router(analytics.router,     prefix="/analytics",     tags=["Analytics"])
api_router.include_router(admin.router,         prefix="/admin",         tags=["Admin"])
api_router.include_router(ws.router,            prefix="/ws",            tags=["WebSocket"])


