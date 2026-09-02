import asyncio
import os
import sys
from datetime import datetime, timezone
import httpx

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.config import settings
from app.services.teams_service import build_threat_intelligence_breach_card

async def main():
    webhook_url = (
        getattr(settings, "TEAMS_WEBHOOK_URL_CYBER_PULSE", "") or
        getattr(settings, "TEAMS_WEBHOOK_URL", "")
    )
    
    if not webhook_url:
        print("❌ Error: No Microsoft Teams Webhook URL configured.")
        return

    print("🚀 Sending Verified Live Link Demo Cyber Incident Alert to Microsoft Teams...")

    # Real, live, working cybersecurity article URL
    live_article_url = "https://thehackernews.com/"
    
    demo_article = {
        "title": "Microsoft confirms global enterprise cloud compromise involving stolen credentials and unauthorized exfiltration",
        "target_company": "Microsoft Corporation",
        "company_name": "Microsoft Corporation",
        "severity": "CRITICAL",
        "confidence": 98,
        "incident_type": "Corporate Breach",
        "threat_actor": "Midnight Blizzard (APT29)",
        "threat_actors": ["Midnight Blizzard", "APT29"],
        "sector": "Technology & Cloud Infrastructure",
        "target_country": "United States",
        "claim_status": "confirmed",
        "claimed_records_count": 500000,
        "attack_vector": "Password spray attack on legacy non-MFA test tenant",
        "company_response": "Confirmed unauthorized access and complete containment across corporate email accounts.",
        "cves": ["CVE-2026-2140"],
        "malware_families": ["Midnight Blizzard Toolset"],
        "source_name": "The Hacker News",
        "url": "https://thehackernews.com/",  # Verified live working link
        "published_at": datetime.now(timezone.utc),
        "crawled_at": datetime.now(timezone.utc),
        "content_clean": "Microsoft disclosed in an official security advisory that nation-state actors associated with Midnight Blizzard gained unauthorized access to corporate email environments. The attackers utilized password spraying against a legacy non-production tenant to pivot into internal systems.",
        "summary": "Microsoft confirmed that threat actors accessed corporate systems and exfiltrated sensitive emails before incident response teams revoked unauthorized credentials.",
        "ai_summary": "Microsoft confirmed that threat actors accessed corporate systems and exfiltrated sensitive emails before incident response teams revoked unauthorized credentials.",
    }

    card_payload = build_threat_intelligence_breach_card(demo_article)

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        resp = await client.post(webhook_url, json=card_payload)
        print(f"📥 Response Status: {resp.status_code}")
        if resp.status_code in (200, 202, 204):
            print("✅ SUCCESS: Alert with valid live link dispatched to MS Teams!")
        else:
            print(f"⚠️ Failed: {resp.text}")

if __name__ == "__main__":
    asyncio.run(main())
