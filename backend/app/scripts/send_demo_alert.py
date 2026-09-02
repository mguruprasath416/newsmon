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
from app.services.teams_service import (
    build_threat_intelligence_breach_card,
    TeamsService
)

async def main():
    webhook_url = (
        getattr(settings, "TEAMS_WEBHOOK_URL_CYBER_PULSE", "") or
        getattr(settings, "TEAMS_WEBHOOK_URL", "")
    )
    
    if not webhook_url:
        print("❌ Error: No Microsoft Teams Webhook URL found in configuration or .env")
        return

    print(f"🚀 Sending Demo Cyber Incident Alert Card to Microsoft Teams...")
    print(f"📡 Webhook Endpoint: {webhook_url[:45]}...")

    demo_article = {
        "title": "CloudStrike Networks confirms Rhysida ransomware extortion attack; 350,000 corporate records exfiltrated",
        "target_company": "CloudStrike Networks",
        "company_name": "CloudStrike Networks",
        "severity": "CRITICAL",
        "confidence": 96,
        "incident_type": "Ransomware Incident",
        "threat_actor": "Rhysida Ransomware Group",
        "threat_actors": ["Rhysida"],
        "sector": "Cloud Infrastructure & Enterprise Software",
        "target_country": "United States",
        "claim_status": "confirmed",
        "claimed_records_count": 350000,
        "attack_vector": "Compromised VPN gateway credentials bypassing legacy MFA",
        "company_response": "Official SEC 8-K filing confirms unauthorized exfiltration and operational containment.",
        "cves": ["CVE-2026-3199"],
        "malware_families": ["Rhysida Encryptor"],
        "source_name": "The Hacker News",
        "url": "https://thehackernews.com/2026/09/cloudstrike-confirms-ransomware-breach.html",
        "published_at": datetime.now(timezone.utc),
        "crawled_at": datetime.now(timezone.utc),
        "content_clean": "CloudStrike Networks disclosed in an official security filing that threat actors associated with Rhysida ransomware gained unauthorized access to internal development servers. 350,000 corporate records and client database backups were exfiltrated before affected nodes were isolated. Forensic teams engaged federal authorities and deployed containment countermeasures.",
        "summary": "CloudStrike Networks confirmed an active extortion attack by Rhysida ransomware resulting in the exfiltration of 350,000 corporate customer and developer database records.",
        "ai_summary": "CloudStrike Networks confirmed an active extortion attack by Rhysida ransomware resulting in the exfiltration of 350,000 corporate customer and developer database records.",
    }

    card_payload = build_threat_intelligence_breach_card(demo_article)

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        resp = await client.post(webhook_url, json=card_payload)
        print(f"📥 Response Code: {resp.status_code}")
        print(f"📥 Response Body: {resp.text}")
        if resp.status_code in (200, 202, 204):
            print("✅ SUCCESS: Demo Cyber Threat Intelligence Alert Card delivered to Microsoft Teams!")
        else:
            print(f"⚠️ Teams Webhook returned status {resp.status_code}: {resp.text}")

if __name__ == "__main__":
    asyncio.run(main())
