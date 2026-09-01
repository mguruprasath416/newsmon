import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from datetime import datetime, timezone
from app.db.mongodb import MongoDB, get_sources_collection

INDIAN_SOURCES = [
    {
        "name": "CERT-In Advisories",
        "slug": "cert-in",
        "category": "cert",
        "rss_url": "https://news.google.com/rss/search?q=site:cert-in.org.in+OR+cert-in+advisory&hl=en-IN&gl=IN&ceid=IN:en",
        "tags": ["india", "cert-in", "advisory", "vulnerability", "mitigation"],
        "priority": 1,
        "enabled": True,
        "collection_method": "rss",
    },
    {
        "name": "India Cyber Breach Tracker",
        "slug": "india-cyber-breach-tracker",
        "category": "news",
        "rss_url": "https://news.google.com/rss/search?q=(India+OR+Indian)+AND+(data+breach+OR+cyberattack+OR+ransomware+OR+hacked+OR+CERT-In)&hl=en-IN&gl=IN&ceid=IN:en",
        "tags": ["india", "data-breach", "cybersecurity", "ransomware"],
        "priority": 1,
        "enabled": True,
        "collection_method": "rss",
    },
    {
        "name": "Economic Times Cybersecurity India",
        "slug": "et-cybersecurity-india",
        "category": "news",
        "rss_url": "https://news.google.com/rss/search?q=site:economictimes.indiatimes.com+(cyberattack+OR+data+breach+OR+hacker+OR+ransomware+OR+CERT-In)&hl=en-IN&gl=IN&ceid=IN:en",
        "tags": ["india", "economic-times", "cybersecurity", "breach"],
        "priority": 1,
        "enabled": True,
        "collection_method": "rss",
    },
    {
        "name": "The CyberSec Guru",
        "slug": "thecybersecguru",
        "category": "news",
        "rss_url": "https://thecybersecguru.com/feed/",
        "tags": ["news", "breach", "indian-cybersecurity"],
        "priority": 1,
        "enabled": True,
        "collection_method": "rss",
    },
]


async def main():
    await MongoDB.connect()
    col = get_sources_collection()

    for src in INDIAN_SOURCES:
        existing = await col.find_one({"slug": src["slug"]})
        if not existing:
            doc = src.copy()
            doc.update({
                "base_url": "",
                "subcategory": None,
                "logo_url": None,
                "health_status": "healthy",
                "last_crawled_at": None,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            })
            await col.insert_one(doc)
            print(f"Added new Indian source: {src['name']}")
        else:
            await col.update_one({"_id": existing["_id"]}, {"$set": {"enabled": True}})
            print(f"Verified active source: {src['name']}")

    all_sources = [s.get("name") async for s in col.find({"enabled": True})]
    print(f"\nTotal active sources: {len(all_sources)}")

if __name__ == "__main__":
    asyncio.run(main())
