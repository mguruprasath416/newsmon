"""
Add Extra RSS/API Intelligence Sources Script
Seeds 10 new high-value RSS feeds into MongoDB and triggers an immediate crawl.
"""
import sys
import os
import asyncio
from datetime import datetime, timezone

sys.path.insert(0, r'd:\Feed\backend')
sys.stdout.reconfigure(encoding='utf-8')

from app.db.mongodb import MongoDB, get_sources_collection, get_articles_collection
from app.services.collector import crawl_source


NEW_SOURCES = [
    # Vendor Research
    {
        "name": "GitHub Security Advisories",
        "slug": "github-advisories",
        "category": "vendor",
        "rss_url": "https://github.com/advisories.atom",
        "base_url": "https://github.com/advisories",
        "collection_method": "rss",
        "tags": ["github", "cve", "supply-chain", "vulnerability"],
        "priority": 1,
    },
    {
        "name": "Zero Day Initiative (ZDI)",
        "slug": "zdi",
        "category": "vendor",
        "rss_url": "https://www.zerodayinitiative.com/blog?format=rss",
        "base_url": "https://www.zerodayinitiative.com",
        "collection_method": "rss",
        "tags": ["zdi", "zero-day", "vulnerability", "exploit"],
        "priority": 1,
    },
    {
        "name": "Malwarebytes Labs",
        "slug": "malwarebytes-labs",
        "category": "vendor",
        "rss_url": "https://www.malwarebytes.com/blog/feed/index.xml",
        "base_url": "https://www.malwarebytes.com/blog",
        "collection_method": "rss",
        "tags": ["malwarebytes", "malware", "ransomware"],
        "priority": 2,
    },

    # News & Breach
    {
        "name": "The Register Security",
        "slug": "theregister-security",
        "category": "news",
        "rss_url": "https://www.theregister.com/security/headlines.atom",
        "base_url": "https://www.theregister.com/security/",
        "collection_method": "rss",
        "tags": ["news", "breach", "malware", "vulnerability"],
        "priority": 1,
    },
    {
        "name": "Help Net Security",
        "slug": "helpnet-security",
        "category": "news",
        "rss_url": "https://www.helpnetsecurity.com/feed/",
        "base_url": "https://www.helpnetsecurity.com/",
        "collection_method": "rss",
        "tags": ["news", "breach", "ciso", "threat-intel"],
        "priority": 1,
    },
    {
        "name": "SecurityAffairs",
        "slug": "securityaffairs",
        "category": "news",
        "rss_url": "https://securityaffairs.com/feed",
        "base_url": "https://securityaffairs.com/",
        "collection_method": "rss",
        "tags": ["osint", "apt", "breach", "malware"],
        "priority": 1,
    },
    {
        "name": "Schneier on Security",
        "slug": "schneier-on-security",
        "category": "news",
        "rss_url": "https://www.schneier.com/feed/atom/",
        "base_url": "https://www.schneier.com/",
        "collection_method": "rss",
        "tags": ["cryptography", "privacy", "analysis"],
        "priority": 2,
    },
    {
        "name": "AlienVault OTX Activity",
        "slug": "alienvault-otx",
        "category": "news",
        "rss_url": "https://otx.alienvault.com/rss",
        "base_url": "https://otx.alienvault.com/",
        "collection_method": "rss",
        "tags": ["alienvault", "otx", "ioc", "threat-intel"],
        "priority": 1,
    },

    # CERT / Govt
    {
        "name": "SANS Internet Storm Center",
        "slug": "sans-isc",
        "category": "cert",
        "official_url": "https://isc.sans.edu/",
        "rss_url": "https://isc.sans.edu/rssfeed.xml",
        "base_url": "https://isc.sans.edu/",
        "collection_method": "rss",
        "tags": ["sans", "isc", "ioc", "incident", "advisory"],
        "priority": 1,
    },
    {
        "name": "Shadowserver Foundation",
        "slug": "shadowserver",
        "category": "cert",
        "official_url": "https://www.shadowserver.org/",
        "rss_url": "https://www.shadowserver.org/news/feed/",
        "base_url": "https://www.shadowserver.org/",
        "collection_method": "rss",
        "tags": ["shadowserver", "botnet", "scanning", "ioc"],
        "priority": 2,
    },
]


async def main():
    await MongoDB.connect()
    sources_col = get_sources_collection()
    articles_col = get_articles_collection()
    now = datetime.now(timezone.utc)

    print("=== SEEDING & CRAWLING 10 NEW RSS/API SOURCES ===")
    added_count = 0

    for src_def in NEW_SOURCES:
        slug = src_def["slug"]
        existing = await sources_col.find_one({"slug": slug})

        if not existing:
            doc = {
                **src_def,
                "schedule_cron": "*/30 * * * *",
                "rate_limit_rpm": 10,
                "is_active": True,
                "language": "en",
                "article_count": 0,
                "health_status": "healthy",
                "created_at": now,
                "updated_at": now,
            }
            res = await sources_col.insert_one(doc)
            doc["_id"] = res.inserted_id
            added_count += 1
            print(f"[+] Added new source to DB: {src_def['name']}")
            src_doc = doc
        else:
            print(f"[*] Source already present: {src_def['name']}")
            src_doc = existing

        # Crawl live feed
        try:
            crawl_res = await crawl_source(src_doc)
            print(f"    └─ Ingested {crawl_res.get('new_articles', 0)} new articles (Status: {crawl_res.get('status')})")
        except Exception as e:
            print(f"    └─ Crawl error for {src_doc['name']}: {e}")

    total_sources = await sources_col.count_documents({})
    total_articles = await articles_col.count_documents({})

    print("\n================ SUMMARY ================")
    print(f"New Sources Inserted:   {added_count}")
    print(f"Total Database Sources: {total_sources}")
    print(f"Total Database Articles:{total_articles}")
    print("=========================================\n")


if __name__ == "__main__":
    asyncio.run(main())
