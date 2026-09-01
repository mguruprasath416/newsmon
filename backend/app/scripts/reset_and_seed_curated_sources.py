"""
Reset & Seed Curated Intelligence Sources Script
Resets MongoDB `sources` collection to contain ONLY the 20 curated core sources
(7 News, 8 Threat Research, 5 Official/Regional CERTs) and runs an initial feed crawl.
"""
import sys
import os
import asyncio
from datetime import datetime, timezone

sys.path.insert(0, r'd:\Feed\backend')
sys.stdout.reconfigure(encoding='utf-8')

from app.db.mongodb import MongoDB, get_sources_collection, get_articles_collection
from app.services.collector import crawl_source

CURATED_SOURCES = [
    # ── News (7) ─────────────────────────────────────────────────────────────
    {
        "name": "The Hacker News",
        "slug": "the-hacker-news",
        "category": "news",
        "rss_url": "https://feeds.feedburner.com/TheHackersNews",
        "base_url": "https://thehackernews.com",
        "collection_method": "rss",
        "tags": ["news", "vulnerability", "breach"],
        "priority": 1,
    },
    {
        "name": "BleepingComputer",
        "slug": "bleepingcomputer",
        "category": "news",
        "rss_url": "https://www.bleepingcomputer.com/feed/",
        "base_url": "https://www.bleepingcomputer.com",
        "collection_method": "rss",
        "tags": ["ransomware", "vulnerability", "breach", "malware"],
        "priority": 1,
    },
    {
        "name": "The Record",
        "slug": "the-record",
        "category": "news",
        "rss_url": "https://therecord.media/feed",
        "base_url": "https://therecord.media",
        "collection_method": "rss",
        "tags": ["news", "ransomware", "government"],
        "priority": 1,
    },
    {
        "name": "KrebsOnSecurity",
        "slug": "krebs-on-security",
        "category": "news",
        "rss_url": "https://krebsonsecurity.com/feed/",
        "base_url": "https://krebsonsecurity.com",
        "collection_method": "rss",
        "tags": ["fraud", "breach", "crime"],
        "priority": 1,
    },
    {
        "name": "Dark Reading",
        "slug": "dark-reading",
        "category": "news",
        "rss_url": "https://www.darkreading.com/rss.xml",
        "base_url": "https://www.darkreading.com",
        "collection_method": "rss",
        "tags": ["news", "threat-intelligence", "vulnerability"],
        "priority": 2,
    },
    {
        "name": "SecurityWeek",
        "slug": "securityweek",
        "category": "news",
        "rss_url": "https://feeds.feedburner.com/Securityweek",
        "base_url": "https://www.securityweek.com",
        "collection_method": "rss",
        "tags": ["news", "vulnerability", "breach"],
        "priority": 1,
    },
    {
        "name": "CyberScoop",
        "slug": "cyberscoop",
        "category": "news",
        "rss_url": "https://cyberscoop.com/feed/",
        "base_url": "https://cyberscoop.com",
        "collection_method": "rss",
        "tags": ["policy", "government", "breach"],
        "priority": 1,
    },

    # ── Threat Research (8) ──────────────────────────────────────────────────
    {
        "name": "Google Threat Intelligence",
        "slug": "google-ti",
        "category": "vendor",
        "rss_url": "https://cloudblog.withgoogle.com/rss/",
        "base_url": "https://cloud.google.com/blog/products/threat-intelligence",
        "collection_method": "rss",
        "tags": ["apt", "malware", "mandiant"],
        "priority": 1,
    },
    {
        "name": "Microsoft Security Blog",
        "slug": "microsoft-security",
        "category": "vendor",
        "rss_url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "base_url": "https://www.microsoft.com/en-us/security/blog/",
        "collection_method": "rss",
        "tags": ["microsoft", "vulnerability", "apt"],
        "priority": 1,
    },
    {
        "name": "Cisco Talos",
        "slug": "cisco-talos",
        "category": "vendor",
        "rss_url": "https://feeds.feedburner.com/feedburner/Talos",
        "base_url": "https://blog.talosintelligence.com",
        "collection_method": "rss",
        "tags": ["malware", "vulnerability", "apt"],
        "priority": 1,
    },
    {
        "name": "Palo Alto Unit42",
        "slug": "unit42",
        "category": "vendor",
        "rss_url": "https://unit42.paloaltonetworks.com/feed/",
        "base_url": "https://unit42.paloaltonetworks.com",
        "collection_method": "rss",
        "tags": ["apt", "malware", "vulnerability"],
        "priority": 1,
    },
    {
        "name": "SentinelOne Blog",
        "slug": "sentinelone",
        "category": "vendor",
        "rss_url": "https://www.sentinelone.com/blog/feed/",
        "base_url": "https://www.sentinelone.com/blog",
        "collection_method": "rss",
        "tags": ["malware", "apt", "edr"],
        "priority": 2,
    },
    {
        "name": "Check Point Research",
        "slug": "checkpoint",
        "category": "vendor",
        "rss_url": "https://research.checkpoint.com/feed/",
        "base_url": "https://research.checkpoint.com",
        "collection_method": "rss",
        "tags": ["malware", "apt", "research"],
        "priority": 2,
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
    {
        "name": "CrowdStrike Blog",
        "slug": "crowdstrike",
        "category": "vendor",
        "rss_url": "https://www.crowdstrike.com/en-us/blog/feed",
        "base_url": "https://www.crowdstrike.com/blog",
        "collection_method": "rss",
        "tags": ["apt", "malware", "threat-intelligence"],
        "priority": 1,
    },

    # ── Official & Regional CERTs (5) ────────────────────────────────────────
    {
        "name": "CISA Alerts",
        "slug": "cisa",
        "category": "cert",
        "official_url": "https://www.cisa.gov/cybersecurity-advisories",
        "rss_url": "https://news.google.com/rss/search?q=site:cisa.gov+advisories+OR+vulnerabilities&hl=en-US&gl=US&ceid=US:en",
        "base_url": "https://www.cisa.gov",
        "collection_method": "rss",
        "tags": ["advisory", "ioc", "mitigation"],
        "priority": 1,
    },
    {
        "name": "CERT-In Advisories (India)",
        "slug": "cert-in",
        "category": "cert",
        "official_url": "https://www.cert-in.org.in/",
        "rss_url": "https://news.google.com/rss/search?q=site:cert-in.org.in+advisory&hl=en-IN&gl=IN&ceid=IN:en",
        "base_url": "https://www.cert-in.org.in",
        "collection_method": "rss",
        "tags": ["india", "cert-in", "advisory", "official"],
        "priority": 1,
    },
    {
        "name": "NCSC UK",
        "slug": "ncsc-uk",
        "category": "cert",
        "official_url": "https://www.ncsc.gov.uk/",
        "rss_url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
        "base_url": "https://www.ncsc.gov.uk",
        "collection_method": "rss",
        "tags": ["advisory", "uk", "mitigation"],
        "priority": 1,
    },
    {
        "name": "SANS Internet Storm Center",
        "slug": "sans-isc",
        "category": "cert",
        "official_url": "https://isc.sans.edu/",
        "rss_url": "https://isc.sans.edu/rssfeed.xml",
        "base_url": "https://isc.sans.edu",
        "collection_method": "rss",
        "tags": ["sans", "isc", "ioc", "incident", "advisory"],
        "priority": 1,
    },
    {
        "name": "DataBreaches.net",
        "slug": "databreaches-net",
        "category": "news",
        "rss_url": "https://www.databreaches.net/feed/",
        "base_url": "https://www.databreaches.net",
        "collection_method": "rss",
        "tags": ["breach", "data-leak", "cybercrime", "ransomware"],
        "priority": 1,
    },
]


async def main():
    await MongoDB.connect()
    sources_col = get_sources_collection()
    articles_col = get_articles_collection()
    now = datetime.now(timezone.utc)

    print("=== RESETTING DATABASE TO 20 CURATED SOURCES ===")
    
    # Reset sources collection
    await sources_col.delete_many({})
    print("[*] Cleared existing sources collection.")

    docs_to_insert = []
    for src in CURATED_SOURCES:
        doc = {
            **src,
            "schedule_cron": "*/30 * * * *",
            "rate_limit_rpm": 10,
            "is_active": True,
            "language": "en",
            "article_count": 0,
            "last_crawled_at": None,
            "last_article_at": None,
            "health_status": "healthy",
            "created_at": now,
            "updated_at": now,
        }
        docs_to_insert.append(doc)

    await sources_col.insert_many(docs_to_insert)
    print(f"[+] Inserted {len(docs_to_insert)} curated sources into MongoDB.")

    # Run crawl across all 20 curated sources
    print("\n=== TRIGGERING FEED CRAWL FOR 20 SOURCES ===")
    all_sources = await sources_col.find({}).to_list(length=100)
    for src_doc in all_sources:
        try:
            crawl_res = await crawl_source(src_doc)
            print(f"  • {src_doc['name']:<30} -> Ingested {crawl_res.get('new_articles', 0)} articles")
        except Exception as e:
            print(f"  • {src_doc['name']:<30} -> Crawl error: {e}")

    total_sources = await sources_col.count_documents({})
    total_articles = await articles_col.count_documents({})

    print("\n================ FINAL SUMMARY ================")
    print(f"Total Curated Sources in DB: {total_sources}")
    print(f"Total Indexed Articles in DB:{total_articles}")
    print("===============================================\n")


if __name__ == "__main__":
    asyncio.run(main())
