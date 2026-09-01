"""
Script to register Reuters Cybersecurity feed in MongoDB and perform initial live crawl.
"""
import sys
import os
sys.path.insert(0, r'd:\Feed\backend')
sys.stdout.reconfigure(encoding='utf-8')
import asyncio
from datetime import datetime, timezone
from app.db.mongodb import MongoDB, get_sources_collection, get_articles_collection
from app.services.collector import crawl_source

REUTERS_SOURCE = {
    "name": "Reuters Cybersecurity",
    "slug": "reuters",
    "category": "news",
    "rss_url": "https://news.google.com/rss/search?q=site:reuters.com+(cybersecurity+OR+breach+OR+hacked+OR+ransomware)&hl=en-US&gl=US&ceid=US:en",
    "base_url": "https://www.reuters.com/technology/cybersecurity/",
    "collection_method": "rss",
    "tags": ["news", "breach", "reuters", "cybersecurity"],
    "priority": 1,
    "schedule_cron": "*/15 * * * *",
    "rate_limit_rpm": 10,
    "is_active": True,
    "enabled": True,
    "language": "en",
    "article_count": 0,
    "health_status": "healthy",
    "created_at": datetime.now(timezone.utc),
    "updated_at": datetime.now(timezone.utc),
}

async def add_and_crawl_reuters():
    await MongoDB.connect()
    sources_col = get_sources_collection()
    articles_col = get_articles_collection()

    existing = await sources_col.find_one({"slug": "reuters"})
    if not existing:
        res = await sources_col.insert_one(REUTERS_SOURCE)
        source_id = res.inserted_id
        source_doc = await sources_col.find_one({"_id": source_id})
        print(f"✅ Added Reuters Cybersecurity source to MongoDB ({source_id})")
    else:
        await sources_col.update_one(
            {"_id": existing["_id"]},
            {"$set": {"rss_url": REUTERS_SOURCE["rss_url"], "enabled": True, "is_active": True}}
        )
        source_doc = await sources_col.find_one({"_id": existing["_id"]})
        print("🔄 Updated existing Reuters Cybersecurity source configuration")

    print("🚀 Starting live crawl for Reuters Cybersecurity...")
    result = await crawl_source(source_doc)
    print(f"📊 Crawl Result: Added {result.get('added', 0)} new articles, skipped {result.get('skipped', 0)} existing.")

    count = await articles_col.count_documents({"source_name": "Reuters Cybersecurity"})
    await sources_col.update_one({"_id": source_doc["_id"]}, {"$set": {"article_count": count}})
    print(f"🎉 Total Reuters Cybersecurity articles in database: {count}")

if __name__ == "__main__":
    asyncio.run(add_and_crawl_reuters())
