"""
ClarityTI — Feed & Intelligence Data Update CLI
========================================================================
Executes full feed collection pipeline:
1. Seeds/verifies admin user & 33 intelligence sources.
2. Crawls all active RSS feeds for latest threat intelligence articles.
3. Synchronizes CISA Known Exploited Vulnerabilities (KEV) catalog.
4. Performs Threat Actor entity matching and count linking across all articles.

Usage:
    python -m scripts.update_feed_data
"""

import sys
import os
import asyncio

# Fix Windows console encoding for UTF-8
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.mongodb import MongoDB, get_sources_collection, get_articles_collection
from app.core.seeder import seed_admin_user
from app.services.collector import crawl_source
from app.services.kev_service import KEVSyncService
from app.services.threat_actor_matcher import link_all_articles_to_threat_actors
import structlog

log = structlog.get_logger()


async def main():
    print("=" * 70)
    print("ClarityTI - Feed & Intelligence Data Update")
    print("=" * 70)

    # 1. Connect to MongoDB
    print("\n[1/4] Connecting to MongoDB...")
    try:
        await MongoDB.connect()
        print("  [+] MongoDB connected successfully.")
    except Exception as e:
        print(f"  [-] MongoDB Connection Error: {e}")
        return

    # Seed admin & sources if needed
    print("\n[2/4] Verifying Admin User and Intelligence Sources...")
    try:
        await seed_admin_user()
        sources_col = get_sources_collection()
        sources_count = await sources_col.count_documents({})
        print(f"  [+] {sources_count} intelligence sources verified in database.")
    except Exception as e:
        print(f"  [!] Warning during seeding check: {e}")

    # 2. Crawl Active Feed Sources
    print("\n[3/4] Crawling active intelligence feeds (RSS/Scrape)...")
    sources = []
    async for src in sources_col.find({"is_active": True}):
        sources.append(src)

    if not sources:
        async for src in sources_col.find({}):
            sources.append(src)

    print(f"  Found {len(sources)} active sources to crawl.\n")

    total_added = 0
    total_skipped = 0
    failed_sources = 0

    # Crawl sources in batches of 5 to avoid network/socket exhaustion
    batch_size = 5
    for i in range(0, len(sources), batch_size):
        batch = sources[i:i + batch_size]
        results = await asyncio.gather(*[crawl_source(src) for src in batch], return_exceptions=True)

        for src, res in zip(batch, results):
            name = src.get("name", "Unknown")
            if isinstance(res, Exception):
                print(f"  [-] [{name}] Error: {res}")
                failed_sources += 1
            elif isinstance(res, dict):
                added = res.get("added", 0)
                skipped = res.get("skipped", 0)
                err = res.get("error")
                total_added += added
                total_skipped += skipped
                if err:
                    print(f"  [!] [{name:<30}] 0 added, skipped {skipped} (Degraded: {err})")
                    failed_sources += 1
                else:
                    print(f"  [+] [{name:<30}] +{added:<3} new articles | {skipped} existing skipped")

    print(f"\n  Crawl Summary:")
    print(f"     - Total New Articles Added : {total_added}")
    print(f"     - Existing Articles Skipped: {total_skipped}")
    print(f"     - Failed / Degraded Feeds : {failed_sources}")

    # 3. Synchronize CISA KEV
    print("\n[4/4] Synchronizing CISA Known Exploited Vulnerabilities (KEV) & Linking Threat Actors...")
    try:
        kev_service = KEVSyncService()
        kev_res = await kev_service.sync()
        print(f"  [+] CISA KEV Sync: {kev_res.get('added', 0)} added, {kev_res.get('updated', 0)} updated (Total Catalog: {kev_res.get('total', 0)})")
    except Exception as e:
        print(f"  [!] CISA KEV Sync failed: {e}")

    # Link Threat Actors
    try:
        link_res = await link_all_articles_to_threat_actors()
        print(f"  [+] Threat Actor Matching: Processed {link_res.get('total_articles', 0)} articles, Tagged {link_res.get('articles_tagged', 0)} articles across {link_res.get('threat_actors_updated', 0)} actors.")

        top_actors = link_res.get("top_linked_actors", {})
        if top_actors:
            print("\n  Top Linked Threat Actors:")
            for actor, count in list(top_actors.items())[:5]:
                print(f"     + {actor:<25} : {count} articles")
    except Exception as e:
        print(f"  [!] Threat Actor Matching error: {e}")

    # Final DB counts
    articles_col = get_articles_collection()
    final_article_count = await articles_col.count_documents({})

    print("\n" + "=" * 70)
    print(f"Update Complete! Total Articles in ClarityTI Database: {final_article_count}")
    print("=" * 70)

    await MongoDB.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
