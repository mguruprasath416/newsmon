"""
ClarityTI — Standalone CLI Script for 2018–Present Historical Backfill
========================================================================
Usage:
    python -m scripts.backfill_2018_present --start-year 2018 --category news
    python -m scripts.backfill_2018_present --source-slug bleepingcomputer --max-articles 2000
"""

import argparse
import asyncio
import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.mongodb import MongoDB, get_sources_collection
from app.services.historical_collector import backfill_source_historical
import structlog

log = structlog.get_logger()


async def main():
    parser = argparse.ArgumentParser(description="ClarityTI Historical Data Backfill CLI (2018 - Present)")
    parser.add_argument("--start-year", type=int, default=2018, help="Start year for backfill (default: 2018)")
    parser.add_argument("--category", type=str, default=None, help="Filter by category (vendor, news, gov)")
    parser.add_argument("--source-slug", type=str, default=None, help="Backfill a specific source slug")
    parser.add_argument("--max-articles", type=int, default=1000, help="Max articles per source (default: 1000)")

    args = parser.parse_args()

    # Connect to MongoDB
    try:
        await MongoDB.connect()
    except Exception as e:
        print(f"[!] MongoDB Connection Error: {e}")
        return

    col = get_sources_collection()
    query = {"is_active": True}

    if args.source_slug:
        query["slug"] = args.source_slug
    elif args.category:
        query["category"] = args.category

    sources = []
    async for doc in col.find(query):
        sources.append(doc)

    if not sources:
        # If no active flag or query returned empty, query all sources
        async for doc in col.find({}):
            sources.append(doc)

    if not sources:
        print(f"[!] No sources found in collection 'sources'.")
        await MongoDB.disconnect()
        return

    print(f"[+] Starting 2018-Present Backfill for {len(sources)} sources (Start Year: {args.start_year})...")

    total_added = 0
    total_skipped = 0

    for i, src in enumerate(sources, start=1):
        name = src.get("name", "Unknown")
        print(f"\n[{i}/{len(sources)}] Backfilling '{name}'...")
        res = await backfill_source_historical(src, start_year=args.start_year, max_articles=args.max_articles)
        added = res.get("added", 0)
        skipped = res.get("skipped", 0)
        total_added += added
        total_skipped += skipped
        print(f"    +-- Result: {added} new articles added, {skipped} skipped.")

    print(f"\n[+] Historical Backfill Completed!")
    print(f"    Total New Articles Added: {total_added}")
    print(f"    Total Duplicates Skipped: {total_skipped}")

    await MongoDB.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
