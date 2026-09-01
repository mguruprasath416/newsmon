"""
ClarityTI — Smart Article Deduplication & Threat Actor Metadata Merger Script
==============================================================================
Evaluates duplicate news articles based on content richness & valuable CTI details:
1. If news_new > news_existing (has more content, named threat actors, CVEs, IOCs):
     -> Promotes news_new to CANONICAL (primary)
     -> Demotes news_existing to DUPLICATE
     -> Merges all threat actors, CVEs, IOCs, tags, and metadata into CANONICAL
2. Matches and links all threat actors across MongoDB.

Usage:
    python backend/scripts/run_smart_deduplication.py
"""
import sys
import os
import re
import asyncio
from datetime import datetime, timezone

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.mongodb import MongoDB, get_articles_collection
from app.services.threat_actor_matcher import link_all_articles_to_threat_actors
from app.services.deduplication_service import calculate_intelligence_score, merge_article_metadata
import structlog

log = structlog.get_logger()


sys.stdout.reconfigure(encoding='utf-8')

async def run_smart_deduplication_and_enrichment():
    print("=================================================================", flush=True)
    print("  CLARITYTI — SMART DEDUPLICATION & THREAT ACTOR ENRICHMENT PIPELINE", flush=True)
    print("=================================================================\n", flush=True)

    await MongoDB.connect()
    articles_col = get_articles_collection()

    # Step 1: Link & Tag Threat Actors across all articles
    print("[1/3] Tagging and linking threat actors across all database articles...", flush=True)
    ta_res = await link_all_articles_to_threat_actors()
    print(f"      Total Articles Processed: {ta_res.get('total_articles')}", flush=True)
    print(f"      Articles Tagged/Updated:  {ta_res.get('articles_tagged')}", flush=True)
    print(f"      Threat Actors Updated:   {ta_res.get('threat_actors_updated')}", flush=True)

    # Step 2: Smart Deduplication & Content Richness Merge
    print("\n[2/3] Evaluating article content richness & merging duplicate metadata...", flush=True)
    cursor = articles_col.find({}).sort("published_at", -1)
    all_articles = [a async for a in cursor]

    stops = {'the', 'a', 'an', 'in', 'on', 'of', 'for', 'to', 'and', 'or', 'with', 'by', 'at', 'from', 'is', 'are', 'could', 'enable', 'new', 'flaw', 'top', 'how', 'why', 'after'}

    def get_token_key(title: str) -> str:
        words = sorted([w for w in re.findall(r'\w+', title.lower()) if len(w) >= 4 and w not in stops])
        if len(words) >= 2:
            return " ".join(words[:4])
        return re.sub(r'[^a-z0-9]', '', title.lower())[:80]

    canonical_map = {} # token_key -> primary_article
    duplicates_demoted = 0
    articles_promoted = 0
    metadata_merged_count = 0

    for art in all_articles:
        art_id = str(art["_id"])
        title = (art.get("title") or "").strip()
        if not title:
            continue

        token_key = get_token_key(title)
        if not token_key:
            continue

        if token_key not in canonical_map:
            canonical_map[token_key] = art
            continue

        # Duplicate match found! Compare richness score (news1 vs news2)
        existing_canonical = canonical_map[token_key]
        existing_id = str(existing_canonical["_id"])

        new_score = calculate_intelligence_score(art)
        existing_score = calculate_intelligence_score(existing_canonical)

        if new_score > existing_score:
            # Current article is RICHER than existing canonical!
            # Promote current article to canonical, demote existing canonical to duplicate
            print(f"  [+] PROMOTING richer article: '{title[:50]}' (Score: {new_score:.1f} vs {existing_score:.1f})")
            
            merged_updates = merge_article_metadata(source_art=existing_canonical, target_art=art)
            merged_updates.update({
                "is_duplicate": False,
                "duplicate_of": None,
                "similarity_score": None,
                "updated_at": datetime.now(timezone.utc),
            })
            await articles_col.update_one({"_id": art["_id"]}, {"$set": merged_updates})
            art.update(merged_updates)

            # Demote existing canonical
            await articles_col.update_one(
                {"_id": existing_canonical["_id"]},
                {
                    "$set": {
                        "is_duplicate": True,
                        "duplicate_of": art_id,
                        "similarity_score": 0.95,
                        "updated_at": datetime.now(timezone.utc),
                    }
                }
            )

            canonical_map[token_key] = art
            articles_promoted += 1
            duplicates_demoted += 1
        else:
            # Existing canonical is equal or richer. Keep existing canonical, demote current article.
            merged_updates = merge_article_metadata(source_art=art, target_art=existing_canonical)
            if merged_updates:
                merged_updates["updated_at"] = datetime.now(timezone.utc)
                await articles_col.update_one({"_id": existing_canonical["_id"]}, {"$set": merged_updates})
                existing_canonical.update(merged_updates)
                metadata_merged_count += 1

            await articles_col.update_one(
                {"_id": art["_id"]},
                {
                    "$set": {
                        "is_duplicate": True,
                        "duplicate_of": existing_id,
                        "similarity_score": 0.95,
                        "updated_at": datetime.now(timezone.utc),
                    }
                }
            )
            duplicates_demoted += 1

    print(f"      Articles Promoted (Richer): {articles_promoted}")
    print(f"      Duplicates Handled/Marked:  {duplicates_demoted}")
    print(f"      Metadata Enriched & Merged: {metadata_merged_count}")

    # Step 3: Final threat actor sync
    print("\n[3/3] Re-syncing threat actor metrics...")
    final_ta_res = await link_all_articles_to_threat_actors()

    print("\n=================================================================")
    print("  SMART DEDUPLICATION & METADATA MERGING COMPLETE!")
    print("=================================================================\n")


if __name__ == "__main__":
    asyncio.run(run_smart_deduplication_and_enrichment())
