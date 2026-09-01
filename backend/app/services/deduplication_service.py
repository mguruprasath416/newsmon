"""
Semantic Vector Deduplication Service — Nemotron-3 1B Embedding Similarity Engine

Implements 6-step deduplication & alert suppression pipeline:
1. New article ingested → generate url_hash (existing)
2. If url_hash matches existing article → mark duplicate, STOP (don't re-alert)
3. If url_hash is new → generate embedding_vector (nemotron-3-embed-1b)
4. Compare against articles from the last 48-72 hours
5. If cosine similarity >= 0.90 with any existing article:
     → set duplicate_of = canonical._id
     → set similarity_score
     → set is_duplicate = true
     → SKIP the Alert Engine step entirely
6. Only articles where is_duplicate = false reach Pipeline D (Alert Engine)
"""
import math
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from bson import ObjectId
import structlog

from app.db.mongodb import get_articles_collection
from app.services.rag_service import NVIDIARAGService

log = structlog.get_logger()

# Deduplication Threshold & Window Configuration
SIMILARITY_THRESHOLD = 0.90  # Cosine similarity >= 0.90 triggers duplicate flag
LOOKBACK_HOURS = 72          # 48-72 hour sliding window for fast vector comparisons


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Calculate cosine similarity between two dense floating point vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot_product = sum(a * b for a, b in zip(v1, v2))
    magnitude1 = math.sqrt(sum(a * a for a in v1))
    magnitude2 = math.sqrt(sum(b * b for b in v2))
    if magnitude1 == 0.0 or magnitude2 == 0.0:
        return 0.0
    return dot_product / (magnitude1 * magnitude2)


def calculate_intelligence_score(art: Dict[str, Any]) -> float:
    """
    Calculate an intelligence quality & richness score for an article.
    Richer articles (more content, named threat actors, CVEs, IOCs, AI summaries)
    get higher scores.
    """
    title = art.get("title") or ""
    summary = art.get("summary") or ""
    ai_summary = art.get("ai_summary") or ""
    content = art.get("content_clean") or art.get("content") or ""

    content_len = len(content)
    summary_len = max(len(summary), len(ai_summary))

    # Threat actors score — bonus for named actors
    actors = [a for a in (art.get("threat_actors") or []) if a and str(a).lower() != "unattributed"]
    actors_score = len(actors) * 1500 + (2000 if actors else 0)

    # CVEs score
    cves = art.get("cves") or []
    cves_score = len(cves) * 800

    # IOCs score
    iocs = art.get("iocs") or {}
    ioc_count = art.get("ioc_count") or (len(iocs.get("hashes", [])) + len(iocs.get("ips", [])) + len(iocs.get("domains", []))) if isinstance(iocs, dict) else 0
    iocs_score = ioc_count * 300

    # AI summary & Severity bonuses
    ai_bonus = 500 if ai_summary else 0
    sev = str(art.get("severity") or "").upper()
    sev_bonus = 500 if sev in ("CRITICAL", "HIGH") else 0

    total_score = content_len + (summary_len * 2) + actors_score + cves_score + iocs_score + ai_bonus + sev_bonus
    return float(total_score)


def merge_article_metadata(source_art: Dict[str, Any], target_art: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge valuable intelligence metadata (threat actors, CVEs, IOCs, tags, sector, country)
    from source_art into target_art so no intelligence is lost.
    Returns update dictionary for target_art.
    """
    update_fields = {}

    # Merge Threat Actors
    src_actors = [a for a in (source_art.get("threat_actors") or []) if a and str(a).lower() != "unattributed"]
    tgt_actors = [a for a in (target_art.get("threat_actors") or []) if a and str(a).lower() != "unattributed"]
    merged_actors = sorted(list(set(src_actors + tgt_actors)))
    if merged_actors and merged_actors != tgt_actors:
        update_fields["threat_actors"] = merged_actors

    # Merge CVEs
    src_cves = source_art.get("cves") or []
    tgt_cves = target_art.get("cves") or []
    merged_cves = sorted(list(set(src_cves + tgt_cves)))
    if merged_cves and merged_cves != tgt_cves:
        update_fields["cves"] = merged_cves

    # Merge Tags
    src_tags = source_art.get("tags") or []
    tgt_tags = target_art.get("tags") or []
    merged_tags = sorted(list(set(src_tags + tgt_tags)))
    if merged_tags and merged_tags != tgt_tags:
        update_fields["tags"] = merged_tags

    # Update content / summary if source is significantly longer
    src_content = source_art.get("content_clean") or ""
    tgt_content = target_art.get("content_clean") or ""
    if len(src_content) > len(tgt_content) + 200:
        update_fields["content_clean"] = src_content
        update_fields["word_count"] = len(src_content.split())

    if not target_art.get("ai_summary") and source_art.get("ai_summary"):
        update_fields["ai_summary"] = source_art["ai_summary"]

    if not target_art.get("sector") and source_art.get("sector"):
        update_fields["sector"] = source_art["sector"]

    if not target_art.get("target_country") and source_art.get("target_country"):
        update_fields["target_country"] = source_art["target_country"]

    return update_fields


class DeduplicationService:
    """Semantic vector deduplication and alert suppression engine."""

    @classmethod
    async def process_article_deduplication(cls, article_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs Step 3 to Step 6 of deduplication pipeline.
        Compares content richness (news1 > news2) and merges metadata.
        Returns dictionary containing deduplication status and vector stats.
        """
        articles_col = get_articles_collection()
        art_id = article_doc.get("_id")
        title = article_doc.get("title", "")
        summary = article_doc.get("summary") or article_doc.get("content_clean") or title

        # Step 3: Generate embedding_vector using Nemotron-3 1B (nvidia/nemotron-3-embed-1b)
        text_to_embed = f"{title}\n{summary}"
        vector = await NVIDIARAGService.generate_embedding(text_to_embed, input_type="query")

        if not vector:
            log.warning("Embedding generation failed, skipping vector comparison", title=title[:40])
            return {"is_duplicate": False, "reason": "no_vector"}

        # Step 4: Compare against non-duplicate articles from the last 48-72 hours
        lookback_time = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
        cursor = articles_col.find({
            "_id": {"$ne": art_id},
            "is_duplicate": {"$ne": True},
            "published_at": {"$gte": lookback_time},
            "embedding_vector": {"$exists": True, "$ne": None},
        }).sort("published_at", -1)

        highest_sim = 0.0
        best_candidate = None

        async for candidate in cursor:
            cand_vec = candidate.get("embedding_vector")
            if not cand_vec:
                continue
            sim = cosine_similarity(vector, cand_vec)
            if sim > highest_sim:
                highest_sim = sim
                best_candidate = candidate

        # Step 5: Check similarity threshold (>= 0.90)
        if highest_sim >= SIMILARITY_THRESHOLD and best_candidate:
            cand_id = str(best_candidate["_id"])
            cand_title = best_candidate.get("title", "")

            # Evaluate content richness (news_new vs news_candidate)
            new_score = calculate_intelligence_score(article_doc)
            cand_score = calculate_intelligence_score(best_candidate)

            if new_score > cand_score:
                # NEW article is richer! Promote new_article to Canonical, demote candidate to Duplicate.
                log.info(
                    "Semantic duplicate detected — NEW article is richer -> PROMOTED to Canonical",
                    new_title=title[:50],
                    cand_title=cand_title[:50],
                    new_score=new_score,
                    cand_score=cand_score,
                    similarity=round(highest_sim, 4),
                )
                merged_updates = merge_article_metadata(source_art=best_candidate, target_art=article_doc)

                # Demote candidate in database
                await articles_col.update_one(
                    {"_id": best_candidate["_id"]},
                    {
                        "$set": {
                            "is_duplicate": True,
                            "duplicate_of": str(art_id),
                            "similarity_score": round(highest_sim, 4),
                            "updated_at": datetime.now(timezone.utc),
                        }
                    }
                )

                # Promote new article in database with merged metadata
                new_update_dict = {
                    "is_duplicate": False,
                    "duplicate_of": None,
                    "similarity_score": None,
                    "embedding_vector": vector,
                    "embedding_model": "nemotron-3-embed-1b",
                    "updated_at": datetime.now(timezone.utc),
                }
                new_update_dict.update(merged_updates)
                await articles_col.update_one({"_id": art_id}, {"$set": new_update_dict})
                article_doc.update(new_update_dict)

                return {
                    "is_duplicate": False,
                    "promoted": True,
                    "duplicate_of": None,
                    "similarity_score": round(highest_sim, 4),
                    "skip_alerts": False,
                }
            else:
                # Candidate is richer or equal. Keep candidate as Canonical, mark new article as Duplicate.
                log.info(
                    "Semantic duplicate detected — Candidate is richer -> Kept Canonical, merging metadata",
                    new_title=title[:50],
                    cand_title=cand_title[:50],
                    new_score=new_score,
                    cand_score=cand_score,
                    similarity=round(highest_sim, 4),
                )
                merged_updates = merge_article_metadata(source_art=article_doc, target_art=best_candidate)

                if merged_updates:
                    merged_updates["updated_at"] = datetime.now(timezone.utc)
                    await articles_col.update_one({"_id": best_candidate["_id"]}, {"$set": merged_updates})

                await articles_col.update_one(
                    {"_id": art_id},
                    {
                        "$set": {
                            "is_duplicate": True,
                            "duplicate_of": cand_id,
                            "similarity_score": round(highest_sim, 4),
                            "embedding_vector": vector,
                            "embedding_model": "nemotron-3-embed-1b",
                            "updated_at": datetime.now(timezone.utc),
                        }
                    }
                )
                return {
                    "is_duplicate": True,
                    "promoted": False,
                    "duplicate_of": cand_id,
                    "similarity_score": round(highest_sim, 4),
                    "skip_alerts": True,
                }

        # Step 6: Unique article — store vector and proceed to Pipeline D (Alert Engine)
        await articles_col.update_one(
            {"_id": art_id},
            {
                "$set": {
                    "is_duplicate": False,
                    "duplicate_of": None,
                    "similarity_score": None,
                    "embedding_vector": vector,
                    "embedding_model": "nemotron-3-embed-1b",
                    "updated_at": datetime.now(timezone.utc),
                }
            }
        )
        return {
            "is_duplicate": False,
            "duplicate_of": None,
            "similarity_score": round(highest_sim, 4),
            "skip_alerts": False,
        }
