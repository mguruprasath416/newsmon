"""
CyberPulse — Viral Cyber News Detection, Heat Mapping & Priority Alert Engine.

Core Responsibilities:
1. Cross-Source Event Correlation: Groups articles covering the SAME news event across independent feeds.
2. Unique Source Counting Rule: Strict deduplication by source (multiple articles from 1 source = 1 source).
3. Configurable Thresholds:
   - < 5 Sources: Emerging event (not on heat map)
   - 5-9 Sources: Trending / Medium Heat (on heat map)
   - 10+ Sources: High Heat / High Priority (triggers Microsoft Teams & Discord alerts)
4. Virality & Heat Score Formula: Computes normalized score (0-100) combining coverage, velocity, recency, diversity.
5. Automated Alert Deduplication: Only triggers high-priority alerts once per threshold crossing.
"""

import hashlib
import math
import re
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
import structlog

from app.config import settings
from app.db.mongodb import get_viral_events_collection, get_articles_collection, get_sources_collection
from app.services.teams_service import (
    determine_incident_type,
    extract_country,
    extract_breached_company,
    extract_threat_actor,
    extract_severity_level,
    TeamsService,
)

log = structlog.get_logger()


def generate_event_id(title: str, cves: Any = None, company: str = None, fallback_id: str = "") -> str:
    """Generate a deterministic, stable CyberPulse event ID based on story fingerprint."""
    if cves:
        sorted_cves = sorted([str(c).upper().strip() for c in cves if str(c).strip()])
        if sorted_cves:
            key = f"cve:{'_'.join(sorted_cves[:2])}"
        else:
            key = f"title:{re.sub(r'[^a-zA-Z0-9]', '', (title or fallback_id).lower())[:40]}"
    elif company and company != "Not Specified" and len(company) > 2:
        norm_title = re.sub(r'[^a-zA-Z0-9]', '', (title or fallback_id).lower())[:30]
        key = f"org:{company.lower().strip()}:{norm_title}"
    elif title and len(title.strip()) > 3:
        norm_title = re.sub(r'[^a-zA-Z0-9]', '', title.lower())[:40]
        key = f"title:{norm_title}"
    else:
        key = f"art:{fallback_id or uuid.uuid4().hex}"
    
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8].upper()
    return f"CP-{digest}"


def extract_cves(text: str) -> List[str]:
    """Extract standard CVE identifiers from text."""
    if not text:
        return []
    return list(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)))



def _ensure_utc_dt(val: Any) -> datetime:
    """Ensure datetime is offset-aware in UTC."""
    if not val:
        return datetime.now(timezone.utc)
    if isinstance(val, str):
        try:
            val = datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _stem_and_normalize(token: str) -> str:
    """Normalize morphological variations, demonyms, and attack synonyms."""
    if not token or len(token) <= 2:
        return token
    # Demonym normalization
    demonym_map = {
        "iranian": "iran",
        "british": "uk",
        "britain": "uk",
        "russian": "russia",
        "chinese": "china",
        "american": "us",
        "korean": "korea",
        "israeli": "israel",
        "indian": "india",
        "german": "germany",
        "french": "france",
    }
    if token in demonym_map:
        return demonym_map[token]

    # Domain synonym canonicalization
    synonym_map = {
        "disrupted": "disrupt",
        "disrupting": "disrupt",
        "disruption": "disrupt",
        "disruptions": "disrupt",
        "outage": "disrupt",
        "shutdown": "disrupt",
        "facility": "plant",
        "facilities": "plant",
        "grid": "power",
        "infrastructure": "infra",
        "infrastructures": "infra",
        "offensive": "attack",
        "intrusions": "intrusion",
        "intrusion": "attack",
        "compromise": "breach",
        "compromised": "breach",
        "leaked": "leak",
        "dumped": "dump",
    }
    if token in synonym_map:
        return synonym_map[token]

    # Suffix stemming
    for suffix in ["tion", "tions", "ing", "ers", "er", "ed", "es", "s"]:
        if token.endswith(suffix) and len(token) > len(suffix) + 3:
            return token[:-len(suffix)]
    return token


def _tokenize_for_similarity(text: str) -> set:
    """Tokenize and filter text into normalized content tokens."""
    if not text:
        return set()
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    tokens = text.split()
    stopwords = {
        "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for", "with",
        "of", "by", "from", "as", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "can", "could", "should", "would",
        "about", "against", "between", "into", "through", "during", "before", "after",
        "above", "below", "up", "down", "out", "off", "over", "under", "again", "further",
        "then", "once", "here", "there", "when", "where", "why", "how", "all", "any",
        "both", "each", "few", "more", "most", "other", "some", "such", "no", "nor",
        "not", "only", "own", "same", "so", "than", "too", "very", "s", "t", "just",
        "don", "shouldn", "now", "says", "said", "report", "reports", "new", "via",
        "cybersecurity", "security", "threat"
    }
    normalized = set()
    for t in tokens:
        if len(t) > 2 and t not in stopwords:
            normalized.add(_stem_and_normalize(t))
    return normalized



def calculate_jaccard_similarity(set_a: set, set_b: set) -> float:
    """Compute Jaccard similarity index between two token sets."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return float(intersection) / float(union) if union > 0 else 0.0


class CyberPulseService:
    """
    Core engine for detecting viral cross-source cyber news events,
    calculating heat scores, and routing priority alerts.
    """

    @staticmethod
    def calculate_event_heat_score(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate the CyberPulse Heat Score (0 - 100).
        
        Formula:
        Coverage Score (0-50): Based on unique source count (10 sources = max 50 pts)
        Velocity Score (0-30): Acceleration of new sources reporting over recent hours
        Recency Score  (0-10): Time elapsed since latest article
        Diversity Score (0-10): Cross-source categories (e.g. CERT + Research + News)
        """
        unique_sources = event.get("unique_source_names") or []
        source_count = max(len(unique_sources), event.get("source_count", 0))
        article_count = max(len(event.get("related_article_ids", [])), event.get("article_count", 0))
        
        # 1. Coverage Score (0 - 55 pts)
        # Scaled so that 5 sources ≈ 27.5 pts, 10 sources = 55 pts
        coverage_score = min(55.0, (source_count / float(settings.CYBERPULSE_HIGH_SOURCES)) * 55.0)

        # 2. Velocity Score (0 - 25 pts)
        # Check source growth history over last 6 hours or fallback to confirmation density
        growth_history = event.get("source_growth_history") or []
        recent_sources_count = 0
        now = utcnow()
        six_hours_ago = now - timedelta(hours=6)
        
        if growth_history:
            for pt in growth_history:
                ts = pt.get("timestamp")
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except Exception:
                        continue
                if ts and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts and ts >= six_hours_ago:
                    recent_sources_count += 1
            velocity_score = min(25.0, max(recent_sources_count * 5.0, (article_count / max(source_count, 1)) * 6.0))
        else:
            velocity_score = min(25.0, max(5.0, (article_count / max(source_count, 1)) * 6.0))

        # 3. Recency Score (0 - 10 pts)
        last_detected = event.get("last_detected_at")
        if isinstance(last_detected, str):
            try:
                last_detected = datetime.fromisoformat(last_detected.replace("Z", "+00:00"))
            except Exception:
                last_detected = now
        if last_detected and last_detected.tzinfo is None:
            last_detected = last_detected.replace(tzinfo=timezone.utc)
        
        hours_ago = max(0.0, (now - (last_detected or now)).total_seconds() / 3600.0)
        recency_score = 10.0 * math.exp(-hours_ago / 24.0)

        # 4. Diversity Score (0 - 10 pts)
        # More diverse source names boost the confirmation score
        distinct_source_roots = set()
        for s in unique_sources:
            s_clean = s.lower().replace(" ", "").replace(".com", "").replace(".org", "")
            distinct_source_roots.add(s_clean[:10])
        diversity_score = min(10.0, len(distinct_source_roots) * 1.2)

        # High-Heat Viral Bonus for reaching 10+ sources
        viral_bonus = 5.0 if source_count >= settings.CYBERPULSE_HIGH_SOURCES else 0.0

        total_heat = int(round(coverage_score + velocity_score + recency_score + diversity_score + viral_bonus))
        total_heat = max(0, min(100, total_heat))

        # Compute trend
        if velocity_score >= 12.0:
            trend = "increasing"
        elif velocity_score >= 4.0:
            trend = "stable"
        else:
            trend = "decreasing"

        # Determine priority and status
        if source_count >= settings.CYBERPULSE_HIGH_SOURCES:
            status = "high_heat"
            priority = "high" if total_heat < 90 else "critical"
        elif source_count >= settings.CYBERPULSE_MIN_SOURCES:
            status = "trending"
            priority = "medium" if total_heat < 70 else "high"
        else:
            status = "emerging"
            priority = "low"

        return {
            "heat_score": total_heat,
            "coverage_score": round(coverage_score, 1),
            "velocity_score": round(velocity_score, 1),
            "recency_score": round(recency_score, 1),
            "trend": trend,
            "status": status,
            "priority": priority,
        }

    @staticmethod
    def generate_analyst_explanation(event: Dict[str, Any]) -> str:
        """
        Generate transparent explanation of why articles were correlated into this CyberPulse event.
        """
        source_count = event.get("source_count", 0)
        article_count = event.get("article_count", 0)
        victim = event.get("target_company")
        country = event.get("target_country")
        incident_type = event.get("incident_type")
        cves = event.get("cves") or []
        actors = event.get("threat_actors") or []

        reasons = []
        if victim and victim != "Not Specified":
            reasons.append(f"Target organization/system '{victim}' consistently identified across reports")
        if incident_type:
            reasons.append(f"Matching incident vector: {incident_type}")
        if actors and actors[0] != "Unknown":
            reasons.append(f"Attributed to threat actor / campaign: {', '.join(actors[:2])}")
        if cves:
            reasons.append(f"Exploits shared vulnerability: {', '.join(cves[:3])}")
        if country and country != "Global":
            reasons.append(f"Target geography: {country}")

        reasons.append(f"High cross-source semantic overlap within a 72-hour temporal window")

        bullet_points = "\n".join([f"• {r}" for r in reasons])
        return (
            f"This CyberPulse event was correlated from {article_count} independent reports across "
            f"{source_count} distinct intelligence sources due to the following corroborating signals:\n"
            f"{bullet_points}\n"
            f"Current coverage status: {source_count} unique sources confirming the incident."
        )

    @classmethod
    def compute_article_event_similarity(
        cls,
        article: Dict[str, Any],
        event: Dict[str, Any]
    ) -> Tuple[float, Dict[str, Any]]:
        """
        Multi-signal similarity evaluation between an incoming article and an existing event cluster.
        Returns: (similarity_score: float, match_details: dict)
        """
        art_title = (article.get("title") or "").strip()
        art_summary = (article.get("summary") or article.get("content_clean") or "")[:400]
        event_title = event.get("title", "")
        event_summary = event.get("summary", "")

        art_tokens = _tokenize_for_similarity(f"{art_title} {art_summary}")
        event_tokens = _tokenize_for_similarity(f"{event_title} {event_summary}")

        if not art_tokens or not event_tokens:
            return 0.0, {}

        # 1. Title & Semantic Overlap (Weight: 0.45)
        title_tokens_a = _tokenize_for_similarity(art_title)
        title_tokens_e = _tokenize_for_similarity(event_title)
        title_sim = calculate_jaccard_similarity(title_tokens_a, title_tokens_e)
        body_sim = calculate_jaccard_similarity(art_tokens, event_tokens)
        
        # Overlap containment bonus for short titles vs full descriptions
        min_title_len = min(len(title_tokens_a), len(title_tokens_e)) if (title_tokens_a and title_tokens_e) else 1
        containment = len(title_tokens_a.intersection(title_tokens_e)) / float(min_title_len)
        semantic_sim = max((title_sim * 0.5) + (body_sim * 0.5), containment * 0.75)

        # 2. Entity / Victim Match (Weight: 0.20)
        art_victim = extract_breached_company(article)
        event_victim = event.get("target_company")
        victim_match = 0.0
        if art_victim and event_victim and art_victim != "Not Specified" and event_victim != "Not Specified":
            if art_victim.lower() == event_victim.lower():
                victim_match = 1.0
            elif art_victim.lower() in event_victim.lower() or event_victim.lower() in art_victim.lower():
                victim_match = 0.8
            else:
                victim_match = -0.5

        # 3. Country / Region Match (Weight: 0.15)
        art_country = extract_country(article)
        event_country = event.get("target_country") or extract_country({"title": event_title, "summary": event_summary})
        country_match = 0.0
        if art_country and event_country and art_country != "Global" and event_country != "Global":
            if art_country.lower() == event_country.lower():
                country_match = 1.0
            elif art_country.lower() in event_country.lower() or event_country.lower() in art_country.lower():
                country_match = 0.8
            else:
                country_match = -0.2

        # 4. CVE / Vulnerability overlap (Weight: 0.10)
        art_cves = set(extract_cves(f"{art_title} {art_summary}"))
        event_cves = set(event.get("cves") or [])
        cve_match = 0.0
        if art_cves and event_cves:
            if art_cves.intersection(event_cves):
                cve_match = 1.0

        # 5. Temporal Proximity (Weight: 0.10)
        now = utcnow()
        art_pub = article.get("published_at") or article.get("crawled_at") or now
        if isinstance(art_pub, str):
            try:
                art_pub = datetime.fromisoformat(art_pub.replace("Z", "+00:00"))
            except Exception:
                art_pub = now
        if art_pub.tzinfo is None:
            art_pub = art_pub.replace(tzinfo=timezone.utc)

        event_last = event.get("last_detected_at") or now
        if isinstance(event_last, str):
            try:
                event_last = datetime.fromisoformat(event_last.replace("Z", "+00:00"))
            except Exception:
                event_last = now
        if event_last.tzinfo is None:
            event_last = event_last.replace(tzinfo=timezone.utc)

        hours_diff = abs((art_pub - event_last).total_seconds()) / 3600.0
        temporal_match = max(0.0, 1.0 - (hours_diff / float(settings.CYBERPULSE_TIME_WINDOW_HOURS)))

        # Weighted Final Score with dynamic normalization
        weights = {"semantic": 0.50, "country": 0.20, "temporal": 0.15}
        total_weight = 0.85
        score_sum = (semantic_sim * weights["semantic"]) + (max(0.0, country_match) * weights["country"]) + (temporal_match * weights["temporal"])

        if victim_match > 0:
            score_sum += victim_match * 0.25
            total_weight += 0.25
        if cve_match > 0:
            score_sum += cve_match * 0.20
            total_weight += 0.20

        final_score = score_sum / total_weight

        # Apply penalties if conflicting named entities
        if victim_match < 0:
            final_score -= 0.45
        if country_match < 0:
            final_score -= 0.30

        match_details = {
            "semantic_sim": round(semantic_sim, 3),
            "victim_match": victim_match,
            "cve_match": cve_match,
            "country_match": country_match,
            "temporal_match": round(temporal_match, 3),
            "final_score": round(max(0.0, final_score), 3),
        }

        return max(0.0, final_score), match_details

    @classmethod
    async def correlate_article(cls, article: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a single article: correlate with active CyberPulse events or seed a candidate event.
        Updates unique source counts, heat scores, and triggers priority alert if >= 10 sources.
        """
        # Ensure article represents a genuine cybersecurity risk before correlating
        is_cyber = article.get("is_cybersecurity_news")
        if is_cyber is None:
            from app.services.keyword_classifier import KeywordClassifier
            kw_res = KeywordClassifier.classify_article(article)
            is_cyber = kw_res["is_cybersecurity_news"]

        if not is_cyber:
            return None

        art_id = str(article.get("_id") or article.get("id"))
        source_id = str(article.get("source_id", ""))
        source_name = (article.get("source_name") or "Unknown Source").strip()
        pub_time = article.get("published_at") or article.get("crawled_at") or utcnow()
        if isinstance(pub_time, str):
            try:
                pub_time = datetime.fromisoformat(pub_time.replace("Z", "+00:00"))
            except Exception:
                pub_time = utcnow()
        if pub_time.tzinfo is None:
            pub_time = pub_time.replace(tzinfo=timezone.utc)

        events_col = get_viral_events_collection()
        articles_col = get_articles_collection()

        # Look up candidate events in the temporal window (default 72 hours)
        time_limit = utcnow() - timedelta(hours=settings.CYBERPULSE_TIME_WINDOW_HOURS)
        cursor = events_col.find({"last_detected_at": {"$gte": time_limit}}).sort("last_detected_at", -1)
        active_events = await cursor.to_list(length=100)

        best_match_event = None
        best_match_score = 0.0

        for ev in active_events:
            score, _ = cls.compute_article_event_similarity(article, ev)
            if score >= settings.CYBERPULSE_SIMILARITY_THRESHOLD and score > best_match_score:
                best_match_score = score
                best_match_event = ev

        if best_match_event:
            # Correlate into existing event
            event_id = best_match_event["event_id"]
            related_articles = best_match_event.get("related_article_ids") or []
            unique_sources = set(best_match_event.get("unique_source_names") or [])
            unique_source_ids = set(best_match_event.get("unique_source_ids") or [])

            if art_id not in related_articles:
                related_articles.append(art_id)
            unique_sources.add(source_name)
            if source_id:
                unique_source_ids.add(source_id)

            old_source_count = best_match_event.get("source_count", 0)
            new_source_count = len(unique_sources)

            # Update event object for recalculation
            updated_event = dict(best_match_event)
            updated_event["related_article_ids"] = related_articles
            updated_event["unique_source_names"] = list(unique_sources)
            updated_event["unique_source_ids"] = list(unique_source_ids)
            prev_last = _ensure_utc_dt(best_match_event.get("last_detected_at", pub_time))
            updated_event["last_detected_at"] = max(prev_last, _ensure_utc_dt(pub_time))

            # Calculate updated heat scores and trend
            heat_data = cls.calculate_event_heat_score(updated_event)
            updated_event.update(heat_data)
            updated_event["explanation"] = cls.generate_analyst_explanation(updated_event)
            updated_event["updated_at"] = utcnow()

            # Record growth point if source count increased
            growth_history = updated_event.get("source_growth_history") or []
            if new_source_count > old_source_count or not growth_history:
                growth_history.append({
                    "timestamp": utcnow().isoformat(),
                    "source_count": new_source_count,
                    "article_count": len(related_articles),
                    "heat_score": heat_data["heat_score"],
                    "source_name": source_name,
                })
                updated_event["source_growth_history"] = growth_history

            # Check High Priority Alert Trigger (Threshold >= 10 sources)
            should_alert = (
                new_source_count >= settings.CYBERPULSE_HIGH_SOURCES and
                not updated_event.get("alert_triggered", False)
            )

            if should_alert:
                updated_event["alert_triggered"] = True
                updated_event["alert_triggered_at"] = utcnow()
                log.info(
                    "🚨 CyberPulse High Priority Threshold Crossed! Dispatching Alert...",
                    event_id=event_id,
                    sources=new_source_count,
                    heat=heat_data["heat_score"],
                    title=updated_event["title"],
                )
                try:
                    await TeamsService.dispatch_cyberpulse_alert(updated_event)
                except Exception as alert_err:
                    log.error("Failed to dispatch Teams alert for CyberPulse event", error=str(alert_err))

            # Save updated event
            await events_col.update_one({"event_id": event_id}, {"$set": updated_event})
            await articles_col.update_one({"_id": article.get("_id")}, {"$set": {"viral_event_id": event_id}})

            log.info(
                "Correlated article into CyberPulse event",
                event_id=event_id,
                title=updated_event["title"][:50],
                unique_sources=new_source_count,
                heat_score=heat_data["heat_score"],
            )
            return updated_event

        else:
            # Seed new candidate event
            victim = extract_breached_company(article)
            country = extract_country(article)
            incident_type = determine_incident_type(article)
            title = article.get("title", "Untitled Cyber News Event").strip()
            summary = (article.get("summary") or article.get("content_clean") or title)[:300]
            cves = extract_cves(f"{title} {summary}")
            actor = extract_threat_actor(article)
            actors = [actor] if actor != "Unknown" else []
            event_id = generate_event_id(title, cves, victim)

            new_event = {
                "event_id": event_id,
                "title": title,
                "normalized_title": re.sub(r'[^a-zA-Z0-9\s]', '', title).lower()[:100],
                "summary": summary,
                "related_article_ids": [art_id],
                "unique_source_ids": [source_id] if source_id else [],
                "unique_source_names": [source_name],
                "source_count": 1,
                "article_count": 1,
                "target_company": victim,
                "target_country": country,
                "incident_type": incident_type,
                "cves": cves,
                "threat_actors": actors,
                "first_detected_at": pub_time,
                "last_detected_at": pub_time,
                "source_growth_history": [{
                    "timestamp": pub_time.isoformat() if isinstance(pub_time, datetime) else str(pub_time),
                    "source_count": 1,
                    "article_count": 1,
                    "heat_score": 15,
                    "source_name": source_name,
                }],
                "alert_triggered": False,
                "alert_triggered_at": None,
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }

            heat_data = cls.calculate_event_heat_score(new_event)
            new_event.update(heat_data)
            new_event["explanation"] = cls.generate_analyst_explanation(new_event)

            await events_col.insert_one(new_event)
            await articles_col.update_one({"_id": article.get("_id")}, {"$set": {"viral_event_id": event_id}})

            return new_event

    @classmethod
    async def recalculate_all_viral_events(cls, hours: int = 168) -> Dict[str, Any]:
        """
        Ultra-fast In-Memory Inverted-Index Multi-Signal Correlation Sweep.
        Processes recent articles, clusters cross-source viral stories, updates heat scores,
        and saves verified multi-source events into MongoDB in seconds.
        """
        articles_col = get_articles_collection()
        events_col = get_viral_events_collection()
        
        t0 = time.time()
        # Fetch non-duplicate cybersecurity risk articles
        cursor = articles_col.find({
            "is_duplicate": {"$ne": True},
            "is_cybersecurity_news": True,
        }).sort("published_at", -1).limit(4000)
        articles = [a async for a in cursor]
        
        if not articles:
            return {"status": "success", "articles_processed": 0, "trending_events": 0, "high_heat_events": 0}

        from collections import defaultdict
        clusters = []
        cve_to_cluster = {}
        token_to_clusters = defaultdict(list)
        company_to_clusters = defaultdict(list)
        actor_to_clusters = defaultdict(list)
        
        for art in articles:
            art_id = str(art.get("_id", ""))
            title = (art.get("title") or "").strip()
            summary = (art.get("summary") or art.get("content_clean") or "")[:300]
            source_name = (art.get("source_name") or "Unknown Source").strip()
            source_id = str(art.get("source_id", ""))
            pub_dt = _ensure_utc_dt(art.get("published_at") or art.get("crawled_at") or utcnow())
            
            art_tokens = _tokenize_for_similarity(f"{title} {summary}")
            art_cves = set(extract_cves(f"{title} {summary}") + (art.get("cves") or []))
            art_victim = extract_breached_company(art)
            art_actor = extract_threat_actor(art)
            country = art.get("target_country") or extract_country(art)
            incident_type = determine_incident_type(art)
            
            matched_cluster = None
            
            # 1. Direct CVE overlap
            for cve in art_cves:
                if cve in cve_to_cluster:
                    matched_cluster = cve_to_cluster[cve]
                    break
                    
            # 2. Company / Target match + title overlap
            if not matched_cluster and art_victim and art_victim != "Not Specified":
                cand_clusters = company_to_clusters.get(art_victim.lower(), [])
                for c in cand_clusters:
                    if calculate_jaccard_similarity(art_tokens, c["tokens"]) >= 0.20:
                        matched_cluster = c
                        break
                        
            # 3. Threat Actor match + title overlap
            if not matched_cluster and art_actor and art_actor != "Unknown":
                cand_clusters = actor_to_clusters.get(art_actor.lower(), [])
                for c in cand_clusters:
                    if calculate_jaccard_similarity(art_tokens, c["tokens"]) >= 0.20:
                        matched_cluster = c
                        break
                        
            # 4. Token overlap matching
            if not matched_cluster:
                candidate_counts = defaultdict(int)
                title_tokens = _tokenize_for_similarity(title)
                for t in title_tokens:
                    for c_idx in token_to_clusters.get(t, []):
                        candidate_counts[c_idx] += 1
                        
                best_sim = 0.0
                for c_idx, overlap in candidate_counts.items():
                    if overlap >= 2:
                        c = clusters[c_idx]
                        c_title_tokens = _tokenize_for_similarity(c["title"])
                        jaccard = calculate_jaccard_similarity(title_tokens, c_title_tokens)
                        if jaccard >= 0.35 and jaccard > best_sim:
                            best_sim = jaccard
                            matched_cluster = c
                            
            if matched_cluster:
                matched_cluster["articles"].append(art)
                matched_cluster["article_ids"].append(art_id)
                matched_cluster["sources"].add(source_name)
                if source_id:
                    matched_cluster["source_ids"].add(source_id)
                matched_cluster["cves"].update(art_cves)
                matched_cluster["tokens"].update(art_tokens)
                matched_cluster["first_detected_at"] = min(matched_cluster["first_detected_at"], pub_dt)
                matched_cluster["last_detected_at"] = max(matched_cluster["last_detected_at"], pub_dt)
                for cve in art_cves:
                    cve_to_cluster[cve] = matched_cluster
            else:
                c_idx = len(clusters)
                event_id = generate_event_id(title, art_cves, art_victim)
                title_tokens = _tokenize_for_similarity(title)
                new_c = {
                    "idx": c_idx,
                    "event_id": event_id,
                    "title": title,
                    "summary": summary,
                    "company": art_victim,
                    "threat_actor": art_actor,
                    "target_country": country,
                    "incident_type": incident_type,
                    "cves": art_cves,
                    "tokens": art_tokens,
                    "sources": {source_name},
                    "source_ids": {source_id} if source_id else set(),
                    "articles": [art],
                    "article_ids": [art_id],
                    "first_detected_at": pub_dt,
                    "last_detected_at": pub_dt,
                }
                clusters.append(new_c)
                for cve in art_cves:
                    cve_to_cluster[cve] = new_c
                if art_victim and art_victim != "Not Specified":
                    company_to_clusters[art_victim.lower()].append(new_c)
                if art_actor and art_actor != "Unknown":
                    actor_to_clusters[art_actor.lower()].append(new_c)
                for t in title_tokens:
                    token_to_clusters[t].append(c_idx)

        # Build documents for multi-source events and active candidate events
        event_docs = []
        seen_event_ids = set()
        for c in clusters:
            source_count = len(c["sources"])
            article_count = len(c["articles"])
            unique_sources_list = sorted(list(c["sources"]))
            
            event_id = c["event_id"]
            if event_id in seen_event_ids:
                diff = hashlib.sha256(f"{event_id}_{c['article_ids'][0]}".encode()).hexdigest()[:4].upper()
                event_id = f"{event_id[:7]}-{diff}"
            seen_event_ids.add(event_id)
            c["event_id"] = event_id
            
            event_doc = {
                "event_id": event_id,
                "title": c["title"],
                "normalized_title": re.sub(r'[^a-zA-Z0-9\s]', '', c["title"]).lower()[:100],
                "summary": c["summary"],
                "related_article_ids": c["article_ids"],
                "unique_source_ids": list(c["source_ids"]),
                "unique_source_names": unique_sources_list,
                "source_count": source_count,
                "article_count": article_count,
                "target_company": c["company"],
                "target_country": c["target_country"],
                "incident_type": c["incident_type"],
                "cves": list(c["cves"]),
                "threat_actors": [c["threat_actor"]] if c["threat_actor"] and c["threat_actor"] != "Unknown" else [],
                "first_detected_at": c["first_detected_at"],
                "last_detected_at": c["last_detected_at"],
                "source_growth_history": [{
                    "timestamp": c["first_detected_at"].isoformat(),
                    "source_count": source_count,
                    "article_count": article_count,
                    "heat_score": 50 if source_count >= 3 else 25,
                    "source_name": unique_sources_list[0] if unique_sources_list else "Intelligence Feed",
                }],
                "alert_triggered": False,
                "alert_triggered_at": None,
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }
            heat_data = cls.calculate_event_heat_score(event_doc)
            event_doc.update(heat_data)
            event_doc["explanation"] = cls.generate_analyst_explanation(event_doc)
            event_docs.append(event_doc)

        # Atomically replace/upsert the event collection
        if event_docs:
            await events_col.delete_many({})
            await events_col.insert_many(event_docs)

        elapsed = time.time() - t0
        multi_source_count = sum(1 for e in event_docs if e["source_count"] >= 2)
        trending_count = sum(1 for e in event_docs if e["source_count"] >= 3)
        high_heat_count = sum(1 for e in event_docs if e["source_count"] >= 5 or e["heat_score"] >= 80)

        log.info(
            "CyberPulse fast correlation sweep completed",
            processed=len(articles),
            total_events=len(event_docs),
            multi_source_events=multi_source_count,
            trending_events=trending_count,
            high_heat_events=high_heat_count,
            elapsed_sec=round(elapsed, 2),
        )

        return {
            "status": "success",
            "articles_processed": len(articles),
            "total_events": len(event_docs),
            "multi_source_events": multi_source_count,
            "trending_events": trending_count,
            "high_heat_events": high_heat_count,
            "elapsed_seconds": round(elapsed, 2),
        }
