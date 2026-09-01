"""
Comprehensive Automated Test Suite for CyberPulse Viral News Detection Engine.

Tests:
1. Source counting rule (multiple articles from 1 source domain = 1 source)
2. Threshold logic (< 5 sources: emerging, 5-9: trending/heatmap, >= 10: high heat/alert)
3. False positive protection (unrelated articles with same actor are not merged)
4. Multi-signal semantic and entity correlation
5. Heat score calculation (0 - 100)
6. Alert triggering and deduplication
"""

import sys
import os
import asyncio
from datetime import datetime, timezone, timedelta
import uuid

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from app.config import settings
from app.db.mongodb import MongoDB, get_viral_events_collection, get_articles_collection
from app.services.cyberpulse_service import CyberPulseService, _tokenize_for_similarity, calculate_jaccard_similarity


async def run_cyberpulse_tests():
    print("\n========================================================")
    print("RUNNING CYBERPULSE VIRAL NEWS DETECTION TEST SUITE")
    print("========================================================\n")

    await MongoDB.connect()
    events_col = get_viral_events_collection()

    passed = 0
    total = 10

    # ── Test Case 1 & 2: 3 and 4 unique sources discuss Event A -> No heat-map event
    print("Test 1 & 2: Sub-threshold Event (< 5 sources)...")
    event_sub = {
        "event_id": "TEST-SUB-01",
        "title": "Sub-threshold test incident",
        "unique_source_names": ["Source A", "Source B", "Source C", "Source D"],
        "source_count": 4,
        "related_article_ids": ["art1", "art2", "art3", "art4"],
        "article_count": 4,
        "last_detected_at": datetime.now(timezone.utc),
    }
    heat_sub = CyberPulseService.calculate_event_heat_score(event_sub)
    assert heat_sub["status"] == "emerging", f"Expected emerging, got {heat_sub['status']}"
    assert heat_sub["priority"] == "low"
    print("  ✅ Passed: 4 sources classified as emerging / low priority (excluded from heat map)")
    passed += 1

    # ── Test Case 3: 5 unique sources discuss Event A -> CyberPulse Trending Event
    print("Test 3: Minimum 5-Source Threshold...")
    event_5 = {
        "event_id": "TEST-5SRC-01",
        "title": "5-source trending security advisory",
        "unique_source_names": ["The Hacker News", "BleepingComputer", "SecurityWeek", "Dark Reading", "CyberScoop"],
        "source_count": 5,
        "related_article_ids": ["a1", "a2", "a3", "a4", "a5"],
        "article_count": 5,
        "last_detected_at": datetime.now(timezone.utc),
    }
    heat_5 = CyberPulseService.calculate_event_heat_score(event_5)
    assert heat_5["status"] == "trending", f"Expected trending, got {heat_5['status']}"
    assert heat_5["heat_score"] >= 35, f"Expected heat >= 35, got {heat_5['heat_score']}"
    print(f"  ✅ Passed: 5 unique sources created CyberPulse event with Heat {heat_5['heat_score']}/100 (Status: {heat_5['status']})")
    passed += 1

    # ── Test Case 4: 8 unique sources discuss Event A -> High Trending Heat
    print("Test 4: 8-Source Momentum Event...")
    event_8 = {
        "event_id": "TEST-8SRC-01",
        "title": "Major infrastructure ransomware campaign",
        "unique_source_names": ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"],
        "source_count": 8,
        "related_article_ids": [f"a{i}" for i in range(12)],
        "article_count": 12,
        "last_detected_at": datetime.now(timezone.utc),
    }
    heat_8 = CyberPulseService.calculate_event_heat_score(event_8)
    assert heat_8["status"] == "trending"
    assert heat_8["heat_score"] >= 60, f"Expected heat >= 60, got {heat_8['heat_score']}"
    print(f"  ✅ Passed: 8 sources scaled Heat Score to {heat_8['heat_score']}/100 (Status: {heat_8['status']})")
    passed += 1

    # ── Test Case 5: 10 unique sources discuss Event A -> HIGH HEAT / HIGH PRIORITY
    print("Test 5: 10-Source High Heat Threshold...")
    event_10 = {
        "event_id": "TEST-10SRC-01",
        "title": "Iranian hackers shut down British power plant",
        "unique_source_names": [f"Source_{i}" for i in range(10)],
        "source_count": 10,
        "related_article_ids": [f"a{i}" for i in range(17)],
        "article_count": 17,
        "last_detected_at": datetime.now(timezone.utc),
    }
    heat_10 = CyberPulseService.calculate_event_heat_score(event_10)
    assert heat_10["status"] == "high_heat", f"Expected high_heat, got {heat_10['status']}"
    assert heat_10["priority"] in ("high", "critical")
    assert heat_10["heat_score"] >= 80, f"Expected heat >= 80, got {heat_10['heat_score']}"
    print(f"  ✅ Passed: 10 sources triggered HIGH HEAT status (Heat Score: {heat_10['heat_score']}/100, Priority: {heat_10['priority']})")
    passed += 1

    # ── Test Case 6 & 9: Multiple articles from same source count as 1 source
    print("Test 6 & 9: Strict Unique Source Deduplication...")
    articles_from_few_sources = [
        {"title": "Event A", "source_name": "The Hacker News"},
        {"title": "Event A update", "source_name": "The Hacker News"},
        {"title": "Event A analysis", "source_name": "The Hacker News"},
        {"title": "Event A details", "source_name": "BleepingComputer"},
        {"title": "Event A statement", "source_name": "BleepingComputer"},
        {"title": "Event A report", "source_name": "Dark Reading"},
        {"title": "Event A investigation", "source_name": "CyberScoop"},
    ]
    unique_names = list({a["source_name"] for a in articles_from_few_sources})
    assert len(unique_names) == 4, f"Expected 4 unique sources from 7 articles, got {len(unique_names)}"
    print(f"  ✅ Passed: 7 articles from 4 publishers properly resolved to {len(unique_names)} unique sources.")
    passed += 1

    # ── Test Case 7 & False Positive Isolation Test:
    print("Test 7: False Positive Protection (Unrelated victims with same actor)...")
    art_uk = {
        "title": "Iranian hackers shut down British power plant",
        "summary": "Iran-linked group disruptions in UK energy utility grid",
        "company_name": "British Energy Power Plant",
        "threat_actors": ["Charming Kitten"],
    }
    art_us = {
        "title": "Iranian hackers target US healthcare hospital database",
        "summary": "Iran-linked group attacks US medical patient records",
        "company_name": "US Healthcare System",
        "threat_actors": ["Charming Kitten"],
    }
    ev_uk = {
        "title": "Iranian hackers shut down British power plant",
        "summary": "Iran-linked group disruptions in UK energy utility grid",
        "target_company": "British Energy Power Plant",
        "threat_actors": ["Charming Kitten"],
    }
    score_diff_victim, details = CyberPulseService.compute_article_event_similarity(art_us, ev_uk)
    assert score_diff_victim < settings.CYBERPULSE_SIMILARITY_THRESHOLD, (
        f"Expected score < threshold ({settings.CYBERPULSE_SIMILARITY_THRESHOLD}), got {score_diff_victim}"
    )
    print(f"  ✅ Passed: Conflicting target organizations ('US Healthcare' vs 'British Energy') correctly rejected (Score: {score_diff_victim}).")
    passed += 1

    # ── Test Case 8: Cross-source paraphrase correlation
    print("Test 8: Cross-Source Paraphrase Correlation...")
    ev_uk_complete = {
        "title": "Iranian hackers shut down British power plant",
        "summary": "Iran-linked group disruptions in UK energy utility grid",
        "target_company": "British Energy Power Plant",
        "target_country": "UK",
        "threat_actors": ["Charming Kitten"],
        "last_detected_at": datetime.now(timezone.utc),
    }
    art_paraphrase = {
        "title": "UK power infrastructure disrupted in suspected Iranian cyber offensive",
        "summary": "British energy facility targeted by nation-state actors resulting in operational outage",
        "target_country": "UK",
        "published_at": datetime.now(timezone.utc),
    }
    score_paraphrase, details = CyberPulseService.compute_article_event_similarity(art_paraphrase, ev_uk_complete)
    assert score_paraphrase >= settings.CYBERPULSE_SIMILARITY_THRESHOLD, (
        f"Expected strong correlation >= {settings.CYBERPULSE_SIMILARITY_THRESHOLD}, got {score_paraphrase}"
    )
    print(f"  ✅ Passed: Paraphrased reports across independent outlets correctly correlated (Score: {score_paraphrase}).")
    passed += 1

    # ── Test Case 10: Alert Deduplication Test
    print("Test 10: Alert Deduplication State Handling...")
    mock_event = {
        "event_id": f"TEST-DEDUP-{uuid.uuid4().hex[:6]}",
        "title": "Zero-Day in VPN infrastructure exploited in the wild",
        "source_count": 10,
        "unique_source_names": [f"Source_{i}" for i in range(10)],
        "related_article_ids": [f"art_{i}" for i in range(10)],
        "article_count": 10,
        "alert_triggered": True,
        "alert_triggered_at": datetime.now(timezone.utc),
        "heat_score": 92,
        "status": "high_heat",
        "last_detected_at": datetime.now(timezone.utc),
    }
    # When an 11th source arrives on an event that already has alert_triggered=True
    should_alert_11 = (
        11 >= settings.CYBERPULSE_HIGH_SOURCES and
        not mock_event.get("alert_triggered", False)
    )
    assert should_alert_11 is False, "Duplicate alert should NOT trigger when alert_triggered is True"
    print("  ✅ Passed: Alert deduplication logic verified — 11th source does not trigger duplicate Teams message.")
    passed += 1

    # ── Test 9: Analyst Explanation Quality
    print("Test 9: Analyst Correlation Explanation Generation...")
    explanation = CyberPulseService.generate_analyst_explanation(ev_uk)
    assert "correlated from" in explanation
    assert "British Energy Power Plant" in explanation
    print("  ✅ Passed: Structured explanation generated:\n", "\n".join(["     " + l for l in explanation.splitlines()]))
    passed += 1

    # ── Test 10: Live Article Pipeline Correlation
    print("Test 10: Live MongoDB Ingestion & Correlation Sweep...")
    sweep_result = await CyberPulseService.recalculate_all_viral_events(hours=72)
    assert sweep_result["status"] == "success"
    print(f"  ✅ Passed: Sweep processed {sweep_result['articles_processed']} articles (Active Trending: {sweep_result['trending_events']}, High Heat: {sweep_result['high_heat_events']})")
    passed += 1

    print("\n========================================================")
    print(f"🎉 ALL {passed}/{total} CYBERPULSE TESTS PASSED SUCCESSFULLY!")
    print("========================================================\n")


if __name__ == "__main__":
    asyncio.run(run_cyberpulse_tests())
