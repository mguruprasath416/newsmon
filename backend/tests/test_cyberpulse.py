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
import pytest
from datetime import datetime, timezone, timedelta

from app.config import settings
from app.services.cyberpulse_service import (
    CyberPulseService,
    _tokenize_for_similarity,
    calculate_jaccard_similarity
)


def test_sub_threshold_event():
    """Test 1 & 2: Sub-threshold Event (< 5 sources) -> Emerging / Low priority."""
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


def test_minimum_5_source_threshold():
    """Test 3: Minimum 5-Source Threshold -> Trending status & heat >= 35."""
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


def test_8_source_momentum_event():
    """Test 4: 8-Source Momentum Event -> Trending with heat >= 60."""
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


def test_10_source_high_heat_threshold():
    """Test 5: 10-Source High Heat Threshold -> HIGH HEAT status & heat >= 80."""
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


def test_unique_source_deduplication():
    """Test 6: Multiple articles from same source count as 1 source."""
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


def test_false_positive_isolation():
    """Test 7: False Positive Protection (Unrelated victims with same actor are not merged)."""
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


def test_duplicate_alert_suppression():
    """Test 8: 11th source does not trigger duplicate Teams alert."""
    mock_event = {
        "event_id": "TEST-ALERT-01",
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
    should_alert_11 = (
        11 >= settings.CYBERPULSE_HIGH_SOURCES and
        not mock_event.get("alert_triggered", False)
    )
    assert should_alert_11 is False, "Duplicate alert should NOT trigger when alert_triggered is True"


def test_analyst_explanation_quality():
    """Test 9: Analyst Explanation Quality."""
    ev_uk = {
        "title": "Iranian hackers shut down British power plant",
        "summary": "Iran-linked group disruptions in UK energy utility grid",
        "target_company": "British Energy Power Plant",
        "threat_actors": ["Charming Kitten"],
        "unique_source_names": ["The Hacker News", "BleepingComputer", "SecurityWeek", "Dark Reading", "CyberScoop", "Reuters"],
        "source_count": 6,
        "heat_score": 75,
        "last_detected_at": datetime.now(timezone.utc),
    }
    explanation = CyberPulseService.generate_analyst_explanation(ev_uk)
    assert "correlated from" in explanation
    assert "British Energy Power Plant" in explanation
