"""
Automated Test Suite for Anti-Hallucination Controls.

Tests:
1. Record count anti-hallucination (no inference from 'thousands', 'millions', or 'GB/TB')
2. Threat actor anti-hallucination ('Unattributed' fallback, no inference from country/malware)
3. CVE anti-hallucination (strict regex verification, non-hallucination)
"""
import pytest
from app.services.teams_service import (
    extract_claimed_records,
    extract_threat_actor
)
from app.services.ai_enrichment import AIEnrichmentService


def test_record_count_anti_hallucination():
    """
    Ensure vague terms ('thousands of records', 'millions of users', '50 GB of data')
    are never inferred as integer numbers. Only explicit integer counts are accepted.
    """
    # 1. Vague 'thousands' -> None
    vague_data = {
        "claimed_records_count": "thousands of records",
        "company_response": None
    }
    AIEnrichmentService._validate_and_sanitize(vague_data)
    assert vague_data["claimed_records_count"] is None

    # 2. File size / Data volume '50 GB' -> None (not record volume)
    size_data = {
        "claimed_records_count": "50 GB of data",
        "company_response": None
    }
    AIEnrichmentService._validate_and_sanitize(size_data)
    assert size_data["claimed_records_count"] is None

    # 3. Explicit integer string '2,500,000' -> 2500000
    explicit_data = {
        "claimed_records_count": "2,500,000",
        "company_response": None
    }
    AIEnrichmentService._validate_and_sanitize(explicit_data)
    assert explicit_data["claimed_records_count"] == 2500000

    # 4. Explicit integer int 150000 -> 150000
    int_data = {
        "claimed_records_count": 150000,
        "company_response": None
    }
    AIEnrichmentService._validate_and_sanitize(int_data)
    assert int_data["claimed_records_count"] == 150000


def test_threat_actor_anti_hallucination():
    """
    Ensure threat actors are not hallucinated.
    If no explicit actor is identified, must return 'Unattributed'.
    """
    # 1. Generic attacker terms -> Unattributed
    generic_cases = [
        {"threat_actor": "hackers"},
        {"threat_actor": "cybercriminals"},
        {"threat_actor": "ransomware group"},
        {"threat_actor": "unknown"},
        {"threat_actor": "none"},
        {"threat_actor": ""},
        {"threat_actor": None},
    ]
    for case in generic_cases:
        AIEnrichmentService._validate_and_sanitize(case)
        assert case["threat_actor"] == "Unattributed"

    # 2. Verified named group -> Preserved
    named_case = {"threat_actor": "LockBit 3.0"}
    AIEnrichmentService._validate_and_sanitize(named_case)
    assert named_case["threat_actor"] == "LockBit 3.0"

    # 3. Text extractor on unattributed text -> Unknown
    art_no_actor = {
        "title": "Corporate database exfiltrated by unknown attackers",
        "summary": "Attackers accessed internal databases without identifying their group.",
        "content_clean": "No group has claimed responsibility."
    }
    actor = extract_threat_actor(art_no_actor)
    assert actor == "Unknown"


def test_cve_anti_hallucination():
    """
    Ensure CVE array only contains valid CVE-YYYY-NNNNN identifiers present in source text.
    """
    sample_data = {
        "cves": [
            "CVE-2026-12345",     # Valid format
            "CVE-2026-9999999",   # Valid format
            "CVE-INVALID",        # Invalid -> must be dropped
            "12345",              # Invalid -> must be dropped
            "VULN-2026-01",       # Invalid -> must be dropped
            "cve-2025-4433",      # Valid lowercase -> capitalized
        ],
        "company_response": None
    }
    AIEnrichmentService._validate_and_sanitize(sample_data)
    assert "CVE-2026-12345" in sample_data["cves"]
    assert "CVE-2026-9999999" in sample_data["cves"]
    assert "CVE-2025-4433" in sample_data["cves"]
    assert "CVE-INVALID" not in sample_data["cves"]
    assert "12345" not in sample_data["cves"]
    assert "VULN-2026-01" not in sample_data["cves"]
    assert len(sample_data["cves"]) == 3
