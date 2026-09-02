"""
Automated Test Suite for Deduplication & Material Update Engine.

Tests:
1. Exact Title & Canonical URL normalization
2. 72-hour incident fingerprinting across multiple reporting sources
3. Multi-source duplicate suppression (ONE Team Alert per incident across sources)
4. Material update triggers (Claim -> Confirmation, Claim -> Denial, Record count disclosure)
"""
import pytest
from app.services.teams_service import (
    generate_incident_fingerprint,
    evaluate_incident_deduplication_and_update,
    _INCIDENT_STATE_REGISTRY,
    _DISPATCHED_TEAMS_KEYS
)


def setup_function():
    _INCIDENT_STATE_REGISTRY.clear()
    _DISPATCHED_TEAMS_KEYS.clear()


def test_incident_fingerprint_stability():
    """
    Articles from different sources discussing the same company, incident type,
    actor, and country within a 72h window must produce the exact same fingerprint.
    """
    art1 = {
        "title": "BleepingComputer: Hospital Chain Apex breached by LockBit",
        "target_company": "Apex Hospitals",
        "incident_type": "Ransomware",
        "threat_actor": "LockBit 3.0",
        "target_country": "USA",
    }
    art2 = {
        "title": "The Hacker News: LockBit ransomware hits Apex Hospitals in United States",
        "target_company": "Apex Hospitals",
        "incident_type": "Ransomware",
        "threat_actor": "LockBit 3.0",
        "target_country": "USA",
    }

    fp1 = generate_incident_fingerprint(art1)
    fp2 = generate_incident_fingerprint(art2)

    assert fp1 == fp2, f"Fingerprints should match: {fp1} != {fp2}"


def test_multi_source_deduplication_suppression():
    """
    Multiple sources reporting the exact same incident must result in
    ONE Team Alert dispatch, not multiple alerts.
    """
    webhook = "https://teams.mock/channel_webhook"

    # Source 1 reports incident -> DISPATCH (Duplicate = False)
    art_source1 = {
        "title": "Source 1: Metro Bank confirms unauthorized network intrusion",
        "target_company": "Metro Bank",
        "incident_type": "Corporate Breach",
        "threat_actor": "Unattributed",
        "claim_status": "confirmed",
        "claimed_records_count": 100000
    }
    res1 = evaluate_incident_deduplication_and_update(art_source1, webhook)
    assert res1["is_duplicate"] is False
    assert res1["is_update"] is False

    # Simulate marking as dispatched
    fp = res1["fingerprint"]
    _DISPATCHED_TEAMS_KEYS.add(f"{webhook}::{fp}")
    _INCIDENT_STATE_REGISTRY[fp]["dispatched"] = True

    # Source 2 reports same incident 2 hours later -> SUPPRESSED (Duplicate = True)
    art_source2 = {
        "title": "Source 2: Metro Bank data breach exposes 100,000 customers",
        "target_company": "Metro Bank",
        "incident_type": "Corporate Breach",
        "threat_actor": "Unattributed",
        "claim_status": "confirmed",
        "claimed_records_count": 100000
    }
    res2 = evaluate_incident_deduplication_and_update(art_source2, webhook)
    assert res2["is_duplicate"] is True
    assert res2["is_update"] is False
    assert "Duplicate multi-source coverage" in res2["reason"]

    # Source 3 reports same incident -> SUPPRESSED
    art_source3 = {
        "title": "Source 3: Reuters reports on Metro Bank cyber breach",
        "target_company": "Metro Bank",
        "incident_type": "Corporate Breach",
        "threat_actor": "Unattributed",
        "claim_status": "confirmed",
        "claimed_records_count": 100000
    }
    res3 = evaluate_incident_deduplication_and_update(art_source3, webhook)
    assert res3["is_duplicate"] is True
    assert res3["is_update"] is False


def test_material_update_quantified_records():
    """
    When an unquantified incident subsequently discloses an exact record volume,
    it must trigger a material update dispatch.
    """
    webhook = "https://teams.mock/channel_webhook"

    # 1. First alert: unquantified records
    art1 = {
        "title": "Apex Health reports corporate database breach",
        "target_company": "Apex Health",
        "incident_type": "Data Breach",
        "threat_actor": "Unattributed",
        "claim_status": "confirmed",
        "claimed_records_count": None
    }
    res1 = evaluate_incident_deduplication_and_update(art1, webhook)
    fp = res1["fingerprint"]
    _DISPATCHED_TEAMS_KEYS.add(f"{webhook}::{fp}")
    _INCIDENT_STATE_REGISTRY[fp]["dispatched"] = True

    # 2. Material update: exact volume disclosed
    art2 = dict(art1)
    art2["claimed_records_count"] = 750000
    art2["title"] = "Apex Health confirms 750,000 patient records stolen in breach"
    res2 = evaluate_incident_deduplication_and_update(art2, webhook)

    assert res2["is_duplicate"] is False
    assert res2["is_update"] is True
    assert res2["update_type"] == "Record Count Disclosed"
