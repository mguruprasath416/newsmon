"""
Automated Test Suite for Claim Lifecycle Handling (Claimed vs Confirmed vs Denied).

Tests:
1. Absolute precedence of explicit denials over threat actor claims
2. Threat actor allegations remain 'claimed' and are not presented as fact
3. Confirmed status requires official statement, SEC filing, or authority confirmation
4. Transition from 'claimed' to 'confirmed' constitutes a material update
5. Transition from 'claimed' to 'denied' constitutes a material update
6. Preservation of denial provenance
"""
import pytest
from app.services.teams_service import (
    determine_breach_status,
    TeamAlertDecisionEngine,
    evaluate_incident_deduplication_and_update,
    _INCIDENT_STATE_REGISTRY,
    _DISPATCHED_TEAMS_KEYS
)
from app.services.ai_enrichment import SourceReliabilityEngine, AIEnrichmentService


def setup_function():
    _INCIDENT_STATE_REGISTRY.clear()
    _DISPATCHED_TEAMS_KEYS.clear()


def test_explicit_denial_precedence():
    """
    Explicit company denial must override any threat actor claim.
    """
    article = {
        "title": "FinTech Corp denies ransomware group claims of data breach",
        "summary": "FinTech Corp released a statement confirming that forensic review found no evidence of intrusion.",
        "content_clean": "LockBit claimed on its leak site to have breached FinTech Corp. The company responded: 'We investigated and confirmed zero unauthorized access. The claim is entirely false.'",
        "company_response": "We investigated and confirmed zero unauthorized access. The claim is entirely false.",
        "claim_status": "claimed"  # passed by initial tagger
    }

    # SourceReliabilityEngine check
    rel = SourceReliabilityEngine.evaluate(article, article["content_clean"])
    assert rel["company_response_status"] == "denied"
    assert rel["claim_status"] == "denied"

    # AIEnrichment heuristic / validation enforcer check
    data_dict = {"company_response": article["company_response"], "claim_status": "claimed"}
    AIEnrichmentService._validate_and_sanitize(data_dict)
    assert data_dict["claim_status"] == "denied"

    # Decision Engine check: Denied incident must NOT fire a Team Alert
    eval_res = TeamAlertDecisionEngine.evaluate(article)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert "denial" in eval_res["reason"].lower() or "denied" in eval_res["reason"].lower()


def test_actor_claim_remains_claimed():
    """
    A threat actor claim alone (e.g. 'LockBit claims X was breached')
    must remain 'claimed' and not be converted to 'confirmed'.
    """
    article = {
        "title": "LockBit claims breach of Zenith Healthcare, threatens data leak",
        "summary": "LockBit ransomware group added Zenith Healthcare to its leak site.",
        "content_clean": "The threat actor claims to hold 50GB of files. No statement has been made by Zenith Healthcare.",
        "target_company": "Zenith Healthcare",
        "threat_actor": "LockBit",
    }
    status = determine_breach_status(article)
    assert status == "CLAIMED"


def test_official_disclosure_is_confirmed():
    """
    Official corporate statement or regulatory disclosure establishes 'confirmed' status.
    """
    article = {
        "title": "Zenith Healthcare SEC 8-K filing confirms corporate data breach",
        "summary": "Zenith Healthcare officially disclosed unauthorized access to patient databases.",
        "content_clean": "In an official SEC filing, Zenith Healthcare confirmed that hackers breached internal servers and stole patient records.",
        "target_company": "Zenith Healthcare",
    }
    status = determine_breach_status(article)
    assert status == "CONFIRMED"


def test_material_update_claimed_to_confirmed():
    """
    When an incident progresses from CLAIMED -> CONFIRMED, the system must recognize it
    as a material update and trigger a refreshed dispatch.
    """
    # 1. First report: Claimed
    art_v1 = {
        "title": "Threat actor claims breach of Global Logistics network",
        "target_company": "Global Logistics",
        "incident_type": "Data Breach",
        "threat_actor": "RansomHub",
        "claim_status": "claimed",
        "severity": "high",
        "claimed_records_count": None
    }
    res1 = evaluate_incident_deduplication_and_update(art_v1, webhook_url="https://teams.mock/webhook")
    assert res1["is_duplicate"] is False
    assert res1["is_update"] is False

    # Simulate dispatch
    fp = res1["fingerprint"]
    _DISPATCHED_TEAMS_KEYS.add(f"https://teams.mock/webhook::{fp}")
    _INCIDENT_STATE_REGISTRY[fp]["dispatched"] = True

    # 2. Second report: Same incident from different source, still claimed -> Duplicate suppressed
    art_v2 = dict(art_v1)
    art_v2["title"] = "Global Logistics alleged hack discussed on cyber forums"
    res2 = evaluate_incident_deduplication_and_update(art_v2, webhook_url="https://teams.mock/webhook")
    assert res2["is_duplicate"] is True
    assert res2["is_update"] is False

    # 3. Third report: Company releases official statement -> CLAIM CONFIRMED (Material Update!)
    art_v3 = dict(art_v1)
    art_v3["title"] = "Global Logistics confirms unauthorized database breach in official press release"
    art_v3["claim_status"] = "confirmed"
    res3 = evaluate_incident_deduplication_and_update(art_v3, webhook_url="https://teams.mock/webhook")
    assert res3["is_duplicate"] is False
    assert res3["is_update"] is True
    assert res3["update_type"] == "Claim Confirmed"


def test_material_update_claimed_to_denied():
    """
    When a previously claimed incident is officially DENIED by the organization,
    it must trigger a material update so analysts/channels receive the denial update.
    """
    art_v1 = {
        "title": "Hacker claims theft of customer data from Prime Retail",
        "target_company": "Prime Retail",
        "incident_type": "Data Theft",
        "threat_actor": "Unattributed",
        "claim_status": "claimed",
        "severity": "high",
    }
    res1 = evaluate_incident_deduplication_and_update(art_v1, webhook_url="https://teams.mock/webhook")
    fp = res1["fingerprint"]
    _DISPATCHED_TEAMS_KEYS.add(f"https://teams.mock/webhook::{fp}")
    _INCIDENT_STATE_REGISTRY[fp]["dispatched"] = True

    # Denial statement arrives
    art_v2 = dict(art_v1)
    art_v2["claim_status"] = "denied"
    art_v2["title"] = "Prime Retail releases statement denying all allegations of security breach"
    res2 = evaluate_incident_deduplication_and_update(art_v2, webhook_url="https://teams.mock/webhook")
    assert res2["is_duplicate"] is False
    assert res2["is_update"] is True
    assert res2["update_type"] == "Incident Denied"
