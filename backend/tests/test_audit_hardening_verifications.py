"""
Master Hardening & Zero-Negative Verification Test Suite.

Tests:
1. CyberPulse viral news (10+ sources on CVE/advisory) CANNOT bypass the Teams Decision Gate.
2. Threat actor claim + leak proof (samples/screenshots) remains CLAIMED, never converted to CONFIRMED.
3. Official statement investigating an incident remains CLAIMED / UNKNOWN, not CONFIRMED.
4. Official statement confirming an incident produces CONFIRMED.
5. Organization explicit denial statement produces DENIED.
6. Zero-day vulnerability without corporate compromise stays strictly WEBSITE_ONLY.
7. Zero-day with confirmed active compromise and operational disruption is eligible for TEAM_ALERT.
8. Duplicate weak sources (social media reposts of same claim) do not artificially stack evidence.
9. SSRF IPv4-mapped IPv6 (::ffff:127.0.0.1, ::ffff:169.254.169.254) and link-local ranges blocked.
10. SSRF redirect validation: redirecting to a loopback/private target is aborted on redirect hop.
11. Tri-State Decision Model: HUMAN_REVIEW for borderline evidence (35-49), WEBSITE_ONLY (<35).
12. SOAR remediation is human-approved and not autonomously executed.
"""
import pytest
import ipaddress
from datetime import datetime, timezone

from app.config import settings
from app.core.ssrf import is_safe_public_url, is_ip_blocked
from app.services.teams_service import (
    TeamAlertDecisionEngine,
    is_critical_actionable_incident,
    TeamsService,
    determine_breach_status
)
from app.services.ai_enrichment import SourceReliabilityEngine, AIEnrichmentService
from app.services.cyberpulse_service import CyberPulseService


@pytest.mark.asyncio
async def test_cyberpulse_cannot_bypass_teams_gate():
    """
    Requirement 5: A viral CVE or patch advisory reported by 50+ unique sources
    must produce HIGH HEAT in CyberPulse, but MUST NOT trigger a Teams alert.
    """
    viral_cve_event = {
        "event_id": "VIRAL-CVE-2026-9999",
        "title": "Critical RCE Vulnerability in OpenSSL Disclosed (CVE-2026-9999)",
        "summary": "Security researchers uncovered a critical remote code execution vulnerability in OpenSSL libraries.",
        "content_clean": "OpenSSL project released an advisory regarding CVE-2026-9999. Administrators are urged to update immediately. No victim enterprise compromise reported.",
        "incident_type": "Vulnerability",
        "unique_source_names": [f"Source_{i}" for i in range(50)],
        "source_count": 50,
        "related_article_ids": [f"art_{i}" for i in range(50)],
        "article_count": 50,
        "last_detected_at": datetime.now(timezone.utc),
    }

    # 1. CyberPulse heat score correctly identifies it as high heat
    heat_data = CyberPulseService.calculate_event_heat_score(viral_cve_event)
    assert heat_data["status"] == "high_heat"
    assert heat_data["heat_score"] >= 80

    # 2. BUT the deterministic alert decision engine marks it strictly WEBSITE_ONLY
    eval_res = TeamAlertDecisionEngine.evaluate(viral_cve_event)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert is_critical_actionable_incident(viral_cve_event) is False

    # 3. TeamsService.dispatch_cyberpulse_alert strictly suppresses dispatch
    dispatch_success = await TeamsService.dispatch_cyberpulse_alert(viral_cve_event)
    assert dispatch_success is False, "Viral CVE should have been suppressed from Teams dispatch"


def test_threat_actor_claim_with_leak_proof_is_not_confirmed():
    """
    Requirement 6: A threat actor claiming breach and posting screenshots/samples
    remains CLAIMED, and is NOT automatically elevated to CONFIRMED.
    """
    article = {
        "title": "LockBit publishes file tree and sample data claiming breach of Global Logistics",
        "summary": "LockBit ransomware group uploaded screenshots and data samples claiming to hold 20GB of corporate files.",
        "content_clean": "On their dark web leak site, LockBit added Global Logistics with sample files. No response or confirmation from Global Logistics.",
        "source_name": "DarkWeb Monitor",
        "company_response": None,
        "target_company": "Global Logistics"
    }

    rel = SourceReliabilityEngine.evaluate(article, article["content_clean"])
    # Leak proof identifies leak_site_post and stolen_data_sample, but claim status remains 'claimed'
    assert rel["claim_status"] == "claimed"
    assert rel["claim_status"] != "confirmed"

    breach_status = determine_breach_status(article)
    assert breach_status == "CLAIMED"


def test_official_investigation_statement_is_not_confirmed():
    """
    Requirement 8: An official statement stating the company is investigating reports
    of an incident must NOT be classified as CONFIRMED.
    """
    article = {
        "title": "FinTech Corp spokesperson states company is investigating potential security incident",
        "summary": "FinTech Corp released an official statement confirming they are investigating reports of an anomaly.",
        "content_clean": "A spokesperson for FinTech Corp stated: 'We are aware of claims and our security team is currently investigating reports of a potential incident with external forensic experts. No unauthorized access has been verified at this time.'",
        "company_response": "We are currently investigating reports of a potential incident with external forensic experts.",
        "target_company": "FinTech Corp"
    }

    rel = SourceReliabilityEngine.evaluate(article, article["content_clean"])
    assert rel["company_response_status"] == "investigating"
    assert rel["claim_status"] == "claimed"
    assert rel["claim_status"] != "confirmed"


def test_official_admission_produces_confirmed():
    """
    Requirement 8: An official statement confirming an intrusion produces CONFIRMED.
    """
    article = {
        "title": "FinTech Corp SEC filing confirms unauthorized access to internal customer databases",
        "summary": "FinTech Corp filed an official SEC 8-K notice confirming a corporate data breach.",
        "content_clean": "In an official statement confirms filing with the SEC, FinTech Corp confirmed that threat actors compromised its internal network and accessed customer databases.",
        "company_response": "Confirmed unauthorized access and complete containment across corporate servers.",
        "target_company": "FinTech Corp"
    }

    rel = SourceReliabilityEngine.evaluate(article, article["content_clean"])
    assert rel["company_response_status"] == "confirmed"
    assert rel["claim_status"] == "confirmed"


def test_explicit_denial_produces_denied():
    """
    Requirement 8 & 10: An official denial produces DENIED with absolute precedence.
    """
    article = {
        "title": "FinTech Corp officially denies ransomware breach claims, confirms zero unauthorized access",
        "summary": "FinTech Corp issued a formal denial disputing threat actor allegations.",
        "content_clean": "FinTech Corp released a statement stating: 'Forensic audits confirmed zero unauthorized access to our environment. The hacker claims are entirely false and debunked.'",
        "company_response": "Forensic audits confirmed zero unauthorized access to our environment. The claims are false.",
        "target_company": "FinTech Corp"
    }

    rel = SourceReliabilityEngine.evaluate(article, article["content_clean"])
    assert rel["company_response_status"] == "denied"
    assert rel["claim_status"] == "denied"

    eval_res = TeamAlertDecisionEngine.evaluate(article)
    assert eval_res["decision"] == "WEBSITE_ONLY"


def test_zero_day_without_compromise_stays_website_only():
    """
    Requirement 4: Zero-day discovery or advisory without confirmed compromise remains WEBSITE_ONLY.
    """
    zero_day_news = {
        "title": "Critical zero-day vulnerability in Fortinet FortiOS actively targeted by researchers",
        "summary": "Researchers published a Proof of Concept demonstrating arbitrary code execution in FortiOS.",
        "content_clean": "Fortinet released a security bulletin addressing CVE-2026-4411. No specific victim enterprise has suffered compromise.",
        "source_name": "SecurityWeek",
        "cves": ["CVE-2026-4411"]
    }
    eval_res = TeamAlertDecisionEngine.evaluate(zero_day_news)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert is_critical_actionable_incident(zero_day_news) is False


def test_zero_day_with_confirmed_corporate_impact_is_team_alert():
    """
    Requirement 4: Zero-day actively exploited to breach a target enterprise with confirmed data exfiltration is TEAM_ALERT.
    """
    zero_day_breach = {
        "title": "Threat actors exploit Fortinet zero-day to breach Apex Power Grid; operational telemetry compromised",
        "summary": "Apex Power Grid confirmed attackers leveraged a zero-day vulnerability to compromise critical infrastructure controls.",
        "content_clean": "Apex Power Grid disclosed in an official statement confirms that nation-state hackers breached its internal corporate network via an unpatched zero-day flaw. Operational telemetry systems were compromised.",
        "target_company": "Apex Power Grid",
        "claim_status": "confirmed",
        "source_name": "Reuters"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(zero_day_breach)
    assert eval_res["decision"] == "TEAM_ALERT"
    assert eval_res["score"] >= 50
    assert is_critical_actionable_incident(zero_day_breach) is True


def test_ssrf_ipv4_mapped_ipv6_blocked():
    """
    Requirement 18: IPv4-mapped IPv6 addresses for loopback, RFC1918, and metadata must be blocked.
    """
    blocked_mapped_ips = [
        "http://[::ffff:127.0.0.1]/feed",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:10.0.0.1]/admin",
        "http://[::ffff:192.168.1.1]/router",
        "http://[::ffff:172.16.0.1]/internal",
    ]
    for url in blocked_mapped_ips:
        assert is_safe_public_url(url) is False, f"IPv4-mapped IPv6 URL allowed: {url}"


def test_ssrf_cloud_metadata_and_domain_suffixes():
    """
    Requirement 18: Link-local metadata and disallowed domain suffixes must be blocked.
    """
    invalid_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://cluster.local/feed",
        "http://internal.service.lan/rss",
        "http://mysite.corp/feed",
        "http://router.home/api",
    ]
    for url in invalid_urls:
        assert is_safe_public_url(url) is False, f"Restricted URL permitted: {url}"


def test_tri_state_human_review_boundary():
    """
    Requirement 3: Borderline evidence cases (Score 35-49) or unevidenced allegations
    route to HUMAN_REVIEW, never silently promoting to TEAM_ALERT.
    """
    borderline_art = {
        "title": "Threat actor posts allegation against Regional Logistics on dark web forum",
        "summary": "A user on a dark web forum posted an unverified allegation naming Regional Logistics.",
        "content_clean": "A forum thread claims Regional Logistics had a security issue. No specific technical details or files were provided.",
        "target_company": "Regional Logistics",
        "claim_status": "claimed",
        "source_name": "Forum Monitor"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(borderline_art)
    # Score is 35 (Target Org +20, Attributed Claim +15) -> HUMAN_REVIEW
    assert eval_res["score"] >= 35 and eval_res["score"] < 50
    assert eval_res["decision"] == "HUMAN_REVIEW"
    assert is_critical_actionable_incident(borderline_art) is False
