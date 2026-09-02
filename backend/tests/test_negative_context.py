"""
Automated Test Suite for Negative-Context & False-Positive Filtering.

Tests rejection of:
1. Hypothetical language ('could allow attackers to')
2. Tabletop exercises and simulated breaches
3. Routine patch announcements and advisories
4. Generic ransomware statistics and trend reports
5. Product marketing and tool announcements
6. Technical malware reverse-engineering writeups
7. Security awareness training materials
8. Historical retrospectives
"""
import pytest
from app.services.teams_service import (
    TeamAlertDecisionEngine,
    is_critical_actionable_incident
)


def test_hypothetical_attack_rejected():
    """Hypothetical scenarios must be classified as WEBSITE_ONLY."""
    article = {
        "title": "Flaw in OAuth 2.0 implementation could allow attackers to bypass authentication",
        "summary": "Researchers discovered a theoretical flaw that might allow unauthorized session hijacking.",
        "content_clean": "A vulnerability in OAuth could allow attackers to forge tokens. No in-the-wild exploitation reported.",
        "source_name": "Dark Reading"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(article)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert not is_critical_actionable_incident(article)


def test_tabletop_simulation_rejected():
    """Tabletop simulations and phishing tests must be classified as WEBSITE_ONLY."""
    article = {
        "title": "Hospital conducts simulated breach in annual tabletop exercise",
        "summary": "Hospital security staff completed a phishing simulation and incident response drill.",
        "content_clean": "In a controlled tabletop exercise, analysts simulated a ransomware attack to test response procedures.",
        "source_name": "Healthcare IT News"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(article)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert not is_critical_actionable_incident(article)


def test_routine_patch_bulletin_rejected():
    """Standard patch bulletins without victim compromise must be classified as WEBSITE_ONLY."""
    article = {
        "title": "Adobe releases security update fixing critical flaw in Acrobat Reader",
        "summary": "Adobe released its monthly patch advisory covering memory corruption vulnerabilities.",
        "content_clean": "Adobe published security bulletin APSB26-01 addressing arbitrary code execution vulnerabilities.",
        "source_name": "Adobe Security",
        "cves": ["CVE-2026-3030"]
    }
    eval_res = TeamAlertDecisionEngine.evaluate(article)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert not is_critical_actionable_incident(article)


def test_generic_ransomware_stats_rejected():
    """Industry statistical reports must be classified as WEBSITE_ONLY."""
    article = {
        "title": "Annual report: Ransomware attacks increased by 40% across financial services sector",
        "summary": "A market research report analyzes macroeconomic trends in extortion demands.",
        "content_clean": "According to the annual threat report, ransomware extortion volume surged across global markets.",
        "source_name": "Infosecurity Magazine"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(article)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert not is_critical_actionable_incident(article)


def test_security_vendor_product_promo_rejected():
    """Vendor product marketing must be classified as WEBSITE_ONLY."""
    article = {
        "title": "SentinelOne launches new Singularity AI module to block ransomware in real time",
        "summary": "SentinelOne announced the release of its automated endpoint protection feature.",
        "content_clean": "The new security tool capability enables SOC teams to detect malicious process behavior.",
        "source_name": "TechCrunch"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(article)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert not is_critical_actionable_incident(article)


def test_malware_analysis_deepdive_rejected():
    """Technical reverse-engineering writeups must be classified as WEBSITE_ONLY."""
    article = {
        "title": "Technical deep-dive into the C2 protocol and evasion techniques of RedLine Stealer",
        "summary": "Reverse engineers analyzed the binary packing and network protocol of RedLine.",
        "content_clean": "The malware analysis report examines string decryption algorithms and command structure.",
        "source_name": "The Hacker News"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(article)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert not is_critical_actionable_incident(article)


def test_historical_retrospective_rejected():
    """Historical retrospectives must be classified as WEBSITE_ONLY."""
    article = {
        "title": "Looking back four years after the SolarWinds supply chain compromise",
        "summary": "A historical editorial reviewing changes in software supply chain security standards.",
        "content_clean": "Years after the historic compromise, security leaders reflect on governance lessons.",
        "source_name": "Dark Reading"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(article)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert not is_critical_actionable_incident(article)
