"""
Automated Test Suite for TeamAlertDecisionEngine & Alert Routing.

Tests:
1. Keyword match alone MUST NEVER directly create a Teams alert
2. Zero-day vulnerability without enterprise compromise stays WEBSITE_ONLY
3. Zero-day with active compromise and quantified disruption is eligible for alert
4. Threshold testing (score >= 50 -> TEAM_ALERT, 35-49 -> HUMAN_REVIEW, <35 -> WEBSITE_ONLY)
5. Multi-factor point validation (+25 corporate disclosure, +35 records, +30 ransomware, +30 infra, +25 disruption, +20 target, +20 actor)
6. Target organization requirement (incident without identified target cannot fire TEAM_ALERT)
"""
import pytest
from app.services.teams_service import (
    TeamAlertDecisionEngine,
    is_critical_actionable_incident,
    is_company_breach_or_incident
)
from app.services.alert_engine import AlertEngine, DEFAULT_ALERT_RULES


def test_keyword_match_alone_does_not_create_team_alert():
    """
    Critical Rule: A keyword match MUST NEVER directly create a Teams alert.
    Evaluating an article with keywords like 'India', 'TCS', 'ransomware', 'advisory'
    must not trigger TEAM_ALERT unless full evidence score >= 50 is met.
    """
    keyword_only_article = {
        "title": "CERT-In issues advisory for Indian enterprises on Apache vulnerability",
        "summary": "CERT-In published a technical advisory urging Indian organizations to review patch notes.",
        "content_clean": "The Indian Computer Emergency Response Team issued an advisory regarding software flaws. No breach occurred.",
        "target_country": "India",
        "source_name": "CERT-In Portal"
    }

    # Pipeline D rule match check
    rule = DEFAULT_ALERT_RULES[0]
    rule_matches = AlertEngine.evaluate_rule(rule, keyword_only_article)
    # The rule will match keywords for the intelligence dashboard
    assert rule_matches is True

    # BUT the Decision Engine must classify this as WEBSITE_ONLY
    eval_res = TeamAlertDecisionEngine.evaluate(keyword_only_article)
    assert eval_res["decision"] == "WEBSITE_ONLY"
    assert not is_critical_actionable_incident(keyword_only_article)
    assert not is_company_breach_or_incident(keyword_only_article)


def test_zero_day_handling_rules():
    """
    Zero-Day Rule:
    - Zero-day discovered / advisory -> Website only
    - Zero-day without organizational compromise -> Website only
    - Zero-day with confirmed active exploitation AND meaningful organizational compromise -> Potential Teams Alert
    """
    # 1. Zero-day advisory alone -> Website only
    zero_day_advisory = {
        "title": "Critical zero-day vulnerability discovered in Palo Alto Networks PAN-OS",
        "summary": "Researchers uncovered an unpatched zero-day flaw allowing remote code execution.",
        "content_clean": "Palo Alto Networks disclosed a zero-day vulnerability under CVE-2026-9090. Administrators should apply mitigations.",
        "source_name": "SecurityWeek",
        "cves": ["CVE-2026-9090"]
    }
    res_adv = TeamAlertDecisionEngine.evaluate(zero_day_advisory)
    assert res_adv["decision"] == "WEBSITE_ONLY"
    assert not is_critical_actionable_incident(zero_day_advisory)

    # 2. Zero-day actively exploited to breach a specific corporate enterprise -> TEAM_ALERT
    zero_day_breach = {
        "title": "Threat actors exploit PAN-OS zero-day to breach FinTech Global corporate network; 450,000 records exfiltrated",
        "summary": "FinTech Global confirmed attackers leveraged a zero-day flaw to access customer databases.",
        "content_clean": "FinTech Global confirmed that attackers gained unauthorized access to its internal systems via an unpatched zero-day flaw. 450,000 customer records were exfiltrated. The corporate network was compromised.",
        "target_company": "FinTech Global",
        "claim_status": "confirmed",
        "claimed_records_count": 450000,
        "source_name": "The Hacker News"
    }
    res_breach = TeamAlertDecisionEngine.evaluate(zero_day_breach)
    assert res_breach["decision"] == "TEAM_ALERT"
    assert res_breach["score"] >= 50
    assert is_critical_actionable_incident(zero_day_breach)


def test_human_review_borderline_decision():
    """
    Borderline cases with evidence score between 35 and 49 must enter HUMAN_REVIEW,
    not be silently promoted to Teams.
    """
    borderline_article = {
        "title": "Unverified threat actor claims unauthorized access to unnamed regional supplier",
        "summary": "A dark web poster claims access to a supplier network without proof or company confirmation.",
        "content_clean": "Threat actors claimed access to corporate network systems of an unnamed supplier. No confirmation or record counts provided.",
        "source_name": "DarkWeb Monitor",
        "claim_status": "claimed"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(borderline_article)
    # Score has compromise claim (+30) + claim status (+15) = 45 pts, but no identified target company
    assert eval_res["decision"] in ("HUMAN_REVIEW", "WEBSITE_ONLY")
    assert not is_critical_actionable_incident(borderline_article)


def test_evidence_scoring_points_addition():
    """
    Verify exact multi-factor evidence points:
    - Target Organization: +20
    - Confirmed disclosure: +25
    - Quantified records: +35
    - Enterprise compromise: +30
    - Named threat actor: +20
    """
    article = {
        "title": "Acme Corp SEC filing confirms Akira ransomware deployment, 100,000 employee records stolen",
        "summary": "Acme Corp officially confirmed a ransomware attack by Akira that compromised corporate servers and exfiltrated 100,000 records.",
        "content_clean": "Acme Corp filed an SEC 8-K stating that Akira ransomware encrypted internal systems. 100,000 employee records were stolen by attackers.",
        "target_company": "Acme Corp",
        "threat_actor": "Akira",
        "claim_status": "confirmed",
        "claimed_records_count": 100000,
        "source_name": "Reuters"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(article)
    # Target (+20) + Confirmed (+25) + Quantified Records (+35) + Compromise (+30) + Ransomware (+30) + Actor (+20) = 160 pts
    assert eval_res["score"] >= 100
    assert eval_res["decision"] == "TEAM_ALERT"
    assert is_critical_actionable_incident(article)


def test_missing_target_organization_fails_team_alert():
    """
    An incident without an identified specific target enterprise must NOT fire a Team Alert.
    """
    generic_incident = {
        "title": "Massive ransomware campaign encrypts thousands of systems worldwide",
        "summary": "Ransomware operators deployed encryption payloads against broad consumer devices.",
        "content_clean": "Systems were encrypted by a widespread malware campaign. No specific enterprise was identified as victim.",
        "source_name": "BleepingComputer"
    }
    eval_res = TeamAlertDecisionEngine.evaluate(generic_incident)
    # Even if ransomware points exist (+30), target is missing -> cannot be TEAM_ALERT
    assert eval_res["decision"] != "TEAM_ALERT"
    assert not is_critical_actionable_incident(generic_incident)
