"""
Pipeline D — Alert Engine & Rule Evaluation Service

Evaluates non-duplicate articles (is_duplicate == False) against structured CTI alert rules.
Supports keyword matching, regex patterns, field matching, target_country conditions, and Microsoft Teams dispatches.
"""
import re
import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import structlog

from app.config import settings
from app.services.teams_service import extract_country, TeamsService

log = structlog.get_logger()

# Curated CTI Terms for Keyword Intelligence Dashboard (50+ Terms)
PRESET_CTI_TERMS = [
    # Critical Targets & Enterprises
    {"term": "TCS", "category": "Critical Targets", "priority": "high"},
    {"term": "HCLTech", "category": "Critical Targets", "priority": "high"},
    {"term": "Infosys", "category": "Critical Targets", "priority": "high"},
    {"term": "Wipro", "category": "Critical Targets", "priority": "high"},
    {"term": "Physics Wallah", "category": "Critical Targets", "priority": "high"},
    {"term": "Razorpay", "category": "Critical Targets", "priority": "high"},
    {"term": "Paytm", "category": "Critical Targets", "priority": "high"},
    {"term": "CERT-In", "category": "Critical Targets", "priority": "high"},
    {"term": "ISRO", "category": "Critical Targets", "priority": "high"},
    {"term": "State Bank of India", "category": "Critical Targets", "priority": "high"},
    {"term": "AIIMS", "category": "Critical Targets", "priority": "high"},

    # Malware & Extortion Operations
    {"term": "LockBit", "category": "Malware & Extortion", "priority": "high"},
    {"term": "DireWolf", "category": "Malware & Extortion", "priority": "high"},
    {"term": "Akira", "category": "Malware & Extortion", "priority": "high"},
    {"term": "Rhysida", "category": "Malware & Extortion", "priority": "high"},
    {"term": "BlackCat", "category": "Malware & Extortion", "priority": "high"},
    {"term": "RansomHub", "category": "Malware & Extortion", "priority": "high"},
    {"term": "LummaStealer", "category": "Malware & Extortion", "priority": "medium"},
    {"term": "RedLine", "category": "Malware & Extortion", "priority": "medium"},
    {"term": "DarkGate", "category": "Malware & Extortion", "priority": "medium"},

    # Zero-Days & Critical Vulnerabilities
    {"term": "Zero-Day", "category": "Vulnerabilities", "priority": "high"},
    {"term": "Kernel RCE", "category": "Vulnerabilities", "priority": "high"},
    {"term": "CVE-2026", "category": "Vulnerabilities", "priority": "high"},
    {"term": "Authentication Bypass", "category": "Vulnerabilities", "priority": "high"},
    {"term": "Privilege Escalation", "category": "Vulnerabilities", "priority": "medium"},
    {"term": "Unpatched RCE", "category": "Vulnerabilities", "priority": "high"},
    {"term": "CISA KEV", "category": "Vulnerabilities", "priority": "medium"},

    # Threat Actors & Espionage
    {"term": "TheHatman", "category": "Threat Actors", "priority": "high"},
    {"term": "Volt Typhoon", "category": "Threat Actors", "priority": "high"},
    {"term": "APT41", "category": "Threat Actors", "priority": "high"},
    {"term": "Lazarus Group", "category": "Threat Actors", "priority": "high"},
    {"term": "TA577", "category": "Threat Actors", "priority": "medium"},

    # Cloud & Application Security
    {"term": "Azure Tenant Dump", "category": "Cloud & Infrastructure", "priority": "high"},
    {"term": "Firebase Misconfiguration", "category": "Cloud & Infrastructure", "priority": "medium"},
    {"term": "AWS S3 Exfiltration", "category": "Cloud & Infrastructure", "priority": "high"},
    {"term": "Artifactory RCE", "category": "Cloud & Infrastructure", "priority": "high"},
    {"term": "SharePoint RCE", "category": "Cloud & Infrastructure", "priority": "high"},
]

# Comprehensive Indian Alert Detection Keywords & Regex Patterns
INDIAN_KEYWORDS = [
    "India", "Indian", "CERT-In", "NIC", "NCIIPC", "Aadhaar", "UIDAI", "CoWIN", "Digilocker",
    "TCS", "HCLTech", "HCL", "Infosys", "Wipro", "Tech Mahindra", "LTIMindtree", "Zoho", "Freshworks",
    "Physics Wallah", "BYJU", "Unacademy", "Vedantu", "UpGrad", "Razorpay", "Paytm", "PhonePe", "BharatPe",
    "CRED", "Swiggy", "Zomato", "Zepto", "Blinkit", "Ola", "Flipkart", "Meesho", "Myntra",
    "State Bank of India", "SBI", "ICICI", "HDFC", "Axis Bank", "PNB", "BOB", "Kotak", "SEBI", "RBI", "NPCI", "UPI",
    "AIIMS", "ISRO", "DRDO", "Reliance", "Jio", "Tata", "Adani", "Mahindra", "Bajaj", "Airtel", "BSNL",
    "Delhi", "Mumbai", "Bengaluru", "Bangalore", "Hyderabad", "Chennai", "Kolkata", "Pune", "Noida", "Gurugram", "Gurgaon"
]

INDIAN_REGEX_PATTERNS = [
    r"\b(India|Indian|CERT-In)\b",
    r"\b(TCS|HCLTech|Infosys|Wipro|SBI|AIIMS|ISRO|Physics\s*Wallah|Razorpay|Paytm|Jio|Airtel)\b",
    r"\b(breach|leak|hack|compromise|ransomware|azure|dump|exfiltrate|cve)\b.*\b(India|Indian|Delhi|Mumbai|Bengaluru|Bangalore|Hyderabad|Chennai|Kolkata|Pune|Noida|Gurugram)\b",
    r"\b(India|Indian)\b.*\b(breach|leak|hack|compromise|ransomware|cve|vulnerability|advisory)\b",
]

# Pre-configured Alert Rules (Pipeline D)
DEFAULT_ALERT_RULES = [
    {
        "id": "rule_india_breaches",
        "name": "India-based data breaches and advisories",
        "enabled": True,
        "keywords": INDIAN_KEYWORDS,
        "regex_patterns": INDIAN_REGEX_PATTERNS,
        "match_fields": ["title", "summary", "content_clean", "target_country", "source_name"],
        "notify": {
            "teams": True,
        },
        "teams_channel": "cyber-pulse",
        "teams_webhook_url": getattr(settings, "TEAMS_WEBHOOK_URL_CYBER_PULSE", "") or getattr(settings, "TEAMS_WEBHOOK_URL", ""),
    }
]


class AlertEngine:
    """Pipeline D Alert Engine for structured rules, live hits matching, and real-time dispatches."""

    @classmethod
    def evaluate_rule(cls, rule: Dict[str, Any], article: Dict[str, Any]) -> bool:
        """
        Evaluate a single article against an alert rule (supports both user query rules and system structured rules).
        Only non-duplicate articles can match.
        """
        if article.get("is_duplicate") is True:
            return False

        if not rule.get("is_active", rule.get("enabled", True)):
            return False

        # Severity filter check
        min_sev = (rule.get("min_severity") or "all").lower()
        art_sev = (article.get("severity") or "informational").lower()
        if min_sev == "critical" and art_sev != "critical":
            return False
        elif min_sev == "high" and art_sev not in ("critical", "high"):
            return False
        elif min_sev == "medium" and art_sev not in ("critical", "high", "medium"):
            return False

        # Source category filter check
        req_source_cat = (rule.get("sources") or "automatic").lower()
        if req_source_cat not in ("automatic", "all", ""):
            art_source_cat = (article.get("source_category") or "news").lower()
            if req_source_cat not in art_source_cat:
                return False

        # Build full searchable text
        title = (article.get("title") or "").lower()
        summary = (article.get("summary") or "").lower()
        content = (article.get("content_clean") or "").lower()
        tags = [t.lower() for t in (article.get("tags") or [])]
        actors = [a.lower() for a in (article.get("threat_actors") or [])]
        cves = [c.lower() for c in (article.get("cves") or [])]
        country = (article.get("target_country") or extract_country(article)).lower()
        source_name = (article.get("source_name") or "").lower()

        search_text = f"{title} {summary} {content} {country} {source_name} {' '.join(tags)} {' '.join(actors)} {' '.join(cves)}"

        # 1. Check user 'query' (e.g. "LockBit", "TCS", "Ransomware")
        user_query = (rule.get("query") or "").strip().lower()
        if user_query:
            if user_query in search_text:
                return True
            if len(user_query) <= 4:
                pattern = r'\b' + re.escape(user_query) + r'\b'
                if re.search(pattern, search_text, re.IGNORECASE):
                    return True
            if not rule.get("keywords") and not rule.get("regex_patterns"):
                return False

        # 2. Check structured 'keywords' array
        keywords = rule.get("keywords", [])
        if keywords:
            if any(kw.lower() in search_text for kw in keywords if kw.strip()):
                return True

        # 3. Check regex_patterns
        regex_patterns = rule.get("regex_patterns", [])
        for pattern in regex_patterns:
            try:
                if re.search(pattern, search_text, re.IGNORECASE):
                    return True
            except Exception:
                pass

        return False

    @classmethod
    def match_article_against_rule(cls, rule: Dict[str, Any], article: Dict[str, Any]) -> bool:
        """Alias for backward compatibility."""
        return cls.evaluate_rule(rule, article)

    @classmethod
    def process_rules_for_articles(cls, rules: List[Dict[str, Any]], articles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processes a list of user alert rules against articles and returns matched hits.
        """
        hits = []
        seen_article_rule_pairs = set()

        for art in articles:
            if art.get("is_duplicate") is True:
                continue
            art_id = str(art.get("_id", art.get("id", "")))

            for rule in rules:
                rule_id = str(rule.get("_id", rule.get("id", "")))
                pair_key = f"{art_id}:{rule_id}"
                if pair_key in seen_article_rule_pairs:
                    continue

                if cls.evaluate_rule(rule, art):
                    seen_article_rule_pairs.add(pair_key)
                    matched_term = rule.get("query") or rule.get("name") or "Keyword Alert"
                    hit = {
                        "id": art_id,
                        "title": art.get("title", ""),
                        "summary": art.get("summary", ""),
                        "url": art.get("url", ""),
                        "source_name": art.get("source_name", "Security Feed"),
                        "source_slug": art.get("source_slug", ""),
                        "severity": art.get("severity", "informational"),
                        "published_at": art.get("published_at").isoformat() if isinstance(art.get("published_at"), datetime) else art.get("published_at"),
                        "target_country": art.get("target_country") or extract_country(art),
                        "cves": art.get("cves", []),
                        "threat_actors": art.get("threat_actors", []),
                        "tags": art.get("tags", []),
                        "rule_id": rule_id,
                        "rule_query": matched_term,
                        "matched_term": matched_term,
                        "matched_at": datetime.now(timezone.utc).isoformat(),
                    }
                    hits.append(hit)

        return hits

    @classmethod
    async def process_article_alerts(cls, article: Dict[str, Any], custom_rules: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Main entry point for Pipeline D (Alert Engine).
        Evaluates article against rules and dispatches notifications.
        """
        if article.get("is_duplicate") is True:
            return []

        rules = custom_rules or DEFAULT_ALERT_RULES
        matched_results = []

        for rule in rules:
            if cls.evaluate_rule(rule, article):
                notify = rule.get("notify", {})
                dispatch_status = {}

                # Teams Dispatch
                if notify.get("teams"):
                    dispatch_status["teams"] = await cls._send_teams_alert(rule, article)

                matched_results.append({
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "dispatch_status": dispatch_status,
                })

        return matched_results

    @staticmethod
    async def _send_teams_alert(rule: Dict[str, Any], article: Dict[str, Any]) -> bool:
        """Dispatch Microsoft Teams individual alert card."""
        webhook_url = (
            rule.get("teams_webhook_url") or
            getattr(settings, "TEAMS_WEBHOOK_URL_CYBER_PULSE", "") or
            getattr(settings, "TEAMS_WEBHOOK_URL", "")
        )
        if not webhook_url:
            return False
        res = await TeamsService.send_company_breaches(webhook_url, [article])
        return res.get("sent", 0) > 0
