"""
Central Cybersecurity News Keyword Classification & Threat Intelligence Engine.

Classifies articles against the structured keyword dictionary in `files/Keywords/`:
- Attacks: Ransomware, DDoS, Phishing, Supply Chain, Cyber Espionage
- Malware: Trojan, RAT, Infostealer, Spyware, Botnet
- Vulnerabilities: CVE, Zero-Day, RCE, Privilege Escalation
- Targets: Government, Banking, Healthcare, Energy, Telecom, Critical Infrastructure
- Threat Actors: APT, Ransomware Groups, Hacktivists, Cybercriminals
- Geography: India, USA, Europe, China, Russia, Middle East

Provides multi-category classification, IOC extraction, and cyber risk scoring.
"""

import os
import re
import unicodedata
from typing import Dict, List, Any, Optional, Set
import structlog
from app.services.ioc_extractor import IOCExtractor

log = structlog.get_logger()

DEFAULT_KEYWORDS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "files", "Keywords")
)
if not os.path.exists(DEFAULT_KEYWORDS_DIR):
    DEFAULT_KEYWORDS_DIR = r"d:\Feed\files\Keywords"

_ioc_extractor = IOCExtractor()


class KeywordClassifier:
    """
    High-performance, regex-compiled hierarchical cybersecurity keyword classifier.
    Uses unified regex compilation for sub-millisecond multi-category matching.
    """
    _instance = None
    _dictionary: Dict[str, Dict[str, List[str]]] = {}
    _compiled_union_patterns: Dict[str, Dict[str, re.Pattern]] = {}
    _is_loaded = False

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.load_dictionary()
        return cls._instance

    @classmethod
    def load_dictionary(cls, base_dir: Optional[str] = None) -> None:
        """Scan and compile all keyword files in the Keywords directory into high-speed union patterns."""
        target_dir = base_dir or DEFAULT_KEYWORDS_DIR
        cls._dictionary = {}
        cls._compiled_union_patterns = {}

        if not os.path.exists(target_dir):
            log.warning("Keywords directory not found", path=target_dir)
            return

        for category_name in os.listdir(target_dir):
            cat_path = os.path.join(target_dir, category_name)
            if not os.path.isdir(cat_path):
                continue

            normalized_cat = category_name.strip()
            cls._dictionary[normalized_cat] = {}
            cls._compiled_union_patterns[normalized_cat] = {}

            for fname in os.listdir(cat_path):
                if not fname.endswith(".txt"):
                    continue

                subcat_name = os.path.splitext(fname)[0].strip()
                file_path = os.path.join(cat_path, fname)

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    log.error("Failed to read keyword file", file=file_path, error=str(e))
                    lines = []

                # Deduplicate and sort by length descending
                unique_keywords = sorted(list(set(lines)), key=len, reverse=True)
                cls._dictionary[normalized_cat][subcat_name] = unique_keywords

                if unique_keywords:
                    escaped_list = []
                    for kw in unique_keywords:
                        escaped = re.escape(kw).replace(r"\ ", r"[\s\-_]+")
                        escaped_list.append(escaped)

                    # Build high-speed single regex pattern for this subcategory
                    union_pattern = rf'(?<![a-zA-Z0-9_-])(?:{"|".join(escaped_list)})(?![a-zA-Z0-9_-])'
                    try:
                        pat = re.compile(union_pattern, re.IGNORECASE)
                        cls._compiled_union_patterns[normalized_cat][subcat_name] = pat
                    except Exception as re_err:
                        log.warning("Could not compile union pattern", subcat=subcat_name, error=str(re_err))

        cls._is_loaded = True
        total_keywords = sum(
            len(kws) for cat in cls._dictionary.values() for kws in cat.values()
        )
        log.info(
            "Cybersecurity Keywords Dictionary Loaded (Union Engine)",
            categories=list(cls._dictionary.keys()),
            total_keywords=total_keywords,
        )

    @classmethod
    def normalize_text(cls, text: str) -> str:
        """Normalize unicode, whitespace, and punctuation for consistent matching."""
        if not text:
            return ""
        text = unicodedata.normalize("NFKD", text)
        text = re.sub(r"\s+", " ", text)
        return text

    @classmethod
    def classify_article(cls, article: Dict[str, Any], extract_full_iocs: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive multi-category classification on an article.
        Searches title, summary, content_clean, and tags.
        """
        if not cls._is_loaded:
            cls.load_dictionary()

        title = article.get("title") or ""
        summary = article.get("summary") or ""
        content = article.get("content_clean") or article.get("content") or ""
        tags = " ".join([str(t) for t in (article.get("tags") or [])])

        search_text = cls.normalize_text(f"{title}\n{summary}\n{content[:4000]}\n{tags}")
        title_norm = cls.normalize_text(title)

        matched_by_category: Dict[str, List[str]] = {
            "Attacks": [],
            "Malware": [],
            "Vulnerabilities": [],
            "Targets": [],
            "Threat Actors": [],
            "Geography": [],
        }
        detailed_matches: Dict[str, Dict[str, List[str]]] = {}
        all_matched_terms: Set[str] = set()

        attack_weight = 0
        vuln_weight = 0
        malware_weight = 0
        target_weight = 0
        actor_weight = 0

        for cat_name, subcats in cls._compiled_union_patterns.items():
            detailed_matches[cat_name] = {}
            for subcat_name, union_pat in subcats.items():
                found_terms = union_pat.findall(search_text)
                if found_terms:
                    # Clean and deduplicate matches
                    unique_found = sorted(list(set(str(t).strip() for t in found_terms if str(t).strip())), key=str.lower)
                    if cat_name not in matched_by_category:
                        matched_by_category[cat_name] = []
                    matched_by_category[cat_name].append(subcat_name)
                    detailed_matches[cat_name][subcat_name] = unique_found
                    all_matched_terms.update(unique_found)

                    # Check title match for high priority flag
                    title_matches = union_pat.findall(title_norm)
                    if title_matches:
                        for tm in title_matches:
                            all_matched_terms.add(f"{tm.strip()} (Title)")

                    # Weight calculations
                    if cat_name == "Attacks":
                        attack_weight += 25
                    elif cat_name == "Malware":
                        malware_weight += 20
                    elif cat_name == "Vulnerabilities":
                        vuln_weight += 25
                    elif cat_name == "Threat Actors":
                        actor_weight += 20
                    elif cat_name == "Targets":
                        target_weight += 10

        # Extract IOCs or reuse existing
        extracted_iocs = {}
        cves_found = []
        if extract_full_iocs:
            if "iocs" in article and isinstance(article["iocs"], dict) and article["iocs"]:
                extracted_iocs = article["iocs"]
            else:
                iocs_obj = _ioc_extractor.extract(f"{title} {summary} {content[:4000]}")
                extracted_iocs = iocs_obj.to_dict() if hasattr(iocs_obj, "to_dict") else {}
            cves_found = extracted_iocs.get("cves") or []
        else:
            # Fast regex for CVEs only
            cves_found = list(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", search_text, re.IGNORECASE)))
            if cves_found:
                extracted_iocs["cves"] = cves_found

        if cves_found and "CVE" not in matched_by_category["Vulnerabilities"]:
            matched_by_category["Vulnerabilities"].append("CVE")
            vuln_weight += 20

        # Check if genuine cybersecurity news
        is_cyber = bool(
            matched_by_category["Attacks"]
            or matched_by_category["Malware"]
            or matched_by_category["Vulnerabilities"]
            or matched_by_category["Threat Actors"]
            or cves_found
            or extracted_iocs.get("ipv4")
            or extracted_iocs.get("sha256")
            or (matched_by_category["Targets"] and (attack_weight > 0 or vuln_weight > 0 or malware_weight > 0))
        )

        # Calculate dynamic Cyber Risk Score (0 - 100)
        base_score = 0
        if is_cyber:
            base_score = min(100, attack_weight + vuln_weight + malware_weight + actor_weight + target_weight)
            if "Ransomware" in matched_by_category["Attacks"] or "Zero-Day" in matched_by_category["Vulnerabilities"]:
                base_score = max(85, base_score)
            if "Critical Infrastructure" in matched_by_category["Targets"] or "Energy" in matched_by_category["Targets"]:
                base_score = max(80, base_score)
            if "Government" in matched_by_category["Targets"] or "Banking" in matched_by_category["Targets"] or "Healthcare" in matched_by_category["Targets"]:
                base_score = max(75, base_score)

        if base_score >= 80:
            severity = "Critical"
        elif base_score >= 60:
            severity = "High"
        elif base_score >= 40:
            severity = "Medium"
        elif base_score > 0:
            severity = "Low"
        else:
            severity = "Informational"

        primary_threat = "General Cyber Advisory"
        if matched_by_category["Attacks"]:
            primary_threat = matched_by_category["Attacks"][0]
        elif matched_by_category["Malware"]:
            primary_threat = f"Malware ({matched_by_category['Malware'][0]})"
        elif matched_by_category["Vulnerabilities"]:
            primary_threat = f"Vulnerability ({matched_by_category['Vulnerabilities'][0]})"
        elif matched_by_category["Threat Actors"]:
            primary_threat = f"Threat Actor ({matched_by_category['Threat Actors'][0]})"

        primary_target = matched_by_category["Targets"][0] if matched_by_category["Targets"] else "General Enterprise"
        primary_geo = matched_by_category["Geography"][0] if matched_by_category["Geography"] else "Global"

        # Accurate Claim Status determination
        title_lower = title.lower()
        combined_lower = f"{title_lower} {summary.lower()} {content[:2000].lower()}"
        claim_status = "verified"
        if any(k in combined_lower for k in ["denies breach", "denied hack", "denies leak", "no evidence of breach", "unaffected by", "false claim"]):
            claim_status = "denied"
        elif any(k in combined_lower for k in ["claims to have", "claimed breach", "claims responsibility", "alleged breach", "threat actor claims", "unverified claim", "unverified breach", "claims 1tb", "claims 100gb", "dark web forum post"]):
            claim_status = "claimed"
        elif cves_found or any(k in combined_lower for k in ["cert-in", "cisa", "nciipc", "security advisory", "vulnerability advisory", "patch tuesday", "security update", "zero-day flaw"]):
            claim_status = "advisory"
        elif any(k in combined_lower for k in ["confirms breach", "confirmed hack", "discloses data breach", "police investigation", "files fir", "under investigation", "notifies customers", "admits breach"]):
            claim_status = "confirmed"

        return {
            "is_cybersecurity_news": is_cyber,
            "cyber_risk_score": base_score,
            "severity": severity,
            "claim_status": claim_status,
            "primary_threat": primary_threat,
            "primary_target": primary_target,
            "primary_geography": primary_geo,
            "attacks": sorted(list(set(matched_by_category["Attacks"]))),
            "malware": sorted(list(set(matched_by_category["Malware"]))),
            "vulnerabilities": sorted(list(set(matched_by_category["Vulnerabilities"]))),
            "targets": sorted(list(set(matched_by_category["Targets"]))),
            "threat_actors": sorted(list(set(matched_by_category["Threat Actors"]))),
            "geography": sorted(list(set(matched_by_category["Geography"]))),
            "matched_keywords": detailed_matches,
            "all_matched_terms": sorted(list(all_matched_terms)),
            "extracted_iocs": extracted_iocs,
            "cves": cves_found,
        }


# Convenience singleton helper
classifier = KeywordClassifier.get_instance()
