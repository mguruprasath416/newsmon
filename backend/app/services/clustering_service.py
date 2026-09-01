"""
Intelligence Article Clustering & Discovery Engine.

Dynamically clusters threat news articles into built-in and user-defined rule clusters.
"""
import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from bson import ObjectId
import structlog

from app.db.mongodb import get_articles_collection, get_cluster_rules_collection
from app.services.teams_service import determine_incident_type, extract_country

log = structlog.get_logger()

# RegEx patterns for built-in high-precision cluster matching
GCC_MIDDLE_EAST_REGEX = re.compile(
    r'\b(uae|united arab emirates|dubai|abu dhabi|sharjah|saudi|saudi arabia|ksa|riyadh|jeddah|aramco|neom|qatar|doha|kuwait|bahrain|manama|oman|muscat|israel|tel aviv|iran|tehran|iraq|baghdad|egypt|cairo|jordan|amman|lebanon|beirut|turkey|türkiye|ankara|yemen|syria|palestine|gcc|middle east|mena)\b',
    re.IGNORECASE
)

INDIAN_COMPANY_REGEX = re.compile(
    r'\b(tcs|tata consultancy|hcl|hcltech|physics wallah|wipro|infosys|tech mahindra|razorpay|paytm|airtel|jio|aadhaar|isro|state bank of india|sbi|drdo|nic\.in|gov\.in)\b|(\bindia\b|\bindian\b).{0,35}\b(company|corporate|firm|enterprise|portal|breach|leak|data|dump|hacked|stolen|employee|bank|telecom)\b',
    re.IGNORECASE
)

RANSOMWARE_REGEX = re.compile(
    r'\b(ransomware|extortion|lockbit|direwolf|esxikill|blackcat|alphv|ransomhub|hellcat|akira|play|rhysida|clop|darkside|medusa|bianlian|c2|wiper|space bears|settra)\b',
    re.IGNORECASE
)

ZERO_DAY_REGEX = re.compile(
    r'\b(zero-day|0-day|cve-\d{4}-\d+|kernel|rce|remote code execution|privilege escalation|authentication bypass|unpatched|vulnerability|exploit)\b',
    re.IGNORECASE
)

APT_REGEX = re.compile(
    r'\b(apt\d*|volt typhoon|apt41|ta577|darkgate|state-sponsored|living-off-the-land|lotl|espionage|chinafans|cert-ua|lazarus|fancy bear|cozy bear|charming kitten)\b',
    re.IGNORECASE
)

CLOUD_SAAS_REGEX = re.compile(
    r'\b(azure|firebase|aws|s3|cloud breach|artifactory|sharepoint|misconfigured|bucket|tenant exfiltration|cloud storage|gcp|opencloud)\b',
    re.IGNORECASE
)

SUPPLY_CHAIN_REGEX = re.compile(
    r'\b(supply chain|npm|pypi|malicious package|dependency|keyv|sandbox escape|package manager|open-source ecosystem|backdoor)\b',
    re.IGNORECASE
)

HEALTHCARE_INFRA_REGEX = re.compile(
    r'\b(healthcare|hospital|patient|amgen|medical|health data|hipaa|pharma|utility|water system|power grid|critical infrastructure)\b',
    re.IGNORECASE
)

CREDENTIAL_STEALER_REGEX = re.compile(
    r'\b(redline|lumma|stealer|telegram|credentials|password dump|browser cookies|infostealer|credential harvesting|login leak)\b',
    re.IGNORECASE
)

CLUSTER_DEFINITIONS = [
    {
        "slug": "gcc-middle-east",
        "title": "GCC & Middle East Threat Intelligence",
        "badge": "🌍 GCC & Middle East",
        "category": "Regional & Sovereign",
        "description": "Cyberattacks, ransomware, data breaches, state-sponsored APT campaigns, and advisories affecting GCC countries (UAE, Saudi Arabia, Qatar, Kuwait, Bahrain, Oman) and Middle East / MENA organizations.",
        "icon": "Globe",
        "priority": 1,
        "regex": GCC_MIDDLE_EAST_REGEX,
        "default_tags": ["GCC", "Middle East", "UAE", "Saudi Arabia", "Qatar", "Cyber Threat"],
    },
    {
        "slug": "indian-companies",
        "title": "Indian Company & Enterprise Breaches",
        "badge": "🇮🇳 India",
        "category": "Regional & Corporate",
        "description": "Data breach incidents, security audits, Azure dump claims, and employee/customer leaks affecting Indian enterprises, tech giants, and regional digital platforms.",
        "icon": "Building2",
        "priority": 2,
        "regex": INDIAN_COMPANY_REGEX,
        "default_tags": ["TCS", "HCLTech", "Physics Wallah", "India", "Data Leak"],
    },
    {
        "slug": "ransomware-extortion",
        "title": "Ransomware & Double Extortion Operations",
        "badge": "🚨 Ransomware",
        "category": "Malware & Threats",
        "description": "Active ransomware outbreaks, double extortion victim leaks, custom hypervisor wipers, and affiliate campaign trackers.",
        "icon": "ShieldAlert",
        "priority": 3,
        "regex": RANSOMWARE_REGEX,
        "default_tags": ["Ransomware", "LockBit", "DireWolf", "Extortion"],
    },
    {
        "slug": "zero-days-cves",
        "title": "Zero-Day & Critical Kernel Exploits",
        "badge": "⚡ Zero-Day",
        "category": "Vulnerabilities",
        "description": "Unpatched zero-day vulnerabilities, Windows/macOS kernel flaws, CISA Known Exploited entries, and remote code execution exploits.",
        "icon": "Bug",
        "priority": 4,
        "regex": ZERO_DAY_REGEX,
        "default_tags": ["Zero-Day", "CVE", "Kernel RCE", "Patch Alert"],
    },
    {
        "slug": "apt-espionage",
        "title": "APT & Nation-State Cyber Espionage",
        "badge": "🕵️ APT Campaign",
        "category": "Adversary Tracking",
        "description": "State-sponsored cyber espionage operations, living-off-the-land techniques, and targeted adversary infrastructure.",
        "icon": "Globe",
        "priority": 5,
        "regex": APT_REGEX,
        "default_tags": ["APT", "Espionage", "Volt Typhoon", "Lazarus"],
    },
    {
        "slug": "cloud-saas",
        "title": "Cloud Infrastructure & SaaS Leaks",
        "badge": "☁️ Cloud Leak",
        "category": "Infrastructure",
        "description": "Exposed S3 buckets, misconfigured Azure blobs, Firebase leaks, and cloud tenant credential exfiltrations.",
        "icon": "CloudOff",
        "priority": 6,
        "regex": CLOUD_SAAS_REGEX,
        "default_tags": ["Azure Dump", "S3 Bucket", "Cloud Security", "Firebase"],
    },
    {
        "slug": "supply-chain",
        "title": "Supply Chain & Ecosystem Hijacks",
        "badge": "📦 Supply Chain",
        "category": "Developer Security",
        "description": "Malicious NPM/PyPI packages, third-party vendor breaches, and open-source dependency compromises.",
        "icon": "Package",
        "priority": 7,
        "regex": SUPPLY_CHAIN_REGEX,
        "default_tags": ["NPM", "PyPI", "Supply Chain", "Dependency Hijack"],
    },
    {
        "slug": "healthcare-infra",
        "title": "Healthcare & Critical Infrastructure",
        "badge": "🏥 Critical Infra",
        "category": "Sectorial Protection",
        "description": "Cyberattacks on hospitals, medical record databases, water treatment facilities, and energy power grids.",
        "icon": "Activity",
        "priority": 8,
        "regex": HEALTHCARE_INFRA_REGEX,
        "default_tags": ["Healthcare", "HIPAA Breach", "Critical Infra", "Medical"],
    },
    {
        "slug": "credential-steal",
        "title": "Infostealers & Credential Dumps",
        "badge": "🔑 Infostealer",
        "category": "Identity & Access",
        "description": "Lumma Stealer logs, Telegram credential dumps, browser password exfiltrations, and cookie theft campaigns.",
        "icon": "Key",
        "priority": 9,
        "regex": CREDENTIAL_STEALER_REGEX,
        "default_tags": ["Lumma", "Infostealer", "Telegram Dump", "Credentials"],
    },
]


class ClusteringService:
    """Clustering & Custom Discovery Rule Engine."""

    @classmethod
    def match_article_to_clusters(cls, article: dict) -> List[str]:
        text = f"{article.get('title', '')} {article.get('summary', '')} {article.get('content_clean', '')} {' '.join(article.get('tags') or [])}"
        matched = []
        for defn in CLUSTER_DEFINITIONS:
            if defn["regex"].search(text):
                matched.append(defn["slug"])
        return matched

    @classmethod
    async def get_all_clusters(cls) -> List[Dict[str, Any]]:
        """Returns all built-in clusters + active user-defined discovery rule clusters."""
        articles_col = get_articles_collection()
        rules_col = get_cluster_rules_collection()

        # Strictly query only non-duplicate cybersecurity risk articles
        cursor = articles_col.find({
            "is_duplicate": {"$ne": True},
            "is_cybersecurity_news": True,
        }).sort("published_at", -1).limit(1000)
        articles = [a async for a in cursor]

        cluster_map: Dict[str, Dict[str, Any]] = {}
        for cdef in CLUSTER_DEFINITIONS:
            cluster_map[cdef["slug"]] = {
                "slug": cdef["slug"],
                "title": cdef["title"],
                "badge": cdef["badge"],
                "category": cdef["category"],
                "description": cdef["description"],
                "icon": cdef["icon"],
                "priority": cdef["priority"],
                "is_custom_rule": False,
                "count": 0,
                "high_severity_count": 0,
                "last_updated": None,
                "tags_set": set(cdef["default_tags"]),
                "sample_articles": [],
            }

        custom_rules_cursor = rules_col.find({"enabled": True})
        custom_rules = [r async for r in custom_rules_cursor]
        for rule in custom_rules:
            r_slug = f"custom-{str(rule['_id'])}"
            cluster_map[r_slug] = {
                "slug": r_slug,
                "rule_id": str(rule["_id"]),
                "title": rule.get("name", "Custom Rule"),
                "badge": f"⚡ {rule.get('name', 'Custom')[:14]}",
                "category": "Custom Discovery Rule",
                "description": rule.get("description") or f"Filter rule: {', '.join(rule.get('keywords') or [])}",
                "icon": "Filter",
                "priority": 10,
                "is_custom_rule": True,
                "count": 0,
                "high_severity_count": 0,
                "last_updated": None,
                "tags_set": set(rule.get("keywords") or []),
                "sample_articles": [],
            }

        for art in articles:
            text = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')} {' '.join(art.get('tags') or [])}".lower()
            art_severity = (art.get("severity") or "").lower()
            art_pub = art.get("published_at")

            for cdef in CLUSTER_DEFINITIONS:
                if cdef["regex"].search(text):
                    cdata = cluster_map[cdef["slug"]]
                    cdata["count"] += 1
                    if art_severity in ("critical", "high"):
                        cdata["high_severity_count"] += 1

                    if not cdata["last_updated"] and art_pub:
                        cdata["last_updated"] = art_pub.isoformat() if hasattr(art_pub, "isoformat") else str(art_pub)

                    for tag in (art.get("tags") or []):
                        if len(cdata["tags_set"]) < 8 and len(tag) <= 18:
                            cdata["tags_set"].add(tag)

                    if len(cdata["sample_articles"]) < 3:
                        cdata["sample_articles"].append({
                            "id": str(art["_id"]),
                            "title": art.get("title"),
                            "url": art.get("url"),
                            "source_name": art.get("source_name"),
                            "published_at": art_pub.isoformat() if hasattr(art_pub, "isoformat") else str(art_pub),
                            "severity": art.get("severity", "medium"),
                        })

            for rule in custom_rules:
                r_slug = f"custom-{str(rule['_id'])}"
                cdata = cluster_map[r_slug]

                keywords = rule.get("keywords") or []
                match_kw = True
                if keywords:
                    match_kw = any(kw.lower() in text for kw in keywords)

                match_country = True
                if rule.get("country") and rule["country"] != "All":
                    art_country = (art.get("target_country") or extract_country(art)).lower()
                    match_country = rule["country"].lower() in art_country

                match_incident = True
                if rule.get("incident_type") and rule["incident_type"] != "All":
                    art_type = determine_incident_type(art).lower()
                    match_incident = rule["incident_type"].lower() in art_type

                if match_kw and match_country and match_incident:
                    cdata["count"] += 1
                    if art_severity in ("critical", "high"):
                        cdata["high_severity_count"] += 1

                    if not cdata["last_updated"] and art_pub:
                        cdata["last_updated"] = art_pub.isoformat() if hasattr(art_pub, "isoformat") else str(art_pub)

                    if len(cdata["sample_articles"]) < 3:
                        cdata["sample_articles"].append({
                            "id": str(art["_id"]),
                            "title": art.get("title"),
                            "url": art.get("url"),
                            "source_name": art.get("source_name"),
                            "published_at": art_pub.isoformat() if hasattr(art_pub, "isoformat") else str(art_pub),
                            "severity": art.get("severity", "medium"),
                        })

        result = []
        for slug, cdata in cluster_map.items():
            cdata["top_tags"] = list(cdata["tags_set"])[:6]
            del cdata["tags_set"]
            result.append(cdata)

        result.sort(key=lambda x: (not x["is_custom_rule"], -x["count"], x["priority"]))
        return result

    @classmethod
    async def get_cluster_detail(cls, slug: str, page: int = 1, page_size: int = 20, q: Optional[str] = None) -> Dict[str, Any]:
        """Fetch matching articles for a specific cluster slug with pagination."""
        articles_col = get_articles_collection()
        rules_col = get_cluster_rules_collection()

        cluster_info = None

        if slug.startswith("custom-"):
            rule_id = slug.replace("custom-", "")
            try:
                rule = await rules_col.find_one({"_id": ObjectId(rule_id)})
            except Exception:
                rule = None

            if not rule:
                raise ValueError("Custom cluster rule not found")

            cluster_info = {
                "slug": slug,
                "title": rule.get("name"),
                "badge": f"⚡ {rule.get('name')[:14]}",
                "category": "Custom Discovery Rule",
                "description": rule.get("description"),
                "icon": "Filter",
                "is_custom_rule": True,
                "rule_id": str(rule["_id"]),
            }

            matched_articles = []
            cursor = articles_col.find({
                "is_duplicate": {"$ne": True},
                "is_cybersecurity_news": True,
            }).sort("published_at", -1).limit(1000)
            async for art in cursor:
                text = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')} {' '.join(art.get('tags') or [])}".lower()
                keywords = rule.get("keywords") or []
                match_kw = True if not keywords else any(kw.lower() in text for kw in keywords)

                match_country = True
                if rule.get("country") and rule["country"] != "All":
                    art_country = (art.get("target_country") or extract_country(art)).lower()
                    match_country = rule["country"].lower() in art_country

                match_incident = True
                if rule.get("incident_type") and rule["incident_type"] != "All":
                    art_type = determine_incident_type(art).lower()
                    match_incident = rule["incident_type"].lower() in art_type

                if match_kw and match_country and match_incident:
                    if q and q.lower() not in text:
                        continue
                    art["id"] = str(art["_id"])
                    del art["_id"]
                    matched_articles.append(art)
        else:
            cdef = next((c for c in CLUSTER_DEFINITIONS if c["slug"] == slug), None)
            if not cdef:
                raise ValueError(f"Unknown cluster slug: {slug}")

            cluster_info = {
                "slug": cdef["slug"],
                "title": cdef["title"],
                "badge": cdef["badge"],
                "category": cdef["category"],
                "description": cdef["description"],
                "icon": cdef["icon"],
                "is_custom_rule": False,
            }

            matched_articles = []
            cursor = articles_col.find({
                "is_duplicate": {"$ne": True},
                "is_cybersecurity_news": True,
            }).sort("published_at", -1).limit(1000)
            async for art in cursor:
                text = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')} {' '.join(art.get('tags') or [])}"
                if cdef["regex"].search(text):
                    if q and q.lower() not in text.lower():
                        continue
                    art["id"] = str(art["_id"])
                    del art["_id"]
                    matched_articles.append(art)

        total_matched = len(matched_articles)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paged_articles = matched_articles[start_idx:end_idx]

        return {
            "cluster": cluster_info,
            "total_articles": total_matched,
            "page": page,
            "page_size": page_size,
            "total_pages": (total_matched + page_size - 1) // page_size if total_matched > 0 else 1,
            "articles": paged_articles,
        }

    # ── Custom Discovery Rules CRUD ──────────────────────────────────────────

    @classmethod
    async def list_rules(cls) -> List[Dict[str, Any]]:
        rules_col = get_cluster_rules_collection()
        cursor = rules_col.find({}).sort("created_at", -1)
        rules = []
        async for r in cursor:
            r["id"] = str(r["_id"])
            del r["_id"]
            rules.append(r)
        return rules

    @classmethod
    async def create_rule(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        rules_col = get_cluster_rules_collection()
        doc = {
            "name": payload["name"].strip(),
            "description": payload.get("description", "").strip(),
            "keywords": [k.strip().upper() for k in payload.get("keywords", []) if k.strip()],
            "country": payload.get("country", "All"),
            "sectors": payload.get("sectors", ["All"]),
            "incident_type": payload.get("incident_type", "All"),
            "enabled": payload.get("enabled", True),
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        res = await rules_col.insert_one(doc)
        doc["id"] = str(res.inserted_id)
        if "_id" in doc:
            del doc["_id"]
        return doc

    @classmethod
    async def update_rule(cls, rule_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        rules_col = get_cluster_rules_collection()
        update_fields = {}
        for field in ("name", "description", "keywords", "country", "sectors", "incident_type", "enabled"):
            if field in payload:
                update_fields[field] = payload[field]

        update_fields["updated_at"] = datetime.now(timezone.utc)
        await rules_col.update_one({"_id": ObjectId(rule_id)}, {"$set": update_fields})
        updated = await rules_col.find_one({"_id": ObjectId(rule_id)})
        if not updated:
            raise ValueError("Rule not found")
        updated["id"] = str(updated["_id"])
        del updated["_id"]
        return updated

    @classmethod
    async def delete_rule(cls, rule_id: str) -> bool:
        rules_col = get_cluster_rules_collection()
        res = await rules_col.delete_one({"_id": ObjectId(rule_id)})
        return res.deleted_count > 0

    @classmethod
    async def run_rule(cls, rule_id: str) -> Dict[str, Any]:
        """Test/execute a rule against active articles and return match statistics."""
        detail = await cls.get_cluster_detail(slug=f"custom-{rule_id}", page=1, page_size=100)
        return {
            "status": "success",
            "rule_id": rule_id,
            "total_matches": detail.get("total_articles", 0),
            "matched_count": detail.get("total_articles", 0),
            "articles": detail.get("articles", []),
            "sample_articles": detail.get("articles", [])[:5],
        }
