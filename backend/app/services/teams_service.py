"""
Microsoft Teams Multi-Channel Webhook Service.

Routes articles strictly to their corresponding Microsoft Teams channel:
1. #breach         — Status-tagged company breaches ([CLAIMED], [CONFIRMED], [DENIED])
2. #ransomware     — Ransomware attacks & extortion groups
3. #vulnerability  — Zero-days, CVEs, RCEs, patches
4. #apt            — Nation-state threat actors & espionage campaigns
5. #indian-based   — India-specific threats & CERT-In advisories
"""
import re
import httpx
import asyncio
import urllib.parse
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from app.config import settings
import structlog

log = structlog.get_logger()

# ── Cyber Relevance Filter for MS Teams ─────────────────────────────────────────
_CYBER_TERMS = re.compile(
    r'\b('
    r'data breach|data leak|ransomware|cyber|hacker|hacking|hacked|malware|phishing|'
    r'vulnerability|exploit|zero.?day|cve-\d|rce|remote code execution|privilege escalation|'
    r'authentication bypass|security flaw|security bug|security incident|security breach|'
    r'credential|infosteal|stealer|botnet|ddos|denial.of.service|wiper|backdoor|trojan|'
    r'apt|lockbit|ransomhub|alphv|blackcat|akira|clop|rhysida|medusa|bianlian|qilin|'
    r'lazarus|volt typhoon|fancy bear|cozy bear|scattered spider|darkside|conti|'
    r'threat.?intel|incident response|pen.?test|penetration test|red team|blue team|'
    r'soc analyst|siem|edr|xdr|firewall|intrusion|network security|endpoint security|'
    r'encryption|decryption|cryptojack|supply chain attack|third.party breach|'
    r'cert-in|cert.in|nciipc|meity|digital india breach|indian cyber|'
    r'gdpr breach|hipaa breach|pci dss|nist csf|cisa advisory|cisa kev|'
    r'cobalt strike|metasploit|mimikatz|c2 server|command.and.control|dark web|darkweb|'
    r'telegram leak|tor|onion site|breach forum|breachforums|shinyHunters|'
    r'cybersecurity|infosecurity|information security|opsec|ioc|indicator.of.compromise|'
    r'threat actor|nation.state|espionage|cyberattack|cyber attack|security advisory|'
    r'patch tuesday|security update|critical update|security researcher|bug bounty'
    r')\b',
    re.IGNORECASE
)


def is_cyber_news(art: Dict[str, Any]) -> bool:
    """Verify that an article is genuine cybersecurity risk news using KeywordClassifier dictionary."""
    is_cyber = art.get("is_cybersecurity_news")
    if is_cyber is not None:
        return bool(is_cyber)
    
    # Fallback to dynamic classification
    try:
        from app.services.keyword_classifier import KeywordClassifier
        kw_res = KeywordClassifier.classify_article(art)
        return bool(kw_res.get("is_cybersecurity_news", False))
    except Exception:
        text = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')}"
        return bool(_CYBER_TERMS.search(text))


_DISPATCHED_TEAMS_KEYS: set = set()


def _get_article_fingerprint(art: Dict[str, Any]) -> str:
    """Generate a stable deduplication key from company, title, or ID."""
    aid = str(art.get("_id") or art.get("id") or "")
    comp = (art.get("target_company") or extract_breached_company(art) or "").strip().lower()
    title = (art.get("title") or "").strip().lower()
    norm_title = re.sub(r'[^a-z0-9]', '', title)[:60]
    if comp and comp != "not specified":
        return f"comp:{comp}_{norm_title[:30]}"
    if aid:
        return f"id:{aid}"
    return f"title:{norm_title}"


def _is_already_dispatched(art: Dict[str, Any], webhook_url: str) -> bool:
    if art.get("teams_dispatched") is True:
        return True
    fp = _get_article_fingerprint(art)
    dispatch_key = f"{webhook_url}::{fp}"
    return dispatch_key in _DISPATCHED_TEAMS_KEYS


async def _mark_dispatched_in_db(art: Dict[str, Any], webhook_url: str):
    fp = _get_article_fingerprint(art)
    dispatch_key = f"{webhook_url}::{fp}"
    _DISPATCHED_TEAMS_KEYS.add(dispatch_key)
    art_id = art.get("_id")
    if art_id:
        try:
            from app.db.mongodb import MongoDB
            await MongoDB.collection("articles").update_one(
                {"_id": art_id},
                {"$set": {"teams_dispatched": True, "teams_dispatched_at": datetime.now(timezone.utc)}}
            )
        except Exception:
            pass


def is_cyber_news(art: Dict[str, Any]) -> bool:
    """Strictly verify if an article is cybersecurity / CTI related."""
    if art.get("cves") or art.get("threat_actors"):
        return True

    tags = [str(t).lower() for t in (art.get("tags") or [])]
    if any(t in tags for t in ["breach", "ransomware", "vulnerability", "malware", "cybersecurity", "cve", "apt", "phishing", "zero-day", "security"]):
        return True

    cat = (art.get("category") or art.get("incident_type") or "").lower()
    if cat and cat not in ("unknown", "general", "other", "news"):
        return True

    text = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')[:1500]}".lower()
    return bool(_CYBER_TERMS.search(text))


def clean_summary_text(art: Dict[str, Any]) -> str:
    """Extract clean, English summary text without HTML or Chinese RSS boilerplate."""
    ai_sum = art.get("ai_summary")
    if ai_sum and len(ai_sum.strip()) > 20:
        return ai_sum.strip()

    text = art.get("summary") or art.get("content_clean") or art.get("title") or ""

    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)

    # Remove Chinese boilerplate from OSINTxLab RSS feed
    text = re.sub(r'[\u4e00-\u9fff]+', ' ', text)
    text = re.sub(r'\b\d+\s*阅读\b', '', text)
    text = re.sub(r'\b\d+\s*分钟\b', '', text)
    text = re.sub(r'阅读全文', '', text)
    text = re.sub(r'事件类型:\s*\w+', '', text)
    text = re.sub(r'报告时间:\s*[\d\-]+', '', text)

    text = re.sub(r'\s+', ' ', text).strip()

    if len(text) < 15:
        text = art.get("title", "No detailed summary available.")

    return text[:350]


def determine_incident_type(art: Dict[str, Any]) -> str:
    """Classify incident type into clean user-facing categories."""
    direct_type = art.get("incident_type") or art.get("category")
    if direct_type and str(direct_type).lower() not in ("unknown", "general", "other", "news", ""):
        dt_clean = str(direct_type).strip().title()
        if dt_clean in ["Zero-Day Exploit", "Vulnerability", "Ransomware", "Supply Chain Attack", "Phishing", "Ddos", "Malware", "Data Leak", "Apt Campaign", "Data Breach"]:
            return dt_clean if dt_clean != "Ddos" else "DDoS"

    text = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')} {' '.join(art.get('tags') or [])}".lower()

    if any(k in text for k in ["zero-day", "0-day", "unpatched zero"]):
        return "Zero-day exploit"
    if any(k in text for k in ["cve-", "vulnerability", "rce", "remote code execution", "security flaw", "patch advisory", "security update", "patch tuesday"]):
        return "Vulnerability"
    if any(k in text for k in ["ransomware", "encryptor", "extortion", "lockbit", "space bears", "direwolf", "settra", "akira", "blackcat", "blackbasta", "ransomhub"]):
        return "Ransomware"
    if any(k in text for k in ["supply chain", "npm package", "pypi", "third-party breach", "dependency hijack"]):
        return "Supply chain attack"
    if any(k in text for k in ["phish", "spear-phishing", "credential harvesting", "social engineering"]):
        return "Phishing"
    if any(k in text for k in ["ddos", "denial of service", "botnet attack"]):
        return "DDoS"
    if any(k in text for k in ["malware", "trojan", "infostealer", "lumma", "redline", "backdoor", "rat ", "rootkit"]):
        return "Malware"
    if any(k in text for k in ["data leak", "leaked database", "credential leak", "dump", "exfiltrat", "exposed bucket", "s3 leak", "azure dump"]):
        return "Data leak"
    if any(k in text for k in ["apt", "threat actor", "espionage", "nation-state", "volt typhoon", "lazarus", "fancy bear"]):
        return "APT Campaign"
    if any(k in text for k in ["data breach", "breached", "hacked", "stolen records", "compromised database"]):
        return "Data breach"

    return "Cyber Advisory"


def determine_breach_status(article: Dict[str, Any]) -> str:
    """Classify breach post status: DENIED, CONFIRMED, CLAIMED."""
    if article.get("claim_status") in ("claimed", "confirmed", "denied"):
        return article["claim_status"].upper()

    text = f"{article.get('title', '')} {article.get('summary', '')} {article.get('content_clean', '')}".lower()

    if any(k in text for k in [
        "denied", "denies", "no evidence of breach", "no evidence of a breach",
        "found no breach", "unaffected", "no operational impact", "debunked",
        "denies claim", "fake breach claim", "no compromise"
    ]):
        return "DENIED"

    if any(k in text for k in [
        "confirms", "confirmed", "verified", "acknowledged", "admitted",
        "disclosed breach", "notified affected", "investigating incident",
        "sec filing confirms", "statement confirms", "suffered data breach"
    ]):
        return "CONFIRMED"

    return "CLAIMED"


def extract_date_reported(art: Dict[str, Any]) -> str:
    """Extract report date formatted like '12 Aug 2026'."""
    pub = art.get("published_at")
    if isinstance(pub, datetime):
        return pub.strftime("%d %b %Y")
    if isinstance(pub, str) and len(pub) >= 10:
        try:
            dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            return dt.strftime("%d %b %Y")
        except Exception:
            return pub[:10]
    return datetime.now(timezone.utc).strftime("%d %b %Y")


INDIA_PATTERNS = re.compile(
    r'\b(india|indian|tcs|infosys|wipro|hcl|hcltech|sbi|aiims|reliance|jio|paytm|razorpay|byju|zomato|swiggy|ola|flipkart|cert-in|gov\.in|nic\.in|physics\s*wallah|drdo|isro)\b',
    re.IGNORECASE
)

COUNTRY_PATTERNS: List[tuple] = [
    ("India", re.compile(r'\b(india|indian|cert-in|gov\.in|nic\.in|mumbai|delhi|bengaluru|hyderabad|chennai|kolkata|pune)\b', re.I)),
    ("USA", re.compile(r'\b(united states|u\.s\.|u\.s\.a|america|cisa|fbi|nsa|pentagon|white house|new york|california|texas)\b', re.I)),
    ("UK", re.compile(r'\b(united kingdom|u\.k\.|britain|british|london|ncsc uk|england|wales|scotland)\b', re.I)),
    ("China", re.compile(r'\b(china|chinese|beijing|shanghai|prc|ccp|cert-cn)\b', re.I)),
    ("Russia", re.compile(r'\b(russia|russian|moscow|kremlin|cert-ru|fsb)\b', re.I)),
    ("Germany", re.compile(r'\b(germany|german|berlin|bsi germany|bundesamt)\b', re.I)),
    ("Australia", re.compile(r'\b(australia|australian|canberra|acsc|asd australia)\b', re.I)),
    ("Japan", re.compile(r'\b(japan|japanese|tokyo|cert-jp)\b', re.I)),
    ("Canada", re.compile(r'\b(canada|canadian|ottawa|cse canada)\b', re.I)),
    ("France", re.compile(r'\b(france|french|paris|anssi)\b', re.I)),
    # ── GCC Countries ──────────────────────────────────────────────────────────
    ("UAE", re.compile(r'\b(uae|united arab emirates|dubai|abu dhabi|sharjah|ajman|ras al khaimah|fujairah|desc|ncsc uae)\b', re.I)),
    ("Saudi Arabia", re.compile(r'\b(saudi|saudi arabia|ksa|riyadh|jeddah|neom|aramco|nca saudi|saudi cert)\b', re.I)),
    ("Qatar", re.compile(r'\b(qatar|qatari|doha|qcert)\b', re.I)),
    ("Kuwait", re.compile(r'\b(kuwait|kuwaiti|kuwait city)\b', re.I)),
    ("Bahrain", re.compile(r'\b(bahrain|bahraini|manama)\b', re.I)),
    ("Oman", re.compile(r'\b(oman|omani|muscat|ocert)\b', re.I)),
    # ── Middle East & MENA Countries ───────────────────────────────────────────
    ("Israel", re.compile(r'\b(israel|israeli|tel aviv|jerusalem|incd)\b', re.I)),
    ("Iran", re.compile(r'\b(iran|iranian|tehran|irgc|cert-ir)\b', re.I)),
    ("Iraq", re.compile(r'\b(iraq|iraqi|baghdad)\b', re.I)),
    ("Egypt", re.compile(r'\b(egypt|egyptian|cairo|eg-cert)\b', re.I)),
    ("Jordan", re.compile(r'\b(jordan|jordanian|amman)\b', re.I)),
    ("Lebanon", re.compile(r'\b(lebanon|lebanese|beirut)\b', re.I)),
    ("Turkey", re.compile(r'\b(turkey|türkiye|turkish|ankara|istanbul|usom)\b', re.I)),
    ("Yemen", re.compile(r'\b(yemen|yemeni|sanaa|aden)\b', re.I)),
    ("Syria", re.compile(r'\b(syria|syrian|damascus)\b', re.I)),
    ("Palestine", re.compile(r'\b(palestine|palestinian|gaza|west bank)\b', re.I)),
    ("Singapore", re.compile(r'\b(singapore|singaporean|csa singapore)\b', re.I)),
    ("Brazil", re.compile(r'\b(brazil|brazilian|sao paulo|rio de janeiro)\b', re.I)),
]


def extract_country(art: Dict[str, Any]) -> str:
    """Extract the most likely target country from article text."""
    if art.get("target_country") and art["target_country"] not in ("Unknown", "", None):
        return art["target_country"]

    text = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')} {' '.join(art.get('tags') or [])}"

    for country_name, pattern in COUNTRY_PATTERNS:
        if pattern.search(text):
            return country_name

    return "Unknown"


def extract_claimed_records(article: Dict[str, Any]) -> Optional[str]:
    """Extract claimed number of records / data volume from article text."""
    if article.get("claimed_records_count"):
        return str(article["claimed_records_count"])

    text = f"{article.get('title', '')} {article.get('summary', '')} {article.get('content_clean', '')}"

    patterns = [
        r'(\d[\d,\.]+)\s*(million|billion|mn|bn|M|B)\s*(?:user|customer|record|row|entry|entries|account|credential)',
        r'(\d[\d,\.]+)\s*(?:user|customer|record|row|entry|entries|account|credential)',
        r'(?:over|more than|approx(?:imately)?|~)\s*(\d[\d,\.]+\s*(?:million|billion|mn|bn|M|B)?)',
        r'(\d+(?:\.\d+)?\s*(?:GB|TB|MB))\s*(?:of data|database|data breach)',
    ]

    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(0).strip()

    return None


def extract_claimed_vector(article: Dict[str, Any]) -> Optional[str]:
    """Extract attack vector / method from article text."""
    if article.get("attack_vector"):
        return article["attack_vector"]

    text = f"{article.get('title', '')} {article.get('summary', '')} {article.get('content_clean', '')}".lower()

    vectors = [
        ("Ransomware", ["ransomware", "encryptor", "lockbit", "akira", "clop", "extortion"]),
        ("Phishing", ["phishing", "spear-phishing", "credential harvesting", "vishing"]),
        ("Supply Chain", ["supply chain", "third-party", "vendor breach", "npm package", "pypi"]),
        ("SQL Injection", ["sql injection", "sqli", "database dump"]),
        ("RCE", ["remote code execution", "rce", "code execution"]),
        ("Zero-Day", ["zero-day", "0-day", "unpatched", "cve-"]),
        ("Credential Theft", ["credential", "stolen password", "bruteforce", "infostealer", "lumma", "redline"]),
        ("Misconfiguration", ["misconfigured", "exposed bucket", "s3 bucket", "firebase", "open database"]),
        ("DDoS", ["ddos", "distributed denial of service", "denial of service"]),
        ("Insider Threat", ["insider threat", "rogue employee", "disgruntled employee"]),
    ]

    for vector_name, keywords in vectors:
        if any(kw in text for kw in keywords):
            return vector_name

    return None


def extract_company_response(article: Dict[str, Any]) -> Optional[str]:
    """Extract company response / official statement from article text."""
    if article.get("company_response"):
        return article["company_response"]

    text = f"{article.get('title', '')} {article.get('summary', '')} {article.get('content_clean', '')}"

    response_patterns = [
        r'(?:company|organization|firm|spokesperson|ceo|cto|ciso|official)\s+(?:said|stated|confirmed|denied|responded|announced|disclosed|issued)\s+.{10,120}',
        r'(?:we are|we have|the company)\s+(?:investigating|notified|working with|launched|confirmed)\s+.{5,100}',
        r'(?:statement|press release|blog post)\s+(?:from|by|issued by)\s+.{5,80}',
    ]

    for pat in response_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            snippet = m.group(0).strip()
            return snippet[:200] if len(snippet) > 200 else snippet

    return None


KNOWN_PUBLISHERS = {
    "bleepingcomputer", "the hacker news", "securityweek", "reuters", "techcrunch",
    "dark reading", "cyberscoop", "security affairs", "threatpost", "zdnet", "forbes",
    "krebs on security", "cisa", "fbi", "cybersecurity news", "the register", "infosecurity magazine",
    "help net security", "recorded future", "cybernews", "security", "clarityti", "osintxlab"
}

KNOWN_ACTORS = {
    "lockbit", "blackcat", "alphv", "akira", "clop", "rhysida", "play", "bianlian",
    "medusa", "qilin", "scattered spider", "volt typhoon", "fancy bear", "lazarus",
    "dragonfly", "apt28", "apt29", "apt41", "charming kitten", "blackbasta", "royal",
    "thehatman", "direwolf", "settra", "space bears", "payload"
}

GENERIC_NON_COMPANIES = {
    "security advisory", "zero-day exploit", "critical patch", "remote code execution",
    "data breach", "patch advisory", "kernel vulnerability", "security bug", "security update",
    "patch tuesday", "cyberattack", "ransomware attack", "data leak", "threat intelligence",
    "emergency directive", "security flaw", "vulnerability advisory", "targeted organization",
    "unknown", "n/a", "none", "no detailed summary available."
}


def extract_breached_company(article: Dict[str, Any]) -> str:
    """
    Extract target organization name strictly.
    Returns 'Not Specified' if no actual company name is present in the article.
    Never returns article titles or random words.
    """
    # 1. Direct fields from DB / AI enrichment
    for key in ("target_organization", "affected_company", "company_name", "company"):
        val = article.get(key)
        if val and isinstance(val, str) and len(val.strip()) >= 2:
            val_clean = val.strip()
            if val_clean.lower() not in GENERIC_NON_COMPANIES and val_clean.lower() not in KNOWN_PUBLISHERS:
                return val_clean

    title = (article.get("title") or "").strip()
    full_text = f"{title} {article.get('summary', '')}"

    # 2. Known company lookup with regex word boundaries
    known_companies = [
        ("Physics Wallah", [r"physics\s*wallah", r"\bpw\b"]),
        ("TCS", [r"\btcs\b", r"tata consultancy"]),
        ("HCLTech", [r"hcltech", r"\bhcl\b"]),
        ("State Bank of India", [r"state bank of india", r"\bsbi\b"]),
        ("AIIMS India", [r"\baiims\b"]),
        ("Infosys", [r"\binfosys\b"]),
        ("Wipro", [r"\bwipro\b"]),
        ("Razorpay", [r"\brazorpay\b"]),
        ("Paytm", [r"\bpaytm\b"]),
        ("Villa Raiano", [r"villa\s*raiano"]),
        ("Fondo", [r"\bfondo\b"]),
        ("B&B Hydraulik", [r"b&b\s*hydraulik"]),
        ("FirstDigital", [r"firstdigital"]),
        ("Swyft Inc", [r"swyft"]),
        ("Cisco", [r"\bcisco\b"]),
        ("Microsoft", [r"\bmicrosoft\b"]),
        ("Google", [r"\bgoogle\b"]),
        ("Apple", [r"\bapple\b"]),
        ("Amazon", [r"\bamazon\b", r"\baws\b"]),
        ("Apache", [r"\bapache\b"]),
        ("Fortinet", [r"\bfortinet\b"]),
        ("Palo Alto Networks", [r"palo\s*alto"]),
        ("CrowdStrike", [r"crowdstrike"]),
        ("VMware", [r"vmware"]),
        ("Ivanti", [r"ivanti"]),
        ("SolarWinds", [r"solarwinds"]),
        ("Citrix", [r"citrix"]),
        ("Okta", [r"okta"]),
        ("WordPress", [r"wordpress"]),
        ("Oracle", [r"\boracle\b"]),
        ("SAP", [r"\bsap\b"]),
        ("IBM", [r"\bibm\b"]),
        ("Samsung", [r"samsung"]),
        ("Sony", [r"sony"]),
        ("AT&T", [r"at&t"]),
        ("T-Mobile", [r"t-mobile"]),
        ("Verizon", [r"verizon"]),
        ("Uber", [r"\buber\b"]),
        ("Meta", [r"\bmeta\b"]),
        ("LinkedIn", [r"linkedin"]),
        ("GitHub", [r"github"]),
        ("GitLab", [r"gitlab"]),
        ("Snowflake", [r"snowflake"]),
        ("MoveIT", [r"moveit"]),
        ("GoAnywhere", [r"goanywhere"]),
        ("Salesforce", [r"salesforce"]),
        # ── GCC & Middle East Major Enterprises ──────────────────────────────
        ("Saudi Aramco", [r"saudi\s*aramco", r"\baramco\b"]),
        ("NEOM", [r"\bneom\b"]),
        ("Etisalat", [r"etisalat", r"\be\&\b"]),
        ("Emirates NBD", [r"emirates\s*nbd"]),
        ("Emirates", [r"emirates\s*airline", r"emirates\s*group"]),
        ("First Abu Dhabi Bank", [r"first\s*abu\s*dhabi\s*bank", r"\bfab\b"]),
        ("Qatar National Bank", [r"qatar\s*national\s*bank", r"\bqnb\b"]),
        ("Saudi Telecom Company", [r"saudi\s*telecom", r"\bstc\b"]),
        ("Ooredoo", [r"ooredoo"]),
        ("Zain Group", [r"\bzain\b"]),
        ("BAPCO", [r"\bbapco\b"]),
    ]

    for comp_name, regexes in known_companies:
        for r in regexes:
            if re.search(r, full_text, re.IGNORECASE):
                return comp_name

    # 3. Breach title patterns targeting company names
    patterns = [
        r'^(?:Data breach at|Breach at|Hackers breach|Cyberattack hits|Ransomware hits|Ransomware attack on|Hackers target|Breach hits)\s+([A-Z0-9][A-Za-z0-9\s\.\,\&\-]{2,30}?)(?:\s+exposes|\s+leaks|\s+data|\s+systems|\s+confirms|\s+discloses|\s+suffers|\s+report|\s+as|\:|\.|\,|$)',
        r'([A-Z0-9][A-Za-z0-9\s\.\&\-]{2,30}?)\s+(?:confirms|suffers|reports|discloses|hit by|targeted by|faces|victim of)\s+(?:major\s+)?(?:data breach|breach|cyberattack|ransomware|security incident)',
        r'([A-Z0-9][A-Za-z0-9\s\.\&\-]{2,30}?)\s+(?:falls victim to|data breach|security breach)',
        r'([A-Z0-9][A-Za-z0-9\s\.\&\-]{2,30}?)\s+hacked\b',
    ]

    for pat in patterns:
        m = re.search(pat, title, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip(" .,:-")
            c_lower = candidate.lower()
            if (
                c_lower not in KNOWN_PUBLISHERS
                and c_lower not in KNOWN_ACTORS
                and c_lower not in GENERIC_NON_COMPANIES
                and len(candidate) >= 3
            ):
                return candidate

    return "Not Specified"


COMPANY_SECTOR_MAP = [
    # Technology & Software (CMS, Web Servers, OS, Software Frameworks, Cloud, Tech Giants)
    (re.compile(r'\b(wordpress|cms|plugin|php|drupal|joomla|apache|nginx|laravel|react|node\.js|python|java|linux|windows|macos|ios|android|github|gitlab|docker|kubernetes|software|vulnerability|zero-day|cve|rce|sql injection|xss|web server|tcs|tata consultancy|infosys|wipro|hcltech|hcl|tech mahindra|microsoft|google|aws|amazon web services|oracle|cisco|ibm|cognizant|capgemini|accenture)\b', re.I), "Technology & Software"),

    # Banking & Finance
    (re.compile(r'\b(sbi|state bank of india|icici|hdfc|axis bank|kotak|razorpay|paytm|qnb|qatar national bank|fab|first abu dhabi bank|emirates nbd|dubai islamic bank|adcb|mashreq|al rajhi|visa|mastercard|paypal|swift|banking|bank|finance|financial|fintech|payment|credit card|crypto|debit card)\b', re.I), "Banking & Finance"),

    # Energy & Utilities (Strict whole words only - prevents 'powerful' or 'powering' misclassifying)
    (re.compile(r'\b(saudi aramco|aramco|bapco|dewa|taqa|sabic|petroleum|oil|gas|power plant|power grid|electric grid|electricity|utility|utilities|nuclear power|solar power)\b', re.I), "Energy & Utilities"),

    # Telecom & Communications
    (re.compile(r'\b(stc|saudi telecom|ooredoo|zain|etisalat|jio|reliance jio|airtel|vodafone|at&t|t-mobile|verizon|telecom|telecommunications|isp|broadband|cellular|5g|4g)\b', re.I), "Telecom & Communications"),

    # Defense & Aerospace
    (re.compile(r'\b(drdo|isro|pentagon|lockheed|boeing|airbus|military|defense|defence|armaments|missile|aerospace|warfare)\b', re.I), "Defense & Aerospace"),

    # Healthcare & Life Sciences
    (re.compile(r'\b(aiims|amgen|pfizer|novartis|roche|hipaa|hospital|patient|medical|pharma|pharmaceutical|healthcare|biotech)\b', re.I), "Healthcare & Life Sciences"),

    # Government & Public Sector
    (re.compile(r'\b(nic\.in|gov\.in|cert-in|meity|nciipc|ministry|parliament|federal|census|voter|government|public sector)\b', re.I), "Government & Public Sector"),

    # Education & Academia
    (re.compile(r'\b(physics wallah|byju|edtech|university|college|academic|school|student|education)\b', re.I), "Education & Academia"),

    # Retail & E-Commerce
    (re.compile(r'\b(zomato|swiggy|flipkart|amazon|walmart|ebay|shopping|ecommerce|e-commerce|retail)\b', re.I), "Retail & E-Commerce"),

    # Transportation & Logistics
    (re.compile(r'\b(flydubai|qatar airways|saudia|emirates airline|airline|airport|maritime|freight|logistics|cargo|railway|transportation)\b', re.I), "Transportation & Logistics"),

    # Manufacturing & Industrial
    (re.compile(r'\b(manufacturing|automotive|factory|industrial|steel|semiconductor|chemical)\b', re.I), "Manufacturing & Industrial"),
]


def determine_sector(art: Dict[str, Any]) -> str:
    """Classify sector into accurate CTI taxonomy categories."""
    explicit_sector = art.get("sector")
    if explicit_sector and str(explicit_sector).strip() and str(explicit_sector).strip() not in ("Unknown", "IT", "Technology & Services"):
        return str(explicit_sector).strip()

    title = art.get("title") or ""
    summary = art.get("summary") or ""
    tags = " ".join(art.get("tags") or [])
    full_text = f"{title} {summary} {tags} {art.get('content_clean', '')[:1000]}"
    comp_name = extract_breached_company(art)
    comb_text = f"{comp_name} {full_text}"

    # 1. Company / Pattern Match with Word Boundaries
    for pattern, sector_name in COMPANY_SECTOR_MAP:
        if pattern.search(comb_text):
            return sector_name

    return "Technology & Software"


# Defined Teams Channels & Keyword Rules (India, Middle East, & High Priority News)
CHANNEL_RULES = [
    {
        "channel_id": "high-priority-news",
        "channel_name": "#high-priority-news",
        "title": "High Priority News",
        "region": "High Priority News (India & Middle East Breaches & Leaks)",
        "env_key": "TEAMS_WEBHOOK_URL_HIGH_PRIORITY_NEWS",
        "teams_link": "https://teams.microsoft.com/l/channel/19%3A69xRCKykkXcRIZu3FwOaxVQV-zqgYeE_SJnfSHLjLwE1%40thread.tacv2/High%20Priority%20News?groupId=ef4a0e0d-45e1-48e7-b801-bb1b0e2be4f1&tenantId=e78b42b1-6acb-4e15-a598-630a52228076",
        "aliases": ["high-priority-news", "high_priority_news", "high_priority", "high-priority", "daily-cti-digest", "daily_cti_digest", "daily-digest", "digest"],
        "color": "9B59B6",
    },
    {
        "channel_id": "indian-breaches",
        "channel_name": "#indian-breaches",
        "region": "India",
        "keywords": ["india", "indian", "cert-in", "nciipc", "meity", "tcs", "infosys", "wipro", "hcl", "sbi", "aiims", "reliance", "jio", "paytm", "razorpay", "zomato", "swiggy", "flipkart", "physics wallah", "drdo", "isro", "cert.in"],
        "env_key": "TEAMS_WEBHOOK_URL_INDIAN_BREACHES",
        "aliases": ["indian-based", "indian_based", "indian_breaches"],
        "color": "FF9933",
    },
    {
        "channel_id": "middle-east-companies",
        "channel_name": "#middle-east-companies",
        "region": "GCC & Middle East",
        "keywords": [
            "gcc", "uae", "united arab emirates", "dubai", "abu dhabi",
            "saudi", "saudi arabia", "ksa", "riyadh", "aramco", "neom", "qatar", "doha",
            "kuwait", "bahrain", "manama", "oman", "muscat"
        ],
        "env_key": "TEAMS_WEBHOOK_URL_MIDDLE_EAST_COMPANIES",
        "aliases": ["gcc-middle-east", "gcc_middle_east", "middle_east_companies"],
        "color": "009688",
    },
]

MIDDLE_EAST_COUNTRIES_SET = {
    "UAE", "Saudi Arabia", "Qatar", "Kuwait", "Bahrain", "Oman",
    "Israel", "Iran", "Iraq", "Egypt", "Jordan", "Lebanon", "Turkey", "Yemen", "Syria", "Palestine"
}
GCC_COUNTRIES_SET = {"UAE", "Saudi Arabia", "Qatar", "Kuwait", "Bahrain", "Oman"}

GCC_COMPANIES_REGEX = re.compile(
    r'\b(saudi aramco|aramco|neom|emirates nbd|first abu dhabi bank|fab|qatar national bank|qnb|saudi telecom|stc|ooredoo|zain|bapco|etisalat|dubai islamic bank|adcb|mashreq|sabic|al rajhi|dewa|taqa|almarai|savola|flydubai|qatar airways|saudia|borouge)\b',
    re.IGNORECASE
)

FOREIGN_IN_MIDDLE_EAST_REGEX = re.compile(
    r'\b(microsoft|amazon|google|apple|samsung|cisco|ibm|cognizant|capgemini|accenture|oracle|dell|hp|intel)\s+(?:uae|dubai|abu\s+dhabi|saudi|ksa|riyadh|qatar|doha|middle\s+east|gcc|mena|in\s+middle\s+east)\b',
    re.IGNORECASE
)

INDIAN_COMPANIES_REGEX = re.compile(
    r'\b(tcs|tata consultancy|tata|infosys|wipro|hcltech|hcl|tech mahindra|mahindra|state bank of india|sbi|icici|hdfc|axis bank|kotak|aiims|physics wallah|paytm|razorpay|reliance|jio|airtel|zomato|swiggy|flipkart|drdo|isro|nic\.in|gov\.in|cert-in|nciipc|ola|uber india|amazon india|google india|microsoft india|apple india|samsung india|cisco india|cognizant india|capgemini india|accenture india)\b',
    re.IGNORECASE
)

FOREIGN_IN_INDIA_REGEX = re.compile(
    r'\b(microsoft|amazon|google|apple|samsung|cisco|ibm|cognizant|capgemini|accenture|oracle|dell|hp|intel)\s+(?:india|indian\s+subsidiary|indian\s+branch|indian\s+unit|in\s+india)\b',
    re.IGNORECASE
)


def extract_severity_level(art: Dict[str, Any]) -> str:
    """Extract standard severity rating: CRITICAL, HIGH, MEDIUM, INFO."""
    sev = str(art.get("severity") or "").strip().upper()
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"):
        return "INFO" if sev in ("LOW", "INFORMATIONAL") else sev

    text = f"{art.get('title', '')} {art.get('summary', '')} {' '.join(art.get('tags') or [])}".lower()
    if any(k in text for k in ["critical", "0-day", "zero-day", "rce", "unauthenticated remote", "active exploitation", "mass exploit"]):
        return "CRITICAL"
    if any(k in text for k in ["high", "ransomware", "data breach", "database leak", "privilege escalation", "authentication bypass"]):
        return "HIGH"
    if any(k in text for k in ["medium", "phishing", "malware", "ddos", "xss", "spoofing"]):
        return "MEDIUM"
    return "INFO"


def format_timestamp_pretty(dt_val: Any) -> str:
    """Format datetime into 'Aug 20, 2026, 07:48 AM'."""
    if isinstance(dt_val, datetime):
        return dt_val.strftime("%b %d, %Y, %I:%M %p")
    if isinstance(dt_val, str) and len(dt_val) >= 10:
        try:
            dt = datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
            return dt.strftime("%b %d, %Y, %I:%M %p")
        except Exception:
            return dt_val[:16]
    return datetime.now(timezone.utc).strftime("%b %d, %Y, %I:%M %p")


def is_company_breach_or_incident(art: Dict[str, Any]) -> bool:
    """
    Detect if an article specifically involves an Enterprise Breach, Data Leak, Ransomware,
    Extortion, or targeted compromise (as opposed to a general CVE / software vulnerability advisory).
    """
    text = f"{art.get('title', '')} {art.get('summary', '')}".lower()
    tags = [str(t).lower() for t in (art.get("tags") or [])]

    # Explicit breach / leak / ransomware keywords
    breach_indicators = [
        "data breach", "database leak", "db leak", "db leaked", "records leaked",
        "records stolen", "ransomware attack", "ransomware hits", "ransomware", "extortion", "claimed breach",
        "confirms breach", "leaked credentials", "compromised database", "dump leaked",
        "hacked", "stolen data", "exfiltrated data", "dark web leak", "stolen records",
        "compromised accounts", "data leak", "data dump"
    ]
    if any(k in text for k in breach_indicators) or any(t in tags for t in ["breach", "data-leak", "ransomware", "leak", "extortion", "data-breach"]):
        return True

    inc_type = determine_incident_type(art).lower()
    if inc_type in ["data breach", "data leak", "ransomware", "supply chain attack"]:
        return True

    # If it is clearly a vulnerability advisory or CVE bulletin, it is a general advisory
    if any(k in text for k in ["vulnerabilit", "security flaw", "patch advisory", "cve-", "security update", "patch tuesday", "advisory ciad-", "buffer overflow"]):
        return False

    # If an affected company is identified
    comp = extract_breached_company(art)
    if comp and comp != "Not Specified":
        return True

    return False


def is_gcc_middle_east_news(art: Dict[str, Any]) -> bool:
    """
    Matches ALL cyber news for GCC & Middle East region:
      - National CERT advisories (aeCERT, NCA Saudi, OCERT Oman, EG-CERT, INCD, CERT-IQ)
      - Middle East / GCC enterprises (Aramco, NEOM, Etisalat, FAB, QNB, STC, BAPCO, etc.)
      - Foreign companies operating in Middle East
      - Regional threat actors, attacks, vulnerabilities, and data breaches
    """
    if not is_cyber_news(art):
        return False

    country_name = art.get("target_country") or extract_country(art)
    company_name = extract_breached_company(art)

    title = art.get("title") or ""
    summary = art.get("summary") or ""
    source_name = (art.get("source_name") or "").lower()
    text = f"{title} {summary} {' '.join(art.get('tags') or [])}".lower()

    # Check for Middle East CERT sources
    if any(k in source_name for k in ["aecert", "uae cert", "nca", "saudi", "ocert", "oman", "eg-cert", "egypt", "incd", "israel", "cert-iq", "iraq"]):
        return True

    # Check if explicitly mentions a Middle East / GCC enterprise or Foreign company in Middle East
    has_me_enterprise = (
        bool(GCC_COMPANIES_REGEX.search(text))
        or bool(FOREIGN_IN_MIDDLE_EAST_REGEX.search(text))
        or (company_name in [
            "Saudi Aramco", "NEOM", "Etisalat", "First Abu Dhabi Bank", "Qatar National Bank",
            "Saudi Telecom Company", "Ooredoo", "Zain Group", "BAPCO"
        ])
    )

    # Check if target country or text mentions GCC / Middle East
    is_me_region = (country_name in MIDDLE_EAST_COUNTRIES_SET) or any(
        kw in text for kw in [
            "gcc", "uae", "united arab emirates", "dubai", "abu dhabi", "saudi", "saudi arabia",
            "ksa", "riyadh", "aramco", "neom", "qatar", "doha", "kuwait", "bahrain", "manama",
            "oman", "muscat", "middle east", "middle-east", "israel", "tel aviv", "egypt", "cairo",
            "iran", "tehran", "iraq", "baghdad", "jordan", "lebanon", "turkey", "istanbul", "yemen", "syria"
        ]
    )

    return is_me_region or has_me_enterprise


def is_indian_news(art: Dict[str, Any]) -> bool:
    """
    Matches ALL cyber news for India:
      - CERT-In & NCIIPC advisories
      - Indian enterprises (TCS, Infosys, SBI, AIIMS, Reliance, Paytm, Razorpay, etc.)
      - Foreign companies operating in India
      - India-specific cyber attacks, threat actors, vulnerabilities, and data breaches
    """
    if not is_cyber_news(art):
        return False

    country_name = art.get("target_country") or extract_country(art)
    company_name = extract_breached_company(art)

    title = art.get("title") or ""
    summary = art.get("summary") or ""
    source_name = (art.get("source_name") or "").lower()
    text = f"{title} {summary} {' '.join(art.get('tags') or [])}".lower()

    # Generic global vulnerability/CVE advisories without explicit Indian enterprise/gov impact are NOT Indian news
    is_generic_vuln = any(k in text for k in ["cve-", "log4j", "zero-day", "0-day", "rce", "buffer overflow", "deserialization"])
    has_explicit_indian_org = any(k in text for k in [
        "tcs", "infosys", "wipro", "hcl", "sbi", "aiims", "aadhaar", "gov.in", "nic.in", "drdo", "isro",
        "indian army", "indian navy", "indian air force", "indian government", "indian bank", "razorpay", "paytm", "jio", "airtel"
    ])
    if is_generic_vuln and not has_explicit_indian_org:
        if not ("cert-in" in source_name or "cert.in" in source_name or "nciipc" in source_name):
            return False

    # Check for Indian enterprise or Foreign enterprise in India
    has_indian_enterprise = (
        bool(INDIAN_COMPANIES_REGEX.search(text))
        or bool(FOREIGN_IN_INDIA_REGEX.search(text))
        or (company_name in ["TCS", "Infosys", "Wipro", "HCLTech", "State Bank of India", "AIIMS", "Physics Wallah", "Paytm", "Razorpay", "Reliance Jio", "Airtel", "Zomato", "Flipkart"])
    )

    is_india_region = (country_name == "India") or any(
        kw in text for kw in [
            "india", "indian", "cert-in", "cert.in", "nciipc", "meity", "delhi", "mumbai",
            "bengaluru", "hyderabad", "chennai", "pune", "kolkata", "digital india", "gov.in", "nic.in"
        ]
    )

    return is_india_region or has_indian_enterprise


def extract_threat_actor(art: Dict[str, Any]) -> str:
    """
    Extract Threat Actor name from article.
    Returns 'Unknown' if no threat actor is identified.
    """
    actors = art.get("threat_actors") or []
    if isinstance(actors, list) and len(actors) > 0:
        valid_actors = [str(a).strip() for a in actors if a and str(a).strip()]
        if valid_actors:
            return ", ".join(valid_actors)
    if isinstance(actors, str) and actors.strip():
        return actors.strip()

    title = art.get("title") or ""
    summary = art.get("summary") or ""
    text = f"{title} {summary} {' '.join(art.get('tags') or [])}"

    for actor in KNOWN_ACTORS:
        if re.search(r'\b' + re.escape(actor) + r'\b', text, re.IGNORECASE):
            return actor.title()

    return "Unknown"


def _time_ago(dt_val: Any) -> str:
    """Return human-readable relative time string, e.g. '2 hours ago'."""
    if isinstance(dt_val, str):
        try:
            dt_val = datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
        except Exception:
            return "recently"
    if not isinstance(dt_val, datetime):
        return "recently"
    if dt_val.tzinfo is None:
        dt_val = dt_val.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt_val
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} minute{'s' if seconds // 60 != 1 else ''} ago"
    if seconds < 86400:
        return f"{seconds // 3600} hour{'s' if seconds // 3600 != 1 else ''} ago"
    days = seconds // 86400
    return f"{days} day{'s' if days != 1 else ''} ago"


def _company_initials(name: str) -> str:
    """Return up to 2 uppercase initials for a company name avatar."""
    words = [w for w in re.split(r'[\s\-&]+', name) if w]
    if len(words) >= 2:
        return (words[0][0] + words[1][0]).upper()
    return name[:2].upper() if len(name) >= 2 else name[0].upper()


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "E74C3C",
        "HIGH":     "E67E22",
        "MEDIUM":   "D4AF37",
        "INFO":     "3498DB",
    }.get(severity.upper(), "D4AF37")


def _impact_tags(art: Dict[str, Any]) -> str:
    """
    Build a 'Potential Impact' line from keyword-matched buckets ONLY.
    Never includes raw article tags (those are noisy/irrelevant for impact).
    Returns empty string if no impact keywords detected.
    """
    buckets: list[str] = []

    # Attack vector from helper
    vector = extract_claimed_vector(art)
    if vector:
        buckets.append(vector)

    text = f"{art.get('title', '')} {art.get('summary', '')}".lower()
    tag_map = [
        ("Unauthorized access", ["unauthorized access", "unauth", "access sold", "access claim"]),
        ("Data exfiltration",   ["exfiltrat", "data stolen", "stolen data", "dump", "leak"]),
        ("Credential theft",    ["credential", "password", "infostealer", "lumma", "redline"]),
        ("Reputational risk",   ["unverified", "claimed", "alleged", "unconfirmed"]),
        ("Ransomware",          ["ransomware", "encrypt", "lockbit", "akira", "clop"]),
        ("Financial impact",    ["financial", "payment", "fraud", "extortion"]),
        ("Service disruption",  ["downtime", "disruption", "outage", "ddos", "denial"]),
        ("Supply chain risk",   ["supply chain", "third-party", "vendor"]),
    ]
    for label, kws in tag_map:
        if label not in buckets and any(k in text for k in kws):
            buckets.append(label)

    if not buckets:
        return ""
    return "  ·  ".join(buckets[:5])


def build_threat_intelligence_breach_card(art: Dict[str, Any]) -> Dict[str, Any]:
    """
    CAO Company Breach Card — Clear · Accurate · Objective

    Teams MessageCard constraints respected:
    - No &nbsp; / HTML entities (render as literal text in Teams)
    - activityTitle/activitySubtitle always stack vertically — no inline columns
    - facts[] is the only reliable 2-column layout
    - severity goes in facts, not in subtitle

    Rendered structure:
      ─────────────────────────────────────────
      🔴 ACTIVE THREAT
      [Company Name]  ·  Country · Sector
      ─────────────────────────────────────────
      🔔 APP — NEW THREAT INTELLIGENCE
      [COUNTRY] Title
      Summary text...

      Severity        | MEDIUM
      Threat actor    | Unattributed
      News source     | OSINTxLab (linked)
      Board / section | Technology & Software
      Category        | Data Breach
      ─────────────────────────────────────────
      ⚠️ POTENTIAL IMPACT
      Unauthorized access  ·  Reputational risk
      ─────────────────────────────────────────
      📥 Collected ...   📡 Published ...
    """
    app_name = (getattr(settings, "APP_NAME", "") or "CLARITYTI").upper()
    platform_name_display = getattr(settings, "APP_NAME", "") or "ClarityTI"
    platform_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

    # ── Title & Country ───────────────────────────────────────────────────────
    raw_title = (art.get("title") or "Company Threat Intelligence Alert").strip()
    clean_title = re.sub(
        r'\s*-\s*(?:Reuters|BleepingComputer|The Hacker News|OSINTxLab|BreachNews|Dark Reading|SecurityWeek|CERT-In).*$',
        '', raw_title, flags=re.IGNORECASE
    ).strip()

    country = (art.get("target_country") or extract_country(art) or "GLOBAL").upper()
    if country == "UNKNOWN":
        country = "GLOBAL"
    formatted_title = clean_title if (clean_title.startswith("[") and "]" in clean_title) else f"[{country}] {clean_title}"

    # ── Company & Sector ──────────────────────────────────────────────────────
    extracted_company = extract_breached_company(art)
    company_val = extracted_company if extracted_company and extracted_company not in ("Not Specified", "") else "Target Enterprise"
    sector = determine_sector(art)
    board_section = "Databases" if any(k in clean_title.lower() for k in ["database", "db", "records", "leak", "dump"]) else sector
    country_display = country.title() if country != "GLOBAL" else "Global"

    # ── Source & URLs ─────────────────────────────────────────────────────────
    source_name = art.get("source_name") or "Threat Intel Feed"
    article_url = art.get("url") or platform_url

    # ── Threat Data ───────────────────────────────────────────────────────────
    threat_actor = extract_threat_actor(art)
    category = determine_incident_type(art)
    if category in ("Cyber Advisory", "Vulnerability"):
        category = "Data Leak" if "leak" in clean_title.lower() else "Data Breach"

    severity = extract_severity_level(art)
    clean_summary = clean_summary_text(art)

    # ── Timestamps ────────────────────────────────────────────────────────────
    collected_at = format_timestamp_pretty(art.get("crawled_at") or datetime.now(timezone.utc))
    published_at = format_timestamp_pretty(art.get("published_at") or datetime.now(timezone.utc))

    # ── Impact Tags ───────────────────────────────────────────────────────────
    impact_line = _impact_tags(art)

    # ── Theme colour ──────────────────────────────────────────────────────────
    theme_color = _severity_color(severity)

    # ── Sections ──────────────────────────────────────────────────────────────
    sections: List[Dict[str, Any]] = [
        # Section 1 — Identity header: company + location, no HTML tricks
        {
            "activityTitle": "🔴 ACTIVE THREAT",
            "activitySubtitle": f"{company_val}  ·  {country_display} · {sector}",
            "markdown": True,
        },
        # Section 2 — Intelligence body with facts grid
        {
            "activityTitle": f"🔔 {app_name} — NEW THREAT INTELLIGENCE",
            "activitySubtitle": formatted_title,
            "text": clean_summary,
            "facts": [
                {"name": "Severity",        "value": severity},
                {"name": "Threat actor",    "value": threat_actor},
                {"name": "News source",     "value": f"[{source_name}]({article_url})"},
                {"name": "Board / section", "value": board_section},
                {"name": "Category",        "value": category},
            ],
            "markdown": True,
        },
    ]

    # Section 3 — Potential Impact (keyword-matched only, no noisy tags)
    if impact_line:
        sections.append({
            "title": "⚠️ POTENTIAL IMPACT",
            "text": impact_line,
            "markdown": True,
        })

    # Section 4 — Timestamps footer
    sections.append({
        "facts": [
            {"name": "Collected",  "value": collected_at},
            {"name": "Published",  "value": published_at},
        ],
        "markdown": True,
    })

    # Evidence screenshot (if available)
    evidence_image_url = art.get("image_url") or art.get("screenshot_url")
    if evidence_image_url and evidence_image_url.startswith("http"):
        sections.append({
            "title": "SCREENSHOT",
            "images": [{"image": evidence_image_url, "title": f"Evidence — {company_val}"}],
            "markdown": True,
        })

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"{app_name}: {formatted_title}",
        "sections": sections,
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "View in Intel Feed",
                "targets": [{"os": "default", "uri": f"{platform_url}/feed/{art.get('_id') or art.get('id')}" if (art.get('_id') or art.get('id')) else f"{platform_url}/feed"}]
            },
            {
                "@type": "OpenUri",
                "name": f"Open {platform_name_display}",
                "targets": [{"os": "default", "uri": platform_url}]
            },
        ],
    }
    return card


    """
    CAO Company Breach Card — Clear · Accurate · Objective

    Layout (mirrors reference screenshot):
      ┌──────────────────────────────────────────┐
      │ 🔴 ACTIVE THREAT              [Category] │
      │ ██  Company Name     country · sector    │
      │     [SEVERITY badge]                      │
      ├──────────────────────────────────────────┤
      │ 🔔 APP — NEW THREAT INTELLIGENCE         │
      │ [COUNTRY] Title (bold)                   │
      │ Summary text ...                         │
      ├──────────────────────────────────────────┤
      │ Threat actor  │  News Source (link)      │
      │ Board/Section │  Category                │
      ├──────────────────────────────────────────┤
      │ ⚠️ POTENTIAL IMPACT                       │
      │ [tag] · [tag] · [tag]                    │
      ├──────────────────────────────────────────┤
      │ Collected: ...   Published: ...           │
      │                           [Details ↗]    │
      └──────────────────────────────────────────┘
    """
    app_name = (getattr(settings, "APP_NAME", "") or "CLARITYTI").upper()
    platform_name_display = getattr(settings, "APP_NAME", "") or "ClarityTI"
    platform_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

    # ── Title & Country ───────────────────────────────────────────────────────
    raw_title = (art.get("title") or "Company Threat Intelligence Alert").strip()
    clean_title = re.sub(
        r'\s*-\s*(?:Reuters|BleepingComputer|The Hacker News|OSINTxLab|BreachNews|Dark Reading|SecurityWeek|CERT-In).*$',
        '', raw_title, flags=re.IGNORECASE
    ).strip()

    country = (art.get("target_country") or extract_country(art) or "GLOBAL").upper()
    if country == "UNKNOWN":
        country = "GLOBAL"

    formatted_title = clean_title if (clean_title.startswith("[") and "]" in clean_title) else f"[{country}] {clean_title}"

    # ── Company & Sector ──────────────────────────────────────────────────────
    extracted_company = extract_breached_company(art)
    company_val = extracted_company if extracted_company and extracted_company not in ("Not Specified", "") else "Target Enterprise"
    initials = _company_initials(company_val)
    sector = determine_sector(art)
    board_section = "Databases" if any(k in clean_title.lower() for k in ["database", "db", "records", "leak", "dump"]) else sector
    country_display = country.title() if country != "GLOBAL" else "Global"

    # ── Source & URLs ─────────────────────────────────────────────────────────
    source_name = art.get("source_name") or "Threat Intel Feed"
    article_url = art.get("url") or platform_url

    # ── Threat Data ───────────────────────────────────────────────────────────
    threat_actor = extract_threat_actor(art)
    category = determine_incident_type(art)
    if category in ("Cyber Advisory", "Vulnerability"):
        category = "Data Leak" if "leak" in clean_title.lower() else "Data Breach"

    severity = extract_severity_level(art)
    clean_summary = clean_summary_text(art)

    # ── Timestamps ────────────────────────────────────────────────────────────
    collected_at = format_timestamp_pretty(art.get("crawled_at") or datetime.now(timezone.utc))
    published_at = format_timestamp_pretty(art.get("published_at") or datetime.now(timezone.utc))

    # ── Impact Tags ───────────────────────────────────────────────────────────
    impact_line = _impact_tags(art)

    # ── Theme colour ──────────────────────────────────────────────────────────
    theme_color = _severity_color(severity)

    # ── Card Sections ─────────────────────────────────────────────────────────
    sections: List[Dict[str, Any]] = [
        # Section 1 — Header banner (company identity + severity)
        {
            "activityTitle": f"🔴 **ACTIVE THREAT** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; **{category}**",
            "activitySubtitle": (
                f"**{initials}** &nbsp; **{company_val}** &nbsp;&nbsp; "
                f"📍 {country_display} · {sector} &nbsp;&nbsp; "
                f"**[{severity}]**"
            ),
            "markdown": True,
        },
        # Section 2 — Intelligence body
        {
            "activityTitle": f"🔔 **{app_name} — NEW THREAT INTELLIGENCE**",
            "activitySubtitle": f"**{formatted_title}**",
            "text": clean_summary,
            "facts": [
                {"name": "Threat actor",  "value": threat_actor},
                {"name": "News source",   "value": f"[{source_name}]({article_url})"},
                {"name": "Board / section", "value": board_section},
                {"name": "Category",      "value": category},
            ],
            "markdown": True,
        },
    ]

    # Section 3 — Potential Impact (only if tags exist)
    if impact_line:
        sections.append({
            "title": "⚠️ POTENTIAL IMPACT",
            "text": impact_line,
            "markdown": True,
        })

    # Section 4 — Timestamps footer
    sections.append({
        "text": (
            f"📥 Collected {collected_at} &nbsp;&nbsp; "
            f"📡 Published {published_at}"
        ),
        "markdown": True,
    })

    # Evidence screenshot (if available)
    evidence_image_url = art.get("image_url") or art.get("screenshot_url")
    if evidence_image_url and evidence_image_url.startswith("http"):
        sections.append({
            "title": "SCREENSHOT",
            "images": [{"image": evidence_image_url, "title": f"Evidence — {company_val}"}],
            "markdown": True,
        })

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"{app_name}: {formatted_title}",
        "sections": sections,
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": f"Details ↗",
                "targets": [{"os": "default", "uri": f"{platform_url}/feed?url={article_url}"}]
            },
            {
                "@type": "OpenUri",
                "name": f"Open in {platform_name_display}",
                "targets": [{"os": "default", "uri": platform_url}]
            },
        ],
    }
    return card



def build_general_advisory_card(art: Dict[str, Any]) -> Dict[str, Any]:
    """
    CAO Non-Company Advisory Card — Clear · Accurate · Objective

    Teams MessageCard constraints respected:
    - No &nbsp; / HTML entities
    - source + time-ago in activitySubtitle (no inline badge tricks)
    - severity as a proper fact row
    - CVSS / exploit / affected systems in facts grid
    - Tags as comma-separated text

    Rendered structure:
      ─────────────────────────────────────────
      🛡️ ZERO-DAY · VULNERABILITY
      Source Name  ·  2 hours ago
      ─────────────────────────────────────────
      Title
      Summary text...

      Severity         | HIGH
      CVSS score       | 9.8 / 10
      Exploit status   | Active ITW
      Affected systems | 12M+ devices
      CVEs / IDs       | CVE-2026-3821
      ─────────────────────────────────────────
      Tags: RCE, VPN, Zero-day, CVE-2026-3821
      ─────────────────────────────────────────
      📅 Aug 20, 2026, 10:00 AM
    """
    platform_name_display = getattr(settings, "APP_NAME", "") or "ClarityTI"
    platform_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

    # ── Title & Country ───────────────────────────────────────────────────────
    raw_title = (art.get("title") or "Cyber Security Advisory").strip()
    clean_title = re.sub(
        r'\s*-\s*(?:Reuters|BleepingComputer|The Hacker News|OSINTxLab|BreachNews|Dark Reading|SecurityWeek|CERT-In).*$',
        '', raw_title, flags=re.IGNORECASE
    ).strip()

    country = (art.get("target_country") or extract_country(art) or "GLOBAL").upper()
    if country == "UNKNOWN":
        country = "GLOBAL"
    formatted_title = clean_title if (clean_title.startswith("[") and "]" in clean_title) else f"[{country}] {clean_title}"

    # ── Source & timing ───────────────────────────────────────────────────────
    source_name = art.get("source_name") or "Cyber Advisory Source"
    article_url = art.get("url") or platform_url
    pub_dt = art.get("published_at") or art.get("crawled_at")
    time_ago_str = _time_ago(pub_dt)
    date_of_publish = format_timestamp_pretty(pub_dt or datetime.now(timezone.utc))

    # ── Classification ────────────────────────────────────────────────────────
    incident_type = determine_incident_type(art)
    severity = extract_severity_level(art)
    clean_summary = clean_summary_text(art)

    # ── CVSS / Exploit status / Affected systems ──────────────────────────────
    cves: list = art.get("cves") or []
    cve_text = ", ".join(cves[:3]) if cves else "N/A"

    cvss_raw = art.get("cvss_score") or art.get("cvss")
    if cvss_raw:
        try:
            cvss_display = f"{float(str(cvss_raw)):.1f} / 10"
        except ValueError:
            cvss_display = str(cvss_raw)
    else:
        m = re.search(r'cvss[:\s]+([0-9]+(?:\.[0-9]+)?)', f"{art.get('title','')} {art.get('summary','')}", re.IGNORECASE)
        cvss_display = f"{float(m.group(1)):.1f} / 10" if m else "N/A"

    exploit_status = art.get("exploit_status") or ""
    if not exploit_status:
        text_lower = f"{art.get('title','')} {art.get('summary','')}".lower()
        if any(k in text_lower for k in ["actively exploit", "in the wild", "itw", "mass exploit"]):
            exploit_status = "Active ITW"
        elif any(k in text_lower for k in ["poc", "proof of concept", "exploit available"]):
            exploit_status = "PoC Available"
        elif any(k in text_lower for k in ["no known exploit", "no exploit"]):
            exploit_status = "No Known Exploit"
        else:
            exploit_status = "Unknown"

    affected_systems = art.get("affected_systems") or art.get("affected_products") or ""
    if not affected_systems:
        m2 = re.search(r'(\d+[MBKmk+,\.]+\s*(?:device|system|user|machine|server|endpoint)s?)', f"{art.get('title','')} {art.get('summary','')}", re.IGNORECASE)
        affected_systems = m2.group(1).strip() if m2 else "N/A"

    # ── Tags — use article tags + CVE IDs, comma-separated plain text ─────────
    raw_tags: list[str] = [str(t).strip() for t in (art.get("tags") or []) if t]
    for cve in cves[:2]:
        if cve.upper() not in [t.upper() for t in raw_tags]:
            raw_tags.append(cve.upper())
    tag_text = ", ".join(raw_tags[:8]) if raw_tags else ""

    # ── Category label ────────────────────────────────────────────────────────
    type_upper = incident_type.upper()
    if "ZERO" in type_upper or "0-DAY" in type_upper:
        category_label = "🛡️ ZERO-DAY · VULNERABILITY"
    elif "RANSOMWARE" in type_upper:
        category_label = "🔴 RANSOMWARE · EXTORTION"
    elif "PHISHING" in type_upper:
        category_label = "🎣 PHISHING · SOCIAL ENGINEERING"
    elif "APT" in type_upper or "NATION" in type_upper:
        category_label = "🕵️ APT · NATION-STATE CAMPAIGN"
    elif "SUPPLY" in type_upper:
        category_label = "🔗 SUPPLY CHAIN · THIRD PARTY RISK"
    else:
        category_label = f"🛡️ {incident_type.upper()} · ADVISORY"

    # ── Theme colour ──────────────────────────────────────────────────────────
    theme_color = _severity_color(severity)

    # ── Sections ─────────────────────────────────────────────────────────────
    sections: List[Dict[str, Any]] = [
        # Section 1 — Category header + source + time-ago (no HTML tricks)
        {
            "activityTitle": category_label,
            "activitySubtitle": f"[{source_name}]({article_url})  ·  {time_ago_str}",
            "markdown": True,
        },
        # Section 2 — Title + summary + structured facts
        {
            "activityTitle": formatted_title,
            "text": clean_summary,
            "facts": [
                {"name": "Severity",         "value": severity},
                {"name": "CVSS score",        "value": cvss_display},
                {"name": "Exploit status",    "value": exploit_status},
                {"name": "Affected systems",  "value": affected_systems},
                {"name": "CVEs / IDs",        "value": cve_text},
            ],
            "markdown": True,
        },
    ]

    # Section 3 — Tags (comma-separated plain text, no bracket noise)
    if tag_text:
        sections.append({
            "title": "Tags",
            "text": tag_text,
            "markdown": True,
        })

    # Section 4 — Timestamp footer
    sections.append({
        "text": f"📅 {date_of_publish}",
        "markdown": True,
    })

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": formatted_title,
        "sections": sections,
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "Mitigate",
                "targets": [{"os": "default", "uri": f"{platform_url}/feed?url={article_url}"}]
            },
            {
                "@type": "OpenUri",
                "name": "Full report",
                "targets": [{"os": "default", "uri": article_url}]
            },
        ],
    }
    return card



def build_high_priority_news_card(
    stats: Dict[str, Any],
    top_india_articles: Optional[List[Dict[str, Any]]] = None,
    top_me_articles: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Build a comprehensive, executive High Priority News card for #high-priority-news.
    Highlights critical & high-severity data breaches, leaks, zero-days, ransomware,
    and major cyber incidents across both Indian & Middle-East regions.
    """
    app_name = (getattr(settings, "APP_NAME", "") or "WAY TO PLUTO").upper()
    platform_name_display = getattr(settings, "APP_NAME", "") or "Way to Pluto"
    teams_channel_url = "https://teams.microsoft.com/l/channel/19%3A69xRCKykkXcRIZu3FwOaxVQV-zqgYeE_SJnfSHLjLwE1%40thread.tacv2/High%20Priority%20News?groupId=ef4a0e0d-45e1-48e7-b801-bb1b0e2be4f1&tenantId=e78b42b1-6acb-4e15-a598-630a52228076"

    date_str = datetime.now(timezone.utc).strftime("%d %b %Y, %I:%M %p UTC")

    india_total = stats.get("india_total", 0)
    india_breaches = stats.get("india_breaches", 0)
    india_advisories = stats.get("india_advisories", 0)

    me_total = stats.get("me_total", 0)
    me_breaches = stats.get("me_breaches", 0)
    me_advisories = stats.get("me_advisories", 0)

    total_dispatched = stats.get("total_dispatched", india_total + me_total)
    critical_count = stats.get("critical_count", 0)

    top_companies = stats.get("top_companies", [])
    top_companies_str = ", ".join(top_companies[:4]) if top_companies else "None reported"

    top_actors = stats.get("top_actors", [])
    top_actors_str = ", ".join(top_actors[:4]) if top_actors else "Unknown / Unattributed"

    # Build Highlights text for India and Middle East breaches & leaks
    highlight_lines = []

    if top_india_articles:
        highlight_lines.append("🇮🇳 **India — Top Breaches & Leaks:**")
        for art in top_india_articles[:4]:
            t = (art.get("title") or "Advisory").strip()[:80]
            u = art.get("url") or "http://localhost:3000"
            is_br = is_company_breach_or_incident(art)
            prefix = "🚨 [HIGH BREACH / LEAK]" if is_br else "🛡️ [ADVISORY]"
            highlight_lines.append(f"• {prefix} [{t}]({u})")
        highlight_lines.append("")

    if top_me_articles:
        highlight_lines.append("🌍 **Middle East — Top Breaches & Leaks:**")
        for art in top_me_articles[:4]:
            t = (art.get("title") or "Advisory").strip()[:80]
            u = art.get("url") or "http://localhost:3000"
            is_br = is_company_breach_or_incident(art)
            prefix = "🚨 [HIGH BREACH / LEAK]" if is_br else "🛡️ [ADVISORY]"
            highlight_lines.append(f"• {prefix} [{t}]({u})")

    highlights_text = "\n".join(highlight_lines) if highlight_lines else "All High Priority Indian & Middle East pipelines active."

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "9B59B6",  # Deep Purple theme
        "summary": f"{app_name} High Priority News: {total_dispatched} Critical Breaches & Leaks Delivered",
        "sections": [
            {
                "activityTitle": f"⚡ **{app_name} — HIGH PRIORITY NEWS**",
                "activitySubtitle": f"🚨 High Priority Breaches, Leaks & Threat Intelligence (India & Middle East) · {date_str}",
                "text": "Automated high-priority threat intelligence summary featuring top breaches, database leaks, and critical security incidents for India and Middle East:",
                "facts": [
                    {
                        "name": "🇮🇳 Indian Breaches & News",
                        "value": f"**{india_total} Delivered** ({india_breaches} Breaches, {india_advisories} Advisories)"
                    },
                    {
                        "name": "🌍 Middle-East Breaches & News",
                        "value": f"**{me_total} Delivered** ({me_breaches} Breaches, {me_advisories} Advisories)"
                    },
                    {
                        "name": "Total Dispatched Alerts",
                        "value": f"**{total_dispatched} Dispatched**"
                    },
                    {
                        "name": "High / Critical Threat Level",
                        "value": f"🔥 {critical_count} Critical Incident(s)"
                    },
                    {
                        "name": "Targeted Organizations",
                        "value": top_companies_str
                    },
                    {
                        "name": "Threat Actors Detected",
                        "value": top_actors_str
                    },
                    {
                        "name": "Channel Link",
                        "value": f"[High Priority News Channel]({teams_channel_url})"
                    }
                ],
                "markdown": True,
            },
            {
                "title": "📋 **High Priority Regional Breaches & Leaks**",
                "text": highlights_text,
                "markdown": True,
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "Open High Priority News Channel",
                "targets": [{"os": "default", "uri": teams_channel_url}]
            },
            {
                "@type": "OpenUri",
                "name": f"Open {platform_name_display} Dashboard",
                "targets": [{"os": "default", "uri": "http://localhost:3000"}]
            }
        ],
    }
    return card


# Alias for backward compatibility
build_daily_cti_digest_card = build_high_priority_news_card


# ── Source Diversity, Company-Priority & Best+Immediate Sorting Helpers ──────────

_MAX_ARTICLES_PER_SOURCE = 3   # No single source dominates a channel dispatch
_MAX_COMPANY_SLOTS = 15        # Reserve up to 15 of the 20 slots for company breaches
_MAX_ADVISORY_SLOTS = 5        # Remaining 5 slots for general advisories
_MAX_DISPATCH_SLOTS = 20       # Total articles per channel dispatch
_IMMEDIATE_HOURS = 6           # Articles published within 6h are treated as "breaking"

# Severity weights — higher = sent first
_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "INFO":     1,
    "INFORMATIONAL": 1,
}


def _article_published_ts(art: Dict[str, Any]) -> datetime:
    """Return timezone-aware published_at datetime for sorting (fallback: epoch)."""
    pub = art.get("published_at") or art.get("crawled_at")
    if isinstance(pub, datetime):
        return pub if pub.tzinfo else pub.replace(tzinfo=timezone.utc)
    if isinstance(pub, str):
        try:
            dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _sort_best_and_immediate(articles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sort articles so the most relevant items appear first.

    Priority key (descending):
      1. Breaking / Immediate — articles published within _IMMEDIATE_HOURS (6h) come before older ones
      2. Severity weight     — CRITICAL > HIGH > MEDIUM > INFO within the same freshness tier
      3. Recency             — newer published_at wins when severity is equal

    This ensures Teams always receives the BEST and most IMMEDIATE intel first.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=_IMMEDIATE_HOURS)

    def _sort_key(art: Dict[str, Any]):
        sev_str = str(art.get("severity") or extract_severity_level(art)).upper()
        sev_weight = _SEVERITY_RANK.get(sev_str, 1)
        pub_ts = _article_published_ts(art)
        is_immediate = 1 if pub_ts >= cutoff else 0   # 1 = breaking, 0 = older
        return (is_immediate, sev_weight, pub_ts)

    return sorted(articles, key=_sort_key, reverse=True)


def _apply_source_diversity_cap(
    articles: List[Dict[str, Any]],
    max_per_source: int = _MAX_ARTICLES_PER_SOURCE,
) -> List[Dict[str, Any]]:
    """
    Enforce per-source diversity cap so no single source (e.g. OSINTxLab) can
    monopolise a channel dispatch.
    Preserves the incoming ordering (caller should pre-sort with _sort_best_and_immediate).
    """
    source_counts: Dict[str, int] = {}
    capped: List[Dict[str, Any]] = []
    for art in articles:
        src = (art.get("source_name") or "unknown").lower().strip()
        count = source_counts.get(src, 0)
        if count < max_per_source:
            capped.append(art)
            source_counts[src] = count + 1
    return capped


def _prioritize_company_breaches(
    articles: List[Dict[str, Any]],
    max_company_slots: int = _MAX_COMPANY_SLOTS,
    max_advisory_slots: int = _MAX_ADVISORY_SLOTS,
) -> List[Dict[str, Any]]:
    """
    Company-specific breach / ransomware / extortion articles are placed first
    (critical for India & Middle East channels per business requirement).
    General advisories, CERT bulletins, and CVE news fill the remaining slots.

    Within each bucket the best+immediate ordering from _sort_best_and_immediate is preserved.
    """
    company_breaches = [art for art in articles if is_company_breach_or_incident(art)]
    general_advisories = [art for art in articles if not is_company_breach_or_incident(art)]
    return company_breaches[:max_company_slots] + general_advisories[:max_advisory_slots]


def build_single_article_card(art: Dict[str, Any]) -> Dict[str, Any]:
    """
    Builds the official CyberPulse High Priority / Severe Alert Adaptive Card
    for high severity and critical intelligence items.
    """
    return TeamsService.build_high_severity_article_card(art)


class TeamsService:
    """Service to send structured threat intelligence, breach cards, and daily digest to MS Teams Webhooks."""

    @staticmethod
    async def send_test_webhook(webhook_url: str) -> bool:
        """Send a test CyberPulse High Priority Alert card to MS Teams."""
        if not webhook_url or not webhook_url.startswith("http"):
            raise ValueError("Invalid Webhook URL. Must start with http:// or https://")

        sample_event = {
            "title": "Microsoft Teams Integration Test Verified — ClarityTI",
            "heat_score": 95,
            "source_count": 12,
            "article_count": 18,
            "trend": "increasing",
            "unique_source_names": [
                "The Hacker News", "BleepingComputer", "SecurityWeek", "Dark Reading", "Recorded Future News",
                "ThreatPost", "Cyble", "Infosecurity Magazine", "The Register", "Security Affairs"
            ],
            "first_detected_at": datetime.now(timezone.utc),
            "last_detected_at": datetime.now(timezone.utc),
            "event_id": "TEST-001"
        }
        card = TeamsService.build_cyberpulse_high_priority_card(sample_event)

        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.post(webhook_url, json=card)
            if resp.status_code not in (200, 202, 204):
                raise RuntimeError(f"MS Teams Webhook returned status {resp.status_code}: {resp.text}")
        return True

    @staticmethod
    async def send_company_breaches(webhook_url: str, articles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Send ONLY verified High/Critical Severity alerts to MS Teams with the official CyberPulse template.
        """
        if not webhook_url:
            return {"sent": 0, "message": "No articles or missing webhook"}

        sent_count = 0
        dispatched_details = []

        # STRICT FILTER: ONLY HIGH & CRITICAL SEVERITY NEWS PUBLISHED WITHIN LAST 24 HOURS (TODAY)
        cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)

        def _is_strictly_today(a):
            p = a.get("published_at") or a.get("crawled_at")
            if not p:
                return True
            if isinstance(p, str):
                try:
                    p = datetime.fromisoformat(p.replace("Z", "+00:00"))
                except Exception:
                    return True
            if p.tzinfo is None:
                p = p.replace(tzinfo=timezone.utc)
            return p >= cutoff_24h

        high_severe_breaches = [
            art for art in articles
            if is_cyber_news(art) and extract_severity_level(art) in ("CRITICAL", "HIGH") and _is_strictly_today(art)
        ]

        if not high_severe_breaches:
            return {"status": "success", "sent": 0, "message": "No fresh high/severe articles published in the last 24 hours."}

        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            for art in high_severe_breaches:
                if _is_already_dispatched(art, webhook_url):
                    continue
                card_payload = TeamsService.build_high_severity_article_card(art)
                company_name = extract_breached_company(art)
                status_tag = determine_breach_status(art)

                try:
                    resp = await client.post(webhook_url, json=card_payload)
                    if resp.status_code in (200, 202, 204):
                        await _mark_dispatched_in_db(art, webhook_url)
                        sent_count += 1
                        dispatched_details.append({
                            "company": company_name,
                            "status_tag": status_tag,
                            "title": art.get("title"),
                            "status": "sent"
                        })
                except Exception as e:
                    log.error("Failed sending high severity alert card to Teams", company=company_name, error=str(e))

                await asyncio.sleep(0.4)

        return {
            "status": "success",
            "sent": sent_count,
            "dispatched": dispatched_details,
            "message": f"Successfully dispatched {sent_count} high-severity alert cards to Teams!",
        }

    @staticmethod
    async def send_todays_news(webhook_url: str, articles: List[Dict[str, Any]], channel_webhooks: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Send Today's High-Severity Cyber News to Microsoft Teams,
        using the standardized CyberPulse High Priority / Severe Alert Template.
        STRICT REJECTION OF ANY NEWS OLDER THAN 24 HOURS.
        """
        if not articles:
            return {"sent": 0, "message": "No articles to dispatch"}

        cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)

        def _is_strictly_today(a):
            p = a.get("published_at") or a.get("crawled_at")
            if not p:
                return True
            if isinstance(p, str):
                try:
                    p = datetime.fromisoformat(p.replace("Z", "+00:00"))
                except Exception:
                    return True
            if p.tzinfo is None:
                p = p.replace(tzinfo=timezone.utc)
            return p >= cutoff_24h

        # Strictly filter out duplicate articles & old articles
        non_duplicate_articles = []
        seen_fingerprints = set()

        for art in articles:
            if art.get("is_duplicate") is True:
                continue
            if not _is_strictly_today(art):
                continue
            title = (art.get("title") or "").strip().lower()
            if not title:
                continue
            fp = re.sub(r'[^a-z0-9]', '', title)[:50]
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)
            non_duplicate_articles.append(art)

        # STRICT FILTER: ONLY HIGH & CRITICAL SEVERITY NEWS
        high_severe_articles = [
            art for art in non_duplicate_articles
            if is_cyber_news(art) and (
                extract_severity_level(art) in ("CRITICAL", "HIGH")
                or str(art.get("severity", "")).upper() in ("CRITICAL", "HIGH")
                or art.get("cves")
                or (art.get("threat_actors") and any(a for a in art.get("threat_actors") if str(a).lower() not in ("unattributed", "unknown", "none")))
            )
        ]

        cyber_articles = [art for art in non_duplicate_articles if is_cyber_news(art)]
        if not cyber_articles:
            return {"status": "success", "sent": 0, "message": "No cyber-related articles to dispatch."}

        webhooks = dict(channel_webhooks or {})

        import os
        # Populate webhooks from environment or settings if missing
        common_pulse = (
            getattr(settings, "TEAMS_WEBHOOK_URL_CYBER_PULSE", "") or
            getattr(settings, "TEAMS_WEBHOOK_URL", "") or
            getattr(settings, "CYBER_PULSE_WEBHOOK_URL", "") or
            os.environ.get("TEAMS_WEBHOOK_URL_CYBER_PULSE", "") or
            os.environ.get("TEAMS_WEBHOOK_URL", "") or
            os.environ.get("CYBER_PULSE_WEBHOOK_URL", "")
        )
        env_map = {
            "cyber-pulse": common_pulse,
            "high-priority-news": getattr(settings, "TEAMS_WEBHOOK_URL_HIGH_PRIORITY_NEWS", "") or common_pulse,
            "daily-cti-digest": getattr(settings, "TEAMS_WEBHOOK_URL_DAILY_DIGEST", "") or common_pulse,
            "indian-breaches": getattr(settings, "TEAMS_WEBHOOK_URL_INDIAN_BREACHES", "") or getattr(settings, "TEAMS_WEBHOOK_URL_INDIAN_BASED", "") or common_pulse,
            "middle-east-companies": getattr(settings, "TEAMS_WEBHOOK_URL_MIDDLE_EAST_COMPANIES", "") or getattr(settings, "TEAMS_WEBHOOK_URL_GCC_MIDDLE_EAST", "") or common_pulse,
        }
        for ch_key, ch_env in env_map.items():
            if ch_env and not webhooks.get(ch_key):
                webhooks[ch_key] = ch_env

        # Also support alias keys passed in webhooks dictionary
        if "cyber_pulse" in webhooks and "cyber-pulse" not in webhooks:
            webhooks["cyber-pulse"] = webhooks["cyber_pulse"]
        if "indian-based" in webhooks and "indian-breaches" not in webhooks:
            webhooks["indian-breaches"] = webhooks["indian-based"]
        if "gcc-middle-east" in webhooks and "middle-east-companies" not in webhooks:
            webhooks["middle-east-companies"] = webhooks["gcc-middle-east"]
        if "daily_digest" in webhooks and "high-priority-news" not in webhooks:
            webhooks["high-priority-news"] = webhooks["daily_digest"]
        if "daily-cti-digest" in webhooks and "high-priority-news" not in webhooks:
            webhooks["high-priority-news"] = webhooks["daily-cti-digest"]
        if "high_priority_news" in webhooks and "high-priority-news" not in webhooks:
            webhooks["high-priority-news"] = webhooks["high_priority_news"]

        total_dispatched_by_channel = {}
        total_sent = 0

        if not high_severe_articles:
            return {"status": "success", "sent": 0, "message": "No high-severity cyber articles matched filter."}

        # Categorize regional articles strictly from high-severity dataset
        raw_india_articles = [art for art in high_severe_articles if is_indian_news(art)]
        raw_me_articles    = [art for art in high_severe_articles if is_gcc_middle_east_news(art)]

        # ── Stage 1: Sort by best (severity) + immediate (recency) ───────────────
        sorted_india = _sort_best_and_immediate(raw_india_articles)
        sorted_me    = _sort_best_and_immediate(raw_me_articles)

        # ── Stage 2: Source diversity cap — max 3 per source ─────────────────────
        capped_india = _apply_source_diversity_cap(sorted_india)
        capped_me    = _apply_source_diversity_cap(sorted_me)

        # ── Stage 3: Company breaches first, then general advisories ─────────────
        matching_india_articles = _prioritize_company_breaches(capped_india)
        matching_me_articles    = _prioritize_company_breaches(capped_me)

        now_utc = datetime.now(timezone.utc)
        _imm_cutoff = now_utc - timedelta(hours=_IMMEDIATE_HOURS)

        log.info(
            "Regional high-severity pipeline: sort -> cap -> prioritise",
            india_raw=len(raw_india_articles),
            india_immediate=sum(1 for a in raw_india_articles if _article_published_ts(a) >= _imm_cutoff),
            india_final=len(matching_india_articles),
            me_raw=len(raw_me_articles),
            me_immediate=sum(1 for a in raw_me_articles if _article_published_ts(a) >= _imm_cutoff),
            me_final=len(matching_me_articles),
        )

        india_sent_count = 0
        india_breaches_count = 0
        india_advisories_count = 0

        me_sent_count = 0
        me_breaches_count = 0
        me_advisories_count = 0

        critical_count = 0
        targeted_companies = set()
        active_threat_actors = set()

        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            # 1. Dispatch individual cards to #indian-breaches (ONLY India articles)
            indian_webhook = webhooks.get("indian-breaches") or webhooks.get("indian-based")
            if indian_webhook and matching_india_articles:
                for art in matching_india_articles[:_MAX_DISPATCH_SLOTS]:
                    is_br = is_company_breach_or_incident(art)
                    if is_br:
                        india_breaches_count += 1
                        comp = extract_breached_company(art)
                        if comp != "Not Specified":
                            targeted_companies.add(comp)
                    else:
                        india_advisories_count += 1

                    sev = extract_severity_level(art)
                    if sev in ("CRITICAL", "HIGH"):
                        critical_count += 1

                    actor = extract_threat_actor(art)
                    if actor != "Unknown":
                        active_threat_actors.add(actor)

                    if _is_already_dispatched(art, indian_webhook):
                        continue
                    card = build_single_article_card(art)
                    try:
                        resp = await client.post(indian_webhook, json=card)
                        if resp.status_code in (200, 202, 204):
                            await _mark_dispatched_in_db(art, indian_webhook)
                            india_sent_count += 1
                            total_sent += 1
                    except Exception as e:
                        log.error("Failed to post card to Indian channel", error=str(e))

                    await asyncio.sleep(0.35)

                total_dispatched_by_channel["#indian-breaches"] = india_sent_count

            # 2. Dispatch individual cards to #middle-east-companies (ONLY Middle East articles)
            me_webhook = webhooks.get("middle-east-companies") or webhooks.get("gcc-middle-east")
            if me_webhook and matching_me_articles:
                for art in matching_me_articles[:_MAX_DISPATCH_SLOTS]:
                    is_br = is_company_breach_or_incident(art)
                    if is_br:
                        me_breaches_count += 1
                        comp = extract_breached_company(art)
                        if comp != "Not Specified":
                            targeted_companies.add(comp)
                    else:
                        me_advisories_count += 1

                    sev = extract_severity_level(art)
                    if sev in ("CRITICAL", "HIGH"):
                        critical_count += 1

                    actor = extract_threat_actor(art)
                    if actor != "Unknown":
                        active_threat_actors.add(actor)

                    if _is_already_dispatched(art, me_webhook):
                        continue
                    card = build_single_article_card(art)
                    try:
                        resp = await client.post(me_webhook, json=card)
                        if resp.status_code in (200, 202, 204):
                            await _mark_dispatched_in_db(art, me_webhook)
                            me_sent_count += 1
                            total_sent += 1
                    except Exception as e:
                        log.error("Failed to post card to Middle East channel", error=str(e))

                    await asyncio.sleep(0.35)

                total_dispatched_by_channel["#middle-east-companies"] = me_sent_count

            # 3. Dispatch separate cards to #high-priority-news (India & Middle East)
            high_priority_webhook = webhooks.get("high-priority-news") or webhooks.get("high_priority_news") or webhooks.get("daily-cti-digest")
            if high_priority_webhook:
                hp_sent_count = 0
                all_high_priority = []
                seen_ids = set()
                for art in matching_india_articles + matching_me_articles:
                    aid = art.get("_id") or art.get("url") or art.get("title")
                    if aid not in seen_ids:
                        seen_ids.add(aid)
                        all_high_priority.append(art)

                # Send separate individual cards for each high priority article
                for art in all_high_priority[:_MAX_DISPATCH_SLOTS]:
                    if _is_already_dispatched(art, high_priority_webhook):
                        continue
                    card = build_single_article_card(art)
                    try:
                        resp = await client.post(high_priority_webhook, json=card)
                        if resp.status_code in (200, 202, 204):
                            await _mark_dispatched_in_db(art, high_priority_webhook)
                            hp_sent_count += 1
                            total_sent += 1
                    except Exception as e:
                        log.error("Failed to post card to High Priority News channel", error=str(e))

                    await asyncio.sleep(0.35)

                total_dispatched_by_channel["#high-priority-news"] = hp_sent_count

            # 4. Dispatch cards to #cyber-pulse (Top High-Severity Threat Pulse)
            cyber_pulse_webhook = webhooks.get("cyber-pulse") or webhooks.get("cyber_pulse")
            if cyber_pulse_webhook:
                pulse_sent_count = 0
                sorted_cyber = _sort_best_and_immediate(high_severe_articles)
                capped_cyber = _apply_source_diversity_cap(sorted_cyber)
                priority_cyber = _prioritize_company_breaches(capped_cyber)

                for art in priority_cyber[:_MAX_DISPATCH_SLOTS]:
                    if _is_already_dispatched(art, cyber_pulse_webhook):
                        continue
                    card = build_single_article_card(art)
                    try:
                        resp = await client.post(cyber_pulse_webhook, json=card)
                        if resp.status_code in (200, 202, 204):
                            await _mark_dispatched_in_db(art, cyber_pulse_webhook)
                            pulse_sent_count += 1
                            total_sent += 1
                    except Exception as e:
                        log.error("Failed to post card to Cyber-Pulse channel", error=str(e))

                    await asyncio.sleep(0.35)

                total_dispatched_by_channel["#cyber-pulse"] = pulse_sent_count

        return {
            "status": "success",
            "sent": total_sent,
            "channels_updated": list(total_dispatched_by_channel.keys()),
            "channel_counts": total_dispatched_by_channel,
            "digest_summary": {
                "india_delivered": india_sent_count or len(matching_india_articles),
                "middle_east_delivered": me_sent_count or len(matching_me_articles),
                "total_dispatched": total_sent,
            }
        }

    @staticmethod
    def build_critical_card(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build the Critical Card (CyberPulse Alert):
        - Score calculated from source corroboration / heat calculation
        - Top Row: [Score Box] | [Threat Actor]
        - Middle Row: [Short Description]
        - Bottom Row: [Details: Country, Sector, Category] | [Title]
        - Action Button: 'View on CyberPulse' -> /cyberpulse?event={event_id}
        """
        title = (event.get("title") or "Critical Cyber Threat Alert").strip()
        
        # Calculate Score strictly based on corroboration / source count if event
        source_count = int(event.get("source_count") or len(event.get("unique_source_names") or []) or 1)
        heat_score = event.get("heat_score")
        if heat_score is not None and int(heat_score) > 0:
            score_val = int(heat_score)
        else:
            # Dynamic heat score calculation based on reporting source breadth
            if source_count >= 10:
                score_val = 95
            elif source_count >= 7:
                score_val = 85
            elif source_count >= 4:
                score_val = 75
            elif source_count >= 2:
                score_val = 65
            else:
                score_val = int(event.get("cyber_risk_score") or 60)

        pill_label = "🔥 CRITICAL" if score_val >= 80 else ("⚡ HIGH" if score_val >= 60 else "🟢 MEDIUM")

        # Threat Actor extraction
        actor = extract_threat_actor(event)
        if actor and actor.lower() not in ("unknown", "unattributed", "none", ""):
            actor_display = actor
            actor_color = "Good"
        else:
            actor_display = "Unattributed"
            actor_color = "Default"

        # Details
        country = (event.get("target_country") or extract_country(event) or "Global").upper()
        sector = determine_sector(event)
        category = determine_incident_type(event)
        summary = clean_summary_text(event)

        event_id = event.get("event_id") or event.get("viral_event_id") or "CP-001"
        platform_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000").rstrip("/")
        pulse_url = f"{platform_url}/cyberpulse?event={event_id}"

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            # Alert Banner Header
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "auto",
                                        "items": [{"type": "TextBlock", "text": "🚨", "size": "ExtraLarge"}]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": "CYBERPULSE — CRITICAL ALERT",
                                                "weight": "Bolder",
                                                "size": "Large",
                                                "color": "Attention"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": f"Severe Cyber Threat Intelligence · {source_count} Sources Corroborating",
                                                "isSubtle": True,
                                                "spacing": "None"
                                            }
                                        ]
                                    }
                                ]
                            },
                            # 1. Top Row: [Score] | [Threat Actor]
                            {
                                "type": "ColumnSet",
                                "spacing": "Medium",
                                "separator": True,
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "auto",
                                        "items": [
                                            {
                                                "type": "Container",
                                                "style": "attention",
                                                "items": [
                                                    {"type": "TextBlock", "text": pill_label, "weight": "Bolder", "size": "Small", "color": "Attention", "horizontalAlignment": "Center"},
                                                    {"type": "TextBlock", "text": f"{score_val}/100", "weight": "Bolder", "size": "ExtraLarge", "color": "Attention", "horizontalAlignment": "Center"},
                                                    {"type": "TextBlock", "text": "CORROBORATION SCORE", "size": "Small", "isSubtle": True, "horizontalAlignment": "Center"}
                                                ]
                                            }
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {"type": "TextBlock", "text": "📄 THREAT ACTOR", "size": "Small", "weight": "Bolder", "color": "Accent"},
                                            {"type": "TextBlock", "text": actor_display, "size": "Large", "weight": "Bolder", "color": actor_color, "wrap": True},
                                            {"type": "TextBlock", "text": f"Corroborated across {source_count} independent feeds", "size": "Small", "isSubtle": True, "spacing": "Small"}
                                        ]
                                    }
                                ]
                            },
                            # 2. Middle Row: [Short Description]
                            {
                                "type": "Container",
                                "spacing": "Medium",
                                "separator": True,
                                "items": [
                                    {"type": "TextBlock", "text": "SUMMARY", "size": "Small", "weight": "Bolder", "color": "Accent"},
                                    {"type": "TextBlock", "text": summary, "wrap": True, "size": "Medium"}
                                ]
                            },
                            # 3. Bottom Row: [Details] | [Title]
                            {
                                "type": "ColumnSet",
                                "spacing": "Medium",
                                "separator": True,
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "1",
                                        "items": [
                                            {"type": "TextBlock", "text": "DETAILS", "size": "Small", "weight": "Bolder", "color": "Accent"},
                                            {"type": "TextBlock", "text": f"• **Country:** {country}\n• **Sector:** {sector}\n• **Category:** {category}", "wrap": True, "size": "Small"}
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "1",
                                        "items": [
                                            {"type": "TextBlock", "text": "EVENT", "size": "Small", "weight": "Bolder", "color": "Accent"},
                                            {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True}
                                        ]
                                    }
                                ]
                            }
                        ],
                        "actions": [
                            {
                                "type": "Action.OpenUrl",
                                "title": "🔎 View on CyberPulse",
                                "url": pulse_url,
                                "style": "positive"
                            }
                        ]
                    }
                }
            ]
        }
        return card

    @staticmethod
    def build_regular_card(art: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build the Regular Card (IntelFeed Alert):
        - Top Row: [Title] | [Threat Actor]
        - Middle Row: [Short Description]
        - Bottom Row: [Details: Country, Sector, Category]
        - Action Button: 'View on IntelFeed' -> /feed/{article_id}
        """
        title = (art.get("title") or "Cyber Security News Advisory").strip()
        
        # Threat Actor extraction
        actor = extract_threat_actor(art)
        if actor and actor.lower() not in ("unknown", "unattributed", "none", ""):
            actor_display = actor
            actor_color = "Good"
        else:
            actor_display = "Unattributed"
            actor_color = "Default"

        # Details
        country = (art.get("target_country") or extract_country(art) or "Global").upper()
        sector = determine_sector(art)
        category = determine_incident_type(art)
        summary = clean_summary_text(art)

        art_id = str(art.get("_id") or art.get("id") or "")
        platform_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000").rstrip("/")
        if art_id:
            feed_url = f"{platform_url}/feed/{art_id}"
        else:
            words = [w for w in re.findall(r'\b[A-Za-z0-9_-]+\b', title) if len(w) > 3]
            encoded_query = urllib.parse.quote(" ".join(words[:3]) if words else title[:25])
            feed_url = f"{platform_url}/feed?q={encoded_query}"

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            # Alert Banner Header
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "auto",
                                        "items": [{"type": "TextBlock", "text": "🔔", "size": "Large"}]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": "NEWSMON — INTEL FEED",
                                                "weight": "Bolder",
                                                "size": "Medium",
                                                "color": "Accent"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": f"Threat Advisory · {category}",
                                                "isSubtle": True,
                                                "spacing": "None"
                                            }
                                        ]
                                    }
                                ]
                            },
                            # 1. Top Row: [Title] | [Threat Actor]
                            {
                                "type": "ColumnSet",
                                "spacing": "Medium",
                                "separator": True,
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "2",
                                        "items": [
                                            {"type": "TextBlock", "text": "EVENT", "size": "Small", "weight": "Bolder", "color": "Accent"},
                                            {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True}
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "1",
                                        "items": [
                                            {"type": "TextBlock", "text": "📄 THREAT ACTOR", "size": "Small", "weight": "Bolder", "color": "Accent"},
                                            {"type": "TextBlock", "text": actor_display, "size": "Medium", "weight": "Bolder", "color": actor_color, "wrap": True}
                                        ]
                                    }
                                ]
                            },
                            # 2. Middle Row: [Short Description]
                            {
                                "type": "Container",
                                "spacing": "Medium",
                                "separator": True,
                                "items": [
                                    {"type": "TextBlock", "text": "SUMMARY", "size": "Small", "weight": "Bolder", "color": "Accent"},
                                    {"type": "TextBlock", "text": summary, "wrap": True, "size": "Small"}
                                ]
                            },
                            # 3. Bottom Row: [Details]
                            {
                                "type": "Container",
                                "spacing": "Medium",
                                "separator": True,
                                "items": [
                                    {"type": "TextBlock", "text": "DETAILS", "size": "Small", "weight": "Bolder", "color": "Accent"},
                                    {"type": "TextBlock", "text": f"• **Country:** {country}   • **Sector:** {sector}   • **Category:** {category}", "wrap": True, "size": "Small"}
                                ]
                            }
                        ],
                        "actions": [
                            {
                                "type": "Action.OpenUrl",
                                "title": "🔎 View on IntelFeed",
                                "url": feed_url,
                                "style": "positive"
                            }
                        ]
                    }
                }
            ]
        }
        return card

    @staticmethod
    def build_cyberpulse_high_priority_card(event: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for Critical Card."""
        return TeamsService.build_critical_card(event)

    @staticmethod
    def build_high_severity_article_card(art: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for Regular Card with IntelFeed target."""
        return TeamsService.build_regular_card(art)
        return card

    @classmethod
    async def dispatch_cyberpulse_alert(cls, event: Dict[str, Any]) -> bool:
        """
        Dispatch a High-Priority CyberPulse alert card to the configured Microsoft Teams webhook.
        """
        webhook_url = (
            getattr(settings, "TEAMS_WEBHOOK_URL_CYBER_PULSE", "") or
            getattr(settings, "TEAMS_WEBHOOK_URL", "") or
            getattr(settings, "CYBER_PULSE_WEBHOOK_URL", "")
        )
        if not webhook_url:
            log.warning("CyberPulse alert skipped — TEAMS_WEBHOOK_URL_CYBER_PULSE not configured")
            return False

        card = cls.build_cyberpulse_high_priority_card(event)

        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            try:
                resp = await client.post(webhook_url, json=card)
                if resp.status_code in (200, 202, 204):
                    log.info(
                        "CyberPulse High Priority alert card posted to Microsoft Teams successfully",
                        event_id=event.get("event_id"),
                        sources=event.get("source_count"),
                        heat=event.get("heat_score"),
                    )
                    return True
                else:
                    log.error(
                        "Failed to post CyberPulse alert to MS Teams",
                        status_code=resp.status_code,
                        body=resp.text[:200],
                    )
                    return False
            except Exception as e:
                log.error("Exception during CyberPulse Teams alert dispatch", error=str(e))
                return False


