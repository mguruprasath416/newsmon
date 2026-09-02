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
import hashlib
import urllib.parse
from typing import List, Dict, Any, Optional, Set
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
    """Strictly verify if an article is genuine cybersecurity risk news using KeywordClassifier."""
    is_cyber = art.get("is_cybersecurity_news")
    if is_cyber is not None:
        return bool(is_cyber)

    try:
        from app.services.keyword_classifier import KeywordClassifier
        kw_res = KeywordClassifier.classify_article(art)
        return bool(kw_res.get("is_cybersecurity_news", False))
    except Exception:
        text = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')[:1500]}".lower()
        return bool(_CYBER_TERMS.search(text))



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
        "denies claim", "fake breach claim", "no compromise", "zero unauthorized access"
    ]):
        return "DENIED"

    # Confirmed requires explicit admission or official confirmation
    if any(k in text for k in [
        "confirms breach", "confirmed breach", "verified breach", "acknowledged unauthorized access",
        "admitted breach", "disclosed breach", "sec filing", "sec 8-k",
        "official statement confirms", "confirmed data breach", "suffered data breach",
        "confirmed that", "confirmed an intrusion", "officials confirmed"
    ]):
        return "CONFIRMED"

    # Mere investigation statement without admission remains CLAIMED
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
    if not is_cyber_news(art):
        return "INFO"

    sev = str(art.get("severity") or "").strip().upper()
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"):
        return "INFO" if sev in ("LOW", "INFORMATIONAL") else sev

    text = f"{art.get('title', '')} {art.get('summary', '')} {' '.join(art.get('tags') or [])}".lower()
    if any(k in text for k in ["critical zero-day", "0-day rce", "actively exploited zero-day", "unauthenticated remote code execution", "mass exploitation in the wild"]):
        return "CRITICAL"
    if any(k in text for k in ["ransomware", "data breach", "database leak", "privilege escalation", "authentication bypass", "cve-"]):
        return "HIGH"
    if any(k in text for k in ["phishing", "malware", "ddos", "xss", "spoofing", "security flaw"]):
        return "MEDIUM"
    return "INFO"


# ── Incident Registry & Multi-Source Correlation ──────────────────────────────
_INCIDENT_STATE_REGISTRY: Dict[str, Dict[str, Any]] = {}
_DISPATCHED_TEAMS_KEYS: Set[str] = set()


def generate_incident_fingerprint(art: Dict[str, Any]) -> str:
    """
    Generate stable canonical incident fingerprint based on:
    - Target Organization (normalized)
    - Incident Type (e.g. ransomware, data_breach)
    - Threat Actor (or unattributed)
    - Target Country
    - 72-Hour Correlation Time Window
    """
    comp = (art.get("target_company") or extract_breached_company(art) or "unknown").strip().lower()
    comp_norm = re.sub(r'[^a-z0-9]', '', comp) or "unknown"
    
    inc_type = (art.get("incident_type") or determine_incident_type(art) or "incident").strip().lower()
    actor = (art.get("threat_actor") or extract_threat_actor(art) or "unattributed").strip().lower()
    country = (art.get("target_country") or extract_country(art) or "global").strip().lower()
    
    # 72-hour correlation window bucket
    p_date = art.get("published_at") or art.get("crawled_at") or datetime.now(timezone.utc)
    if isinstance(p_date, str):
        try:
            p_date = datetime.fromisoformat(p_date.replace("Z", "+00:00"))
        except Exception:
            p_date = datetime.now(timezone.utc)
    if p_date.tzinfo is None:
        p_date = p_date.replace(tzinfo=timezone.utc)
        
    day_epoch = int(p_date.timestamp() // (3 * 86400))
    seed = f"{comp_norm}::{inc_type}::{actor}::{country}::{day_epoch}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def evaluate_incident_deduplication_and_update(art: Dict[str, Any], webhook_url: str = "") -> Dict[str, Any]:
    """
    Evaluates multi-source incident deduplication and material update tracking:
    - Same incident from multiple sources -> ONE Team Alert (Duplicate = True)
    - Claim -> Confirmation transition -> Material Update (Duplicate = False, Update = True)
    - Claim -> Denial transition -> Material Update (Duplicate = False, Update = True)
    - New record count disclosed -> Material Update (Duplicate = False, Update = True)
    """
    fp = generate_incident_fingerprint(art)
    dispatch_key = f"{webhook_url}::{fp}"
    
    existing_incident = _INCIDENT_STATE_REGISTRY.get(fp)
    claim_status = (art.get("claim_status") or determine_breach_status(art) or "claimed").lower()
    records_count = art.get("claimed_records_count")
    severity = (art.get("severity") or extract_severity_level(art) or "medium").lower()
    
    if not existing_incident:
        _INCIDENT_STATE_REGISTRY[fp] = {
            "fingerprint": fp,
            "claim_status": claim_status,
            "claimed_records_count": records_count,
            "severity": severity,
            "target_company": art.get("target_company") or extract_breached_company(art),
            "first_seen": datetime.now(timezone.utc),
            "source_count": 1,
            "dispatched": False
        }
        return {
            "is_duplicate": False,
            "is_update": False,
            "fingerprint": fp,
            "reason": "New qualifying incident"
        }

    # Compare for material updates
    existing_status = existing_incident.get("claim_status")
    existing_records = existing_incident.get("claimed_records_count")
    existing_incident["source_count"] += 1

    # 1. Claim -> Confirmation Transition
    if existing_status == "claimed" and claim_status == "confirmed":
        existing_incident["claim_status"] = "confirmed"
        return {
            "is_duplicate": False,
            "is_update": True,
            "fingerprint": fp,
            "update_type": "Claim Confirmed",
            "reason": "Incident officially confirmed by organization/authority"
        }

    # 2. Claim/Confirmed -> Denial Transition
    if existing_status in ("claimed", "confirmed") and claim_status == "denied":
        existing_incident["claim_status"] = "denied"
        return {
            "is_duplicate": False,
            "is_update": True,
            "fingerprint": fp,
            "update_type": "Incident Denied",
            "reason": "Organization issued official denial statement"
        }

    # 3. New Record Count Disclosed
    if existing_records is None and records_count is not None:
        existing_incident["claimed_records_count"] = records_count
        return {
            "is_duplicate": False,
            "is_update": True,
            "fingerprint": fp,
            "update_type": "Record Count Disclosed",
            "reason": f"New record volume disclosed: {records_count}"
        }

    # If already dispatched and no material change -> Suppress as duplicate coverage
    if dispatch_key in _DISPATCHED_TEAMS_KEYS or existing_incident.get("dispatched"):
        return {
            "is_duplicate": True,
            "is_update": False,
            "fingerprint": fp,
            "reason": f"Duplicate multi-source coverage (Reported by {existing_incident['source_count']} sources)"
        }

    return {
        "is_duplicate": False,
        "is_update": False,
        "fingerprint": fp,
        "reason": "First dispatch for this incident"
    }


def _is_already_dispatched(art: Dict[str, Any], webhook_url: str) -> bool:
    """Helper used during dispatch loop to suppress duplicate alerts."""
    res = evaluate_incident_deduplication_and_update(art, webhook_url)
    return res["is_duplicate"] and not res.get("is_update")


async def _mark_dispatched_in_db(art: Dict[str, Any], webhook_url: str):
    """Mark incident fingerprint as dispatched to prevent duplicate notifications."""
    fp = generate_incident_fingerprint(art)
    dispatch_key = f"{webhook_url}::{fp}"
    _DISPATCHED_TEAMS_KEYS.add(dispatch_key)
    if fp in _INCIDENT_STATE_REGISTRY:
        _INCIDENT_STATE_REGISTRY[fp]["dispatched"] = True


def is_indian_news(art: Dict[str, Any]) -> bool:
    """Check if article involves Indian victim entity or target country."""
    target_c = (art.get("target_country") or extract_country(art) or "").strip()
    target_c_clean = re.sub(r'[\U0001F1E6-\U0001F1FF\U0001F300-\U0001F9FF]', '', target_c).strip().lower()
    if target_c_clean in ("india", "in", "ind"):
        return True
    
    comp = (art.get("target_company") or extract_breached_company(art) or "").strip()
    title = art.get("title") or ""
    summary = art.get("summary") or ""
    clean_body = (art.get("content_clean") or "")[:2000]
    full_text = f"{comp} {title} {summary} {clean_body}"
    
    return bool(INDIAN_COMPANIES_REGEX.search(full_text) or FOREIGN_IN_INDIA_REGEX.search(full_text))


def is_gcc_middle_east_news(art: Dict[str, Any]) -> bool:
    """Check if article involves Middle East / GCC victim entity or target country."""
    target_c = (art.get("target_country") or extract_country(art) or "").strip()
    target_c_clean = re.sub(r'[\U0001F1E6-\U0001F1FF\U0001F300-\U0001F9FF]', '', target_c).strip().lower()
    if any(c.lower() in target_c_clean for c in MIDDLE_EAST_COUNTRIES_SET):
        return True
        
    comp = (art.get("target_company") or extract_breached_company(art) or "").strip()
    title = art.get("title") or ""
    summary = art.get("summary") or ""
    clean_body = (art.get("content_clean") or "")[:2000]
    full_text = f"{comp} {title} {summary} {clean_body}"
    
    if any(c.lower() in full_text.lower() for c in MIDDLE_EAST_COUNTRIES_SET):
        return True
    
    return bool(GCC_COMPANIES_REGEX.search(full_text) or FOREIGN_IN_MIDDLE_EAST_REGEX.search(full_text))


def get_target_channel_route(art: Dict[str, Any]) -> str:
    """
    Strict target/victim-based regional channel routing:
    - Target in India -> #indian-breaches
    - Target in Middle East / GCC -> #middle-east-companies
    - Global / Other Critical -> #high-priority-news
    """
    if is_indian_news(art):
        return "#indian-breaches"
    if is_gcc_middle_east_news(art):
        return "#middle-east-companies"
    return "#high-priority-news"


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


# ── Critical Actionable Incident Engine for Team Alerts ───────────────────────
_CRITICAL_INCIDENT_TERMS = re.compile(
    r'\b('
    # Data Breach & Theft
    r'data breach|database breach|corporate breach|company breach|security breach|'
    r'customer data breach|employee data breach|database compromised|network breach|system breach|'
    r'massive data breach|large-scale data breach|sensitive data exposed|customer records exposed|'
    r'personal data exposed|mass data exposure|confidential data exposed|'
    r'data stolen|data theft|stolen customer data|stolen employee data|stolen corporate data|'
    r'sensitive data stolen|customer records stolen|employee records stolen|personal data stolen|'
    r'financial data stolen|medical records stolen|patient data stolen|database stolen|database exfiltrated|'
    r'data exfiltration|mass data exfiltration|large-scale data theft|information stolen|records stolen|'
    # Ransomware Incidents & Encryptions
    r'ransomware attack|ransomware hit|ransomware incident|ransomware victim|company hit by ransomware|'
    r'organization hit by ransomware|hospital hit by ransomware|bank hit by ransomware|government hit by ransomware|'
    r'ransomware outbreak|ransomware infection|systems encrypted|systems were encrypted|files encrypted|'
    r'network encrypted|operations disrupted by ransomware|ransom demand|ransomware extortion|double extortion|'
    r'triple extortion|ransomware data leak|ransomware data theft|ransomware data exfiltration|'
    # Company Compromise & Unauthorized Access
    r'company compromised|company hacked|company breached|organization compromised|organization hacked|'
    r'organization breached|corporate network compromised|corporate systems compromised|internal systems compromised|'
    r'enterprise network compromised|enterprise systems compromised|corporate account compromised|'
    r'cloud account compromised|administrator account compromised|employee accounts compromised|'
    r'company credentials stolen|corporate credentials stolen|unauthorized access to company|'
    r'threat actors gained access|attackers gained access|attacker gained access|'
    # Critical Infrastructure & Major Disruption
    r'critical infrastructure attack|critical infrastructure cyberattack|critical infrastructure compromised|'
    r'power grid attack|electric grid attack|power plant cyberattack|energy infrastructure attack|'
    r'water infrastructure attack|water utility cyberattack|telecom infrastructure attack|'
    r'hospital infrastructure attack|transportation infrastructure attack|airport cyberattack|'
    r'railway cyberattack|pipeline cyberattack|nuclear facility cyberattack|critical infrastructure ransomware|'
    r'service disrupted by cyberattack|major service disruption|cyberattack disrupts services|'
    r'cyberattack disrupted operations|business operations disrupted|network outage caused by cyberattack|'
    # Extortion & Major Leaks
    r'threat actor claims breach|hacker claims breach|hacker claims data theft|threat group claims data theft|'
    r'extortion claim|extortion attack|data extortion|stolen data published|stolen data leaked|breached data published'
    r')\b',
    re.IGNORECASE
)

_ORDINARY_NEWS_EXCLUSIONS = re.compile(
    r'\b('
    r'security advisory|patch tuesday|security update|firmware update|patch available|'
    r'bug bounty|cve-\d{4}-\d+|vulnerability in|zero-day in|flaw in|bug in|'
    r'cisa adds|cisa adds two|known exploited vulnerabilities|kev catalog|'
    r'proof of concept|poc published|security researchers discover|researchers find|'
    r'how to patch|mitigation steps|advisory released|security bulletin|release notes|'
    r'annual report|threat report|market report|market research|annual threat report|'
    r'survey shows|statistics show|ransomware payments surged|ransomware trends|cyber trends|'
    r'launches new|unveils new|announces new|product feature|new module|falcon module|security tool|'
    r'technical deep-dive|deep-dive into|reverse-engineering|reverse engineering|malware analysis report|'
    r'deconstructs the|analysis of the new|academic paper|timing attack on|post-quantum|lattice-based|'
    r'security awareness|awareness training|best practices for|simulated phishing|phishing awareness|'
    r'looking back|five years after|years after the|anniversary of|historic.*compromise'
    r')\b',
    re.IGNORECASE
)


# ── Anti-False-Positive & Hypothetical Context Filter ────────────────────────
_HYPOTHETICAL_OR_NON_INCIDENT = re.compile(
    r'\b('
    r'could allow attackers to|could lead to a breach|could allow data theft|'
    r'potential vulnerability that might|theoretically allow|theoretical attack|'
    r'hypothetical scenario|simulation|simulated breach|tabletop exercise|'
    r'penetration testing writeup|pen.?test demo|security training|awareness training|'
    r'phishing simulation|phishing test|proof of concept demonstrates how|'
    r'vulnerability could be exploited to|flaw could allow|theoretical study'
    r')\b',
    re.IGNORECASE
)

_EXPLICIT_DENIAL_PATTERNS = re.compile(
    r'\b('
    r'denies.*breach|denies.*hack|denies.*leak|denies.*claim|disputes.*claim|'
    r'no evidence of compromise|no evidence of intrusion|no evidence of unauthorized|'
    r'no customer data was accessed|confirms zero unauthorized access|false claim|'
    r'blocked the attack|unaffected by'
    r')\b',
    re.IGNORECASE
)


class TeamAlertDecisionEngine:
    """
    Explicit 4-Stage Decision Layer for Team Alerts:
    Stage 1: Keyword Candidate Tagging (Non-Alerting)
    Stage 2: Anti-False-Positive Protection (Hypothetical, Advisory, & Denial Filter)
    Stage 3: Multi-Factor Evidence Validation Gate (Score >= 50, Target Org, Real Impact)
    Stage 4: Deterministic Alert Routing (TEAM_ALERT vs HUMAN_REVIEW vs WEBSITE_ONLY)
    """

    @classmethod
    def evaluate(cls, art: Dict[str, Any]) -> Dict[str, Any]:
        if not is_cyber_news(art):
            return {"decision": "WEBSITE_ONLY", "score": 0, "reason": "Non-cyber content", "factors": []}

        title = (art.get("title") or "").strip()
        summary = (art.get("summary") or "").strip()
        clean_body = (art.get("content_clean") or "")[:4000]
        full_text = f"{title} {summary} {clean_body}".lower()

        # ── Stage 2: Anti-False-Positive & Negative-Context Protection ──
        if _HYPOTHETICAL_OR_NON_INCIDENT.search(title) or _HYPOTHETICAL_OR_NON_INCIDENT.search(summary[:400]):
            return {
                "decision": "WEBSITE_ONLY",
                "score": 0,
                "reason": "Hypothetical, simulation, or non-incident vulnerability context",
                "factors": ["Hypothetical / Tabletop / Simulation Detected"]
            }

        # Check explicit denial precedence
        claim_status_val = (art.get("claim_status") or "").lower().strip()
        comp_response_val = (art.get("company_response") or "").lower().strip()
        is_denied = (
            claim_status_val == "denied"
            or _EXPLICIT_DENIAL_PATTERNS.search(comp_response_val)
            or (_EXPLICIT_DENIAL_PATTERNS.search(title) and not any(k in title.lower() for k in ["confirms", "admits", "sec filing", "sec 8-k"]))
        )
        if is_denied:
            return {
                "decision": "WEBSITE_ONLY",
                "score": 0,
                "reason": "Organization issued explicit denial statement with zero evidence of compromise",
                "factors": ["Explicit Denial Statement"]
            }

        # Check for ordinary vulnerability / CVE / Patchwork / Research / Stats without active victim breach
        has_victim_headline = any(k in title.lower() for k in [
            "stolen", "breached", "hits", "hit by", "hacked", "extort", "compromised",
            "leaked", "confirms breach", "claims breach", "claims data", "data leak", "encrypted",
            "sec 8-k", "discloses cyber incident"
        ])
        if _ORDINARY_NEWS_EXCLUSIONS.search(title) and not has_victim_headline:
            return {
                "decision": "WEBSITE_ONLY",
                "score": 0,
                "reason": "Routine vulnerability, advisory, research, tool release, or statistical report without active victim incident",
                "factors": ["Ordinary News / Advisory / Research Exclusion"]
            }

        # ── Stage 3: Multi-Factor Evidence Validation Gate ──
        evidence_score = 0
        evidence_factors = []

        # Target Organization Verification (+20)
        comp = art.get("target_company") or extract_breached_company(art)
        has_victim_company = bool(comp and comp not in ("Not Specified", "Unknown", "Target Organization", "None", ""))
        if has_victim_company:
            evidence_score += 20
            evidence_factors.append(f"Target Organization: {comp} (+20)")

        # Factor 1: Confirmed Disclosure vs Unverified Claim (+25 for confirmed, +15 for attributed claim)
        has_confirmed = (
            claim_status_val == "confirmed"
            or any(k in full_text for k in [
                "sec filing confirms", "sec 8-k", "company confirmed", "disclosed breach",
                "official statement confirms", "confirmed data breach", "confirmed corporate",
                "disclosed today that threat actors compromised", "officials confirmed an intrusion",
                "issued an official security notice admitting"
            ])
        )
        if has_confirmed:
            evidence_score += 25
            evidence_factors.append("Confirmed Incident Disclosure (+25)")
        elif claim_status_val == "claimed" or any(k in full_text for k in ["claims breach", "claims data", "leak site", "threat actor claims", "lists on dark web", "added to leak portal"]):
            evidence_score += 15
            evidence_factors.append("Attributed Actor Claim (+15)")

        # Factor 2: Data Theft & Exfiltration Evidence (+35 for quantified, +20 for unquantified)
        claimed_records = art.get("claimed_records_count")
        if claimed_records is None:
            raw_rec = extract_claimed_records(art)
            if raw_rec and raw_rec != "Not disclosed":
                nums = re.findall(r"\d[\d,]*", raw_rec)
                if nums:
                    try:
                        claimed_records = int(nums[0].replace(",", ""))
                    except ValueError:
                        pass

        has_data_theft = bool(claimed_records) or any(k in full_text for k in [
            "records stolen", "data stolen", "stolen customer data", "stolen employee data",
            "patient records", "customer database", "database exfiltrated", "mass data exfiltration",
            "stolen credentials", "data theft", "database stolen", "exfiltrated customer", "data exfiltrated",
            "exfiltrated", "sensitive databases and published"
        ])
        if claimed_records and claimed_records > 0:
            evidence_score += 35
            evidence_factors.append(f"Quantified Stolen Records: {claimed_records:,} (+35)")
        elif has_data_theft:
            evidence_score += 20
            evidence_factors.append("Data Theft / Exfiltration Evidence (+20)")

        # Factor 3: Corporate Compromise & Unauthorized Access (+30)
        has_compromise = any(k in full_text for k in [
            "corporate network compromised", "company compromised", "enterprise network compromised",
            "organization compromised", "internal systems compromised", "unauthorized access to internal",
            "unauthorized access to company", "attackers gained access", "threat actors gained access",
            "compromised corporate", "bank compromised", "company breached", "organization breached", "was breached",
            "compromised its internal corporate network", "unauthorized access to its customer management system",
            "intrusion into the", "internal servers of"
        ])
        if has_compromise:
            evidence_score += 30
            evidence_factors.append("Enterprise Compromise / Unauthorized Access (+30)")

        # Factor 4: Ransomware Deployment & Encrypted Systems (+30)
        has_ransomware = any(k in full_text for k in [
            "ransomware attack", "systems encrypted", "files encrypted", "operations disrupted by ransomware",
            "hit by ransomware", "ransom demand", "double extortion", "ransomware outbreak", "ransomware victim",
            "deployed ransomware", "encrypted operational control systems", "systems were encrypted"
        ])
        if has_ransomware:
            evidence_score += 30
            evidence_factors.append("Ransomware Deployment / Systems Encrypted (+30)")

        # Factor 5: Extortion / Leak Site Listing (+25)
        has_extortion = any(k in full_text for k in [
            "leak site", "extortion site", "proof of breach", "proof samples", "threat actor claims breach",
            "hacker claims breach", "ransomware group claims", "listed on leak site", "added to leak site",
            "dark web leak portal", "extortion leak site"
        ])
        if has_extortion:
            evidence_score += 25
            evidence_factors.append("Extortion Leak Site Listing / Proof Samples (+25)")

        # Factor 6: Critical Infrastructure / Essential Services Impact (+30)
        has_infra = any(k in full_text for k in [
            "critical infrastructure", "power grid", "electric grid", "water utility",
            "hospital infrastructure", "emergency operations", "pipeline cyberattack", "telecom network",
            "fuel pipeline", "energy systems", "pipeline network", "electronic health systems"
        ])
        if has_infra:
            evidence_score += 30
            evidence_factors.append("Critical Infrastructure / Essential Services Impact (+30)")

        # Factor 7: Major Service Disruption / Operational Outage (+25)
        has_disruption = any(k in full_text for k in [
            "service disruption", "major service disruption", "disrupted operations",
            "disrupting services", "network outage caused by", "systems taken offline", "operations disrupted",
            "operations were disrupted", "forced an emergency shutdown", "halting aircraft component",
            "halting manufacturing", "crippled"
        ])
        if has_disruption:
            evidence_score += 25
            evidence_factors.append("Major Operational / Service Disruption (+25)")

        # Factor 8: Named Threat Actor Attribution (+20)
        actor = extract_threat_actor(art)
        if actor and actor.lower() not in ("unknown", "unattributed", "none", "n/a"):
            evidence_score += 20
            evidence_factors.append(f"Threat Actor Identified: {actor} (+20)")

        # ── Stage 4: Deterministic Alert Routing ──
        # Threshold: Score >= 50 AND identified target organization required for Team Alert
        if evidence_score >= 50 and has_victim_company:
            decision = "TEAM_ALERT"
            reason = f"Qualifying critical actionable incident (Evidence Score: {evidence_score})"
        elif evidence_score >= 35:
            decision = "HUMAN_REVIEW"
            reason = f"Borderline incident requiring analyst review (Evidence Score: {evidence_score})"
        else:
            decision = "WEBSITE_ONLY"
            reason = f"Evidence score {evidence_score} below Team Alert threshold (50 pts)"

        return {
            "decision": decision,
            "score": evidence_score,
            "factors": evidence_factors,
            "target_company": comp if has_victim_company else "N/A",
            "reason": reason
        }


def is_critical_actionable_incident(art: Dict[str, Any]) -> bool:
    """Evaluates if an article passes the explicit 4-stage Team Alert Decision Engine."""
    eval_result = TeamAlertDecisionEngine.evaluate(art)
    return eval_result["decision"] == "TEAM_ALERT"


def is_company_breach_or_incident(art: Dict[str, Any]) -> bool:
    """Alias pointing to the unified critical incident evaluation engine."""
    return is_critical_actionable_incident(art)






def extract_threat_actor(art: Dict[str, Any]) -> str:
    """
    Extract verified threat actor name from article text or metadata.
    Returns 'Unknown' if none detected.
    """
    actors = art.get("threat_actors") or art.get("threat_actor")
    if isinstance(actors, list) and actors:
        for a in actors:
            a_clean = str(a).strip()
            if a_clean and a_clean.lower() not in ("unknown", "unattributed", "none", "n/a"):
                return a_clean
    elif isinstance(actors, str) and actors.strip() and actors.strip().lower() not in ("unknown", "unattributed", "none", "n/a"):
        return actors.strip()

    title = art.get("title") or ""
    summary = art.get("summary") or ""
    full_text = f"{title} {summary} {art.get('content_clean', '')[:1000]}".lower()

    # Actor alias catalog
    actor_map = [
        ("LockBit 3.0", ["lockbit", "lockbit 3.0", "lockbit 2.0", "lockbit-supp"]),
        ("BlackCat (ALPHV)", ["blackcat", "alphv"]),
        ("RansomHub", ["ransomhub"]),
        ("Akira", ["akira ransomware", "akira group"]),
        ("Clop", ["clop", "cl0p"]),
        ("Rhysida", ["rhysida"]),
        ("Qilin", ["qilin", "agenda ransomware"]),
        ("BianLian", ["bianlian"]),
        ("Play Ransomware", ["play ransomware", "play crypt"]),
        ("Medusa", ["medusa ransomware", "medusa blog"]),
        ("Scattered Spider", ["scattered spider", "unc3944", "0ktapus"]),
        ("Volt Typhoon", ["volt typhoon", "bronze silhouette"]),
        ("Lazarus Group", ["lazarus group", "lazarus", "hidden cobra", "apt38"]),
        ("Fancy Bear (APT28)", ["fancy bear", "apt28", "strontium", "sofacy"]),
        ("Cozy Bear (APT29)", ["cozy bear", "apt29", "nobelium", "midnight blizzard"]),
        ("Black Basta", ["black basta", "blackbasta"]),
        ("Direwolf", ["direwolf"]),
        ("Settra", ["settra"]),
        ("Space Bears", ["space bears"]),
        ("DarkSide", ["darkside"]),
        ("Conti", ["conti ransomware", "conti group"]),
        ("ShinyHunters", ["shinyhunters", "shiny hunters"]),
    ]

    for display_name, aliases in actor_map:
        if any(re.search(rf'\b{re.escape(alias)}\b', full_text) for alias in aliases):
            return display_name

    return "Unknown"


def _company_initials(name: str) -> str:
    """Extract 2-character initials for company logo badge."""
    words = [w for w in name.split() if w.isalnum()]
    if len(words) >= 2:
        return f"{words[0][0]}{words[1][0]}".upper()
    if words and len(words[0]) >= 2:
        return words[0][:2].upper()
    return "CO"


def _time_ago(dt_val: Any) -> str:
    """Return friendly relative time like '2 hours ago', 'Yesterday'."""
    if not dt_val:
        return "Recently"
    if isinstance(dt_val, str):
        try:
            dt_val = datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
        except Exception:
            return "Recently"
    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            dt_val = dt_val.replace(tzinfo=timezone.utc)
        diff = datetime.now(timezone.utc) - dt_val
        seconds = int(diff.total_seconds())
        if seconds < 60:
            return "Just now"
        if seconds < 3600:
            m = seconds // 60
            return f"{m}m ago"
        if seconds < 86400:
            h = seconds // 3600
            return f"{h}h ago"
        d = seconds // 86400
        return f"{d}d ago"
    return "Recently"


def _severity_color(severity: str) -> str:
    """Return hex color without '#' for Microsoft Teams themeColor."""
    palette = {
        "CRITICAL": "D9534F",
        "HIGH": "E67E22",
        "MEDIUM": "F1C40F",
        "LOW": "3498DB",
        "INFO": "2ECC71",
        "INFORMATIONAL": "2ECC71",
    }
    return palette.get(severity.upper(), "3498DB")


def _impact_tags(art: Dict[str, Any]) -> str:
    """Generate concise impact tags based on article contents."""
    text = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')}".lower()
    tag_map = [
        ("Unauthorized access", ["unauthorized access", "compromised account", "credential"]),
        ("Reputational risk", ["data breach", "leaked", "dump", "defacement"]),
        ("Ransom demand", ["ransom", "extortion", "encryptor"]),
        ("Data exfiltration", ["exfiltrat", "downloaded records", "stolen data"]),
        ("Service disruption", ["ddos", "outage", "system down", "offline"]),
        ("Supply chain risk", ["supply chain", "third-party", "vendor"]),
    ]
    buckets = []
    for label, kws in tag_map:
        if label not in buckets and any(k in text for k in kws):
            buckets.append(label)

    if not buckets:
        return ""
    return "  ·  ".join(buckets[:5])


def build_threat_intelligence_breach_card(art: Dict[str, Any]) -> Dict[str, Any]:
    """
    Template 1: Company Cyber Incident / Intelligence Alert
    """
    app_name = (getattr(settings, "APP_NAME", "") or "CLARITYTI").upper()
    platform_name_display = getattr(settings, "APP_NAME", "") or "ClarityTI"
    platform_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000").rstrip("/")

    raw_title = (art.get("title") or "Company Cyber Incident Alert").strip()
    clean_title = re.sub(
        r'\s*-\s*(?:Reuters|BleepingComputer|The Hacker News|OSINTxLab|BreachNews|Dark Reading|SecurityWeek|CERT-In).*$',
        '', raw_title, flags=re.IGNORECASE
    ).strip()

    company_val = extract_breached_company(art)
    if not company_val or company_val in ("Not Specified", "Unknown", ""):
        # Check title for company or subject entity
        words = clean_title.split(":")
        company_val = words[0].strip() if len(words) > 1 and len(words[0].strip()) < 35 else "Target Organization"

    severity = extract_severity_level(art)
    theme_color = _severity_color(severity)

    # AI Assessment (2-3 lines)
    ai_assessment = (art.get("ai_summary") or clean_summary_text(art)).strip()

    # Threat Profile Fields - Accurately extracted, never arbitrarily forced to Ransomware
    attack_type = determine_incident_type(art)
    threat_actor = extract_threat_actor(art)
    sector = determine_sector(art)
    country = (art.get("target_country") or extract_country(art) or "Global").title()
    if country.upper() == "UNKNOWN":
        country = "Global"

    # Dynamic confidence calculation based on corroboration and indicator presence
    confidence_score = art.get("confidence_score") or art.get("confidence") or art.get("ai_confidence")
    if confidence_score is not None:
        try:
            val_float = float(confidence_score)
            conf_val = f"{int(val_float * 100 if val_float <= 1.0 else val_float)}%"
        except Exception:
            conf_val = "90%"
    else:
        cves_found = art.get("cves") or []
        iocs_found = art.get("iocs") or {}
        has_iocs = bool(iocs_found.get("ips") or iocs_found.get("hashes") or iocs_found.get("domains"))
        if threat_actor != "Unknown" and (cves_found or has_iocs):
            conf_val = "94%"
        elif threat_actor != "Unknown" or cves_found:
            conf_val = "88%"
        elif severity in ("CRITICAL", "HIGH"):
            conf_val = "82%"
        else:
            conf_val = "75%"

    # Technical Indicators: CVE, Malware, MITRE, IOCs (Accurate - N/A if absent)
    cves_list = art.get("cves") or []
    cve_str = ", ".join(cves_list[:2]) if cves_list else "N/A"

    malware_list = art.get("malware_families") or []
    malware_str = ", ".join(malware_list[:2]) if malware_list else ("Unattributed" if attack_type in ("Malware", "Ransomware") else "N/A")

    mitre_list = [m.get("technique_id", m) if isinstance(m, dict) else str(m) for m in (art.get("mitre_techniques") or [])]
    if mitre_list:
        mitre_str = ", ".join(mitre_list[:2])
    elif "ransomware" in attack_type.lower():
        mitre_str = "T1486"
    elif "phishing" in attack_type.lower():
        mitre_str = "T1566"
    elif "zero-day" in attack_type.lower() or "vulnerability" in attack_type.lower():
        mitre_str = "T1190"
    else:
        mitre_str = "N/A"

    iocs_data = art.get("iocs") or {}
    total_iocs = int(art.get("ioc_count") or 0)
    if total_iocs == 0 and isinstance(iocs_data, dict):
        total_iocs = len(iocs_data.get("ips", [])) + len(iocs_data.get("domains", [])) + len(iocs_data.get("hashes", []))
    iocs_str = str(total_iocs) if total_iocs > 0 else "N/A"

    # Facts: Source, Date, Threat Actor, Company
    source_name = art.get("source_name") or "Threat Intel Feed"
    article_url = art.get("url") or platform_url
    pub_date_str = extract_date_reported(art)
    art_id = str(art.get("_id") or art.get("id") or "")
    report_url = f"{platform_url}/feed/{art_id}" if art_id else (f"{platform_url}/feed?url={article_url}")

    card_body = (
        f"### 🔴 {severity} | {app_name} INTELLIGENCE ALERT\n\n"
        f"### 🚨 COMPANY CYBER INCIDENT\n\n"
        f"**{company_val}**  \n"
        f"{clean_title}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"**AI ASSESSMENT**\n\n"
        f"{ai_assessment}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"**🎯 THREAT PROFILE**\n\n"
        f"• **Attack**       : {attack_type}  \n"
        f"• **Threat Actor** : {threat_actor}  \n"
        f"• **Sector**       : {sector}  \n"
        f"• **Region**       : {country}  \n"
        f"• **Severity**     : {severity}  \n"
        f"• **Confidence**   : {conf_val}\n\n"
        f"**🧩 TECHNICAL INDICATORS**\n\n"
        f"• **CVE**          : {cve_str}  \n"
        f"• **Malware**      : {malware_str}  \n"
        f"• **MITRE**        : {mitre_str}  \n"
        f"• **IOCs**         : {iocs_str}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"**📌 INTELLIGENCE FACTS**\n\n"
        f"• **Source**       : [{source_name}]({article_url})  \n"
        f"• **Date**         : {pub_date_str}  \n"
        f"• **Threat Actor** : {threat_actor}  \n"
        f"• **Company**      : {company_val}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"*{platform_name_display} | Automated Threat Intelligence*"
    )

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"🔴 {severity} | {app_name} ALERT: {company_val}",
        "sections": [
            {
                "text": card_body,
                "markdown": True,
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "VIEW FULL REPORT →",
                "targets": [{"os": "default", "uri": report_url}]
            }
        ]
    }
    return card


def build_general_advisory_card(art: Dict[str, Any]) -> Dict[str, Any]:
    """
    Template 2: Cyber News Advisory Card
    Layout:
      ┌──────────────────────────────────────────────────────────────┐
      │ 📰 CYBER NEWS                                    [DATE]      │
      │ [Title]                                                      │
      │ ──────────────────────────────────────────────────────────── │
      │ [Summary / Content]                                          │
      │ ──────────────────────────────────────────────────────────── │
      │ CATEGORY                                                     │
      │ 🛡 [Category]                                                 │
      │ SOURCE                                                       │
      │ [Source Name]                                                │
      │ PUBLISHED                                                    │
      │ [Date]                                                       │
      │ REGION                                                       │
      │ 🌍 [Region]                                                  │
      │ ──────────────────────────────────────────────────────────── │
      │ 🔎 AI INSIGHT                                                │
      │ [Insight Text]                                               │
      │                         [ READ FULL NEWS → ]                 │
      └──────────────────────────────────────────────────────────────┘
    """
    platform_name_display = getattr(settings, "APP_NAME", "") or "ClarityTI"
    platform_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000").rstrip("/")

    raw_title = (art.get("title") or "Cyber Security News Advisory").strip()
    clean_title = re.sub(
        r'\s*-\s*(?:Reuters|BleepingComputer|The Hacker News|OSINTxLab|BreachNews|Dark Reading|SecurityWeek|CERT-In).*$',
        '', raw_title, flags=re.IGNORECASE
    ).strip()

    pub_date = extract_date_reported(art)
    pub_date_upper = pub_date.upper()

    summary_text = clean_summary_text(art).strip()
    category = determine_incident_type(art)
    source_name = art.get("source_name") or "Cyber News Source"
    article_url = art.get("url") or platform_url
    country = (art.get("target_country") or extract_country(art) or "Global").title()
    if country.upper() == "UNKNOWN":
        country = "Global"

    severity = extract_severity_level(art)
    theme_color = _severity_color(severity)

    # AI Insight
    ai_sum = art.get("ai_summary")
    if ai_sum and len(ai_sum.strip()) > 15:
        first_sentence = ai_sum.strip().split(".")[0].strip()
        ai_insight = f"{first_sentence}."
    else:
        if "zero" in category.lower() or "cve" in clean_title.lower():
            ai_insight = "Critical vulnerability requiring security-team attention and patch deployment."
        elif "ransomware" in category.lower():
            ai_insight = "Active extortion operation detected; review offline backups and perimeter access."
        elif "breach" in category.lower() or "leak" in category.lower():
            ai_insight = "Enterprise data exposure reported; conduct credential rotation and account audits."
        else:
            ai_insight = "Security advisory requiring infrastructure monitoring and threat response readiness."

    art_id = str(art.get("_id") or art.get("id") or "")
    read_news_url = article_url if article_url and article_url.startswith("http") else (f"{platform_url}/feed/{art_id}" if art_id else platform_url)

    card_body = (
        f"### 📰 CYBER NEWS &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; {pub_date_upper}\n\n"
        f"**{clean_title}**\n\n"
        f"────────────────────────────────────────────────────────────\n\n"
        f"{summary_text}\n\n"
        f"────────────────────────────────────────────────────────────\n\n"
        f"**CATEGORY**  \n"
        f"🛡 {category}\n\n"
        f"**SOURCE**  \n"
        f"[{source_name}]({article_url})\n\n"
        f"**PUBLISHED**  \n"
        f"{pub_date}\n\n"
        f"**REGION**  \n"
        f"🌍 {country}\n\n"
        f"────────────────────────────────────────────────────────────\n\n"
        f"**🔎 AI INSIGHT**  \n"
        f"{ai_insight}\n"
    )

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"📰 CYBER NEWS: {clean_title}",
        "sections": [
            {
                "text": card_body,
                "markdown": True,
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "READ FULL NEWS →",
                "targets": [{"os": "default", "uri": read_news_url}]
            }
        ]
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
    max_slots: int = _MAX_DISPATCH_SLOTS,
) -> List[Dict[str, Any]]:
    """
    Company-specific breach / ransomware / extortion articles passing the 4-Stage Decision Gate.
    General advisories and non-incident articles are strictly excluded from Teams dispatch.
    """
    company_breaches = [art for art in articles if is_critical_actionable_incident(art)]
    return company_breaches[:max_slots]


def build_single_article_card(art: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build standard high-impact Teams incident card (Template 1).
    """
    return build_threat_intelligence_breach_card(art)


class TeamsService:
    """Service to send structured threat intelligence, breach cards, and daily digest to MS Teams Webhooks."""

    @staticmethod
    def build_critical_card(event: Dict[str, Any]) -> Dict[str, Any]:
        """Template 1: Company Cyber Incident / High Severity Alert."""
        return build_threat_intelligence_breach_card(event)

    @staticmethod
    def build_regular_card(art: Dict[str, Any]) -> Dict[str, Any]:
        """Template 1: High Severity Actionable Alert Card."""
        return build_threat_intelligence_breach_card(art)

    @staticmethod
    def build_cyberpulse_high_priority_card(event: Dict[str, Any]) -> Dict[str, Any]:
        """Template 1: CyberPulse High Priority Event Card."""
        return build_threat_intelligence_breach_card(event)

    @staticmethod
    def build_high_severity_article_card(art: Dict[str, Any]) -> Dict[str, Any]:
        """Build single article card (Template 1 based on verified incident)."""
        return build_single_article_card(art)

    @staticmethod
    async def send_test_webhook(webhook_url: str) -> bool:
        """Send a test CyberPulse High Priority Alert card to MS Teams."""
        if not webhook_url or not webhook_url.startswith("http"):
            raise ValueError("Invalid Webhook URL. Must start with http:// or https://")

        sample_event = {
            "title": "Microsoft Teams Integration Test Verified — ClarityTI",
            "company_name": "Microsoft Corporation",
            "target_company": "Microsoft Corporation",
            "severity": "HIGH",
            "confidence": 92,
            "incident_type": "Ransomware",
            "threat_actors": ["LockBit 3.0"],
            "sector": "Technology & Software",
            "target_country": "Global",
            "cves": ["CVE-2026-65618"],
            "malware_families": ["LockBit"],
            "source_name": "The Hacker News",
            "published_at": datetime.now(timezone.utc),
            "ai_summary": "Active enterprise extortion campaign detected targeting software supply chain pipelines.",
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
        Send ONLY verified High/Critical Severity Team Alerts passing the 4-Stage Decision Gate.
        """
        if not webhook_url:
            return {"sent": 0, "message": "No articles or missing webhook"}

        sent_count = 0
        dispatched_details = []

        # STRICT FILTER: ONLY ARTICLES PASSING TEAM_ALERT 4-STAGE GATE
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
            if is_critical_actionable_incident(art) and _is_strictly_today(art)
        ]

        if not high_severe_breaches:
            return {"status": "success", "sent": 0, "message": "No qualifying critical actionable incidents to dispatch."}

        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            for art in high_severe_breaches:
                if _is_already_dispatched(art, webhook_url):
                    continue
                card_payload = build_single_article_card(art)
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
                    log.error("Failed sending alert card to Teams", company=company_name, error=str(e))

                await asyncio.sleep(0.4)

        return {
            "status": "success",
            "sent": sent_count,
            "dispatched": dispatched_details,
            "message": f"Successfully dispatched {sent_count} alert cards to Teams!",
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

        # STRICT FILTER: ONLY CRITICAL ACTIONABLE INCIDENTS FOR TEAM ALERTS (ORDINARY CVES/ADVISORIES KEPT ON WEBSITE ONLY)
        high_severe_articles = [
            art for art in non_duplicate_articles
            if is_critical_actionable_incident(art)
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

    @classmethod
    async def dispatch_cyberpulse_alert(cls, event: Dict[str, Any]) -> bool:
        """
        Dispatch a High-Priority CyberPulse alert card to the configured Microsoft Teams webhook
        ONLY if the viral event qualifies as a Critical Actionable Incident under the 4-Stage Gate.
        A CVE or patch advisory reported by 50+ sources remains strictly Website Only.
        """
        if not is_critical_actionable_incident(event):
            log.info(
                "CyberPulse Teams dispatch suppressed: Event is viral on website, but does not meet Critical Incident 4-Stage Gate (WEBSITE_ONLY)",
                title=event.get("title", "")[:60],
                event_id=event.get("event_id"),
                sources=event.get("source_count")
            )
            return False

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



