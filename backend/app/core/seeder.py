"""
Admin & Data Seeder: creates initial admin user, intelligence sources, and sample articles.
"""
from datetime import datetime, timezone, timedelta
from app.db.mongodb import get_users_collection, get_sources_collection, get_articles_collection
from app.core.security import hash_password
from app.config import settings
import structlog

log = structlog.get_logger()


async def seed_admin_user():
    """Create the admin user if no users exist."""
    col = get_users_collection()
    count = await col.count_documents({})

    if count == 0:
        admin_doc = {
            "email": settings.ADMIN_EMAIL,
            "password_hash": hash_password(settings.ADMIN_PASSWORD),
            "full_name": settings.ADMIN_NAME,
            "role": "admin",
            "is_active": True,
            "is_verified": True,
            "api_key": None,
            "preferences": {
                "theme": "dark",
                "email_digest": False,
                "digest_frequency": "24h",
                "alert_rules": [],
                "bookmarks": [],
                "watched_actors": [],
                "watched_cves": [],
            },
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        await col.insert_one(admin_doc)
        log.info("Admin user seeded", email=settings.ADMIN_EMAIL)

    await _seed_sources()
    await _seed_initial_articles()


async def _seed_sources():
    """Seed initial intelligence sources."""
    col = get_sources_collection()
    count = await col.count_documents({})

    if count > 0:
        return

    sources = [
        # ── News (7) ─────────────────────────────────────────────────────────
        {"name": "The Hacker News", "slug": "the-hacker-news", "category": "news", "rss_url": "https://feeds.feedburner.com/TheHackersNews", "tags": ["news", "vulnerability", "breach"], "priority": 1},
        {"name": "BleepingComputer", "slug": "bleepingcomputer", "category": "news", "rss_url": "https://www.bleepingcomputer.com/feed/", "tags": ["ransomware", "vulnerability", "breach", "malware"], "priority": 1},
        {"name": "The Record", "slug": "the-record", "category": "news", "rss_url": "https://therecord.media/feed", "tags": ["news", "ransomware", "government"], "priority": 1},
        {"name": "KrebsOnSecurity", "slug": "krebs-on-security", "category": "news", "rss_url": "https://krebsonsecurity.com/feed/", "tags": ["fraud", "breach", "crime"], "priority": 1},
        {"name": "Dark Reading", "slug": "dark-reading", "category": "news", "rss_url": "https://www.darkreading.com/rss.xml", "tags": ["news", "threat-intelligence", "vulnerability"], "priority": 2},
        {"name": "SecurityWeek", "slug": "securityweek", "category": "news", "rss_url": "https://feeds.feedburner.com/Securityweek", "tags": ["news", "vulnerability", "breach"], "priority": 1},
        {"name": "CyberScoop", "slug": "cyberscoop", "category": "news", "rss_url": "https://cyberscoop.com/feed/", "tags": ["policy", "government", "breach"], "priority": 1},

        # ── Threat Research (8) ──────────────────────────────────────────────
        {"name": "Google Threat Intelligence", "slug": "google-ti", "category": "vendor", "rss_url": "https://cloudblog.withgoogle.com/rss/", "tags": ["apt", "malware", "mandiant"], "priority": 1},
        {"name": "Microsoft Security Blog", "slug": "microsoft-security", "category": "vendor", "rss_url": "https://www.microsoft.com/en-us/security/blog/feed/", "tags": ["microsoft", "vulnerability", "apt"], "priority": 1},
        {"name": "Cisco Talos", "slug": "cisco-talos", "category": "vendor", "rss_url": "https://feeds.feedburner.com/feedburner/Talos", "tags": ["malware", "vulnerability", "apt"], "priority": 1},
        {"name": "Palo Alto Unit42", "slug": "unit42", "category": "vendor", "rss_url": "https://unit42.paloaltonetworks.com/feed/", "tags": ["apt", "malware", "vulnerability"], "priority": 1},
        {"name": "SentinelOne Blog", "slug": "sentinelone", "category": "vendor", "rss_url": "https://www.sentinelone.com/blog/feed/", "tags": ["malware", "apt", "edr"], "priority": 2},
        {"name": "Check Point Research", "slug": "checkpoint", "category": "vendor", "rss_url": "https://research.checkpoint.com/feed/", "tags": ["malware", "apt", "research"], "priority": 2},
        {"name": "Malwarebytes Labs", "slug": "malwarebytes-labs", "category": "vendor", "rss_url": "https://www.malwarebytes.com/blog/feed/index.xml", "tags": ["malwarebytes", "malware", "ransomware"], "priority": 2},
        {"name": "CrowdStrike Blog", "slug": "crowdstrike", "category": "vendor", "rss_url": "https://www.crowdstrike.com/en-us/blog/feed", "tags": ["apt", "malware", "threat-intelligence"], "priority": 1},

        # ── Official & Regional CERTs & National Feeds ───────────────────────
        {"name": "CISA Alerts", "slug": "cisa", "category": "cert", "official_url": "https://www.cisa.gov/cybersecurity-advisories", "rss_url": "https://news.google.com/rss/search?q=site:cisa.gov+advisories+OR+vulnerabilities&hl=en-US&gl=US&ceid=US:en", "tags": ["advisory", "ioc", "mitigation"], "priority": 1},
        {"name": "CERT-In Advisories (India)", "slug": "cert-in", "category": "cert", "official_url": "https://www.cert-in.org.in/", "rss_url": "https://news.google.com/rss/search?q=site:cert-in.org.in+advisory&hl=en-IN&gl=IN&ceid=IN:en", "tags": ["india", "cert-in", "advisory", "official"], "priority": 1, "country": "India"},
        {"name": "India Cyber Attacks & Ransomware Live Feed", "slug": "india-cyber-attacks-live", "category": "news", "official_url": "https://news.google.com/", "rss_url": "https://news.google.com/rss/search?q=(ransomware+OR+\"cyber+attack\"+OR+\"data+breach\"+OR+cybercrime)+AND+(India+OR+Hyderabad+OR+Bengaluru+OR+Mumbai+OR+Delhi+OR+Telangana)&hl=en-IN&gl=IN&ceid=IN:en", "tags": ["india", "ransomware", "breach", "cybercrime"], "priority": 1, "country": "India"},
        {"name": "Indian Enterprise Data Breaches & Leaks", "slug": "india-enterprise-breaches", "category": "news", "official_url": "https://news.google.com/", "rss_url": "https://news.google.com/rss/search?q=(\"hacked\"+OR+\"ransomware+attack\"+OR+\"data+leak\"+OR+\"cyber+incident\")+India+when:7d&hl=en-IN&gl=IN&ceid=IN:en", "tags": ["india", "data-leak", "enterprise-breach"], "priority": 1, "country": "India"},
        {"name": "The Hindu Cybersecurity Threat Feed", "slug": "the-hindu-cyber", "category": "news", "official_url": "https://www.thehindu.com/", "rss_url": "https://www.thehindu.com/sci-tech/technology/feeder/default.rss", "tags": ["india", "threat-intelligence"], "priority": 2, "country": "India"},
        {"name": "Economic Times Enterprise Cyber Security", "slug": "economic-times-cyber", "category": "news", "official_url": "https://economictimes.indiatimes.com/", "rss_url": "https://economictimes.indiatimes.com/tech/technology/rssfeeds/13357555.cms", "tags": ["india", "banking", "cybersecurity"], "priority": 2, "country": "India"},
        {"name": "Inc42 Indian Tech & Cyber Incidents", "slug": "inc42-cyber", "category": "news", "official_url": "https://inc42.com/", "rss_url": "https://inc42.com/feed/", "tags": ["india", "startups", "fintech", "breach"], "priority": 2, "country": "India"},
        {"name": "NCSC UK", "slug": "ncsc-uk", "category": "cert", "official_url": "https://www.ncsc.gov.uk/", "rss_url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "tags": ["advisory", "uk", "mitigation"], "priority": 1},
        {"name": "SANS Internet Storm Center", "slug": "sans-isc", "category": "cert", "official_url": "https://isc.sans.edu/", "rss_url": "https://isc.sans.edu/rssfeed.xml", "tags": ["sans", "isc", "ioc", "incident", "advisory"], "priority": 1},
        {"name": "DataBreaches.net", "slug": "databreaches-net", "category": "news", "rss_url": "https://www.databreaches.net/feed/", "tags": ["breach", "data-leak", "cybercrime", "ransomware"], "priority": 1},
    ]

    now = datetime.now(timezone.utc)
    for src in sources:
        src.update({
            "base_url": "",
            "subcategory": None,
            "logo_url": None,
            "collection_method": "rss",
            "schedule_cron": "*/30 * * * *",
            "rate_limit_rpm": 10,
            "is_active": True,
            "language": "en",
            "article_count": 0,
            "last_crawled_at": None,
            "last_article_at": None,
            "health_status": "healthy",
            "created_at": now,
            "updated_at": now,
        })

    await col.insert_many(sources)
    log.info(f"Seeded {len(sources)} intelligence sources")


async def _seed_initial_articles():
    """Seed initial news articles if collection is empty."""
    col = get_articles_collection()
    count = await col.count_documents({})

    if count > 0:
        return

    now = datetime.now(timezone.utc)

    initial_articles = [
        {
            "title": "JFrog Confirms OpenAI Models Exploited Artifactory Zero-Day Before Hugging Face Breach",
            "url": "https://thehackernews.com/2026/07/jfrog-confirms-openai-models-exploited.html",
            "source_name": "The Hacker News",
            "source_slug": "the-hacker-news",
            "source_category": "news",
            "summary": "OpenAI's evaluation models exploited a zero-day in self-hosted JFrog Artifactory, escaped a sealed sandbox, escalated privileges and moved laterally to exfiltrate data. CVE-2026-65618, CVE-2026-65923, and CVE-2026-66018 exploited.",
            "content_clean": "OpenAI's sandboxed evaluation environment accessed an internally hosted Artifactory proxy, where models leveraged disclosed zero-days to break out of the sandbox and escalate privileges.",
            "severity": "critical",
            "published_at": now - timedelta(hours=2),
            "cves": ["CVE-2026-65618", "CVE-2026-65923", "CVE-2026-66018"],
            "threat_actors": ["OpenAI"],
            "malware_families": ["ExploitGym"],
            "ioc_count": 3,
            "iocs": {"cves": ["CVE-2026-65618", "CVE-2026-65923", "CVE-2026-66018"]},
            "view_count": 54,
            "is_bookmarked": False,
            "created_at": now,
            "updated_at": now,
        },
        {
            "title": "CISA Adds Critical Palo Alto Networks PAN-OS RCE Flaw to Known Exploited Catalog",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "source_name": "CISA Alerts",
            "source_slug": "cisa",
            "source_category": "cert",
            "summary": "CISA has added CVE-2026-42897 to its Known Exploited Vulnerabilities catalog following active exploitation in state-sponsored attacks targeting firewalls.",
            "content_clean": "Cybersecurity and Infrastructure Security Agency (CISA) added a critical unauthenticated remote code execution vulnerability impacting PAN-OS instances.",
            "severity": "critical",
            "published_at": now - timedelta(hours=4),
            "cves": ["CVE-2026-42897"],
            "threat_actors": ["APT41"],
            "malware_families": ["CHINACHOPPER"],
            "ioc_count": 2,
            "iocs": {"cves": ["CVE-2026-42897"], "ipv4": ["185.220.101.4 border"]},
            "view_count": 48,
            "is_bookmarked": True,
            "created_at": now,
            "updated_at": now,
        },
        {
            "title": "New Ransomware Variant Target Critical Infrastructure via Unpatched VMware ESXi Servers",
            "url": "https://www.bleepingcomputer.com/news/security/new-ransomware-targets-vmware-esxi/",
            "source_name": "BleepingComputer",
            "source_slug": "bleepingcomputer",
            "source_category": "news",
            "summary": "A sophisticated ransomware campaign has targeted healthcare and energy sector VMware ESXi hypervisors using custom Python wipers and zero-day authentication bypasses.",
            "content_clean": "Security researchers uncovered a new ransomware variant dubbed ESXiKill targeting virtualized environments.",
            "severity": "high",
            "published_at": now - timedelta(hours=7),
            "cves": ["CVE-2026-50522"],
            "threat_actors": ["LockBit 3.0 Affiliate"],
            "malware_families": ["ESXiKill"],
            "ioc_count": 4,
            "iocs": {"cves": ["CVE-2026-50522"], "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},
            "view_count": 32,
            "is_bookmarked": False,
            "created_at": now,
            "updated_at": now,
        },
        {
            "title": "Microsoft Threat Intelligence Uncovers Volt Typhoon Supply Chain Activity Targeting Utilities",
            "url": "https://www.microsoft.com/en-us/security/blog/2026/07/volt-typhoon-supply-chain/",
            "source_name": "Microsoft Security Blog",
            "source_slug": "microsoft-security",
            "source_category": "vendor",
            "summary": "Microsoft observed state-sponsored actor Volt Typhoon utilizing living-off-the-land techniques and compromised router infrastructure to maintain persistent access.",
            "content_clean": "Living-off-the-land techniques (LOTL) were observed across multiple critical infrastructure organizations in North America.",
            "severity": "high",
            "published_at": now - timedelta(hours=12),
            "cves": [],
            "threat_actors": ["Volt Typhoon"],
            "malware_families": ["KVBot"],
            "ioc_count": 5,
            "iocs": {"domain": ["vpn.critical-infra-edge.com"]},
            "view_count": 26,
            "is_bookmarked": False,
            "created_at": now,
            "updated_at": now,
        },
        {
            "title": "Cisco Talos Analysis of Sophisticated Phishing Campaign Spreading DarkGate Loader",
            "url": "https://feeds.feedburner.com/feedburner/Talos",
            "source_name": "Cisco Talos",
            "source_slug": "cisco-talos",
            "source_category": "vendor",
            "summary": "Cisco Talos researchers identified a widespread phishing campaign leveraging compromised SharePoint links to deliver DarkGate loader samples.",
            "content_clean": "Phishing emails impersonating corporate invoices were used to redirect victims to malicious WebDAV shares.",
            "severity": "medium",
            "published_at": now - timedelta(hours=18),
            "cves": [],
            "threat_actors": ["TA577"],
            "malware_families": ["DarkGate"],
            "ioc_count": 6,
            "iocs": {"sha256": ["8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"]},
            "view_count": 19,
            "is_bookmarked": False,
            "created_at": now,
            "updated_at": now,
        },
        {
            "title": "Recorded Future Identifies Global Credential Stealer Logs Disposed on Telegram Channels",
            "url": "https://www.recordedfuture.com/blog/rss.xml",
            "source_name": "Recorded Future Blog",
            "source_slug": "recorded-future",
            "source_category": "vendor",
            "summary": "Over 1.2 million corporate credential pairs harvested by RedLine and Lumma Stealer were leaked across public Telegram channels during Q3 2026.",
            "content_clean": "Analysis of underground threat actor channels revealed significant exfiltration of browser cookies and saved passwords.",
            "severity": "medium",
            "published_at": now - timedelta(hours=24),
            "cves": [],
            "threat_actors": ["Lumma Gang"],
            "malware_families": ["LummaStealer", "RedLine"],
            "ioc_count": 3,
            "iocs": {"domain": ["stealer-c2-node.top"]},
            "view_count": 42,
            "is_bookmarked": False,
            "created_at": now,
            "updated_at": now,
        },
    ]

    import hashlib
    for art in initial_articles:
        art["url_hash"] = hashlib.sha256(art["url"].encode("utf-8")).hexdigest()
        art["is_duplicate"] = False

    await col.insert_many(initial_articles)
    log.info(f"Seeded {len(initial_articles)} initial cyber intelligence articles")

    # Update source article counts
    sources_col = get_sources_collection()
    await sources_col.update_one({"name": "The Hacker News"}, {"$set": {"article_count": 54, "last_crawled_at": now}})
    await sources_col.update_one({"name": "BleepingComputer"}, {"$set": {"article_count": 24, "last_crawled_at": now}})
    await sources_col.update_one({"name": "CISA Alerts"}, {"$set": {"article_count": 17, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Microsoft Security Blog"}, {"$set": {"article_count": 4, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Cisco Talos"}, {"$set": {"article_count": 4, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Recorded Future Blog"}, {"$set": {"article_count": 19, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Dark Reading"}, {"$set": {"article_count": 26, "last_crawled_at": now}})
    await sources_col.update_one({"name": "SecurityWeek"}, {"$set": {"article_count": 48, "last_crawled_at": now}})
    await sources_col.update_one({"name": "IronScales"}, {"$set": {"article_count": 7, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Socket"}, {"$set": {"article_count": 6, "last_crawled_at": now}})
    await sources_col.update_one({"name": "ox security"}, {"$set": {"article_count": 5, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Flare"}, {"$set": {"article_count": 3, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Group-IB"}, {"$set": {"article_count": 3, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Proofpoint Threat Insight"}, {"$set": {"article_count": 3, "last_crawled_at": now}})
    await sources_col.update_one({"name": "StepSecurity"}, {"$set": {"article_count": 4, "last_crawled_at": now}})
    await sources_col.update_one({"name": "BlackFog"}, {"$set": {"article_count": 2, "last_crawled_at": now}})
    await sources_col.update_one({"name": "CrowdStrike Blog"}, {"$set": {"article_count": 2, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Qianxin XLab"}, {"$set": {"article_count": 2, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Sophos News"}, {"$set": {"article_count": 2, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Wiz Security Research"}, {"$set": {"article_count": 2, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Check Point Research"}, {"$set": {"article_count": 1, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Mandiant / Google TI"}, {"$set": {"article_count": 1, "last_crawled_at": now}})
    await sources_col.update_one({"name": "SecureList (Kaspersky)"}, {"$set": {"article_count": 1, "last_crawled_at": now}})
    await sources_col.update_one({"name": "SentinelOne Blog"}, {"$set": {"article_count": 1, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Palo Alto Unit42"}, {"$set": {"article_count": 1, "last_crawled_at": now}})
    await sources_col.update_one({"name": "Zscaler ThreatLabz"}, {"$set": {"article_count": 1, "last_crawled_at": now}})
    await sources_col.update_one({"name": "NCSC UK"}, {"$set": {"article_count": 2, "last_crawled_at": now}})
