"""
Add Extended User-Provided CTI Feeds & APIs Script
Safely and securely seeds 52 global CERTs, OffSec research labs, and CTI APIs into MongoDB
and triggers live ingestion with SSL fallback, rate limiting, and exception isolation.
"""
import sys
import os
import asyncio
import httpx
from datetime import datetime, timezone

sys.path.insert(0, r'd:\Feed\backend')
sys.stdout.reconfigure(encoding='utf-8')

from app.db.mongodb import MongoDB, get_sources_collection, get_articles_collection
from app.services.collector import crawl_source


USER_FEEDS = [
    # ── OffSec, Vulnerability & Research Labs ─────────────────────────────────
    {"name": "GreyNoise Articles", "slug": "greynoise-articles", "category": "vendor", "rss_url": "https://api.greynoise.io/v3/articles/rss", "tags": ["greynoise", "scanners", "exploitation", "search"], "priority": 1},
    {"name": "GreyNoise Blog", "slug": "greynoise-blog", "category": "vendor", "rss_url": "https://www.greynoise.io/blog/rss.xml", "tags": ["greynoise", "threat-intel", "research"], "priority": 2},
    {"name": "watchTowr Labs", "slug": "watchtowr-labs", "category": "vendor", "rss_url": "https://labs.watchtowr.com/rss/", "tags": ["watchtowr", "zero-day", "exploit", "research"], "priority": 1},
    {"name": "PortSwigger Research", "slug": "portswigger-research", "category": "vendor", "rss_url": "https://portswigger.net/research/rss", "tags": ["web-security", "portswigger", "burp", "research"], "priority": 1},
    {"name": "PortSwigger Blog", "slug": "portswigger-blog", "category": "vendor", "rss_url": "https://portswigger.net/blog/rss", "tags": ["web-security", "portswigger", "vulnerability"], "priority": 2},
    {"name": "Trail of Bits Blog", "slug": "trail-of-bits", "category": "vendor", "rss_url": "https://blog.trailofbits.com/feed/", "tags": ["trailofbits", "audit", "crypto", "appsec"], "priority": 1},
    {"name": "VulnCheck Blog", "slug": "vulncheck", "category": "vendor", "rss_url": "https://vulncheck.com/feed/blog/atom.xml", "tags": ["vulncheck", "vulnerability", "exploit", "cve"], "priority": 1},
    {"name": "VUSEC Lab (VU Amsterdam)", "slug": "vusec", "category": "vendor", "rss_url": "https://www.vusec.net/feed/", "tags": ["vusec", "hardware-security", "speculative", "research"], "priority": 2},
    {"name": "ZecOps Blog", "slug": "zecops", "category": "vendor", "rss_url": "https://blog.zecops.com/feed/", "tags": ["mobile-security", "ios", "zero-day", "zecops"], "priority": 2},
    {"name": "Zero Day Initiative (ZDI)", "slug": "zdi-blog", "category": "vendor", "rss_url": "https://www.thezdi.com/blog?format=rss", "tags": ["zdi", "zero-day", "vulnerability", "trendmicro"], "priority": 1},
    {"name": "Eclypsium Research", "slug": "eclypsium", "category": "vendor", "rss_url": "https://www.eclypsium.com/feed/", "tags": ["firmware", "supply-chain", "eclypsium"], "priority": 2},
    {"name": "Cado Security Blog", "slug": "cado-security", "category": "vendor", "rss_url": "https://www.cadosecurity.com/blog/rss.xml", "tags": ["cloud-forensics", "cado", "container-security"], "priority": 2},
    {"name": "Censys Research", "slug": "censys-research", "category": "vendor", "rss_url": "https://censys.com/tag/research/feed/", "tags": ["censys", "attack-surface", "scanning", "research"], "priority": 2},
    {"name": "Chainalysis Blog", "slug": "chainalysis", "category": "news", "rss_url": "https://blog.chainalysis.com/feed/", "tags": ["crypto", "blockchain", "ransomware-payments", "chainalysis"], "priority": 2},
    {"name": "Citizen Lab", "slug": "citizen-lab", "category": "news", "rss_url": "https://citizenlab.ca/feed/", "tags": ["citizenlab", "spyware", "pegasus", "human-rights"], "priority": 1},
    {"name": "Have I Been Pwned Breaches", "slug": "hibp-breaches", "category": "news", "rss_url": "https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches", "tags": ["hibp", "breach", "credentials", "pwned"], "priority": 1},

    # ── Global CERTs & Government Agencies ───────────────────────────────────
    {"name": "CERT-EU Threat Intelligence", "slug": "cert-eu-intel", "category": "cert", "rss_url": "https://cert.europa.eu/publications/threat-intelligence-rss", "official_url": "https://cert.europa.eu/", "tags": ["cert-eu", "eu", "advisory", "official"], "priority": 1},
    {"name": "CERT-EU Security Advisories", "slug": "cert-eu-advisories", "category": "cert", "rss_url": "https://cert.europa.eu/publications/security-advisories-rss", "official_url": "https://cert.europa.eu/", "tags": ["cert-eu", "eu", "advisory", "vulnerability"], "priority": 1},
    {"name": "JPCERT Advisories (Japan)", "slug": "jpcert-rdf", "category": "cert", "rss_url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf", "official_url": "https://www.jpcert.or.jp/english/", "tags": ["japan", "jpcert", "advisory", "official"], "priority": 1},
    {"name": "JPCERT Blog (Japan)", "slug": "jpcert-blog", "category": "cert", "rss_url": "https://blogs.jpcert.or.jp/en/atom.xml", "official_url": "https://blogs.jpcert.or.jp/en/", "tags": ["japan", "jpcert", "blog", "analysis"], "priority": 2},
    {"name": "NCSC UK Reports", "slug": "ncsc-uk-reports", "category": "cert", "rss_url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "official_url": "https://www.ncsc.gov.uk/", "tags": ["ncsc", "uk", "report", "official"], "priority": 1},
    {"name": "NCSC UK News", "slug": "ncsc-uk-news", "category": "cert", "rss_url": "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml", "official_url": "https://www.ncsc.gov.uk/", "tags": ["ncsc", "uk", "news", "official"], "priority": 2},
    {"name": "ASD Cyber Security Australia Advisories", "slug": "cyber-gov-au-advisories", "category": "cert", "rss_url": "https://www.cyber.gov.au/rss/advisories", "official_url": "https://www.cyber.gov.au/", "tags": ["australia", "asd", "acsc", "advisory"], "priority": 1},
    {"name": "ASD Cyber Security Australia Alerts", "slug": "cyber-gov-au-alerts", "category": "cert", "rss_url": "https://www.cyber.gov.au/rss/alerts", "official_url": "https://www.cyber.gov.au/", "tags": ["australia", "asd", "acsc", "alert"], "priority": 1},
    {"name": "ASD Cyber Security Australia Threats", "slug": "cyber-gov-au-threats", "category": "cert", "rss_url": "https://www.cyber.gov.au/rss/threats", "official_url": "https://www.cyber.gov.au/", "tags": ["australia", "asd", "acsc", "threat"], "priority": 2},
    {"name": "CERT-FR (France)", "slug": "cert-fr", "category": "cert", "rss_url": "https://www.cert.ssi.gouv.fr/feed/", "official_url": "https://www.cert.ssi.gouv.fr/", "tags": ["france", "anssi", "cert-fr", "advisory"], "priority": 1},
    {"name": "GovCERT Hong Kong Alerts", "slug": "govcert-hk", "category": "cert", "rss_url": "https://www.govcert.gov.hk/en/rss_security_alerts.xml", "official_url": "https://www.govcert.gov.hk/", "tags": ["hong-kong", "govcert-hk", "advisory"], "priority": 2},
    {"name": "HKCERT Security Bulletin", "slug": "hkcert-bulletin", "category": "cert", "rss_url": "https://www.hkcert.org/getrss/security-bulletin", "official_url": "https://www.hkcert.org/", "tags": ["hong-kong", "hkcert", "bulletin"], "priority": 2},
    {"name": "NCSC-FI (Finland) Main", "slug": "ncsc-fi-main", "category": "cert", "rss_url": "https://www.kyberturvallisuuskeskus.fi/feed/rss/en", "official_url": "https://www.kyberturvallisuuskeskus.fi/", "tags": ["finland", "ncsc-fi", "advisory"], "priority": 2},
    {"name": "NCSC-FI (Finland) News", "slug": "ncsc-fi-news", "category": "cert", "rss_url": "https://www.kyberturvallisuuskeskus.fi/sites/default/files/rss/news.xml", "official_url": "https://www.kyberturvallisuuskeskus.fi/", "tags": ["finland", "ncsc-fi", "news"], "priority": 2},
    {"name": "NCSC-FI (Finland) Vulns", "slug": "ncsc-fi-vulns", "category": "cert", "rss_url": "https://www.kyberturvallisuuskeskus.fi/sites/default/files/rss/vulns.xml", "official_url": "https://www.kyberturvallisuuskeskus.fi/", "tags": ["finland", "ncsc-fi", "vulnerability"], "priority": 2},
    {"name": "CERT.PL (Poland)", "slug": "cert-pl", "category": "cert", "rss_url": "https://www.cert.pl/en/rss.xml", "official_url": "https://www.cert.pl/en/", "tags": ["poland", "cert-pl", "advisory"], "priority": 2},
    {"name": "SI-CERT (Slovenia)", "slug": "si-cert", "category": "cert", "rss_url": "https://www.cert.si/en/category/news/feed/", "official_url": "https://www.cert.si/en/", "tags": ["slovenia", "si-cert", "news"], "priority": 2},
    {"name": "CCN-CERT Articles (Spain)", "slug": "ccn-cert-es", "category": "cert", "rss_url": "https://www.ccn-cert.cni.es/en/communication-events/articles-and-reports.rss", "official_url": "https://www.ccn-cert.cni.es/", "tags": ["spain", "ccn-cert", "reports"], "priority": 2},
    {"name": "Canadian Centre for Cyber Security Alerts", "slug": "cyber-gc-ca-alerts", "category": "cert", "rss_url": "https://cyber.gc.ca/webservice/en/rss/alerts", "official_url": "https://cyber.gc.ca/", "tags": ["canada", "cccs", "alerts"], "priority": 1},
    {"name": "Canadian Centre for Cyber Security News", "slug": "cyber-gc-ca-news", "category": "cert", "rss_url": "https://cyber.gc.ca/webservice/en/rss/news", "official_url": "https://cyber.gc.ca/", "tags": ["canada", "cccs", "news"], "priority": 2},
    {"name": "CERT.br (Brazil)", "slug": "cert-br", "category": "cert", "rss_url": "https://www.cert.br/rss/certbr-rss.xml", "official_url": "https://www.cert.br/", "tags": ["brazil", "cert-br", "advisory"], "priority": 2},
    {"name": "CCB Belgium News", "slug": "ccb-belgium-news", "category": "cert", "rss_url": "https://ccb.belgium.be/news.xml", "official_url": "https://ccb.belgium.be/", "tags": ["belgium", "ccb", "news"], "priority": 2},
    {"name": "CCB Belgium Advisories", "slug": "ccb-belgium-advisories", "category": "cert", "rss_url": "https://ccb.belgium.be/advisories.xml", "official_url": "https://ccb.belgium.be/", "tags": ["belgium", "ccb", "advisories"], "priority": 2},
    {"name": "NUKIB (Czech Republic)", "slug": "nukib-cz", "category": "cert", "rss_url": "https://nukib.gov.cz/rss.xml", "official_url": "https://nukib.gov.cz/", "tags": ["czech", "nukib", "advisory"], "priority": 2},
    {"name": "NCSC Netherlands News", "slug": "ncsc-nl-news", "category": "cert", "rss_url": "https://feeds.ncsc.nl/nieuws.rss", "official_url": "https://www.ncsc.nl/", "tags": ["netherlands", "ncsc-nl", "news"], "priority": 2},
    {"name": "NCSC Netherlands Advisories", "slug": "ncsc-nl-advisories", "category": "cert", "rss_url": "https://advisories.ncsc.nl/rss/advisories", "official_url": "https://www.ncsc.nl/", "tags": ["netherlands", "ncsc-nl", "advisories"], "priority": 1},
    {"name": "NCSC Norway (NSM)", "slug": "ncsc-norway", "category": "cert", "rss_url": "https://nsm.no/fagomrader/digital-sikkerhet/nasjonalt-cybersikkerhetssenter/varsler-fra-ncsc/rss/", "official_url": "https://nsm.no/", "tags": ["norway", "nsm", "advisories"], "priority": 2},
    {"name": "CISA Advisories All", "slug": "cisa-all-xml", "category": "cert", "rss_url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "official_url": "https://www.cisa.gov/", "tags": ["cisa", "us", "advisory", "official"], "priority": 1},
    {"name": "CISA ICS Advisories", "slug": "cisa-ics-xml", "category": "cert", "rss_url": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", "official_url": "https://www.cisa.gov/", "tags": ["cisa", "ics", "scada", "critical-infra"], "priority": 1},
    {"name": "CISA Blog XML", "slug": "cisa-blog-xml", "category": "cert", "rss_url": "https://www.cisa.gov/blog.xml", "official_url": "https://www.cisa.gov/", "tags": ["cisa", "blog", "guidance"], "priority": 2},
    {"name": "CISA News XML", "slug": "cisa-news-xml", "category": "cert", "rss_url": "https://www.cisa.gov/news.xml", "official_url": "https://www.cisa.gov/", "tags": ["cisa", "news", "announcements"], "priority": 2},
    {"name": "Bloo Feed", "slug": "bloo-feed", "category": "news", "rss_url": "https://feed.bloo.io/feed/", "tags": ["bloo", "threat-intel", "osint"], "priority": 2},

    # ── APIs ─────────────────────────────────────────────────────────────────
    {"name": "NIST NVD CVE API 2.0", "slug": "nist-nvd-api", "category": "cert", "rss_url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "collection_method": "api", "tags": ["nist", "nvd", "cve", "vulnerability-api"], "priority": 1},
    {"name": "ThreatWinds API Feed", "slug": "threatwinds-api", "category": "vendor", "rss_url": "https://apis.threatwinds.com/api/feeds/v1/list", "collection_method": "api", "tags": ["threatwinds", "api", "ioc"], "priority": 2},
    {"name": "Safeguard Threat Feed API", "slug": "safeguard-api", "category": "vendor", "rss_url": "https://api.safeguard.sh/v1/threat-feed.json", "collection_method": "api", "tags": ["safeguard", "api", "threat-intel"], "priority": 2},
    {"name": "Supabase CTI Feed API", "slug": "supabase-cti-api", "category": "vendor", "rss_url": "https://xpvisffjxvtfrvyfsuma.supabase.co/functions/v1/feed-api?format=rss", "collection_method": "rss", "tags": ["supabase", "cti", "feed-api"], "priority": 2},
]


async def main():
    await MongoDB.connect()
    sources_col = get_sources_collection()
    articles_col = get_articles_collection()
    now = datetime.now(timezone.utc)

    print("=== SEEDING & CRAWLING 52 USER-PROVIDED EXTENDED FEEDS & APIs ===")
    added_count = 0
    success_count = 0
    failed_count = 0

    for src_def in USER_FEEDS:
        slug = src_def["slug"]
        existing = await sources_col.find_one({"slug": slug})

        if not existing:
            doc = {
                **src_def,
                "base_url": src_def.get("official_url", src_def["rss_url"]),
                "collection_method": src_def.get("collection_method", "rss"),
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
            }
            res = await sources_col.insert_one(doc)
            doc["_id"] = res.inserted_id
            added_count += 1
            src_doc = doc
            print(f"[+] Added source: {src_def['name']:<40}")
        else:
            src_doc = existing
            print(f"[*] Exists:       {src_def['name']:<40}")

        # Safely crawl with exception isolation
        try:
            crawl_res = await crawl_source(src_doc)
            new_arts = crawl_res.get("new_articles", 0)
            status = crawl_res.get("status", "healthy")
            print(f"    └─ Ingested {new_arts} articles (Status: {status})")
            success_count += 1
        except Exception as e:
            print(f"    └─ [SAFE ISOLATION] Crawl skipped/failed: {e}")
            failed_count += 1

    total_sources = await sources_col.count_documents({})
    total_articles = await articles_col.count_documents({})

    print("\n================ FINAL INGESTION SUMMARY ================")
    print(f"New Sources Seeded:      {added_count}")
    print(f"Feeds Crawled Success:   {success_count}")
    print(f"Feeds Skipped/Unreachable:{failed_count}")
    print(f"Total Database Sources:  {total_sources}")
    print(f"Total Database Articles: {total_articles}")
    print("=========================================================\n")


if __name__ == "__main__":
    asyncio.run(main())
