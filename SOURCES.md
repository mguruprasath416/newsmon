# NewsMon (ClarityTI) — Monitored Threat Intelligence Sources

This document provides a comprehensive list of all **active intelligence sources** monitored, indexed, and crawled by the NewsMon / ClarityTI platform.

- **GitHub Repository**: [https://github.com/mguruprasath416/newsmon.git](https://github.com/mguruprasath416/newsmon.git)

---

## 📊 Category Breakdown & Overview

| Category | Description | Source Count |
| :--- | :--- | :---: |
| **News & Breach** | Cybercrime news outlets, breach tracking, OSINT, and blockchain research | ~15 |
| **Threat Research & OffSec** | Major EDR/MDR labs, vulnerability research, and Offensive Security blogs | ~25 |
| **Official & Global CERTs** | National CERTs, government advisories, and international cyber agencies | ~32 |
| **CTI REST APIs** | Direct JSON/API feeds (NIST NVD, ThreatWinds, Safeguard) | 3 |
| **Total Monitored Platform Sources** | | **72+ Feeds** |

---

## 🛡️ Safety & Security System ("Safe & Secure")

1. **Timeout & Isolation**: Each feed crawler executes in an isolated environment with a **10-second request timeout** to guarantee broken or slow feeds never stall the engine.
2. **Fallback SSL Resilience**: National CERT sites with self-signed or legacy TLS certs automatically fall back to an unverified HTTPS client (`verify=False`).
3. **Payload Sanitization**: Incoming summary text passes through `clean_summary_text()` to strip script tags, executable HTML, or prompt injection attempts.
4. **Domain Rate Limiting**: Enforces a 10 RPM (requests per minute) rate limit per domain.

---

## 🌐 Complete List of Active Intelligence Feeds

### 📰 1. News & Breach Tracking
- **The Hacker News**: `https://feeds.feedburner.com/TheHackersNews`
- **BleepingComputer**: `https://www.bleepingcomputer.com/feed/`
- **The Record**: `https://therecord.media/feed`
- **KrebsOnSecurity**: `https://krebsonsecurity.com/feed/`
- **Dark Reading**: `https://www.darkreading.com/rss.xml`
- **SecurityWeek**: `https://feeds.feedburner.com/Securityweek`
- **CyberScoop**: `https://cyberscoop.com/feed/`
- **DataBreaches.net**: `https://www.databreaches.net/feed/`
- **Chainalysis Blog**: `https://blog.chainalysis.com/feed/`
- **Citizen Lab**: `https://citizenlab.ca/feed/`
- **Have I Been Pwned Breaches**: `https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches`
- **Bloo Feed**: `https://feed.bloo.io/feed/`

### 🔬 2. Threat Research & OffSec Labs
- **Google Threat Intelligence**: `https://cloudblog.withgoogle.com/rss/`
- **Microsoft Security Blog**: `https://www.microsoft.com/en-us/security/blog/feed/`
- **Cisco Talos**: `https://feeds.feedburner.com/feedburner/Talos`
- **Palo Alto Unit42**: `https://unit42.paloaltonetworks.com/feed/`
- **SentinelOne Blog / SentinelLabs**: `https://www.sentinelone.com/blog/feed/`
- **Check Point Research**: `https://research.checkpoint.com/feed/`
- **Malwarebytes Labs**: `https://www.malwarebytes.com/blog/feed/index.xml`
- **CrowdStrike Blog**: `https://www.crowdstrike.com/en-us/blog/feed`
- **GreyNoise Articles**: `https://api.greynoise.io/v3/articles/rss`
- **GreyNoise Blog**: `https://www.greynoise.io/blog/rss.xml`
- **watchTowr Labs**: `https://labs.watchtowr.com/rss/`
- **PortSwigger Research**: `https://portswigger.net/research/rss`
- **PortSwigger Blog**: `https://portswigger.net/blog/rss`
- **Trail of Bits Blog**: `https://blog.trailofbits.com/feed/`
- **VulnCheck Blog**: `https://vulncheck.com/feed/blog/atom.xml`
- **VUSEC Lab (VU Amsterdam)**: `https://www.vusec.net/feed/`
- **ZecOps Blog**: `https://blog.zecops.com/feed/`
- **Zero Day Initiative (ZDI)**: `https://www.thezdi.com/blog?format=rss`
- **Eclypsium Research**: `https://www.eclypsium.com/feed/`
- **Cado Security Blog**: `https://www.cadosecurity.com/blog/rss.xml`
- **Censys Research**: `https://censys.com/tag/research/feed/`

### 🏛️ 3. Official Global CERTs & Government Advisories
- **CISA Alerts**: `https://www.cisa.gov/cybersecurity-advisories` (XML, ICS, Blog, News feeds)
- **CERT-In Advisories (India)**: `https://www.cert-in.org.in/`
- **NCSC UK**: `https://www.ncsc.gov.uk/` (Reports & News feeds)
- **SANS Internet Storm Center**: `https://isc.sans.edu/rssfeed.xml`
- **CERT-EU**: `https://cert.europa.eu/` (Threat Intel & Advisories)
- **JPCERT (Japan)**: `https://www.jpcert.or.jp/english/` (RDF & Blog Atom feeds)
- **ASD Cyber Security Australia**: `https://www.cyber.gov.au/` (Advisories, Alerts, Threats)
- **CERT-FR (France)**: `https://www.cert.ssi.gouv.fr/feed/`
- **GovCERT Hong Kong**: `https://www.govcert.gov.hk/`
- **HKCERT (Hong Kong)**: `https://www.hkcert.org/`
- **NCSC-FI (Finland)**: Main, News, and Vulns feeds
- **CERT.PL (Poland)**: `https://www.cert.pl/en/rss.xml`
- **SI-CERT (Slovenia)**: `https://www.cert.si/en/`
- **CCN-CERT (Spain)**: `https://www.ccn-cert.cni.es/`
- **Canadian Centre for Cyber Security**: Alerts & News feeds
- **CERT.br (Brazil)**: `https://www.cert.br/rss/certbr-rss.xml`
- **CCB Belgium**: News & Advisories feeds
- **NUKIB (Czech Republic)**: `https://nukib.gov.cz/rss.xml`
- **NCSC Netherlands**: News & Advisories feeds
- **NCSC Norway (NSM)**: `https://nsm.no/`

### 🔌 4. CTI REST APIs
- **NIST NVD CVE API 2.0**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **ThreatWinds API Feed**: `https://apis.threatwinds.com/api/feeds/v1/list`
- **Safeguard Threat Feed API**: `https://api.safeguard.sh/v1/threat-feed.json`