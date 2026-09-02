# ClarityTI — Complete System & Database Schemas

This document contains the complete database schemas, datatypes, indexes, Pydantic models, and JSON object structures used across the **ClarityTI** platform.

Database: **MongoDB 7.0** (`clarityti` database)  
Search Engine: **Elasticsearch 8.16** (`clarityti_*` indices)

---

## 📑 Table of Contents

1. [`sources` Collection](#1-sources-collection)
2. [`articles` Collection](#2-articles-collection)
3. [`threat_actors` Collection](#3-threat_actors-collection)
4. [`ta_aliases` Collection](#4-ta_aliases-collection)
5. [`ta_vendor_reports` Collection](#5-ta_vendor_reports-collection)
6. [`ta_relationships` Collection](#6-ta_relationships-collection)
7. [`ta_references` Collection](#7-ta_references-collection)
8. [`malware` Collection](#8-malware-collection)
9. [`campaigns` Collection](#9-campaigns-collection)
10. [`iocs` Collection](#10-iocs-collection)
11. [`cisa_kev` Collection](#11-cisa_kev-collection)
12. [`digests` Collection](#12-digests-collection)
13. [`reports` Collection](#13-reports-collection)
14. [`users` Collection](#14-users-collection)
15. [`logs` Collection](#15-logs-collection)
16. [Performance Compound Indexes & Optimizations](#16-performance-compound-indexes--optimizations)
17. [Pydantic Models & API Schemas](#17-pydantic-models--api-schemas)

---

## 1. `sources` Collection

Stores configured intelligence sources (RSS feeds, scrapers, APIs).

| Field | Type | Required | Default | Description | Index |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Auto | Unique primary key | Primary |
| `name` | `string` | Yes | - | Display name of intelligence source | - |
| `slug` | `string` | Yes | - | Unique URL slug | **Unique Index** |
| `category` | `string` | Yes | - | Feed category (`vendor`, `news`, `cert`) | Index |
| `subcategory` | `string` | No | `null` | Sub-category (e.g. `cloud`, `endpoint`) | - |
| `base_url` | `string` | Yes | - | Main website homepage URL | - |
| `rss_url` | `string` | No | `null` | Feed RSS/Atom XML URL | - |
| `logo_url` | `string` | No | `null` | Source favicon/logo URL | - |
| `collection_method` | `string` | Yes | `"rss"` | Ingestion method (`rss`, `scraper`, `api`) | - |
| `schedule_cron` | `string` | Yes | `"*/30 * * * *"` | Cron execution pattern | - |
| `rate_limit_rpm` | `integer` | Yes | `10` | Rate limit requests per minute | - |
| `priority` | `integer` | Yes | `2` | Priority weight (1-5) | Index |
| `is_active` | `boolean` | Yes | `true` | Active ingestion flag | Index |
| `article_count` | `integer` | Yes | `0` | Total articles collected | - |
| `health_status` | `string` | Yes | `"healthy"` | Health status (`healthy`, `degraded`, `failing`) | Index |
| `last_error_reason` | `string` | No | `null` | Fast triage error code (`RATE_LIMITED_429`, `FORBIDDEN_403`, `NOT_FOUND_404`, `DNS_CONNECT_TIMEOUT`, `PARSE_ERROR`, `SSL_CERT_ERROR`) | Index |
| `last_error` | `string` | No | `null` | Raw error message traceback | - |
| `last_crawled_at` | `datetime` | No | `null` | Last crawl timestamp | Index |
| `created_at` | `datetime` | Yes | UTC Now | Creation timestamp | - |

---

## 2. `articles` Collection

Stores ingested threat intelligence articles, security advisories, and news items.

| Field | Type | Required | Default | Description | Index |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Auto | Primary key | Primary |
| `source_id` | `string` | Yes | - | Foreign key string to `sources._id` | Index |
| `source_name` | `string` | Yes | - | Source name denormalized | - |
| `source_category` | `string` | Yes | - | Category (`vendor`, `news`, `cert`) | Index |
| `source_slug` | `string` | Yes | - | Source slug | - |
| `url` | `string` | Yes | - | Original article Web URL | - |
| `url_hash` | `string` | Yes | - | SHA256 hash of normalized URL | **Unique Index** |
| `title` | `string` | Yes | - | Article title | **Text Index** |
| `summary` | `string` | No | `null` | Extracted or AI-generated summary | **Text Index** |
| `content_raw` | `string` | No | `null` | Uncleaned HTML content | - |
| `content_clean` | `string` | No | `null` | Trafilatura extracted plaintext | - |
| `content_markdown` | `string` | No | `null` | Markdown formatted text | - |
| `author` | `string` | No | `null` | Author name | - |
| `published_at` | `datetime` | No | `null` | Article publication timestamp | Index |
| `crawled_at` | `datetime` | Yes | UTC Now | Ingestion timestamp | Index |
| `severity` | `string` | Yes | `"informational"` | `critical`, `high`, `medium`, `low`, `informational` | Index |
| `severity_score` | `float` | Yes | `0.0` | Numerical score (0.0 to 10.0) | - |
| `tags` | `array[string]` | Yes | `[]` | Categorization tags | Index |
| `threat_actors` | `array[string]` | Yes | `[]` | Matched threat actor canonical names & aliases | **Compound Index** |
| `malware_families` | `array[string]` | Yes | `[]` | Extracted malware family names | Index |
| `cves` | `array[string]` | Yes | `[]` | Extracted CVE IDs (e.g. `CVE-2026-65618`) | Index |
| `mitre_techniques` | `array[object]` | Yes | `[]` | MITRE ATT&CK techniques | - |
| `iocs` | `object` | Yes | `{}` | Structured IOC dictionary (ips, domains, hashes, cves) | - |
| `ioc_count` | `integer` | Yes | `0` | Total IOC count | - |
| `enrichment_status` | `string` | Yes | `"pending"` | Status (`pending`, `completed`, `failed`) | Index |
| `ai_summary` | `string` | No | `null` | Executive GPT-4.1 summary | **Text Index** |
| `is_duplicate` | `boolean` | Yes | `false` | Duplicate detection flag | Index |
| `claim_status` | `string` | Yes | `"claimed"` | `claimed`, `confirmed`, `denied` | Index |
| `claimed_records_count` | `integer` | No | `null` | Records the actor claims were taken (e.g. `250000`) | - |
| `attack_vector` | `string` | No | `null` | Claimed method (e.g. `"compromised Azure credentials"`) | - |
| `company_response` | `string` | No | `null` | Company's stated position (e.g. `"no systems breached"`) | - |
| `target_country` | `string` | No | `null` | Country of the targeted/victim organization | Index |
| `duplicate_of` | `string` | No | `null` | `articles._id` of the canonical article, if `is_duplicate` is `true` | Index |
| `similarity_score` | `float` | No | `null` | Cosine similarity to `duplicate_of` (0.0–1.0) | - |
| `embedding_vector` | `array[float]` | No | `null` | Vector output from the embedding model | - |
| `embedding_model` | `string` | No | `null` | Model used to generate `embedding_vector` (e.g. `"nemotron-3-embed-1b"`) | Index |
| `rerank_score` | `float` | No | `null` | Relevance score from the reranker for the query that retrieved this article | - |
| `ai_summary_model` | `string` | No | `null` | Model used to generate `ai_summary` | - |
| `ai_summary_generated_at` | `datetime` | No | `null` | Timestamp `ai_summary` was generated | - |

---

## 3. `threat_actors` Collection

Master knowledge graph profiles for state-sponsored APTs and cybercrime groups.

| Field | Type | Required | Default | Description | Index |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Auto | Unique primary key | Primary |
| `name` | `string` | Yes | - | Display name | **Text Index** |
| `canonical_name` | `string` | Yes | - | Normalized unique identity name | **Unique Index / Text** |
| `slug` | `string` | Yes | - | URL slug | **Unique Index** |
| `aliases` | `array[string]` | Yes | `[]` | Alternative names (e.g. `Evil Corp`, `DEV-0243`) | **Text / Index** |
| `type` | `string` | Yes | `"unknown"` | `apt`, `ransomware-group`, `hacktivist`, `criminal` | Index |
| `origin_country` | `string` | No | `null` | Country of origin | Index |
| `motivation` | `array[string]` | Yes | `[]` | Financial, Espionage, Sabotage | - |
| `active_status` | `string` | Yes | `"active"` | `active`, `inactive`, `disrupted` | Index |
| `mitre_group_id` | `string` | No | `null` | MITRE ATT&CK Group ID (e.g. `G0119`) | Index |
| `targeted_sectors` | `array[string]` | Yes | `[]` | Targeted industries | Index |
| `targeted_countries` | `array[string]` | Yes | `[]` | Targeted geographical countries | - |
| `confidence_score` | `float` | Yes | `0.5` | Attribution confidence (0.0 to 1.0) | **Compound Index** |
| `article_count` | `integer` | Yes | `0` | Total linked intelligence articles | **Compound Index** |
| `report_count` | `integer` | Yes | `0` | Total linked vendor reports | - |
| `sources` | `array[string]` | Yes | `[]` | Source origins (`mitre`, `misp`, `vendor_report`) | - |
| `tools` | `array[string]` | Yes | `[]` | Tools & malware used | - |
| `cves` | `array[string]` | Yes | `[]` | Associated CVE IDs | - |
| `ttps` | `array[string]` | Yes | `[]` | MITRE TTP technique IDs | - |

---

## 4. `ta_aliases` Collection

Cross-reference map mapping any threat actor alias string to its canonical threat actor document ID.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `alias` | `string` | Yes | Alias string (e.g. `Wizard Spider`) | **Unique Index** |
| `alias_lowercase` | `string` | Yes | Normalized lowercase alias | **Unique Index** |
| `canonical_name` | `string` | Yes | Canonical target actor name | Index |
| `actor_id` | `string` | Yes | Target `threat_actors._id` string | Index |
| `source` | `string` | Yes | Source of alias (`mitre`, `misp`, `vendor`) | - |

---

## 5. `ta_vendor_reports` Collection

Stores deep-dive vendor intelligence reports published by security research teams.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `title` | `string` | Yes | Report title | **Text Index** |
| `url` | `string` | Yes | Report URL | **Unique Index** |
| `publisher` | `string` | Yes | Vendor name (e.g., Mandiant, CrowdStrike) | Index |
| `actor_ids` | `array[string]` | Yes | Linked `threat_actors._id` list | Index |
| `summary` | `string` | No | Report summary | - |
| `body_text` | `string` | No | Extracted full text | - |
| `published_at` | `datetime` | Yes | Publication date | Index |
| `extracted_iocs` | `object` | Yes | IOC dictionary | - |
| `cves` | `array[string]` | Yes | Associated CVE IDs | - |

---

## 6. `ta_relationships` Collection

Stores entity relationship links for building threat actor knowledge graphs.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `source_id` | `string` | Yes | Source entity ID (`threat_actors._id`) | Index |
| `source_type` | `string` | Yes | Source entity type (`threat_actor`) | - |
| `target_id` | `string` | Yes | Target entity ID (`malware._id` or `campaign._id`) | Index |
| `target_type` | `string` | Yes | Target type (`malware`, `campaign`, `tool`) | - |
| `relationship_type` | `string` | Yes | Relationship (`uses`, `attributed_to`, `targets`) | Index |

---

## 7. `ta_references` Collection

External URL citations and report references linked to threat actors.

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key |
| `actor_id` | `string` | Yes | Linked `threat_actors._id` |
| `url` | `string` | Yes | Reference URL |
| `title` | `string` | No | Page or article title |
| `source_name` | `string` | No | Publisher or domain name |

---

## 8. `malware` Collection

Stores cataloged malware families, tools, and ransomware payloads.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `name` | `string` | Yes | Malware family name | **Unique Index** |
| `type` | `string` | Yes | Type (`ransomware`, `rat`, `stealer`, `loader`, `wiper`) | Index |
| `aliases` | `array[string]` | Yes | Alternative names | - |
| `associated_actors` | `array[string]` | Yes | Linked threat actor names | Index |
| `cves` | `array[string]` | Yes | Exploited CVE IDs | - |

---

## 9. `campaigns` Collection

Stores cyber threat campaigns and multi-phase intrusion operations.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `name` | `string` | Yes | Campaign name | **Unique Index** |
| `actor_name` | `string` | No | Primary threat actor | Index |
| `targeted_sectors` | `array[string]` | Yes | Targeted industries | - |
| `first_seen` | `datetime` | No | Campaign start date | Index |
| `last_seen` | `datetime` | No | Campaign end/latest date | Index |

---

## 10. `iocs` Collection

Normalized Indicators of Compromise master database.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `value` | `string` | Yes | Indicator value (IP, domain, SHA256) | **Unique Index** |
| `type` | `string` | Yes | Type (`ip`, `domain`, `sha256`, `md5`, `url`, `cve`, `email`) | Index |
| `first_seen_article_id` | `string` | Yes | First article ID where IOC was seen | Index |
| `article_count` | `integer` | Yes | Total articles mentioning this IOC | Index |
| `threat_actors` | `array[string]` | Yes | Associated threat actors | - |

---

## 11. `cisa_kev` Collection

Mirror of CISA Known Exploited Vulnerabilities catalog.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `cve_id` | `string` | Yes | CVE ID (e.g., `CVE-2024-30080`) | **Unique Index** |
| `vendor_project` | `string` | Yes | Affected vendor or open-source project | Index |
| `product` | `string` | Yes | Affected product | - |
| `vulnerability_name` | `string` | Yes | Vulnerability title | **Text Index** |
| `date_added` | `datetime` | Yes | Date added to CISA KEV | Index |
| `short_description` | `string` | Yes | Vulnerability summary | - |
| `required_action` | `string` | Yes | Remediation action | - |
| `dueDate` | `datetime` | No | Remediation due date | - |
| `known_ransomware` | `boolean` | Yes | Associated with ransomware campaigns | Index |
| `epss_score` | `float` | Yes | EPSS probability score (0.0 to 1.0) | Index |

---

## 12. `digests` Collection

Stores daily 24-hour executive AI threat briefings.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `digest_date` | `string` | Yes | Date string (`YYYY-MM-DD`) | **Unique Index** |
| `title` | `string` | Yes | Executive briefing title | - |
| `executive_summary` | `string` | Yes | High-level synthesis | - |
| `top_threats` | `array[object]` | Yes | Top 5 threat items of the day | - |
| `cve_highlights` | `array[object]` | Yes | New KEV additions & high EPSS CVEs | - |
| `article_count` | `integer` | Yes | Total articles analyzed for digest | - |
| `created_at` | `datetime` | Yes | Generation timestamp | Index |

---

## 13. `reports` Collection

Stores Advisory Lens real-time AI document and URL threat analysis reports.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `title` | `string` | Yes | Analysis title | **Text Index** |
| `input_type` | `string` | Yes | Input mode (`url`, `file`, `text`) | Index |
| `source_url` | `string` | No | Original URL analyzed | - |
| `filename` | `string` | No | Name of uploaded document | - |
| `executive_summary` | `string` | Yes | GPT-4.1 executive summary | - |
| `key_takeaways` | `array[string]` | Yes | Key findings list | - |
| `severity` | `string` | Yes | `critical`, `high`, `medium`, `low`, `informational` | Index |
| `attributed_actors` | `array[string]` | Yes | Attributed threat actor entities | - |
| `cves` | `array[string]` | Yes | Extracted CVE IDs | - |
| `iocs` | `object` | Yes | Extracted IOC dictionary | - |
| `mitre_techniques` | `array[object]` | Yes | Identified TTPs | - |
| `created_at` | `datetime` | Yes | Creation timestamp | Index |

---

## 14. `users` Collection

Stores user authentication, roles, and notification preferences.

| Field | Type | Required | Default | Description | Index |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Auto | Unique user ID | Primary |
| `email` | `string` | Yes | - | User email address | **Unique Index** |
| `hashed_password` | `string` | Yes | - | Bcrypt password hash | - |
| `full_name` | `string` | Yes | - | User display name | - |
| `role` | `string` | Yes | `"analyst"` | User role (`admin`, `analyst`, `viewer`) | Index |
| `is_active` | `boolean` | Yes | `true` | Account active flag | - |
| `preferences` | `object` | Yes | `{}` | UI themes, webhooks, alert preferences | - |
| `created_at` | `datetime` | Yes | UTC Now | Account creation timestamp | - |

---

## 15. `logs` Collection

System-wide ingestion, audit, and worker execution logs.

| Field | Type | Required | Description | Index |
| :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Primary key | Primary |
| `event_type` | `string` | Yes | Event category (`crawl`, `enrichment`, `digest`, `alert`) | Index |
| `source_name` | `string` | No | Target source name | - |
| `status` | `string` | Yes | Outcome (`success`, `warning`, `error`) | Index |
| `message` | `string` | Yes | Log details message | - |
| `details` | `object` | No | Additional context JSON | - |
---

## 16. `viral_events` Collection (CyberPulse Heat Map)

Stores real-time clustered outbreak events, heat scores, and multi-source growth velocity.

| Field | Type | Required | Default | Description | Index |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `_id` | `ObjectId` | Yes | Auto | Primary key | Primary |
| `event_id` | `string` | Yes | - | Unique event identifier | **Unique Index** |
| `title` | `string` | Yes | - | Canonical event title | - |
| `normalized_title` | `string` | Yes | - | Normalized lowercase title | Index |
| `summary` | `string` | Yes | - | Executive event summary | - |
| `explanation` | `string` | Yes | - | Technical breach explanation | - |
| `related_article_ids` | `array[string]` | Yes | `[]` | Foreign keys to `articles._id` | - |
| `unique_source_names` | `array[string]` | Yes | `[]` | Distinct sources reporting the story | - |
| `source_count` | `integer` | Yes | `0` | Total distinct reporting sources | Index |
| `article_count` | `integer` | Yes | `0` | Total reporting articles | - |
| `heat_score` | `integer` | Yes | `0` | Calculated viral heat metric (0-100) | Index |
| `coverage_score` | `float` | Yes | `0.0` | Source diversity score | - |
| `velocity_score` | `float` | Yes | `0.0` | Publication velocity score | - |
| `recency_score` | `float` | Yes | `0.0` | Temporal recency decay score | - |
| `trend` | `string` | Yes | `"increasing"` | `increasing`, `stable`, `decreasing` | - |
| `priority` | `string` | Yes | `"medium"` | `critical`, `high`, `medium` | Index |
| `status` | `string` | Yes | `"trending"` | `emerging`, `trending`, `high_heat` | Index |
| `target_company` | `string` | No | `null` | Targeted organization name | Index |
| `target_country` | `string` | No | `null` | Victim country / region | Index |
| `incident_type` | `string` | No | `null` | Incident category (`Ransomware`, `Breach`, `Zero-Day`) | Index |
| `first_detected_at` | `datetime` | Yes | UTC Now | Outbreak start timestamp | Index |
| `last_detected_at` | `datetime` | Yes | UTC Now | Latest update timestamp | Index |
| `alert_triggered` | `boolean` | Yes | `false` | True if dispatched to MS Teams | Index |

---

## 17. Performance Compound Indexes & Optimizations

To ensure sub-second query speeds across **100,000+ historical articles and threat actors**, the following compound indexes are configured:

1. **Threat Actor Timeline Index**: `{"threat_actors": 1, "published_at": -1}`
   - Enables instant lookup of historical article timelines for any specific APT or ransomware group.
2. **Category Feed Timeline Index**: `{"source_category": 1, "published_at": -1}`
   - Powers high-performance filtering across `Vendor Research`, `News & Investigation`, and `Government / CERTs`.
3. **Severity Alert Index**: `{"severity": 1, "published_at": -1}`
   - Powers real-time critical and high-priority alert dashboards.
4. **Threat Actor Directory Sorting Index**: `{"article_count": -1}`
   - Allows instant sorting of 900+ threat actors by intelligence activity.
5. **Claim Status Timeline Index**: `{"claim_status": 1, "published_at": -1}`
   - Powers a feed view filtered to `claimed`-only or `denied`-only articles.
6. **Duplicate Cluster Index**: `{"duplicate_of": 1}`
   - Speeds up pulling every article clustered under one canonical story.
7. **Embedding Model Index**: `{"embedding_model": 1, "crawled_at": -1}`
   - Useful when re-embedding after a model swap — lets you find every article still on the old model.

---

## 17. Pydantic Models & API Schemas

### Article Schema (`app/models/article.py`)
```python
class RawArticle(BaseModel):
    url: str
    title: str
    content: str = ""
    summary: str = ""
    author: Optional[str] = None
    published_at: Optional[datetime] = None
    tags: List[str] = []
    metadata: Dict[str, Any] = {}
```

### Threat Actor Create Schema (`app/models/threat.py`)
```python
class ThreatActorCreate(BaseModel):
    name: str
    canonical_name: Optional[str] = None
    aliases: List[str] = []
    type: str = "unknown"
    origin_country: Optional[str] = None
    motivation: List[str] = []
    active_status: str = "active"
    mitre_group_id: Optional[str] = None
    targeted_sectors: List[str] = []
    targeted_countries: List[str] = []
    description: Optional[str] = None
```

### Microsoft Teams Webhook Request Schema (`app/api/v1/teams.py`)
```python
class TeamsWebhookRequest(BaseModel):
    webhook_url: str
    channel: Optional[str] = "high_priority_news"  # 'high_priority_news' | 'indian_breaches' | 'middle_east_companies'
    auto_dispatch: Optional[bool] = False
```

---

## 18. Critical Alerts & Decision Engine Schema

Defines the triage criteria used by `is_critical_actionable_incident()` to separate broad website intelligence from emergency Team Alerts:

```python
class CriticalAlertDecision(BaseModel):
    is_actionable_incident: bool
    incident_category: str          # 'Data Breach' | 'Data Theft' | 'Ransomware' | 'Critical Infrastructure' | 'Service Disruption' | 'Company Compromise'
    target_organization: Optional[str]
    target_sector: Optional[str]
    claim_status: Optional[str]     # 'confirmed' | 'claimed' | 'denied'
    ai_insight: str                 # Synthesized by Google Gemini Flash
    dispatch_destination: str       # 'WEBSITE_ONLY' | 'TEAM_ALERT'
```

