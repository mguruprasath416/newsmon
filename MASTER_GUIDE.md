# NewsMon / ClarityTI — Master System Architecture & CTI Research Specification

> **Document Version:** 2.0.0-PROD  
> **Target Audience:** Threat Intelligence Analysts, Security Engineers, AI/ML Research Teams, and Future Core Developers  
> **Platform Classification:** Enterprise Automated Cyber Threat Intelligence (CTI) & Incident Radar  

---

## 📑 Master Table of Contents
1. [Executive Vision & Core Architecture](#1-executive-vision--core-architecture)
2. [The Core Philosophy: Website Intelligence vs. Team Alerts](#2-the-core-philosophy-website-intelligence-vs-team-alerts)
3. [End-to-End Data Ingestion & Normalization Pipeline](#3-end-to-end-data-ingestion--normalization-pipeline)
4. [Hierarchical Keyword Taxonomy & Classification Engine](#4-hierarchical-keyword-taxonomy--classification-engine)
5. [AI Threat Intelligence Enrichment & Executive Synthesis](#5-ai-threat-intelligence-enrichment--executive-synthesis)
6. [Multi-Channel Notification & Adaptive Card Engineering](#6-multi-channel-notification--adaptive-card-engineering)
7. [Semantic Search (RAG), Advisory Lens & CyberPulse Engine](#7-semantic-search-rag-advisory-lens--cyberpulse-engine)
8. [Database Schemas, Microservices & Container Architecture](#8-database-schemas-microservices--container-architecture)
9. [Future Research & Engineering Development Roadmap](#9-future-research--engineering-development-roadmap)
10. [Master System Prompt (Universal CTI Agent Prompt)](#10-master-system-prompt-universal-cti-agent-prompt)

---

## 1. Executive Vision & Core Architecture

**NewsMon (ClarityTI)** is an automated, real-time Cyber Threat Intelligence (CTI) harvesting, enrichment, correlation, and alerting platform. It unifies intelligence across **72+ global sources**, eliminating visibility gaps and analyst alert fatigue.

```
                                  ┌────────────────────────┐
                                  │   72+ GLOBAL SOURCES   │
                                  │ (CERTs, RSS, KEV, OSINT)│
                                  └───────────┬────────────┘
                                              │
                                              ▼
                                  ┌────────────────────────┐
                                  │ Ingestion & Deduplication│
                                  │ (SHA-256 URL/Title Hash)│
                                  └───────────┬────────────┘
                                              │
                                              ▼
                                  ┌────────────────────────┐
                                  │  Keyword Classification │
                                  │ (590+ Regex Union Tax.)│
                                  └───────────┬────────────┘
                                              │
                                              ▼
                                  ┌────────────────────────┐
                                  │  AI Enrichment Engine   │
                                  │ (Google Gemini Flash)  │
                                  └───────────┬────────────┘
                                              │
                    ┌─────────────────────────┴─────────────────────────┐
                    ▼                                                   ▼
        ┌───────────────────────┐                           ┌───────────────────────┐
        │  ALL CYBERSECURITY    │                           │  CRITICAL ACTIONABLE  │
        │      INTELLIGENCE     │                           │       INCIDENTS       │
        │ (CVEs, Advisories,    │                           │ (Breaches, Ransomware,│
        │  Patches, Research)   │                           │  Theft, Disruption)   │
        └───────────┬───────────┘                           └───────────┬───────────┘
                    ▼                                                   ▼
        ┌───────────────────────┐                           ┌───────────────────────┐
        │   WEBSITE PLATFORM    │                           │    MS TEAMS ALERTS    │
        │  (Next.js Dashboard)  │                           │ (High-Impact Cards)   │
        └───────────────────────┘                           └───────────────────────┘
```

---

---

## 2. The Core Philosophy: Website Intelligence vs. Team Alerts

The platform implements a strict separation of concerns to prevent alert fatigue:

### 🛡️ System Architecture Scorecard

| Component | Status | Production Implementation |
| :--- | :---: | :--- |
| **Website vs Teams separation** | 🟢 **Strong** | Website catalogs all broad CTI; Teams alerts strictly on actionable emergencies. |
| **10-field CTI schema** | 🟢 **Strong** | Full JSON extraction (`claim_status`, `severity`, `threat_actor`, `sector`, etc.). |
| **Claim/confirmation concept** | 🟢 **Strong** | Strict integrity rule: actor allegations never turned into confirmed corporate breaches. |
| **AI executive insight** | 🟢 **Strong** | Single, concise `🔎 AI INSIGHT` synthesized by Google Gemini Flash. |
| **Keyword taxonomy** | 🟢 **Strong** | 590+ terms across 7 categories used strictly as candidate taggers (non-alerting). |
| **Keyword-only alerting avoidance** | 🟢 **Strong** | Zero keyword-only triggers; keywords feed the candidate pool only. |
| **Evidence validation gate** | 🟢 **Strong** | Multi-factor evidence scoring ($\ge 50$ pts) requiring victim, records, or active disruption. |
| **Team Alert decision layer** | 🟢 **Strong** | Explicit `TeamAlertDecisionEngine` class with deterministic 4-stage evaluation. |
| **False-positive protection** | 🟢 **Strong** | Negative context filter blocks hypothetical, simulation, tabletop, and patch PR noise. |
| **Architecture overall** | 🟢 **Strong** | High-performance, async, Docker-ready, resilient microservice foundation. |

---

### 🌐 Layer 1: Website Platform (Broad CTI Repository)
- **Scope:** Everything cybersecurity-related.
- **Includes:** New CVE disclosures, vendor patchworks, zero-day research, bug bounties, CERT bulletins, minor malware campaigns, cryptography updates, and tool releases.
- **Purpose:** Centralized catalog for searching, filtering, threat actor profiling, and historical lookups.

### 🚨 Layer 2: Team Alerts (Explicit 4-Stage Decision Layer)
- **Stage 1 (Candidate Tagging):** Keywords tag candidate articles without firing alerts.
- **Stage 2 (False-Positive Filter):** Rejects theoretical flaws ("could allow attackers to"), tabletop simulations, phishing tests, and generic patch advisories.
- **Stage 3 (Evidence Validation Gate):** Requires $\ge 50$ evidence points:
  - *Confirmed Corporate Disclosure:* **+25 pts**
  - *Quantified Stolen Records / Data Exfiltration:* **+35 pts**
  - *Ransomware Deployment / Encrypted Systems:* **+30 pts**
  - *Critical Infrastructure / Public Safety Impact:* **+30 pts**
  - *Major Operational / Service Disruption:* **+25 pts**
  - *Identified Target Enterprise:* **+20 pts**
  - *Identified Threat Actor:* **+20 pts**
- **Stage 4 (Deterministic Routing):** If Score $\ge 50$, dispatches adaptive card to Microsoft Teams. Otherwise, stays on **Website Only**.

---

## 3. End-to-End Data Ingestion & Normalization Pipeline

### 3.1 Intelligence Collectors
- **RSS/Atom Collectors:** Asynchronously polled every 30 minutes via Celery.
- **National CERT Portals:** Official feeds from India (CERT-In), UAE (aeCERT), Saudi Arabia (NCA), Israel (INCD), Oman (OCERT), Egypt (EG-CERT), and Iraq (CERT-IQ).
- **CISA KEV Catalog:** Synchronized automatically to flag actively exploited vulnerabilities.

### 3.2 Deduplication Engine
1. **Tier 1 (URL SHA-256):** Exact match hash on normalized URL string.
2. **Tier 2 (Title SHA-256):** Normalized title string (lowercased, stripped of non-alphanumeric noise).
3. **Tier 3 (In-Memory Alert Fingerprint):** Stable key `f"{webhook_url}::{fingerprint}"` recorded in `_DISPATCHED_TEAMS_KEYS` and stored with `teams_dispatched: True` in MongoDB.

---

## 4. Hierarchical Keyword Taxonomy & Classification Engine

Located in `files/Keywords/`, the taxonomy is compiled into unified, high-speed regex patterns:

```
files/Keywords/
├── Critical_Alerts/          # 8 Incident Decision Files
│   ├── Data_Breach.txt
│   ├── Data_Theft.txt
│   ├── Ransomware_Incident.txt
│   ├── Company_Compromise.txt
│   ├── Critical_Infrastructure_Attack.txt
│   ├── Major_Cyberattack.txt
│   ├── Service_Disruption.txt
│   └── Extortion_Leak.txt
├── Attacks/                  # Ransomware, DDoS, Phishing, Supply Chain, Espionage
├── Geography/                # India, USA, Middle East, Europe, China, Russia
├── Malware/                  # Infostealer, RAT, Trojan, Botnet, Spyware
├── Targets/                  # Banking, Energy, Gov, Healthcare, Telecom, Infrastructure
├── Threat Actors/            # APTs, Ransomware Groups, Hacktivists, Cybercriminals
└── Vulnerabilities/          # Zero-Day, RCE, Privilege Escalation, CVE
```

### Risk Scoring Matrix
$$\text{Cyber Risk Score} = \min(100, W_{\text{critical}} + W_{\text{attack}} + W_{\text{vuln}} + W_{\text{malware}} + W_{\text{actor}} + W_{\text{target}})$$
- Critical Alerts: **+40** (Base floor 85)
- Active Ransomware / Zero-Day: **+25** (Base floor 85)
- Critical Infrastructure / Energy Targets: **+10** (Base floor 80)
- Government / Banking / Healthcare: **+10** (Base floor 75)

---

## 5. AI Threat Intelligence Enrichment & Executive Synthesis

### 5.1 Primary Engine: Google Gemini (`gemini-3-flash-preview` / `gemini-2.5-flash`)
Gemini extracts 10 structured CTI parameters in valid JSON format:
- `claim_status`: `claimed` | `confirmed` | `denied`
- `severity`: `critical` | `high` | `medium` | `low` | `informational`
- `threat_actor`: Named actor (or `Unattributed`)
- `target_country`: Full country name
- `sector`: Target industry vertical
- `claimed_records_count`: Extracted numeric volume
- `attack_vector`: Method of compromise
- `company_response`: Organization's public position
- `cves`: List of CVE IDs
- `summary`: Objective 2–3 sentence analysis

### 5.2 Executive `🔎 AI INSIGHT` Synthesis
Generates an actionable, executive risk statement and immediate technical defense measure displayed cleanly on all critical alert cards.

---

## 6. Multi-Channel Notification & Adaptive Card Engineering

### Microsoft Teams Channel Architecture
- **`#high-priority-news`:** Global critical data breaches, leaks, zero-days, and executive digests.
- **`#indian-breaches`:** India-specific enterprise compromises, data leaks, and CERT-In advisories.
- **`#middle-east-companies`:** GCC & Middle East corporate incidents and regional CERT alerts.

### Card Format Specification
```
📰 CYBER NEWS                                        [DATE]
[Incident Headline]
────────────────────────────────────────────────────────────
[Factual plain-language summary of what happened, who was affected, and scope]
────────────────────────────────────────────────────────────
CATEGORY
🛡 [Incident Category]

SOURCE
[Source Name](URL)

PUBLISHED
[Publish Date]

REGION
🌍 [Target Region]
────────────────────────────────────────────────────────────
🔎 AI INSIGHT
[Actionable risk assessment and defensive guidance synthesized by Gemini]
```

---

## 7. Semantic Search (RAG), Advisory Lens & CyberPulse Engine

- **Advisory Lens:** Upload raw text, web URLs, or PDF documents. PyMuPDF and Trafilatura extract clean text, spaCy and regex extract IOCs, and Gemini produces executive summaries and mitigation playbooks.
- **RAG Semantic Search:** Hybrid BM25 (Elasticsearch 8.16) + Vector Embeddings (NVIDIA Nemotron-3 1B) + Reranking (NVIDIA Mistral-4B) for sub-second threat entity search.
- **CyberPulse Viral News Engine:** Clusters multi-source reporting of identical breaking events within a 72-hour window using MinHash LSH and cosine similarity ($\ge 0.55$).

---

## 8. Database Schemas, Microservices & Container Architecture

- **Backend:** FastAPI (Python 3.12), Motor, Celery 5.4, spaCy.
- **Frontend:** Next.js 15, React 19, TypeScript, TailwindCSS, TanStack Query v5.
- **Databases:** MongoDB 7.0 (Core documents), Elasticsearch 8.16 (Search index), Redis 7.4 (Task queue & Cache).
- **Orchestration:** `docker-compose.yml` mounting `./files:/files:ro` for live keyword taxonomy synchronization.

---

## 9. Future Research & Engineering Development Roadmap

For research teams developing future iterations:

1. **Autonomous Dark Web Crawler Integration:** Automated scraping of Tor `.onion` leak blogs (LockBit, RansomHub, BianLian) with automated image OCR for leak proof verification.
2. **Predictive Zero-Day Weaponization Model:** ML classifier predicting in-the-wild exploit probability before CISA KEV listing by correlating EPSS, CVSS vector strings, PoC availability on GitHub, and exploit-broker dark web mentions.
3. **Automated STIX 2.1 Graph Visualizer:** Interactive dynamic entity graph linking Threat Actors $\rightarrow$ Campaigns $\rightarrow$ TTPs $\rightarrow$ CVEs $\rightarrow$ Target Organizations.
4. **Autonomous SOAR Remediation Dispatch:** Automated generation of Snort/Suricata rules, Sigma detection rules, and firewall blocklists for extracted IOCs.

---

## 10. Master System Prompt (Universal CTI Agent Prompt)

Use this master system prompt to initialize any AI agent, LLM subagent, or prompt-based automation interacting with this platform:

```markdown
# NewsMon / ClarityTI — Advanced CTI Triage & Team Alert Prompt

You are the Master Cyber Threat Intelligence (CTI) AI Engine for NewsMon (ClarityTI).

Your mission is to analyze cybersecurity news, threat intelligence, security research, breach reports, ransomware incidents, vulnerability disclosures, advisories, malware campaigns, and cyberattack reports.

Your highest priority is to maintain a strict separation between general Website Intelligence and high-impact Team Alerts.

---

## 1. STRICT TRIAGE SEPARATION

### 🌐 WEBSITE FEED
The Website Feed contains all relevant cybersecurity intelligence, including:
* CVEs
* Vulnerability disclosures
* Security research
* Vendor security updates
* Patch releases
* Security advisories
* CERT bulletins
* Bug bounty disclosures
* Malware research
* Minor malware campaigns
* Threat actor research
* Cybersecurity tools
* Cryptography updates
* Security configuration guidance
* General cybersecurity news

These articles should normally remain Website Feed only unless they describe an actual high-impact incident.

---

### 🚨 TEAM ALERTS
Team Alerts are reserved exclusively for high-impact, actionable cyber incidents.
A Team Alert may be generated when at least one of the following conditions is satisfied:

1. Corporate Breach: An organization is confirmed or credibly alleged to have been breached.
2. Data Theft: Customer, employee, patient, financial, government, or other sensitive records are stolen or exfiltrated.
3. Ransomware Incident: Systems/networks are encrypted, ransomware deployment is reported, double/triple extortion is reported, or a ransomware group claims an organization's compromise.
4. Company Compromise: Unauthorized access to corporate infrastructure, cloud infrastructure compromise, administrative account compromise, or internal systems compromise.
5. Critical Infrastructure Attack: Power, energy, water, healthcare infrastructure, telecommunications, government infrastructure, or other critical operational infrastructure.
6. Major Cyberattack: A significant cyberattack against a named organization with meaningful operational or business impact.
7. Major Service Disruption: A cyberattack causes significant disruption to an organization's services, systems, portals, or operations.
8. Extortion / Leak: A threat actor claims to possess stolen corporate data, or publishes/threatens to publish an organization's stolen database.

---

## 2. HARD REJECTION RULE

The following MUST NOT trigger a Team Alert by themselves:
* Ordinary CVEs / Critical CVEs
* Zero-day disclosures without an actual organizational compromise
* Patch Tuesday
* Vendor security updates
* Security advisories & CERT advisories
* Generic vulnerability research & Proof-of-concept releases
* General malware research & Threat actor research
* General ransomware research without a named victim
* General phishing campaigns without a confirmed/claimed organizational compromise
* General DDoS capability reports without an actual significant victim
* Security tool releases

A vulnerability can have severity = "critical" while still having team_alert = false. Severity and Team Alert eligibility are separate decisions.

---

## 3. KEYWORD MATCHING IS ONLY CANDIDATE DETECTION

Do NOT treat keyword matches as sufficient evidence for a Team Alert.
The keyword engine is only responsible for identifying potentially relevant articles.
Always execute: Keyword Match → AI Classification → Evidence Validation → Impact Decision → Team Alert.

---

## 4. INCIDENT DETECTION & CLASSIFICATION

For every article, determine whether an actual cyber incident occurred or is being credibly claimed:
incident_detected = true | false

Classify incident_type:
data_breach | data_theft | ransomware | company_compromise | critical_infrastructure | major_cyberattack | service_disruption | extortion_leak | vulnerability | advisory | security_research | malware_campaign | other

---

## 5. EVIDENCE CLASSIFICATION & CLAIM STATUS

Determine the strongest available evidence:
evidence_type = official_confirmation | regulatory_disclosure | law_enforcement | reputable_reporting | threat_actor_claim | researcher_claim | unknown

Always use exactly one claim_status:
- claimed: A ransomware group claims a breach, a threat actor claims data theft, a leak site claims compromise, or third party alleges incident without verification.
- confirmed: Officially confirmed by the company, regulator, law enforcement, or reliable corroborated evidence.
- denied: Organization explicitly denies the reported incident.

Never convert "threat actor claims" into "confirmed breach".

---

## 6. RECORD COUNT INTEGRITY

Never invent record numbers.
- If reported: "claimed_records_count": 2000000
- If unstated: "claimed_records_count": null
- Preserve unverified status via "claim_status": "claimed". Never manufacture or estimate counts.

---

## 7. CORE 10-FIELD CTI EXTRACTION SCHEMA

Every article must be normalized into exactly these 10 core fields:
```json
{
  "claim_status": "claimed | confirmed | denied",
  "severity": "critical | high | medium | low | informational",
  "threat_actor": "Named group or Unattributed",
  "target_country": "Full country name or null",
  "sector": "Target industry sector or null",
  "claimed_records_count": "Integer or null",
  "attack_vector": "Method of compromise or null",
  "company_response": "Official company statement summary or null",
  "cves": [],
  "summary": "Neutral 2-3 sentence objective overview"
}
```

---

## 8. EXECUTIVE AI INSIGHT GENERATION

Generate an AI Insight ONLY for critical Team Alerts:
```text
🔎 AI INSIGHT

[Direct business/operational risk]; [immediate technical defense/mitigation].
```
Do not include model branding.

---

## 9. OBJECTIVITY RULES

Never hallucinate threat actors, victim organizations, record counts, attack vectors, company responses, CVEs, countries, sectors, or breach confirmations. If unknown, use null, "Unattributed", or [].
```

---

## 11. AI Enrichment Accuracy & Validation Framework

Enforces the 19-point validation hierarchy across all incoming threat intelligence:

### 1. Source-First Principle
- All extractions must be directly grounded in the source text. No speculative inference of missing parameters.

### 2. Claim vs. Confirmation Separation
- Verbs such as *"claims"*, *"alleges"*, *"reportedly"* strictly produce `claim_status = "claimed"`.
- Official statements (e.g. SEC 8-K filings, corporate disclosures) produce `claim_status = "confirmed"`.
- Explicit investigations without admission remain `claim_status = "claimed"`.

### 3. Record Count vs. Data Volume Guard
- Only explicit integer quantities are extracted into `claimed_records_count`.
- File sizes (e.g., `700 GB`, `2 TB`) and percentages strictly remain `claimed_records_count = null`.

### 4. Cross-Field Consistency Enforcement (Rules A–G)
- **Rule A:** `incident_type = vulnerability` $\rightarrow$ `team_alert = false` (unless separate active compromise exists).
- **Rule B:** `claimed_records_count != null` $\rightarrow$ must be an explicitly cited record quantity.
- **Rule C:** `claim_status = confirmed` $\rightarrow$ requires official confirmation evidence.
- **Rule D:** `claim_status = denied` $\rightarrow$ requires explicit company denial statement.
- **Rule E:** `threat_actor` $\rightarrow$ `"Unattributed"` when no named actor is explicitly stated.
- **Rule F:** `cves` $\rightarrow$ `[]` when no explicit CVE ID is cited.
- **Rule G:** `team_alert = true` $\rightarrow$ requires $\ge 50$ points on the Multi-Factor Evidence Validation Gate.

### 5. Final Extraction & Validation Hierarchy
$$\text{SOURCE} \rightarrow \text{FACTS} \rightarrow \text{EVIDENCE} \rightarrow \text{CLAIM STATUS} \rightarrow \text{CTI EXTRACTION} \rightarrow \text{SEVERITY} \rightarrow \text{INCIDENT CLASSIFICATION} \rightarrow \text{TEAM ALERT DECISION} \rightarrow \text{🔎 AI INSIGHT}$$

---

## 12. End-to-End Team Alert Quality, Deduplication & Routing Framework

Enforces the 24-section QA and multi-source incident deduplication standard:

### 1. Multi-Level Deduplication Architecture
- **Tier 1 (Exact URL SHA-256):** Prevents duplicate ingestion of identical URLs.
- **Tier 2 (Normalized Title SHA-256):** Rejects identical headlines stripped of formatting/whitespace.
- **Tier 3 (Canonical Incident Fingerprint):** Hashes `target_company::incident_type::threat_actor::target_country::time_bucket` over a 72-hour correlation window.
- **Multi-Source Rule:** 5 news sources reporting the same event generate **exactly ONE Team Alert** on the initial report, while updating the repository catalog.

### 2. Incident State & Material Update Protocol
A new alert is dispatched for an existing incident **only upon materially new intelligence**:
- **Claim $\rightarrow$ Confirmation:** When the organization officially verifies an earlier claim.
- **Claim $\rightarrow$ Denial:** When the organization issues an explicit denial statement.
- **Scope & Record Disclosures:** When an unknown record volume is quantified (e.g. 250,000 records exfiltrated).
- **Escalated Impact:** When operations are confirmed halted or critical infrastructure disrupted.

### 3. Strict Victim-Centric Regional Routing
- **`#indian-breaches`:** Target enterprise located in India (regardless of foreign threat actor nationality).
- **`#middle-east-companies`:** Target enterprise located in GCC / Middle East region.
- **`#high-priority-news`:** Global critical data breaches, zero-days, and executive intelligence briefings.

### 4. Operational Principle
$$\text{DETECT} \rightarrow \text{CLASSIFY} \rightarrow \text{VALIDATE} \rightarrow \text{CORRELATE} \rightarrow \text{DEDUPLICATE} \rightarrow \text{ASSESS UPDATE} \rightarrow \text{ROUTE} \rightarrow \text{DISPATCH}$$
> **"One real incident $\rightarrow$ one useful alert."**

---

## 13. Source Reliability, Evidence Scoring & Claim Verification Framework

Enforces transparent, evidence-based threat intelligence verification across all ingested intelligence:

### 1. Source Classification & Reliability Tiers
- **VERY HIGH:** `official_company`, `government`, `regulator` (SEC filings), `law_enforcement`, `cert`.
- **HIGH:** `security_vendor` (Mandiant, CrowdStrike, Recorded Future), `reputable_media` (BleepingComputer, Reuters, TechCrunch).
- **MEDIUM:** `security_researcher`, established independent investigative blogs.
- **VERY LOW:** `threat_actor` (dark web leak sites), `social_media` (unverified X/Telegram posts).

### 2. Evidence Strength Scale (0–5)
- **Score 5:** Official company statement, regulatory disclosure (SEC 8-K), or law-enforcement indictment.
- **Score 4:** Validated technical forensic evidence or confirmed stolen data samples reported by tier-1 cybersecurity outlets.
- **Score 3:** Reputable media investigation with named sources.
- **Score 2:** Leak-site listings, proof-of-breach screenshots, or single-source claims.
- **Score 1:** Unsubstantiated threat actor claim.
- **Score 0:** Speculation or theoretical vulnerability.

### 3. Claim, Confirmation & Denial Precedence
- **Denial Precedence:** If an affected organization explicitly denies a claim, `claim_status` is locked to `"denied"` and `conflicting_claims = true`.
- **Unverified Threat Actor Claims:** Preserved strictly as `claim_status = "claimed"`, `confidence = "low"`, and `threat_actor = "[Named Group]"`.
- **Preserve Provenance:** If threat actors claim 5,000,000 records and the company later confirms 100,000 records, both figures are preserved in their respective provenance fields rather than merged.

### 4. Verification Hierarchy
$$\text{SOURCE} \rightarrow \text{EVIDENCE} \rightarrow \text{CLAIM} \rightarrow \text{CORROBORATION} \rightarrow \text{COMPANY RESPONSE} \rightarrow \text{CONFIDENCE} \rightarrow \text{CLAIM STATUS} \rightarrow \text{SEVERITY} \rightarrow \text{TEAM ALERT}$$

---

## 14. RAG, Semantic Search & CyberPulse Incident Graph Framework

Enforces the 34-section hybrid retrieval and cross-source intelligence correlation standard:

### 1. Hybrid Search Architecture
- **BM25 Lexical Matching:** Exact matches for CVE identifiers, threat actor names, company entities, and specific malware families.
- **Vector Semantic Search (NVIDIA Nemotron-3 1B):** Discovers conceptually related incidents, similar extortion narratives, and attack patterns across disparate sources.
- **Cross-Encoder Reranking (NVIDIA Mistral-4B):** Prioritizes exact entity overlaps, verified disclosures, and temporal relevance.

### 2. Tri-State Incident Correlation Engine
Evaluates relationship between intelligence reports:
- **`SAME_INCIDENT`:** Same victim organization + identical event within a 72-hour window.
- **`RELATED_INCIDENT`:** Same threat actor or campaign, but targeting distinct victim organizations.
- **`UNRELATED`:** Different organizations, distinct event types, and unrelated actors.

### 3. CyberPulse Dynamic Heat & Incident Timeline
$$\text{ARTICLE} \rightarrow \text{ENTITIES} \rightarrow \text{HYBRID SEARCH} \rightarrow \text{RERANKING} \rightarrow \text{CORRELATION} \rightarrow \text{CYBERPULSE CLUSTER} \rightarrow \text{TIMELINE} \rightarrow \text{RAG GRAPH}$$
> **"Semantic similarity suggests a relationship; entities, time, technical details, and evidence determine whether that relationship is real."**

---

## 15. Production Architecture, Microservices & Database Audit Specification

Enforces enterprise-grade fault tolerance, idempotency, and asynchronous state management across the distributed CTI platform:

### 1. Service Boundaries & Decoupling
- **FastAPI (API Gateway & Query Service):** Exclusively serves synchronous client requests, analyst graph search, authentication, and monitoring endpoints. Never blocks on long-running AI or crawler tasks.
- **Celery 5.4 + Redis 7.4 (Distributed Task Broker):** Orchestrates asynchronous feed polling, AI enrichment queues, batch vectorization, and periodic maintenance sweeps.
- **MongoDB 7.0 (Authoritative Document Store):** Maintains structured models with compound indexes for `articles`, `incidents`, `evidence`, `threat_actors`, and `alert_dispatches`.
- **Elasticsearch 8.16 (Search & RAG Index):** Provides full-text BM25 and dense vector search. Automatically synchronizes from MongoDB with retry queues on network interruption.

### 2. Explicit Article State Machine
$$\text{INGESTED} \rightarrow \text{NORMALIZED} \rightarrow \text{DEDUPLICATED} \rightarrow \text{CLASSIFIED} \rightarrow \text{AI\_ENRICHED} \rightarrow \text{VALIDATED} \rightarrow \text{INCIDENT\_CORRELATED} \rightarrow \text{INDEXED} \rightarrow \text{ALERT\_EVALUATED} \rightarrow \text{DISPATCHED / WEBSITE\_ONLY}$$

### 3. Fault Tolerance & Dead-Letter Isolation
- **Component Isolation:** If an external AI provider (Gemini / NVIDIA NIM) encounters transient rate limits, the ingestion pipeline remains uninterrupted and flags articles as `processing_status = "retrying"`.
- **Idempotent Dispatch Keys:** Teams notifications are protected against duplicates across worker retries using `f"{webhook_url}::{incident_fingerprint}"`.
- **Alert Audit Trail:** Every dispatched card writes an `AlertDispatchDB` record logging the exact timestamp, channel, fingerprint, version, and reason.

### 4. Production Pipeline Flow
$$\text{SOURCE} \rightarrow \text{INGESTION} \rightarrow \text{DEDUPLICATION} \rightarrow \text{KEYWORD CANDIDATES} \rightarrow \text{AI ENRICHMENT} \rightarrow \text{EVIDENCE GATE} \rightarrow \text{INCIDENT REGISTRY} \rightarrow \text{CYBERPULSE} \rightarrow \text{ROUTER} \rightarrow \text{TEAMS}$$
> **"An event-driven, fault-tolerant intelligence pipeline where every alert is traceable, explainable, and idempotent."**






