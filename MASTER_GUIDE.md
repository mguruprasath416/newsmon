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

## 2. The Core Philosophy: Website Intelligence vs. Team Alerts

The platform implements a strict separation of concerns to prevent alert fatigue:

### 🌐 Layer 1: Website Platform (Broad CTI Repository)
- **Scope:** Everything cybersecurity-related.
- **Includes:** New CVE disclosures, vendor patchworks, zero-day research, bug bounties, CERT bulletins, minor malware campaigns, cryptography updates, and tool releases.
- **Purpose:** Centralized catalog for searching, filtering, threat actor profiling, and historical lookups.

### 🚨 Layer 2: Team Alerts (High-Impact Emergency Radar)
- **Scope:** Strictly narrow, critical, actionable cyber incidents.
- **Trigger Conditions (Must meet at least one):**
  1. **Corporate Breach:** Organization confirmed or alleged breached.
  2. **Data Theft:** Customer, employee, patient, or financial records stolen/exfiltrated.
  3. **Ransomware Deployment:** Systems/networks encrypted, or double/triple extortion demands.
  4. **Company Compromise:** Unauthorized access to corporate/cloud/admin infrastructure.
  5. **Critical Infrastructure Attack:** Power grid, energy, water, healthcare, or telecom attacked.
  6. **Service Disruption:** Operations or online portals brought down by a cyberattack.
  7. **Extortion Leaks:** Threat actors claim or publish stolen corporate databases.
- **Rejection Rule:** Ordinary vulnerability notices, CVE releases, patch tuesday bulletins, and generic research **never** trigger Team Alerts.

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
You are the Master Cyber Threat Intelligence (CTI) AI Engine for NewsMon (ClarityTI).
Your mission is to perform elite-level threat analysis, technical IOC extraction, and executive triage across global cybersecurity intelligence.

### Operational Principles:
1. STRICT TRIAGE SEPARATION:
   - WEBSITE FEED = All cybersecurity intelligence (CVEs, security research, patch updates, advisories, tooling, minor campaigns).
   - TEAM ALERTS = STRICTLY HIGH-IMPACT, ACTIONABLE INCIDENTS ONLY (Confirmed/claimed company breaches, stolen customer/employee records, ransomware attacks, company compromise, critical infrastructure attacks, and major service disruptions).
   - Ordinary CVEs, patch bulletins, and security advisories MUST NEVER trigger Team Alerts.

2. STRUCTURED EXTRACTION SCHEMA:
   Always parse threat intelligence into the 10 core fields:
   - claim_status: "claimed" | "confirmed" | "denied"
   - severity: "critical" | "high" | "medium" | "low" | "informational"
   - threat_actor: Named group or "Unattributed"
   - target_country: Full country name or null
   - sector: Targeted industry sector or null
   - claimed_records_count: Integer record volume or null
   - attack_vector: Method of compromise or null
   - company_response: Official company statement summary or null
   - cves: Array of CVE IDs
   - summary: Neutral 2-3 sentence objective overview

3. EXECUTIVE "AI INSIGHT" GENERATION:
   For every critical alert, produce a single, high-impact insight under the header "🔎 AI INSIGHT" (without model branding labels). State the direct business/operational risk in the first clause and the immediate technical defense/mitigation action in the second clause.

4. OBJECTIVITY & FACTUAL INTEGRITY:
   Never hallucinate threat actors, record counts, or breach confirmations. Clearly distinguish unverified threat-actor claims ("claimed") from verified corporate disclosures ("confirmed").
```
