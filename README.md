# NewsMon — Enterprise Cyber Threat Intelligence Platform

[![GitHub Repository](https://img.shields.io/badge/GitHub-mguruprasath416%2Fnewsmon-blue?logo=github)](https://github.com/mguruprasath416/newsmon)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.12-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Frontend](https://img.shields.io/badge/Frontend-Next.js%2015%20%7C%20React%2019-black?logo=next.js)](https://nextjs.org)
[![Database](https://img.shields.io/badge/Database-MongoDB%207.0%20%7C%20Elasticsearch%208.16-green?logo=mongodb)](https://mongodb.com)

**NewsMon** (ClarityTI) is an enterprise-grade Cyber Threat Intelligence (CTI) and analytics platform designed for Threat Intelligence Analysts, SOC Teams, Incident Responders, Vulnerability Analysts, Government CERT teams, and Security Researchers.

It continuously collects, normalizes, enriches, analyzes, correlates, searches, and visualizes cyber intelligence from 72+ trusted sources (vendors, security news, official national CERT advisories, and CISA KEV).

### 🎯 Key Architectural Distinction
- **🌐 Website Platform:** Comprehensive, broad cybersecurity intelligence including CVE disclosures, vendor advisories, patch updates, zero-day research, and security news.
- **🚨 Team Alerts (Microsoft Teams):** Strictly filters for high-impact, actionable cyber incidents (confirmed/claimed enterprise breaches, customer data theft, ransomware attacks, company compromises, and critical infrastructure attacks) powered by **Google Gemini** for executive `🔎 AI INSIGHT` generation.

---

## 📁 Repository Structure

```text
newsmon/
├── backend/                  # FastAPI 3.12 Backend API & Celery Task Workers
│   ├── app/
│   │   ├── api/v1/          # REST Endpoints (Feed, CyberPulse, Teams, Lens, KEV, etc.)
│   │   ├── core/            # Security, Celery configs, exceptions, seeder
│   │   ├── db/              # MongoDB, Elasticsearch, Redis connectors & indexes
│   │   ├── models/          # Article, CyberPulse, Threat data models
│   │   ├── scripts/         # Ingestion, crawling & feed management scripts
│   │   ├── services/        # AI enrichment, IOC extraction, clustering, Teams bot
│   │   └── tasks/           # Celery background tasks
│   ├── scripts/             # Standalone operational & backfill scripts
│   ├── workers/             # Celery worker application & queue definitions
│   ├── Dockerfile           # Backend container image
│   └── requirements.txt     # Python dependencies
├── files/
│   └── Keywords/            # CTI Taxonomy Keyword lists (590+ Terms)
│       ├── Critical_Alerts/ # Data Breach, Data Theft, Ransomware, Compromise, Infrastructure
│       ├── Attacks/         # DDoS, Ransomware, Supply Chain, Phishing, Espionage
│       ├── Geography/       # India, USA, China, Europe, Russia, Middle East
│       ├── Malware/         # Infostealer, RAT, Trojan, Botnet, Spyware
│       ├── Targets/         # Banking, Energy, Gov, Healthcare, Telecom, Infra
│       ├── Threat Actors/   # APT, Ransomware Groups, Hacktivists, Cybercriminals
│       └── Vulnerabilities/ # Zero-Day, RCE, Privilege Escalation, CVE
├── frontend/                 # Next.js 15 App Router Frontend
│   ├── app/
│   │   ├── (platform)/      # Dashboard, CyberPulse, Feed, KEV, Lens, Clusters, etc.
│   │   ├── login/           # Authentication page
│   │   └── globals.css      # Design system & dark-mode styling
│   ├── components/          # Charts, breach alert cards, TopBar, Sidebar
│   ├── lib/                 # API client, Zustand state stores
│   ├── Dockerfile           # Frontend container image
│   └── package.json         # Node dependencies
├── docker-compose.yml        # Multi-service orchestration (Mongo, Redis, ES, App, Workers)
├── DOCUMENTATION.md          # Comprehensive architecture and technical manual
├── PROJECT_REPORT.md         # 5-page enterprise completion report
├── schema.md                 # Database schemas, datatypes & API schemas
├── SOURCES.md                # Catalog of 72+ monitored intelligence sources
└── README.md                 # Project overview and quick start guide
```

---

## 🏗️ Architecture Stack

- **Backend**: FastAPI (Python 3.12), Motor (Async MongoDB), Elasticsearch 8.16, Redis 7.4, Celery 5.4, Trafilatura, spaCy, OpenAI GPT-4.1.
- **Frontend**: Next.js 15 (App Router), React 19, TypeScript, TailwindCSS, Zustand, TanStack Query v5, ECharts, Framer Motion.
- **Data Layer**: MongoDB 7.0 (Primary Store), Elasticsearch 8.16 (Full-Text Search Engine), Redis 7.4 (Cache & Task Queue Broker).
- **Deployment**: Docker, Docker Compose, Uvicorn.

---

## ⚡ Quick Start: Running via Docker Compose (Recommended)

Running via Docker starts all microservices (MongoDB, Redis, Elasticsearch, FastAPI, Celery Worker, Celery Beat, Next.js UI, Flower Monitor) automatically with healthchecks.

### 1. Clone Repository & Setup Environment
```powershell
git clone https://github.com/mguruprasath416/newsmon.git
cd newsmon
cp .env.example .env
```

### 2. Build and Start All Containers
```powershell
docker compose up -d --build
```

### 3. Service Access Endpoints
- 🌐 **Web Platform UI**: [http://localhost:3000](http://localhost:3000)
- 🔌 **FastAPI OpenAPI Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- 🌸 **Celery Flower Task Monitor**: [http://localhost:5555](http://localhost:5555)

---

## 💻 Local Development Setup (Step-by-Step Commands)

If you prefer to run services individually without Docker:

### Prerequisites
- Python 3.12+
- Node.js 20+
- Running instances of MongoDB (`localhost:27017`), Redis (`localhost:6379`), and Elasticsearch (`localhost:9200`).

---

### Step 1: Backend Setup

#### 1. Navigate to project root & create virtual environment
```powershell
cd d:\Feed
python -m venv venv
```

#### 2. Activate Virtual Environment
- **Windows (PowerShell)**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **Linux / macOS**:
  ```bash
  source venv/bin/activate
  ```

#### 3. Install Python Dependencies
```powershell
cd backend
pip install -r requirements.txt
```

#### 4. Download spaCy Language Model
```powershell
python -m spacy download en_core_web_sm
```

#### 5. Start FastAPI Backend Server
```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

### Step 2: Celery Worker & Beat Scheduler (Background Crawls)

In a new terminal window (with virtual environment activated):

#### Start Celery Worker
- **Using Python Runner Script (Windows & Linux)**:
  ```powershell
  cd d:\Feed\backend
  python run_celery_worker.py
  ```
- **Windows CLI Command**:
  ```powershell
  cd d:\Feed\backend
  python -m celery -A workers.celery_app worker --loglevel=info --pool=solo -Q default,collection,digest,lens
  ```

#### Start Celery Beat (Scheduler)
- **Using Python Runner Script (Windows & Linux)**:
  ```powershell
  cd d:\Feed\backend
  python run_celery_beat.py
  ```
- **CLI Command**:
  ```powershell
  cd d:\Feed\backend
  python -m celery -A workers.celery_app beat --loglevel=info
  ```

#### Start Flower Task Monitor (Optional)
```powershell
cd d:\Feed\backend
python -m celery -A workers.celery_app flower --port=5555
```

---

### Step 3: Frontend Setup

In a new terminal window:

#### 1. Navigate to Frontend Directory
```powershell
cd d:\Feed\frontend
```

#### 2. Install Node Dependencies
```powershell
npm install
```

#### 3. Start Next.js Development Server
```powershell
npm run dev
```

The web application will open at **[http://localhost:3000](http://localhost:3000)**.

---

## 🗺️ Key Platform Features & Modules

| Module | Route | Key Capabilities |
| :--- | :--- | :--- |
| **Dashboard** | `/dashboard` | Executive intel metrics, live threat strip, 30-day severity timeline, trending actors/malware |
| **CyberPulse Heat Map** | `/cyberpulse` | Real-time global breach outbreak tracker, viral threat heat maps, MS Teams regional webhook integration |
| **Intel Feed** | `/feed` | Real-time threat feed with infinite scroll, category filters (Vendor/News/CERT), severity badges, and IOC counts |
| **News Clusters** | `/clusters` | Threat news clusters & custom discovery rules for auto-grouping regional and sector CTI |
| **Advisory Lens** | `/lens` | AI-powered CTI analysis supporting URL fetch, raw text, and file upload (PDF/MD/TXT/HTML) with GPT-4.1 |
| **CISA KEV** | `/kev` | Known Exploited Vulnerabilities catalog with EPSS exploitation probabilities, CVSS scores, and ransomware flags |
| **Unified Search** | `/search` | Full-text Elasticsearch + MongoDB search with autocomplete suggestions |
| **Threat Actors** | `/threat-actors` | APT groups and cybercrime organization profiles with 946+ mapped groups |
| **Malware Library** | `/malware` | Malware family registry (Ransomware, RATs, InfoStealers, Loaders) |
| **Campaigns** | `/campaigns` | Attack campaign tracking and timelines |
| **Reports** | `/reports` | Saved CTI reports with Markdown, STIX 2.1 JSON Bundle, and CSV IOC exports |
| **AI Digest** | `/digest` | Automated 24-hour executive AI threat intelligence briefing |
| **Sources** | `/sources` | Monitor 72+ pre-configured intelligence RSS, vendor blogs, and official national CERT advisories |
| **Analytics** | `/analytics` | Platform threat landscape metrics and MITRE ATT&CK tactic breakdown |

---

## ⚙️ Environment Variables Reference (`.env`)

Copy `.env.example` to `.env` and configure your credentials:

```env
# General
APP_NAME=NewsMon
ENVIRONMENT=development
JWT_SECRET_KEY=your-secure-random-secret-key

# Databases
MONGODB_URL=mongodb://localhost:27017/
MONGODB_DB_NAME=clarityti
REDIS_URL=redis://localhost:6379/0
ELASTICSEARCH_URL=http://localhost:9200

# OpenAI Integration (Optional for full Advisory Lens & Digest)
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4.1

# Microsoft Teams Webhook (Optional for Automated Alerts)
TEAMS_WEBHOOK_URL_CYBER_PULSE=https://outlook.office.com/webhook/...
```

---

## 📄 License & Attribution
- Built with **FastAPI**, **Next.js 15**, **MongoDB**, **Elasticsearch**, **Redis**, and **Celery**.
- Repository: [mguruprasath416/newsmon](https://github.com/mguruprasath416/newsmon)
