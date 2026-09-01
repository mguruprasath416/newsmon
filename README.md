# NewsMon — Enterprise Cyber Threat Intelligence Platform

**NewsMon** is an enterprise-grade Cyber Threat Intelligence (CTI) Platform designed for Threat Intelligence Analysts, SOC Teams, Incident Responders, Vulnerability Analysts, Government CERT teams, and Security Researchers.

It continuously collects, normalizes, enriches, analyzes, correlates, searches, and visualizes cyber intelligence from 39+ trusted sources (vendors, security news, official national CERT advisories).

---

## 🏗️ Architecture Stack

- **Backend**: FastAPI (Python 3.12), Motor (Async MongoDB), Elasticsearch 8.16, Redis 7.4, Celery, Trafilatura, spaCy, OpenAI GPT-4.1.
- **Frontend**: Next.js 15 (App Router), React 19, TypeScript, TailwindCSS, Zustand, TanStack Query v5, ECharts, Framer Motion.
- **Data Layer**: MongoDB 7.0 (Primary Store), Elasticsearch 8.16 (Full-Text Search Engine), Redis 7.4 (Cache & Task Queue Broker).
- **Deployment**: Docker, Docker Compose, Uvicorn.

---

## ⚡ Quick Start: Running via Docker Compose (Recommended)

Running via Docker starts all microservices (MongoDB, Redis, Elasticsearch, FastAPI, Celery Worker, Celery Beat, Next.js UI, Flower Monitor) automatically with healthchecks.

### 1. Copy Environment Configuration
```powershell
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
python -m venv FEED
```

#### 2. Activate Virtual Environment
- **Windows (PowerShell)**:
  ```powershell
  .\FEED\Scripts\Activate.ps1
  ```
- **Linux / macOS**:
  ```bash
  source FEED/bin/activate
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

### Step 2: Celery Worker & Beat Scheduler (Optional for Background Crawls)

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
- **Linux / macOS CLI Command**:
  ```bash
  cd backend
  celery -A workers.celery_app worker --loglevel=info --pool=prefork -Q default,collection,digest,lens
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
| **Intel Feed** | `/feed` | Real-time threat feed with infinite scroll, category filters (Vendor/News/CERT), severity badges, and IOC counts |
| **News Clusters** | `/clusters` | Threat news clusters & custom discovery rules for auto-grouping regional CTI |
| **Advisory Lens** | `/lens` | AI-powered CTI analysis supporting URL fetch, raw text, and file upload (PDF/MD/TXT/HTML) with GPT-4.1 |
| **CISA KEV** | `/kev` | Known Exploited Vulnerabilities catalog with EPSS exploitation probabilities, CVSS scores, and ransomware flags |
| **Unified Search** | `/search` | Full-text Elasticsearch + MongoDB search with autocomplete suggestions |
| **Threat Actors** | `/threat-actors` | APT groups and cybercrime organization profiles |
| **Malware Library** | `/malware` | Malware family registry (Ransomware, RATs, InfoStealers, Loaders) |
| **Campaigns** | `/campaigns` | Attack campaign tracking and timelines |
| **Reports** | `/reports` | Saved CTI reports with Markdown, STIX 2.1 JSON Bundle, and CSV IOC exports |
| **AI Digest** | `/digest` | Automated 24-hour executive AI threat intelligence briefing |
| **Sources** | `/sources` | Monitor 39+ pre-configured intelligence RSS, vendor blogs, and official national CERT advisories |
| **Analytics** | `/analytics` | Platform threat landscape metrics and MITRE ATT&CK tactic breakdown |

---

## ⚙️ Environment Variables Reference (`.env`)

```env
# General
APP_NAME=NewsMon
APP_ENV=development
SECRET_KEY=newsmon_super_secret_key_change_in_production_32bytes!

# Databases
MONGODB_URL=mongodb://newsmon:newsmon_secret@localhost:27017/newsmon?authSource=admin
REDIS_URL=redis://:redis_secret@localhost:6379/0
ELASTICSEARCH_URL=http://localhost:9200

# OpenAI Integration (Optional for full Advisory Lens & Digest)
OPENAI_API_KEY=sk-your-openai-key-here
OPENAI_MODEL=gpt-4.1
```

---

## 📄 License & Attribution
- Built with **FastAPI**, **Next.js 15**, **MongoDB**, **Elasticsearch**, **Redis**, and **Celery**.
- TLP: WHITE · NewsMon v1.0.0
