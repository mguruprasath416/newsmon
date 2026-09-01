# ── ClarityTI Backend Dockerfile ──────────────────────────────────────────
FROM python:3.12-slim

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH=/app

WORKDIR /app

# Install system build dependencies & tools
# - libmagic-dev / libmagic1  : for python-magic
# - libpango-1.0-0, libcairo2, libgdk-pixbuf-2.0-0, fonts-liberation : for weasyprint
# - libxml2-dev, libxslt1-dev, zlib1g-dev : for lxml / trafilatura
# - libnss3, libatk1.0-0, libatk-bridge2.0-0, etc. : for playwright chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    # python-magic
    libmagic1 \
    libmagic-dev \
    # lxml / trafilatura
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    # weasyprint rendering deps
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    fonts-liberation \
    # playwright runtime deps
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -U pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Install Playwright browser binaries (chromium only to keep image size down)
RUN python -m playwright install chromium

# Install spaCy English NLP model
RUN python -m spacy download en_core_web_sm || true

# Copy application source code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
