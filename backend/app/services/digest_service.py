"""
AI Daily Digest Generation Service
"""
import re
import json
import httpx
from datetime import datetime, timezone, timedelta
from app.db.mongodb import get_articles_collection, get_digests_collection
from app.config import settings
import structlog

log = structlog.get_logger()


class DigestGenerationService:
    async def generate(self, hours: int = 24):
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(hours=hours)

        log.info("Generating AI digest", period_start=period_start.isoformat())

        articles_col = get_articles_collection()

        # Fetch recent critical/high articles
        cursor = articles_col.find(
            {
                "published_at": {"$gte": period_start},
                "severity": {"$in": ["critical", "high"]},
                "is_duplicate": {"$ne": True},
            },
            {
                "title": 1, "summary": 1, "ai_summary": 1, "source_name": 1,
                "severity": 1, "threat_actors": 1, "malware_families": 1, "cves": 1, "url": 1,
            }
        ).sort("published_at", -1).limit(50)

        articles = [a async for a in cursor]

        if not articles:
            log.info("No articles found for digest period")
            return

        # Build digest using AI
        digest_content = await self._generate_ai_digest(articles)

        article_ids = [str(a["_id"]) for a in articles]

        # Store in DB
        digests_col = get_digests_collection()
        doc = {
            "period_start": period_start,
            "period_end": now,
            "generated_at": now,
            "article_count_analyzed": len(articles),
            "ai_model": settings.OPENAI_MODEL,
            "digest": digest_content,
            "article_ids": article_ids,
            "sent_at": None,
            "sent_to": [],
        }
        await digests_col.insert_one(doc)
        log.info("Digest saved", articles_analyzed=len(articles))

    async def _generate_ai_digest(self, articles: list) -> dict:
        articles_text = "\n".join([
            f"- [{a.get('severity','').upper()}] {a.get('title','')} | Source: {a.get('source_name','')} | "
            f"CVEs: {', '.join(a.get('cves',[])[:3])} | Actors: {', '.join(a.get('threat_actors',[])[:2])}"
            for a in articles
        ])

        prompt = f"""You are a Senior Threat Intelligence Analyst. Analyze these recent cybersecurity events and produce a structured intelligence briefing:

EVENTS (last 24 hours):
{articles_text[:15000]}

Return a JSON object with:
{{
  "headline": "string (compelling single-line summary of the day's threat landscape)",
  "todays_highlights": "string (3-5 sentences, key developments)",
  "critical_threats": [
    {{"title": "string", "summary": "string", "severity": "critical|high", "source": "string", "url": "string"}}
  ],
  "top_ransomware": [{{"name": "string", "activity": "string"}}],
  "apt_activity": [{{"group": "string", "activity": "string", "targets": "string"}}],
  "major_breaches": [{{"name": "string", "details": "string", "impact": "string"}}],
  "trending_threat_actors": ["list of names"],
  "trending_malware": ["list of names"],
  "trending_vendors": ["list of vendors mentioned"],
  "analyst_note": "string (key recommendation for security teams today)"
}}"""

        # ── 1. Google Gemini ──────────────────────────────────────────
        if settings.GEMINI_API_KEY:
            try:
                import httpx
                model = getattr(settings, "GEMINI_MODEL", "gemini-2.5-flash") or "gemini-2.5-flash"
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={settings.GEMINI_API_KEY}"
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.2,
                        "response_mime_type": "application/json",
                    }
                }
                async with httpx.AsyncClient(timeout=45.0) as client:
                    resp = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
                    resp.raise_for_status()
                    data = resp.json()

                raw_content = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                raw_content = re.sub(r"^```(?:json)?\s*", "", raw_content, flags=re.MULTILINE)
                raw_content = re.sub(r"\s*```$", "", raw_content, flags=re.MULTILINE).strip()
                return json.loads(raw_content)
            except Exception as e:
                log.error("Gemini AI digest generation failed, trying fallback", error=str(e))

        # ── 2. OpenAI ────────────────────────────────────────────────
        if settings.OPENAI_API_KEY:
            try:
                from openai import AsyncOpenAI
                client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
                response = await client.chat.completions.create(
                    model=settings.OPENAI_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.2,
                    max_tokens=3000,
                    response_format={"type": "json_object"},
                )
                return json.loads(response.choices[0].message.content)
            except Exception as e:
                log.error("OpenAI digest generation failed", error=str(e))

        return self._mock_digest(articles, articles_text)

    def _mock_digest(self, articles: list, articles_text: str) -> dict:
        # Extract trending entities from articles
        actors = set()
        malware = set()
        for a in articles:
            actors.update(a.get("threat_actors", [])[:3])
            malware.update(a.get("malware_families", [])[:3])

        return {
            "headline": f"[DEMO MODE] {len(articles)} critical/high intelligence items processed",
            "todays_highlights": f"Demo digest generated without AI. Configure OPENAI_API_KEY for full analysis. {len(articles)} items analyzed.",
            "critical_threats": [
                {"title": a.get("title", ""), "summary": a.get("summary", "")[:200], "severity": a.get("severity", ""), "source": a.get("source_name", "")}
                for a in articles[:5]
            ],
            "top_ransomware": [],
            "apt_activity": [],
            "major_breaches": [],
            "trending_threat_actors": list(actors)[:5],
            "trending_malware": list(malware)[:5],
            "trending_vendors": [],
            "analyst_note": "Configure OPENAI_API_KEY to enable AI-powered digest analysis.",
        }
