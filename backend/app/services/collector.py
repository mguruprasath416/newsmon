"""
Intelligence Collection Engine — Base Collector and Factory
"""
import asyncio
import hashlib
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import feedparser
import httpx
from app.db.mongodb import get_articles_collection, get_sources_collection, get_logs_collection
from app.services.ioc_extractor import IOCExtractor
import structlog

# AI Enrichment (lazy import to avoid circular deps at startup)
_ai_enrichment = None

def _get_ai_enrichment():
    global _ai_enrichment
    if _ai_enrichment is None:
        from app.services.ai_enrichment import AIEnrichmentService
        _ai_enrichment = AIEnrichmentService
    return _ai_enrichment

log = structlog.get_logger()

# ─── Cyber Relevance Filter ───────────────────────────────────────────────────
# Matches ANY article that is genuinely cyber/security-related.
# Sources that publish mixed content (Reuters, TOI, BBC, etc.) will only have
# their cyber articles ingested — all other articles are dropped.
_CYBER_TERMS = re.compile(
    r'\b('
    # Incident types
    r'data breach|data leak|ransomware|cyber|hacker|hacking|hacked|malware|phishing|'
    r'vulnerability|exploit|zero.?day|cve-\d|rce|remote code execution|privilege escalation|'
    r'authentication bypass|security flaw|security bug|security incident|security breach|'
    r'credential|infosteal|stealer|botnet|ddos|denial.of.service|wiper|backdoor|trojan|'
    # Threat actors & groups
    r'apt|lockbit|ransomhub|alphv|blackcat|akira|clop|rhysida|medusa|bianlian|qilin|'
    r'lazarus|volt typhoon|fancy bear|cozy bear|scattered spider|darkside|conti|'
    # Security concepts
    r'threat.?intel|incident response|pen.?test|penetration test|red team|blue team|'
    r'soc analyst|siem|edr|xdr|firewall|intrusion|network security|endpoint security|'
    r'encryption|decryption|cryptojack|supply chain attack|third.party breach|'
    # Indian & Middle East / GCC CERT context
    r'cert-in|cert.in|nciipc|meity|digital india breach|indian cyber|'
    r'incd|israel national cyber|uae cert|aecert|nca saudi|saudi cert|cert-oman|ocert|cert-iq|eg-cert|egcert|'
    # Regulatory/Compliance
    r'gdpr breach|hipaa breach|pci dss|nist csf|cisa advisory|cisa kev|'
    # Tools & infra
    r'cobalt strike|metasploit|mimikatz|c2 server|command.and.control|dark web|darkweb|'
    r'telegram leak|tor|onion site|breach forum|breachforums|shinyHunters|'
    # General security
    r'cybersecurity|infosecurity|information security|opsec|ioc|indicator.of.compromise|'
    r'threat actor|nation.state|espionage|cyberattack|cyber attack|security advisory|'
    r'patch tuesday|security update|critical update|security researcher|bug bounty'
    r')\b',
    re.IGNORECASE,
)


def is_cyber_relevant(title: str, summary: str, content: str, source_config: dict) -> bool:
    """
    Returns True if the article is cyber/security-related.

    Dedicated cyber sources bypass the check (all current sources qualify).
    If a new mixed-content source is added (e.g., BBC, TOI, Reuters general),
    set 'dedicated_cyber': False in its source config to force keyword filtering.
    """
    # Explicitly marked as non-cyber mixed source — must pass keyword check
    if source_config.get("dedicated_cyber") is False:
        text = f"{title} {summary} {content[:2000]}"
        return bool(_CYBER_TERMS.search(text))

    # All other sources are assumed to be cybersecurity-focused — always pass
    return True


@dataclass
class RawArticle:
    url: str
    title: str
    content: str = ""
    summary: str = ""
    author: Optional[str] = None
    published_at: Optional[datetime] = None
    tags: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class BaseCollector(ABC):
    """Abstract base class for all intelligence collectors."""

    def __init__(self, source_config: dict):
        self.config = source_config
        self.source_id = str(source_config.get("_id", ""))
        self.source_name = source_config.get("name", "Unknown")
        self.ioc_extractor = IOCExtractor()

    @abstractmethod
    async def fetch(self) -> list[RawArticle]:
        """Fetch articles from the source."""
        ...

    def compute_url_hash(self, url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()

    async def store_articles(self, articles: list[RawArticle]) -> dict:
        """Store fetched articles in MongoDB, skipping duplicates."""
        col = get_articles_collection()
        added = 0
        skipped = 0
        for article in articles:
            # Step 1: url_hash dedup (exact URL match)
            url_hash = self.compute_url_hash(article.url)
            exists = await col.find_one({"url_hash": url_hash})
            if exists:
                skipped += 1
                continue

            # Step 2: title-hash dedup (same title from different URLs, e.g. Medium redirects)
            clean_title = re.sub(r'\s+', ' ', article.title.strip().lower())
            title_hash = hashlib.sha256(clean_title.encode()).hexdigest()
            title_exists = await col.find_one({"title_hash": title_hash})
            if title_exists:
                skipped += 1
                continue

            # Step 3: Cyber-relevance filter — drop non-security articles from mixed sources
            if not is_cyber_relevant(
                title=article.title,
                summary=article.summary,
                content=article.content,
                source_config=self.config,
            ):
                log.debug(
                    "Dropped non-cyber article",
                    source=self.source_name,
                    title=article.title[:80],
                )
                skipped += 1
                continue

            # Extract IOCs
            iocs = self.ioc_extractor.extract(
                article.content or article.summary or article.title
            )

            # Estimate severity from content
            severity = self._estimate_severity(article.content or "")

            # ── Run Cybersecurity Keyword Classifier Engine ──
            from app.services.keyword_classifier import KeywordClassifier
            kw_classification = KeywordClassifier.classify_article(
                {
                    "title": article.title,
                    "summary": article.summary,
                    "content_clean": article.content,
                    "tags": list(set(self.config.get("tags", []) + article.tags)),
                }
            )

            is_cyber_flag = bool(kw_classification.get("is_cybersecurity_news", False))
            if not is_cyber_flag:
                computed_severity = "informational"
                computed_score = 0.0
            else:
                computed_severity = kw_classification["severity"].lower() if kw_classification["severity"] in ("Critical", "High", "Medium", "Low") else severity
                computed_score = float(kw_classification["cyber_risk_score"])

            doc = {
                "source_id": self.source_id,
                "source_name": self.source_name,
                "source_category": self.config.get("category", "vendor"),
                "source_slug": self.config.get("slug", ""),
                "url": article.url,
                "url_hash": url_hash,
                "title_hash": title_hash,
                "title": article.title[:500],
                "summary": (article.summary or article.content[:500])[:1000],
                "content_raw": article.content[:100000],  # Cap at 100k chars
                "content_clean": article.content[:50000],
                "author": article.author,
                "published_at": article.published_at or datetime.now(timezone.utc),
                "crawled_at": datetime.now(timezone.utc),
                "enriched_at": None,
                "language": "en",
                "word_count": len((article.content or "").split()),
                "severity": computed_severity,
                "severity_score": computed_score,
                "tags": list(set(self.config.get("tags", []) + article.tags)),
                "tlp_level": "white",
                "threat_actors": kw_classification["threat_actors"],
                "malware_families": kw_classification["malware"],
                "campaigns": [],
                "cves": list(set(iocs.cves + kw_classification["cves"])),
                "mitre_techniques": [],
                "iocs": iocs.to_dict(),
                "ioc_count": iocs.total_count,
                "enrichment_status": "pending",
                "ai_summary": None,
                "ai_confidence": 0.0,
                "is_duplicate": False,
                # Structured Keyword Classification Fields
                "is_cybersecurity_news": kw_classification["is_cybersecurity_news"],
                "cyber_risk_score": kw_classification["cyber_risk_score"],
                "attacks": kw_classification["attacks"],
                "malware": kw_classification["malware"],
                "vulnerabilities": kw_classification["vulnerabilities"],
                "targets": kw_classification["targets"],
                "geography": kw_classification["geography"],
                "matched_keywords": kw_classification["matched_keywords"],
                "all_matched_terms": kw_classification["all_matched_terms"],
                # New Schema Fields
                "claim_status": kw_classification.get("claim_status", "verified"),
                "claimed_records_count": None,
                "attack_vector": kw_classification["primary_threat"],
                "company_response": None,
                "target_country": kw_classification["primary_geography"] if kw_classification["geography"] else None,
                "sector": kw_classification["primary_target"] if kw_classification["targets"] else None,
                "duplicate_of": None,
                "similarity_score": None,
                "embedding_vector": None,
                "embedding_model": None,
                "rerank_score": None,
                "ai_summary_model": None,
                "ai_summary_generated_at": None,
                "bookmarked_by": [],
                "analyst_notes": [],
                "view_count": 0,
                "report_generated": False,
                "report_id": None,
            }

            try:
                await col.insert_one(doc)
                added += 1

                # ── AI Enrichment: Classify & extract 10 CTI structured fields ──
                try:
                    AIEnrich = _get_ai_enrichment()
                    enriched = await AIEnrich.enrich_article(
                        title=doc["title"],
                        body_text=doc.get("content_clean") or doc.get("summary") or "",
                    )
                    # ── Extract Threat Actors using taxonomy & alias patterns ──
                    from app.services.threat_actor_matcher import extract_threat_actors_from_text
                    text_for_ta = f"{doc['title']} {doc.get('summary', '')} {doc.get('content_clean', '')[:8000]}"
                    extracted_tas = extract_threat_actors_from_text(text_for_ta)
                    ai_ta = enriched.get("threat_actor")
                    existing_tas = [a for a in doc.get("threat_actors", []) if a and a.lower() not in ("unattributed", "unknown")]
                    if ai_ta and ai_ta.lower() not in ("unattributed", "unknown", "none"):
                        existing_tas.append(ai_ta)

                    final_tas = sorted(list(set(existing_tas + extracted_tas)))

                    enrich_update = {
                        "claim_status": enriched.get("claim_status", "claimed"),
                        "severity": enriched.get("severity", doc.get("severity", "medium")),
                        "threat_actors": final_tas,
                        "target_country": enriched.get("target_country"),
                        "sector": enriched.get("sector"),
                        "claimed_records_count": enriched.get("claimed_records_count"),
                        "attack_vector": enriched.get("attack_vector"),
                        "company_response": enriched.get("company_response"),
                        "cves": list(set((doc.get("cves") or []) + (enriched.get("cves") or []))),
                        "ai_summary": enriched.get("summary"),
                        "enriched_at": datetime.now(timezone.utc),
                        "enrichment_status": "enriched",
                    }
                    await col.update_one({"url_hash": url_hash}, {"$set": enrich_update})
                    doc.update(enrich_update)
                    log.info(
                        "Article AI-enriched",
                        title=doc["title"][:60],
                        claim_status=enriched.get("claim_status"),
                        severity=enriched.get("severity"),
                        threat_actors=final_tas,
                    )
                except Exception as enrich_err:
                    log.warning("AI enrichment failed, continuing", error=str(enrich_err))

                # ── Steps 3 to 6: Vector Deduplication & Pipeline D Alert Engine ──
                try:
                    from app.services.deduplication_service import DeduplicationService
                    from app.services.alert_engine import AlertEngine

                    dedup_res = await DeduplicationService.process_article_deduplication(doc)
                    if not dedup_res.get("is_duplicate", False):
                        doc["is_duplicate"] = False
                        await AlertEngine.process_article_alerts(doc)
                    else:
                        log.info(
                            "Alert Engine SKIPPED for semantic duplicate",
                            title=doc.get("title", "")[:50],
                            similarity=dedup_res.get("similarity_score"),
                        )
                except Exception as pipeline_err:
                    log.error("Deduplication / Pipeline D Alert Engine error", error=str(pipeline_err))
            except Exception as e:
                if "duplicate key" in str(e).lower():
                    skipped += 1
                else:
                    log.error("Article insert failed", url=article.url, error=str(e))



        # Update source stats
        if added > 0:
            sources_col = get_sources_collection()
            from bson import ObjectId
            try:
                await sources_col.update_one(
                    {"_id": ObjectId(self.source_id)},
                    {
                        "$inc": {"article_count": added},
                        "$set": {
                            "last_crawled_at": datetime.now(timezone.utc),
                            "last_article_at": datetime.now(timezone.utc),
                            "health_status": "healthy",
                        }
                    }
                )
            except Exception:
                pass

        return {"added": added, "skipped": skipped}

    def _estimate_severity(self, text: str) -> str:
        text_lower = text.lower()
        if any(kw in text_lower for kw in ["zero-day", "0-day", "remote code execution", "rce", "ransomware", "nation-state", "apt", "critical vulnerability"]):
            return "critical"
        elif any(kw in text_lower for kw in ["exploit", "vulnerability", "cve", "patch", "backdoor", "malware campaign"]):
            return "high"
        elif any(kw in text_lower for kw in ["phishing", "malware", "threat actor", "incident", "breach"]):
            return "medium"
        elif any(kw in text_lower for kw in ["advisory", "update", "security"]):
            return "low"
        return "informational"


class RSSCollector(BaseCollector):
    """Collects articles from RSS/Atom feeds."""

    async def fetch(self) -> list[RawArticle]:
        rss_url = self.config.get("rss_url")
        if not rss_url:
            raise ValueError(f"No RSS URL for source: {self.source_name}")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,application/rss+xml,text/xml;q=0.8,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            feed_text = ""
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(10.0, connect=5.0),
                    headers=headers,
                    follow_redirects=True,
                    verify=True,
                ) as client:
                    resp = await client.get(rss_url)
                    resp.raise_for_status()
                    feed_text = resp.text
            except asyncio.CancelledError:
                raise
            except httpx.TimeoutException:
                raise
            except Exception as first_err:
                # Only fallback if error is SSL/Certificate related
                if "ssl" in str(first_err).lower() or "certificate" in str(first_err).lower():
                    async with httpx.AsyncClient(
                        timeout=httpx.Timeout(10.0, connect=5.0),
                        headers=headers,
                        follow_redirects=True,
                        verify=False,
                    ) as client:
                        resp = await client.get(rss_url)
                        resp.raise_for_status()
                        feed_text = resp.text
                else:
                    raise

            feed = feedparser.parse(feed_text)
            articles = []

            for entry in feed.entries[:50]:  # Max 50 per crawl
                published_at = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    import time
                    published_at = datetime.fromtimestamp(
                        time.mktime(entry.published_parsed), tz=timezone.utc
                    )

                content = ""
                if hasattr(entry, 'content') and entry.content:
                    content = entry.content[0].get('value', '')
                elif hasattr(entry, 'summary'):
                    content = entry.summary
                elif hasattr(entry, 'description'):
                    content = entry.description

                # Extract clean text from HTML if needed
                if '<' in content:
                    try:
                        from bs4 import BeautifulSoup
                        content = BeautifulSoup(content, 'lxml').get_text(separator=' ', strip=True)
                    except Exception:
                        pass

                # Clean summary — strip HTML if present (e.g. Medium RSS)
                raw_summary = entry.get('summary', '') or ''
                if '<' in raw_summary:
                    try:
                        from bs4 import BeautifulSoup as _BS
                        raw_summary = _BS(raw_summary, 'lxml').get_text(separator=' ', strip=True)
                    except Exception:
                        import re as _re
                        raw_summary = _re.sub(r'<[^>]+>', ' ', raw_summary).strip()
                raw_summary = raw_summary[:1000]

                articles.append(RawArticle(
                    url=entry.get('link', ''),
                    title=entry.get('title', 'Untitled')[:500],
                    content=content,
                    summary=raw_summary,
                    author=entry.get('author', None),
                    published_at=published_at,
                    tags=[tag.term for tag in getattr(entry, 'tags', []) if hasattr(tag, 'term')],
                ))

            return articles

        except asyncio.CancelledError:
            raise
        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}" if str(e) else type(e).__name__
            log.warning("RSS fetch failed", source=self.source_name, rss_url=rss_url, error=err_msg)
            raise


class HTMLScraperCollector(BaseCollector):
    """Collects articles by scraping web pages (e.g., OSINTxLab)."""

    async def fetch(self) -> list[RawArticle]:
        target_url = self.config.get("base_url") or self.config.get("url") or self.config.get("rss_url")
        if not target_url:
            raise ValueError(f"No target URL configured for scraper source: {self.source_name}")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            async with httpx.AsyncClient(
                headers=headers,
                follow_redirects=True,
                timeout=20.0,
                verify=False,
            ) as client:
                resp = await client.get(target_url)
                resp.raise_for_status()
                html_text = resp.text

            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_text, 'html.parser')

            articles = []
            seen_urls = set()

            for a in soup.find_all('a', href=True):
                href = a['href']
                title = a.get_text(strip=True)

                if href.startswith('#') or 'javascript:' in href or '/category/' in href or '/page/' in href:
                    continue

                # Strip Chinese characters & Chinese boilerplate from title
                clean_title = re.sub(r'[\u4e00-\u9fff]+', ' ', title)
                clean_title = re.sub(r'\s+', ' ', clean_title).strip()

                if not clean_title or clean_title.lower() in ['read more', 'osintxlab', 'all posts'] or len(clean_title) < 5:
                    continue

                if not href.startswith('http'):
                    base_prefix = target_url.rstrip('/')
                    if href.startswith('/'):
                        from urllib.parse import urlparse
                        parsed = urlparse(target_url)
                        base_prefix = f"{parsed.scheme}://{parsed.netloc}"
                    href = base_prefix + href

                if href in seen_urls:
                    continue
                seen_urls.add(href)

                parent = a.find_parent(['article', 'div', 'section', 'li'])
                summary = parent.get_text(separator=' ', strip=True) if parent else clean_title

                # Clean Chinese text & RSS boilerplate from summary
                clean_sum = re.sub(r'[\u4e00-\u9fff]+', ' ', summary)
                clean_sum = re.sub(r'\b\d+\s*阅读\b', '', clean_sum)
                clean_sum = re.sub(r'\b\d+\s*分钟\b', '', clean_sum)
                clean_sum = re.sub(r'阅读全文', '', clean_sum)
                clean_sum = re.sub(r'事件类型:\s*\w+', '', clean_sum)
                clean_sum = re.sub(r'报告时间:\s*[\d\-]+', '', clean_sum)
                clean_sum = re.sub(r'\s+', ' ', clean_sum).strip()

                if len(clean_sum) < 15:
                    clean_sum = clean_title

                articles.append(RawArticle(
                    url=href,
                    title=clean_title[:500],
                    content=clean_sum[:50000],
                    summary=clean_sum[:1000],
                    published_at=datetime.now(timezone.utc),
                    tags=self.config.get("tags", []),
                ))

                if len(articles) >= 30:
                    break

            return articles

        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.error("HTML Scrape failed", source=self.source_name, target_url=target_url, error=str(e))
            raise


class CollectorFactory:
    """Creates the appropriate collector for a given source config."""

    _registry = {
        "rss": RSSCollector,
        "scrape": HTMLScraperCollector,
    }

    @classmethod
    def create(cls, source_config: dict) -> BaseCollector:
        method = source_config.get("collection_method", "rss")
        collector_cls = cls._registry.get(method, RSSCollector)
        return collector_cls(source_config)


def categorize_error_reason(e: Exception) -> str:
    """Categorize raw feed errors into actionable triage categories."""
    if isinstance(e, (httpx.TimeoutException, asyncio.TimeoutError, TimeoutError)):
        return "DNS_CONNECT_TIMEOUT"
    if isinstance(e, httpx.HTTPStatusError):
        status = e.response.status_code
        if status == 429:
            return "RATE_LIMITED_429"
        elif status == 403:
            return "FORBIDDEN_403"
        elif status == 404:
            return "NOT_FOUND_404"
        elif status >= 500:
            return f"HTTP_ERROR_{status}"
    err_str = f"{type(e).__name__} {str(e)}".lower()
    if "429" in err_str or "rate limit" in err_str or "too many requests" in err_str:
        return "RATE_LIMITED_429"
    if "403" in err_str or "forbidden" in err_str:
        return "FORBIDDEN_403"
    if "404" in err_str or "not found" in err_str:
        return "NOT_FOUND_404"
    if "timeout" in err_str or "connect" in err_str or "dns" in err_str or "getaddrinfo" in err_str or "readtimeout" in err_str:
        return "DNS_CONNECT_TIMEOUT"
    if "ssl" in err_str or "certificate" in err_str:
        return "SSL_CERT_ERROR"
    if "xml" in err_str or "parse" in err_str or "syntax" in err_str:
        return "PARSE_ERROR"
    return "UNKNOWN_ERROR"


async def crawl_source(source_config: dict) -> dict:
    """Main entry point to crawl a single source."""
    collector = CollectorFactory.create(source_config)
    try:
        articles = await collector.fetch()
        result = await collector.store_articles(articles)
        
        # Mark source healthy and clear error reason
        sources_col = get_sources_collection()
        from bson import ObjectId
        try:
            await sources_col.update_one(
                {"_id": ObjectId(str(source_config.get("_id")))},
                {
                    "$set": {
                        "health_status": "healthy",
                        "last_error_reason": None,
                        "last_error": None,
                        "last_crawled_at": datetime.now(timezone.utc),
                    }
                }
            )
        except Exception:
            pass

        log.info(
            "Source crawled",
            source=source_config.get("name"),
            added=result["added"],
            skipped=result["skipped"],
        )
        return result
    except asyncio.CancelledError:
        log.info("Source crawl cancelled during task shutdown", source=source_config.get("name"))
        raise
    except Exception as e:
        reason = categorize_error_reason(e)
        health = "failing" if reason in ["NOT_FOUND_404", "FORBIDDEN_403"] else "degraded"
        err_msg = f"{type(e).__name__}: {str(e)}" if str(e) else type(e).__name__
        log.warning("Source crawl degraded", source=source_config.get("name"), reason=reason, error=err_msg)
        
        # Update source health and last_error_reason for fast triage
        sources_col = get_sources_collection()
        from bson import ObjectId
        try:
            await sources_col.update_one(
                {"_id": ObjectId(str(source_config.get("_id")))},
                {
                    "$set": {
                        "health_status": health,
                        "last_error_reason": reason,
                        "last_error": err_msg,
                        "last_crawled_at": datetime.now(timezone.utc),
                    }
                }
            )
        except Exception:
            pass
        return {"added": 0, "skipped": 0, "error": err_msg, "error_reason": reason}
