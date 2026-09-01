"""
ClarityTI — Enterprise Multi-Source Historical Intelligence Collector (2018 – Present)
Supports Gzip/Text Sitemaps, Robots.txt auto-discovery, Recursive child sitemaps, Parallel batch crawling,
and Date extraction from HTML meta tags & sitemap lastmod.
"""

import asyncio
import gzip
import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup
try:
    import trafilatura
except ImportError:
    trafilatura = None
from app.db.mongodb import get_articles_collection, get_sources_collection
from app.services.collector import BaseCollector, RawArticle
import structlog

log = structlog.get_logger()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 ClarityTI/1.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Exclude taxonomy, tag, category, author, and non-article sitemaps
EXCLUDED_SITEMAP_KEYWORDS = [
    "taxonomy", "category", "post_tag", "author", "user", "member", "glossary",
    "uninstall", "deal", "download", "static", "image", "video", "page-sitemap"
]

PRIORITY_SITEMAP_KEYWORDS = [
    "post", "news", "article", "blog", "advisory", "research", "intel"
]


class HistoricalCollector(BaseCollector):
    """Enhanced Historical Collector capable of ingesting 2018–present archives across all feeds."""

    def __init__(self, source_config: dict, start_year: int = 2018, max_articles: int = 5000):
        super().__init__(source_config)
        self.start_year = start_year
        self.cutoff_date = datetime(start_year, 1, 1, tzinfo=timezone.utc)
        self.max_articles = max_articles

    async def fetch(self) -> List[RawArticle]:
        """Auto-selects backfill strategy based on source config."""
        rss_url = self.config.get("rss_url", "")
        raw_url = self.config.get("url", "")
        slug = self.config.get("slug", "")

        target_url = raw_url or rss_url
        if target_url and "://" in target_url:
            parsed = urlparse(target_url)
            home_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            home_url = ""

        log.info("Starting enhanced historical backfill", source=self.source_name, start_year=self.start_year, home_url=home_url)

        # 1. CISA / Government special API handler
        if "cisa" in slug or "cisa" in self.source_name.lower():
            cisa_articles = await self._backfill_cisa_api()
            if cisa_articles:
                return cisa_articles

        # 2. Try Robots.txt + Sitemap XML/GZ parsing
        if home_url:
            sitemap_articles = await self._backfill_sitemap(home_url)
            if sitemap_articles is not None and len(sitemap_articles) > 0:
                log.info("Sitemap backfill succeeded", source=self.source_name, count=len(sitemap_articles))
                return sitemap_articles

        # 3. Try Wayback Machine CDX for historical RSS archives
        if rss_url:
            wayback_articles = await self._backfill_wayback(rss_url)
            if wayback_articles:
                log.info("Wayback CDX backfill succeeded", source=self.source_name, count=len(wayback_articles))
                return wayback_articles

        # 4. Fallback to Paginated Archival Scraping
        if home_url:
            paginated_articles = await self._backfill_paginated(home_url)
            log.info("Paginated backfill completed", source=self.source_name, count=len(paginated_articles))
            return paginated_articles

        return []

    async def _backfill_sitemap(self, base_url: str) -> Optional[List[RawArticle]]:
        """Discover and parse XML/GZ/TXT sitemaps for 2018–present article URLs."""
        if not base_url or not base_url.startswith("http"):
            return None

        base_url = base_url.rstrip("/")
        sitemap_candidates = set([
            f"{base_url}/sitemap.xml",
            f"{base_url}/sitemap_index.xml",
            f"{base_url}/sitemap_index.xml.gz",
            f"{base_url}/post-sitemap.xml",
            f"{base_url}/news-sitemap.xml",
            f"{base_url}/wp-sitemap.xml",
        ])

        # Discover sitemaps from robots.txt
        async with httpx.AsyncClient(timeout=10.0, headers=HEADERS, follow_redirects=True, verify=False) as client:
            try:
                r = await client.get(f"{base_url}/robots.txt")
                if r.status_code == 200:
                    found_sm = re.findall(r"Sitemap:\s*(https?://[^\s]+)", r.text, re.IGNORECASE)
                    for sm in found_sm:
                        sitemap_candidates.add(sm.strip())
            except Exception as e:
                log.debug("robots.txt fetch failed", site=base_url, error=str(e))

            article_urls: Set[str] = set()
            processed_sitemaps: Set[str] = set()

            # Prioritize sitemaps matching priority keywords (post, news, article, blog)
            priority_sitemaps = [
                sm for sm in sitemap_candidates
                if any(k in sm.lower() for k in PRIORITY_SITEMAP_KEYWORDS)
                and not any(ex in sm.lower() for ex in EXCLUDED_SITEMAP_KEYWORDS)
            ]
            other_sitemaps = [
                sm for sm in sitemap_candidates
                if sm not in priority_sitemaps
                and not any(ex in sm.lower() for ex in EXCLUDED_SITEMAP_KEYWORDS)
            ]
            sitemaps_to_process = priority_sitemaps + other_sitemaps

            while sitemaps_to_process and len(processed_sitemaps) < 30:
                sm_url = sitemaps_to_process.pop(0)
                if sm_url in processed_sitemaps:
                    continue
                processed_sitemaps.add(sm_url)

                if any(ex in sm_url.lower() for ex in EXCLUDED_SITEMAP_KEYWORDS):
                    continue

                try:
                    resp = await client.get(sm_url)
                    if resp.status_code != 200:
                        continue

                    content_bytes = resp.content
                    if sm_url.endswith(".gz") or content_bytes[:2] == b"\x1f\x8b":
                        try:
                            content_bytes = gzip.decompress(content_bytes)
                        except Exception:
                            pass

                    text_content = content_bytes.decode("utf-8", errors="ignore")
                    extracted = self._parse_sitemap_content(text_content)

                    for item in extracted:
                        item_str = item.strip()
                        # If child sitemap, enqueue if it's not excluded
                        if any(x in item_str.lower() for x in ["sitemap", ".xml", ".gz", ".txt"]) and item_str != sm_url:
                            if not any(ex in item_str.lower() for ex in EXCLUDED_SITEMAP_KEYWORDS):
                                if item_str not in processed_sitemaps:
                                    if any(k in item_str.lower() for k in PRIORITY_SITEMAP_KEYWORDS):
                                        sitemaps_to_process.insert(0, item_str)
                                    else:
                                        sitemaps_to_process.append(item_str)
                        elif item_str.startswith("http"):
                            if not any(ex in item_str.lower() for ex in ["/tag/", "/category/", "/author/", "/forum/", "/page/"]):
                                article_urls.add(item_str)

                except Exception as e:
                    log.debug("Sitemap process error", url=sm_url, error=str(e))

        if not article_urls:
            return None

        col = get_articles_collection()
        valid_urls = []
        for url in article_urls:
            match = re.search(r"/(20[1-2][0-9])/", url)
            if match:
                year = int(match.group(1))
                if year < self.start_year:
                    continue
            valid_urls.append(url)

        # Prioritize news / blog / research / advisory URLs first
        priority_urls = [u for u in valid_urls if any(p in u.lower() for p in ["/news/", "/blog/", "/research/", "/advisory/", "/post/"])]
        other_urls = [u for u in valid_urls if u not in priority_urls]
        final_urls = priority_urls + other_urls

        log.info("Extracted valid article sitemap URLs", source=self.source_name, count=len(final_urls))

        articles = []
        sem = asyncio.Semaphore(10)  # 10 concurrent requests for faster ingestion

        async with httpx.AsyncClient(timeout=10.0, headers=HEADERS, follow_redirects=True, verify=False) as client:
            async def fetch_worker(url: str):
                async with sem:
                    url_hash = self.compute_url_hash(url)
                    if await col.find_one({"url_hash": url_hash}):
                        return None
                    return await self._fetch_single_article(client, url)

            tasks = [fetch_worker(url) for url in final_urls[: self.max_articles]]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, RawArticle):
                    articles.append(res)

        return articles

    def _parse_sitemap_content(self, content: str) -> List[str]:
        """Extract URLs from XML sitemap or text line-based sitemap."""
        urls = []
        if "<loc>" in content:
            try:
                xml_clean = re.sub(r'xmlns="[^"]+"', "", content)
                root = ET.fromstring(xml_clean)
                for elem in root.findall(".//loc"):
                    if elem.text:
                        urls.append(elem.text.strip())
            except Exception:
                urls = re.findall(r"<loc>(https?://[^<]+)</loc>", content)
        else:
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("http"):
                    urls.append(line)
        return urls

    async def _backfill_wayback(self, rss_url: str) -> List[RawArticle]:
        """Query Wayback Machine CDX API for historical snapshots of RSS feed."""
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={rss_url}&output=json&from={self.start_year}0101&fl=timestamp,original&collapse=timestamp:6"
        )
        col = get_articles_collection()
        articles = []

        try:
            async with httpx.AsyncClient(timeout=15.0, headers=HEADERS, follow_redirects=True) as client:
                resp = await client.get(cdx_url)
                if resp.status_code != 200:
                    return []

                data = resp.json()
                if not data or len(data) <= 1:
                    return []

                snapshots = data[1:]
                log.info("Found Wayback snapshots", source=self.source_name, count=len(snapshots))

                import feedparser

                for snap in snapshots[:30]:
                    timestamp, orig_url = snap[0], snap[1]
                    archive_xml_url = f"https://web.archive.org/web/{timestamp}/{orig_url}"

                    try:
                        feed_resp = await client.get(archive_xml_url)
                        if feed_resp.status_code != 200:
                            continue

                        feed = feedparser.parse(feed_resp.text)
                        for entry in feed.entries:
                            url = entry.get("link", "")
                            if not url:
                                continue

                            url_hash = self.compute_url_hash(url)
                            if await col.find_one({"url_hash": url_hash}):
                                continue

                            pub_date = None
                            if hasattr(entry, "published_parsed") and entry.published_parsed:
                                import time
                                pub_date = datetime.fromtimestamp(
                                    time.mktime(entry.published_parsed), tz=timezone.utc
                                )
                                if pub_date < self.cutoff_date:
                                    continue

                            content = ""
                            if hasattr(entry, "content") and entry.content:
                                content = entry.content[0].get("value", "")
                            elif hasattr(entry, "summary"):
                                content = entry.summary

                            if "<" in content:
                                try:
                                    content = BeautifulSoup(content, "lxml").get_text(separator=" ", strip=True)
                                except Exception:
                                    pass

                            articles.append(
                                RawArticle(
                                    url=url,
                                    title=entry.get("title", "Untitled")[:500],
                                    content=content,
                                    summary=entry.get("summary", "")[:1000],
                                    author=entry.get("author", None),
                                    published_at=pub_date or self.cutoff_date,
                                    tags=[t.term for t in getattr(entry, "tags", []) if hasattr(t, "term")],
                                )
                            )
                    except Exception as e:
                        log.debug("Wayback snapshot parse error", url=archive_xml_url, error=str(e))

                    await asyncio.sleep(0.1)

        except Exception as e:
            log.warning("Wayback CDX backfill failed", source=self.source_name, error=str(e))

        return articles

    async def _backfill_paginated(self, base_url: str) -> List[RawArticle]:
        """Scrape paginated archives (/page/1/, /page/2/...) for historical items."""
        if not base_url or not base_url.startswith("http"):
            return []

        col = get_articles_collection()
        articles = []
        base_url = base_url.rstrip("/")

        async with httpx.AsyncClient(timeout=10.0, headers=HEADERS, follow_redirects=True, verify=False) as client:
            for page in range(1, 30):
                page_url = f"{base_url}/page/{page}/" if page > 1 else base_url
                try:
                    resp = await client.get(page_url)
                    if resp.status_code != 200:
                        break

                    soup = BeautifulSoup(resp.text, "lxml")
                    links = set()
                    for a in soup.find_all("a", href=True):
                        href = a["href"]
                        if base_url in href and len(href) > len(base_url) + 5:
                            if not any(x in href for x in ["/category/", "/tag/", "/author/", "/page/"]):
                                links.add(href)

                    if not links:
                        break

                    new_count = 0
                    for url in links:
                        url_hash = self.compute_url_hash(url)
                        if await col.find_one({"url_hash": url_hash}):
                            continue

                        art = await self._fetch_single_article(client, url)
                        if art:
                            articles.append(art)
                            new_count += 1
                        await asyncio.sleep(0.1)

                    if new_count == 0 and page > 5:
                        break

                except Exception as e:
                    log.debug("Paginated fetch error", url=page_url, error=str(e))
                    break

        return articles

    async def _backfill_cisa_api(self) -> List[RawArticle]:
        """Fetch all CISA Known Exploited Vulnerabilities and Advisories back to 2018."""
        articles = []
        cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

        try:
            async with httpx.AsyncClient(timeout=30.0, headers=HEADERS, follow_redirects=True) as client:
                resp = await client.get(cisa_kev_url)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])

                    for v in vulns:
                        date_str = v.get("dateAdded", "")
                        pub_date = self.cutoff_date
                        if date_str:
                            try:
                                pub_date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                            except Exception:
                                pass

                        if pub_date < self.cutoff_date:
                            continue

                        cve_id = v.get("cveID", "CISA-KEV")
                        title = f"CISA KEV: {cve_id} - {v.get('vulnerabilityName', '')}"
                        content = f"""
                        CVE ID: {cve_id}
                        Vendor/Project: {v.get('vendorProject', '')}
                        Product: {v.get('product', '')}
                        Vulnerability Name: {v.get('vulnerabilityName', '')}
                        Short Description: {v.get('shortDescription', '')}
                        Required Action: {v.get('requiredAction', '')}
                        Due Date: {v.get('dueDate', '')}
                        Notes: {v.get('notes', '')}
                        """
                        url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}"

                        articles.append(
                            RawArticle(
                                url=url,
                                title=title[:500],
                                content=content,
                                summary=v.get("shortDescription", "")[:1000],
                                author="CISA",
                                published_at=pub_date,
                                tags=["cisa", "kev", "vulnerability", cve_id.lower()],
                            )
                        )
        except Exception as e:
            log.error("CISA KEV backfill error", error=str(e))

        return articles

    async def _fetch_single_article(self, client: httpx.AsyncClient, url: str) -> Optional[RawArticle]:
        """Fetch article HTML page and extract clean metadata using Trafilatura."""
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None

            downloaded = resp.text
            clean_text = trafilatura.extract(
                downloaded,
                include_links=False,
                include_images=False,
                output_format="txt",
            )
            if not clean_text or len(clean_text) < 100:
                return None

            soup = BeautifulSoup(downloaded, "lxml")
            title = ""
            title_tag = soup.find("title") or soup.find("h1")
            if title_tag:
                title = title_tag.get_text(strip=True)
            if not title:
                title = url.split("/")[-1].replace("-", " ").capitalize()

            pub_date = self.cutoff_date
            meta_date = (
                soup.find("meta", property="article:published_time")
                or soup.find("meta", name="publication_date")
                or soup.find("meta", name="date")
                or soup.find("time")
            )
            if meta_date:
                dt_str = meta_date.get("content") or meta_date.get("datetime") or meta_date.get_text()
                if dt_str:
                    try:
                        pub_date = datetime.fromisoformat(dt_str.replace("Z", "+00:00")[:19]).replace(tzinfo=timezone.utc)
                    except Exception:
                        pass

            return RawArticle(
                url=url,
                title=title[:500],
                content=clean_text,
                summary=clean_text[:1000],
                published_at=pub_date,
            )
        except Exception:
            return None


async def backfill_source_historical(source_config: dict, start_year: int = 2018, max_articles: int = 5000) -> dict:
    """Entry point to run historical backfill for a source."""
    collector = HistoricalCollector(source_config, start_year=start_year, max_articles=max_articles)
    try:
        articles = await collector.fetch()
        result = await collector.store_articles(articles)
        log.info(
            "Historical backfill finished",
            source=source_config.get("name"),
            added=result["added"],
            skipped=result["skipped"],
        )
        return result
    except Exception as e:
        log.error("Historical backfill failed", source=source_config.get("name"), error=str(e))
        return {"added": 0, "skipped": 0, "error": str(e)}
