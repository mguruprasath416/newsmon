"""
CISA KEV Synchronization Service
Fetches and stores the CISA Known Exploited Vulnerabilities catalog.
"""
import httpx
from datetime import datetime, timezone
from app.config import settings
from app.db.mongodb import get_kev_collection
import structlog

log = structlog.get_logger()


class KEVSyncService:
    """Synchronizes the CISA KEV catalog."""

    async def sync(self) -> dict:
        """Fetch and upsert KEV catalog."""
        log.info("Starting CISA KEV sync")
        col = get_kev_collection()
        added = 0
        updated = 0

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(settings.CISA_KEV_URL)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            log.error("KEV fetch failed", error=str(e))
            raise

        vulnerabilities = data.get("vulnerabilities", [])
        log.info(f"Fetched {len(vulnerabilities)} KEV entries")

        for entry in vulnerabilities:
            doc = self._parse_entry(entry)
            result = await col.update_one(
                {"cve_id": doc["cve_id"]},
                {"$set": doc},
                upsert=True,
            )
            if result.upserted_id:
                added += 1
            elif result.modified_count:
                updated += 1

        log.info(f"KEV sync complete: {added} added, {updated} updated")
        return {"added": added, "updated": updated, "total": len(vulnerabilities)}

    def _parse_entry(self, entry: dict) -> dict:
        """Parse a KEV catalog entry."""
        date_added = self._parse_date(entry.get("dateAdded"))
        due_date = self._parse_date(entry.get("dueDate"))

        return {
            "cve_id": entry.get("cveID", "").upper(),
            "vendor": entry.get("vendorProject", "Unknown"),
            "product": entry.get("product", "Unknown"),
            "vulnerability_name": entry.get("vulnerabilityName", ""),
            "description": entry.get("shortDescription", ""),
            "date_added": date_added,
            "due_date": due_date,
            "required_action": entry.get("requiredAction", ""),
            "known_ransomware": entry.get("knownRansomwareCampaignUse", "Unknown").lower() == "known",
            "notes": entry.get("notes", ""),
            "references": [],
            "synced_at": datetime.now(timezone.utc),
            "threat_actors": [],
            "campaigns": [],
            "cvss_v3_score": None,
            "epss_score": None,
            "epss_percentile": None,
        }

    def _parse_date(self, date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"]:
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    async def enrich_epss(self) -> int:
        """Enrich all KEV entries with EPSS scores."""
        col = get_kev_collection()
        enriched = 0

        # Get all CVE IDs without EPSS
        cursor = col.find({"epss_score": None}, {"cve_id": 1})
        cve_ids = [doc["cve_id"] async for doc in cursor]

        if not cve_ids:
            log.info("All KEV entries already have EPSS scores")
            return 0

        # Batch fetch EPSS (max 100 per request)
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i:i+100]
            scores = await self._fetch_epss_batch(batch)

            for cve_id, score_data in scores.items():
                await col.update_one(
                    {"cve_id": cve_id},
                    {"$set": {
                        "epss_score": score_data.get("epss"),
                        "epss_percentile": score_data.get("percentile"),
                        "epss_date": datetime.now(timezone.utc),
                    }}
                )
                enriched += 1

        log.info(f"EPSS enrichment complete: {enriched} entries enriched")
        return enriched

    async def _fetch_epss_batch(self, cve_ids: list[str]) -> dict:
        """Fetch EPSS scores for a batch of CVEs."""
        cve_param = ",".join(cve_ids)
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    settings.EPSS_API_URL,
                    params={"cve": cve_param}
                )
                resp.raise_for_status()
                data = resp.json()
                return {item["cve"]: item for item in data.get("data", [])}
        except Exception as e:
            log.warning("EPSS batch fetch failed", error=str(e))
            return {}
