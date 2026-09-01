"""
Check & Remove Inactive / Dead Sources Script
Tests HTTP health status for all sources in MongoDB.
Removes any source returning 404, 410, DNS resolution failure, or permanent connection error.
"""
import sys
import os
import asyncio
import httpx
from datetime import datetime, timezone

sys.path.insert(0, r'd:\Feed\backend')
sys.stdout.reconfigure(encoding='utf-8')

from app.db.mongodb import MongoDB, get_sources_collection


async def check_source_health(client_ssl, client_nossl, url: str) -> tuple[bool, str]:
    """Test HTTP connection to RSS/API feed URL."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/rss+xml, application/xml, application/atom+xml, application/json, text/xml, */*"
    }
    
    try:
        resp = await client_ssl.get(url, headers=headers)
        if resp.status_code in (200, 301, 302, 304, 307, 308):
            return True, f"HTTP {resp.status_code}"
        elif resp.status_code in (404, 410, 403, 500, 502, 503):
            # Try SSL fallback or mark dead
            if resp.status_code in (404, 410):
                return False, f"HTTP {resp.status_code}"
    except httpx.SSLError:
        pass
    except Exception as e:
        pass

    # SSL fallback check
    try:
        resp = await client_nossl.get(url, headers=headers)
        if resp.status_code in (200, 301, 302, 304, 307, 308):
            return True, f"HTTP {resp.status_code} (SSL Bypass)"
        return False, f"HTTP {resp.status_code}"
    except Exception as e:
        err_msg = str(e)
        if "Name or service not known" in err_msg or "getaddrinfo failed" in err_msg:
            return False, "DNS Resolution Failed"
        return False, f"Error: {type(e).__name__}"


async def main():
    await MongoDB.connect()
    sources_col = get_sources_collection()
    
    all_sources = await sources_col.find({}).to_list(length=200)
    print(f"=== CHECKING HEALTH FOR {len(all_sources)} SOURCES IN DATABASE ===\n")

    active_sources = []
    inactive_sources = []

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=True) as client_ssl:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client_nossl:
            for src in all_sources:
                name = src.get("name", "Unknown")
                url = src.get("rss_url", "")
                
                if not url:
                    inactive_sources.append((src, "Missing URL"))
                    continue

                is_healthy, status_str = await check_source_health(client_ssl, client_nossl, url)

                # Fallback for Cloudflare-blocked feeds (e.g. BleepingComputer)
                if not is_healthy and "bleepingcomputer.com" in url:
                    fallback_url = "https://news.google.com/rss/search?q=site:bleepingcomputer.com+cybersecurity&hl=en-US&gl=US&ceid=US:en"
                    is_healthy, status_str = await check_source_health(client_ssl, client_nossl, fallback_url)
                    if is_healthy:
                        url = fallback_url
                        status_str += " (Google Mirror)"
                
                if is_healthy:
                    active_sources.append((src, status_str))
                    print(f"  🟢 [ACTIVE]   {name:<42} -> {status_str}")
                    await sources_col.update_one({"_id": src["_id"]}, {"$set": {"health_status": "healthy", "is_active": True, "rss_url": url}})
                else:
                    inactive_sources.append((src, status_str))
                    print(f"  🔴 [REMOVED]  {name:<42} -> {status_str}")

    # Remove inactive sources from MongoDB
    removed_ids = [src["_id"] for src, _ in inactive_sources]
    if removed_ids:
        res = await sources_col.delete_many({"_id": {"$in": removed_ids}})
        print(f"\n[*] Deleted {res.deleted_count} inactive sources from database.")

    total_remaining = await sources_col.count_documents({})

    print("\n================ SUMMARY ================")
    print(f"Total Sources Checked:  {len(all_sources)}")
    print(f"Active & Kept:         {len(active_sources)}")
    print(f"Inactive & Removed:    {len(inactive_sources)}")
    print(f"Remaining DB Sources:  {total_remaining}")
    print("=========================================\n")

    if inactive_sources:
        print("--- Removed Inactive Sources List ---")
        for src, reason in inactive_sources:
            print(f"  • {src.get('name')} ({src.get('rss_url')}) -> Reason: {reason}")


if __name__ == "__main__":
    asyncio.run(main())
