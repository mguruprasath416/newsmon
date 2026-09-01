"""
ClarityTI — Standalone CLI Script for Threat Actor Article Entity Matching & Linking
======================================================================================
Usage:
    python -m scripts.link_threat_actors
"""

import asyncio
import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.mongodb import MongoDB
from app.services.threat_actor_matcher import link_all_articles_to_threat_actors
import structlog

log = structlog.get_logger()


async def main():
    print("[+] Connecting to MongoDB...")
    await MongoDB.connect()

    print("[+] Running Threat Actor Article Entity Matching & Count Linking...")
    result = await link_all_articles_to_threat_actors()

    print("\n[+] Threat Actor Article Linking Completed!")
    print(f"    Total Articles Processed: {result.get('total_articles')}")
    print(f"    Articles Tagged/Updated:  {result.get('articles_tagged')}")
    print(f"    Threat Actors Updated:   {result.get('threat_actors_updated')}")

    top_linked = result.get("top_linked_actors", {})
    if top_linked:
        print("\n[+] Top Threat Actors Linked to Articles:")
        for actor, cnt in top_linked.items():
            print(f"    +-- {actor:<30} : {cnt} articles")

    await MongoDB.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
