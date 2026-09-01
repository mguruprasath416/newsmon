import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import structlog
from app.tasks.feed_tasks import _async_crawl_all_feeds, _async_dispatch_teams_daily_news

log = structlog.get_logger()


async def main():
    log.info("Starting Crawl & Teams Dispatch pipeline...")
    
    # 1. Crawl all feeds including India sources
    crawl_result = await _async_crawl_all_feeds()
    log.info("Crawl finished", result=crawl_result)

    # 2. Dispatch to Teams channels (#high-priority-news, #indian-breaches, #middle-east-companies)
    dispatch_result = await _async_dispatch_teams_daily_news()
    log.info("Teams Dispatch finished", result=dispatch_result)

    print("\n================ PIPELINE EXECUTION SUMMARY ================")
    print(f"Crawl Result:    {crawl_result}")
    print(f"Teams Dispatch:  {dispatch_result}")
    print("============================================================\n")

if __name__ == "__main__":
    asyncio.run(main())
